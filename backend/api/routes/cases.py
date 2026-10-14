"""
Case Management Endpoints — AegisShield
========================================
Implements investigation case triage and analyst review workflow (UX 15%):
- GET  /api/cases             — List cases with filters (status, priority)
- GET  /api/cases/{id}        — Full case detail with detection & asset metadata
- POST /api/cases/{id}/review — Record analyst decision, transition status, log audit event
"""

from typing import Optional, Dict, Any
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session
from sqlalchemy import desc

from db.session import get_db
from db.models import Case, Detection, Asset, AuditEvent

router = APIRouter()


@router.get("/cases")
async def list_cases(
    case_status: Optional[str] = Query(None, alias="status", description="Filter by status (open, reviewing, escalated, closed)"),
    priority: Optional[str] = Query(None, description="Filter by priority (low, medium, high)"),
    offset: int = Query(0, ge=0, description="Number of cases to skip (pagination)"),
    limit: int = Query(50, ge=1, le=100),
    db: Session = Depends(get_db)
):
    """Return cases joined with detection score, tier, and asset value with pagination."""
    query = db.query(Case).join(Detection).join(Asset)

    if case_status:
        query = query.filter(Case.status == case_status)
    if priority:
        query = query.filter(Case.priority == priority)

    total = query.count()
    records = query.order_by(desc(Case.id)).offset(offset).limit(limit).all()

    items = []
    for c in records:
        det = c.detection
        asset = det.asset if det else None
        items.append({
            "id": c.id,
            "status": c.status,
            "priority": c.priority,
            "created_at": c.created_at.isoformat() if c.created_at else None,
            "closed_at": c.closed_at.isoformat() if c.closed_at else None,
            "detection": {
                "id": det.id if det else None,
                "final_score": det.final_score if det else 0.0,
                "tier": det.tier if det else 0,
                "tier_label": "Escalate (Critical)" if det and det.tier == 2 else ("Review (Suspected)" if det and det.tier == 1 else "Observe (Benign)"),
                "reason_codes": det.reason_codes_json or [] if det else [],
            } if det else None,
            "asset": {
                "id": asset.id if asset else None,
                "value": asset.value if asset else "",
                "type": asset.type if asset else "",
                "source": asset.source if asset else "",
            } if asset else None,
        })

    return {"total": total, "offset": offset, "limit": limit, "cases": items}


@router.get("/cases/{case_id}")
async def get_case(case_id: int, db: Session = Depends(get_db)):
    """Get full case detail including detection signals and component scores."""
    c = db.query(Case).filter(Case.id == case_id).first()
    if not c:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Case {case_id} not found."
        )

    det = c.detection
    asset = det.asset if det else None

    return {
        "id": c.id,
        "status": c.status,
        "priority": c.priority,
        "created_at": c.created_at.isoformat() if c.created_at else None,
        "closed_at": c.closed_at.isoformat() if c.closed_at else None,
        "detection": {
            "id": det.id if det else None,
            "final_score": det.final_score if det else 0.0,
            "tier": det.tier if det else 0,
            "component_scores": det.component_scores_json or {} if det else {},
            "reason_codes": det.reason_codes_json or [] if det else [],
            "model_version": det.model_version if det else None,
            "rule_version": det.rule_version if det else None,
        } if det else None,
        "asset": {
            "id": asset.id if asset else None,
            "value": asset.value if asset else "",
            "type": asset.type if asset else "",
            "source": asset.source if asset else "",
        } if asset else None,
    }


@router.post("/cases/{case_id}/review")
async def review_case(case_id: int, payload: Dict[str, Any], db: Session = Depends(get_db)):
    """Record reviewer label, update status, and log audit event."""
    c = db.query(Case).filter(Case.id == case_id).first()
    if not c:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Case {case_id} not found."
        )

    VALID_STATUSES = {"open", "reviewing", "escalated", "closed"}
    VALID_PRIORITIES = {"low", "medium", "high"}

    prev_status = c.status
    new_status = payload.get("status", prev_status).lower() if "status" in payload else prev_status
    new_priority = payload.get("priority", c.priority).lower() if "priority" in payload else c.priority
    reviewer = payload.get("reviewer", "SOC Analyst")

    if new_status not in VALID_STATUSES:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid status '{new_status}'. Allowed: {', '.join(sorted(VALID_STATUSES))}"
        )
    if new_priority not in VALID_PRIORITIES:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid priority '{new_priority}'. Allowed: {', '.join(sorted(VALID_PRIORITIES))}"
        )

    c.status = new_status
    c.priority = new_priority
    if new_status == "closed":
        c.closed_at = datetime.utcnow()

    audit = AuditEvent(
        actor=reviewer,
        role="analyst",
        action=f"Reviewed case {case_id}: status '{prev_status}' -> '{new_status}'",
        case_id=c.id,
        previous_state=prev_status,
        new_state=new_status,
    )
    db.add(audit)
    db.commit()

    return {
        "message": "Review recorded successfully",
        "case_id": case_id,
        "status": c.status,
        "priority": c.priority
    }

