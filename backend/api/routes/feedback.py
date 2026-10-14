"""
Analyst Feedback & Active Learning API — AegisShield
=====================================================
Captures SOC analyst verdicts on detections for active learning, precision tracking,
and automated case state transitions:
- POST /api/feedback         — Submit verdict (confirmed_threat, false_positive, uncertain)
- GET  /api/feedback/summary — Real-time accuracy, precision, and false-positive statistics
"""

from datetime import datetime
from typing import Optional, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from sqlalchemy import desc

from db.session import get_db
from db.models import Detection, Case, CaseNote, AuditEvent, User

router = APIRouter()


@router.post("/feedback")
async def submit_feedback(payload: Dict[str, Any], db: Session = Depends(get_db)):
    """
    Store analyst verdict on a detection record.
    Automatically syncs linked case status and appends to the immutable audit log.
    """
    detection_id = payload.get("detection_id")
    if not detection_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Missing required field: 'detection_id'"
        )

    detection = db.query(Detection).filter(Detection.id == detection_id).first()
    if not detection:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Detection with id {detection_id} not found"
        )

    verdict = payload.get("verdict", "confirmed_threat").lower()
    valid_verdicts = ["confirmed_threat", "false_positive", "uncertain"]
    if verdict not in valid_verdicts:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid verdict. Must be one of: {', '.join(valid_verdicts)}"
        )

    analyst_id = payload.get("analyst_id")
    notes = payload.get("notes") or payload.get("reason", "")
    analyst_name = "SOC Reviewer"

    if analyst_id:
        analyst_user = db.query(User).filter(User.id == analyst_id).first()
        if analyst_user:
            analyst_name = analyst_user.name

    # Find linked case if one exists
    linked_case = db.query(Case).filter(Case.detection_id == detection.id).first()
    case_id = linked_case.id if linked_case else None
    prev_case_status = linked_case.status if linked_case else "none"

    if linked_case:
        if verdict == "confirmed_threat":
            linked_case.status = "escalated"
            linked_case.priority = "high"
        elif verdict == "false_positive":
            linked_case.status = "closed"
            linked_case.closed_at = datetime.utcnow()
        elif verdict == "uncertain":
            linked_case.status = "reviewing"

        if notes:
            note_obj = CaseNote(
                case_id=linked_case.id,
                user_id=analyst_id,
                text=f"Analyst Verdict: {verdict.upper()} — {notes}"
            )
            db.add(note_obj)

    # Record immutable audit event
    audit_evt = AuditEvent(
        actor=analyst_name,
        role="analyst",
        action=f"FEEDBACK_{verdict.upper()}",
        case_id=case_id,
        previous_state=prev_case_status,
        new_state=linked_case.status if linked_case else verdict,
    )
    db.add(audit_evt)
    db.commit()

    return {
        "status": "success",
        "message": f"Analyst feedback recorded as '{verdict}'",
        "detection_id": detection.id,
        "case_id": case_id,
        "case_new_status": linked_case.status if linked_case else None,
        "recorded_at": datetime.utcnow().isoformat(),
    }


@router.get("/feedback/summary")
async def get_feedback_summary(db: Session = Depends(get_db)):
    """
    Returns aggregate analyst feedback metrics, false-positive rates, and model precision.
    """
    events = (
        db.query(AuditEvent)
        .filter(AuditEvent.action.like("FEEDBACK_%"))
        .all()
    )

    total_reviews = len(events)
    confirmed_count = sum(1 for e in events if "CONFIRMED_THREAT" in e.action)
    false_pos_count = sum(1 for e in events if "FALSE_POSITIVE" in e.action)
    uncertain_count = sum(1 for e in events if "UNCERTAIN" in e.action)

    fp_rate = round((false_pos_count / total_reviews) * 100.0, 1) if total_reviews > 0 else 0.0
    precision = round((confirmed_count / (confirmed_count + false_pos_count)) * 100.0, 1) if (confirmed_count + false_pos_count) > 0 else 100.0

    recent_events = (
        db.query(AuditEvent)
        .filter(AuditEvent.action.like("FEEDBACK_%"))
        .order_by(desc(AuditEvent.created_at))
        .limit(10)
        .all()
    )

    return {
        "status": "success",
        "total_reviews": total_reviews,
        "confirmed_threats": confirmed_count,
        "false_positives": false_pos_count,
        "uncertain": uncertain_count,
        "false_positive_rate_pct": fp_rate,
        "model_precision_pct": precision,
        "recent_feedback": [
            {
                "actor": e.actor,
                "action": e.action,
                "case_id": e.case_id,
                "timestamp": e.created_at.isoformat() if e.created_at else None,
            }
            for e in recent_events
        ]
    }
