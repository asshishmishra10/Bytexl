"""
Detections Feed API — AegisShield
==================================
Lists and filters threat detections recorded by the platform (UX 15%):
- GET /api/detections — Filter by tier, asset type, or limit
"""

from typing import Optional
from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from sqlalchemy import desc

from db.session import get_db
from db.models import Detection, Asset
from services.fusion.engine import get_tier_label

router = APIRouter()


@router.get("/detections")
async def list_detections(
    tier: Optional[int] = Query(None, description="Filter by risk tier (0, 1, 2)"),
    asset_type: Optional[str] = Query(None, description="Filter by asset type (profile, app)"),
    offset: int = Query(0, ge=0, description="Number of detections to skip (pagination)"),
    limit: int = Query(50, ge=1, le=100),
    db: Session = Depends(get_db)
):
    """Return stored detections joined with asset values, provenance, SHAP, and reason codes."""
    query = db.query(Detection).join(Asset)

    if tier is not None:
        query = query.filter(Detection.tier == tier)
    if asset_type:
        query = query.filter(Asset.type == asset_type)

    total = query.count()
    records = query.order_by(desc(Detection.id)).offset(offset).limit(limit).all()

    items = []
    for d in records:
        items.append({
            "id": d.id,
            "asset_id": d.asset_id,
            "asset_value": d.asset.value if d.asset else "",
            "asset_type": d.asset.type if d.asset else "",
            "asset_source": d.asset.source if d.asset else "",
            "provenance": d.asset.provenance if d.asset and d.asset.provenance else "live",
            "final_score": d.final_score,
            "tier": d.tier,
            "tier_label": get_tier_label(d.tier, d.asset.type if d.asset else None),
            "component_scores": d.component_scores_json or {},
            "reason_codes": d.reason_codes_json or [],
            "shap": d.shap_json or {},
            "model_version": d.model_version or "v1.0",
            "rule_version": d.rule_version or "v1.0",
            "created_at": d.created_at.isoformat() if d.created_at else None
        })

    return {
        "total": total,
        "offset": offset,
        "limit": limit,
        "detections": items
    }


@router.get("/detections/{detection_id}")
async def get_detection(detection_id: int, db: Session = Depends(get_db)):
    """Retrieve full detail for a single detection record, including SHAP, provenance, and components."""
    d = db.query(Detection).filter(Detection.id == detection_id).first()
    if not d:
        from fastapi import HTTPException, status
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Detection {detection_id} not found."
        )

    return {
        "id": d.id,
        "asset_id": d.asset_id,
        "asset_value": d.asset.value if d.asset else "",
        "asset_type": d.asset.type if d.asset else "",
        "asset_source": d.asset.source if d.asset else "",
        "provenance": d.asset.provenance if d.asset and d.asset.provenance else "live",
        "final_score": d.final_score,
        "tier": d.tier,
        "tier_label": get_tier_label(d.tier, d.asset.type if d.asset else None),
        "component_scores": d.component_scores_json or {},
        "reason_codes": d.reason_codes_json or [],
        "shap": d.shap_json or {},
        "model_version": d.model_version or "v1.0",
        "rule_version": d.rule_version or "v1.0",
        "created_at": d.created_at.isoformat() if d.created_at else None
    }
