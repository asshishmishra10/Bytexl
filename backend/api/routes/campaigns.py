"""
Threat Campaigns API — AegisShield
===================================
Correlates isolated impersonation events into coordinated multi-vector campaigns:
- GET /api/campaigns        — List all detected campaigns with summary metrics and graph topologies
- GET /api/campaigns/{id}   — Retrieve single campaign detail with full node and edge network
"""

from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from db.session import get_db
from services.correlation.engine import build_threat_campaigns

router = APIRouter()


@router.get("/campaigns")
async def list_campaigns(
    brand_id: Optional[int] = Query(None, description="Filter campaigns targeting a specific brand"),
    db: Session = Depends(get_db)
):
    """Return all active threat campaigns with linked assets and graph topology."""
    campaigns = build_threat_campaigns(db, brand_id=brand_id)
    return {
        "status": "success",
        "total": len(campaigns),
        "campaigns": campaigns,
    }


@router.get("/campaigns/{campaign_id}")
async def get_campaign(campaign_id: str, db: Session = Depends(get_db)):
    """Get single campaign detail with graph nodes and edges."""
    campaigns = build_threat_campaigns(db)
    matched = next((c for c in campaigns if c["id"].lower() == campaign_id.lower()), None)
    if not matched:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Campaign '{campaign_id}' not found"
        )
    return {
        "status": "success",
        "campaign": matched,
        "nodes": matched.get("nodes", []),
        "edges": matched.get("edges", []),
    }
