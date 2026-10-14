"""
Blocklist Export API — AegisShield
===================================
Exports corroborated threat indicators (package names, scam handles, domains, hashes)
for ingestion by firewalls, EDR agents, and enterprise SIEMs (Splunk, Elastic, Sentinel).
Supports JSON, CSV, and plain-text feed formats.
"""

from datetime import datetime
import io
import csv
from typing import Optional
from fastapi import APIRouter, Depends, Query, Response
from sqlalchemy.orm import Session
from sqlalchemy import desc

from db.session import get_db
from db.models import Detection, Asset

router = APIRouter()


@router.get("/blocklist")
async def export_blocklist(
    format: str = Query("json", description="Output format: json, csv, or text"),
    min_tier: int = Query(2, ge=1, le=2, description="Minimum threat tier to include (1=Review, 2=Escalate)"),
    asset_type: Optional[str] = Query(None, description="Filter by asset type (profile, app, domain)"),
    db: Session = Depends(get_db)
):
    """
    Export active threat indicators of compromise (IOCs).
    Default exports confirmed Tier 2 threats.
    """
    query = (
        db.query(Detection, Asset)
        .join(Asset, Detection.asset_id == Asset.id)
        .filter(Detection.tier >= min_tier)
    )

    if asset_type:
        query = query.filter(Asset.type == asset_type)

    results = query.order_by(desc(Detection.final_score)).all()

    seen_indicators = set()
    indicators = []
    for det, asset in results:
        val = asset.value.strip()
        if not val or val in seen_indicators:
            continue
        seen_indicators.add(val)

        reason_codes = det.reason_codes_json if isinstance(det.reason_codes_json, list) else []
        indicators.append({
            "indicator": val,
            "type": asset.type,
            "tier": det.tier,
            "threat_score": det.final_score,
            "reason_codes": reason_codes,
            "provenance": asset.provenance,
            "detected_at": det.created_at.isoformat() if det.created_at else None,
        })

    # 1. Plain text format (standard proxy/firewall blocklist — one indicator per line)
    if format.lower() == "text":
        lines = [item["indicator"] for item in indicators]
        content = "\n".join(lines) + "\n"
        return Response(content=content, media_type="text/plain")

    # 2. CSV format (standard SIEM import)
    if format.lower() == "csv":
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["indicator", "type", "tier", "threat_score", "reason_codes", "provenance", "detected_at"])
        for item in indicators:
            writer.writerow([
                item["indicator"],
                item["type"],
                item["tier"],
                item["threat_score"],
                ";".join(item["reason_codes"]),
                item["provenance"],
                item["detected_at"],
            ])
        return Response(
            content=output.getvalue(),
            media_type="text/csv",
            headers={"Content-Disposition": "attachment; filename=aegisshield_blocklist.csv"}
        )

    # 3. Default JSON format (rich SOAR payload)
    return {
        "status": "success",
        "generated_at": datetime.utcnow().isoformat(),
        "total": len(indicators),
        "min_tier": min_tier,
        "indicators": indicators,
    }
