"""
Simplified 3-Part Fusion & Corroboration Engine — AegisShield
==============================================================
Fuses Identity/Branding signals with Behavioral ML models per Challenge Brief:
1. Social: Identity Similarity (RapidFuzz + Lookalike) + Account Behavior (social_xgb)
2. Mobile: App Store Branding (Name, Dev, Desc, Logo) + Rogue Permissions (mobile_xgb)
3. Enforces Corroboration Tiers & Official Asset Exclusion:
   - Official Assets: Always Tier 0 (Benign) — "official accounts should not be flagged"
   - Tier 0 (Observe): Score < 40
   - Tier 1 (Review): Score 40–74, opens an investigation case
   - Tier 2 (Escalate): Score >= 75 with multi-signal corroboration
"""

from typing import Dict, Any, List, Optional


def get_tier_label(tier: int, asset_type: Optional[str] = None) -> str:
    """
    Canonical mapping from tier number to human-readable label to eliminate drift.
    """
    if tier == 2:
        if asset_type == "app":
            return "Escalate (Critical Rogue App)"
        elif asset_type == "profile":
            return "Escalate (Critical Impersonator)"
        return "Escalate (Critical)"
    elif tier == 1:
        if asset_type == "app":
            return "Review (Suspected Rogue App)"
        elif asset_type == "profile":
            return "Review (Suspected Threat)"
        return "Review (Suspected)"
    else:
        return "Observe (Benign)"



def fuse_social_threat(
    identity_res: Dict[str, Any],
    ml_probability: float,
) -> Dict[str, Any]:
    """
    Fuses Identity and ML behavior scores for Social Media Monitoring (30%).
    """
    # 1. Enforce Official Exclusion Rule (Judges requirement)
    if identity_res.get("is_official"):
        return {
            "score": 0.0,
            "tier": 0,
            "tier_label": "Observe (Benign)",
            "components": {
                "identity": 0.0,
                "behavior": 0.0,
                "branding": 0.0
            },
            "signals": identity_res.get("signals", []),
            "reason_codes": identity_res.get("reason_codes", ["OFFICIAL_ACCOUNT_VERIFIED"])
        }

    # 2. Enforce Allowlist Rule
    if identity_res.get("is_allowlisted"):
        return {
            "score": 15.0,
            "tier": 0,
            "tier_label": "Observe (Allowlisted)",
            "components": {
                "identity": identity_res.get("score", 0.0),
                "behavior": round(ml_probability * 100.0, 1),
                "branding": 0.0
            },
            "signals": identity_res.get("signals", []),
            "reason_codes": identity_res.get("reason_codes", ["ALLOWLISTED_PARTNER_OR_FAN"])
        }

    id_score = float(identity_res.get("score", 0.0))
    beh_score = float(ml_probability * 100.0)

    # Balanced 50/50 weighting between Identity Claim and Behavioral Anomaly
    final_score = round((0.5 * id_score) + (0.5 * beh_score), 1)

    signals = list(identity_res.get("signals", []))
    reason_codes = list(identity_res.get("reason_codes", []))

    if beh_score >= 60.0:
        reason_codes.append("SUSPICIOUS_PROFILE_BEHAVIOR")
        signals.append({
            "code": "SUSPICIOUS_PROFILE_BEHAVIOR",
            "description": f"ML model flagged fake profile behavior ({beh_score:.1f}% confidence from post/follower metrics).",
            "severity": "high" if beh_score >= 80 else "medium"
        })

    # Tier Decision Logic with Corroboration Gating
    if final_score >= 75.0 and (id_score >= 70.0 and beh_score >= 50.0):
        tier = 2
        tier_label = "Escalate (Critical Impersonator)"
    elif final_score >= 40.0 or id_score >= 80.0 or beh_score >= 75.0:
        tier = 1
        tier_label = "Review (Suspected Threat)"
    else:
        tier = 0
        tier_label = "Observe (Low Risk)"

    return {
        "score": final_score,
        "tier": tier,
        "tier_label": tier_label,
        "components": {
            "identity": round(id_score, 1),
            "behavior": round(beh_score, 1),
            "branding": round(id_score, 1)
        },
        "signals": signals,
        "reason_codes": reason_codes
    }


def fuse_app_threat(
    app_signals_res: Dict[str, Any],
    ml_probability: float,
) -> Dict[str, Any]:
    """
    Fuses App Store Signals and Rogue Permission ML scores for App Store Monitoring (30%).
    """
    # 1. Enforce Official App Exclusion
    if app_signals_res.get("is_official"):
        return {
            "score": 0.0,
            "tier": 0,
            "tier_label": "Observe (Benign)",
            "components": {
                "identity": 0.0,
                "behavior": 0.0,
                "branding": 0.0
            },
            "signals": app_signals_res.get("signals", []),
            "reason_codes": app_signals_res.get("reason_codes", ["OFFICIAL_APP_VERIFIED"])
        }

    branding_score = float(app_signals_res.get("score", 0.0))
    beh_score = float(ml_probability * 100.0)

    final_score = round((0.5 * branding_score) + (0.5 * beh_score), 1)

    signals = list(app_signals_res.get("signals", []))
    reason_codes = list(app_signals_res.get("reason_codes", []))

    if beh_score >= 60.0:
        reason_codes.append("MALICIOUS_PERMISSION_PROFILE")
        signals.append({
            "code": "MALICIOUS_PERMISSION_PROFILE",
            "description": f"ML model flagged rogue mobile app permissions ({beh_score:.1f}% risk score).",
            "severity": "high" if beh_score >= 80 else "medium"
        })

    # Tier Decision Logic with Corroboration Gating
    if final_score >= 75.0 and (branding_score >= 70.0 and beh_score >= 50.0):
        tier = 2
        tier_label = "Escalate (Critical Rogue App)"
    elif final_score >= 40.0 or branding_score >= 75.0 or beh_score >= 75.0:
        tier = 1
        tier_label = "Review (Suspected Rogue App)"
    else:
        tier = 0
        tier_label = "Observe (Low Risk)"

    app_comps = app_signals_res.get("components", {})
    name_sim = float(app_comps.get("name_similarity", 0.0))
    dev_mismatch = float(app_comps.get("developer_mismatch", 0.0))
    desc_sim = float(app_comps.get("description_similarity", 0.0))
    logo_sim = float(app_comps.get("logo_similarity", 0.0))

    return {
        "score": final_score,
        "tier": tier,
        "tier_label": tier_label,
        "components": {
            "identity": round(name_sim, 1),
            "behavior": round(beh_score, 1),
            "branding": round(branding_score, 1),
            "name_similarity": round(name_sim, 1),
            "developer_mismatch": round(dev_mismatch, 1),
            "description_similarity": round(desc_sim, 1),
            "logo_similarity": round(logo_sim, 1),
            "rogue_ml": round(beh_score, 1),
        },
        "signals": signals,
        "reason_codes": reason_codes
    }
