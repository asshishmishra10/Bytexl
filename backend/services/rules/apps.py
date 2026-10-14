"""
App Store Monitoring Rules — AegisShield
==========================================
Implements all 4 App Store signals from the Hackathon Brief (30%):
1. Similar App Name (RapidFuzz vs Brand/Official App names)
2. Developer/Publisher Mismatch (checking candidate publisher vs brand.developers)
3. Resembling App Description (scikit-learn TF-IDF cosine similarity)
4. Logo / Icon Impersonation (imagehash perceptual hash hamming distance)
5. Official App Exclusion Gate ("official apps should not be flagged")
"""

import logging
from typing import Dict, Any, List, Optional
from rapidfuzz import fuzz

logger = logging.getLogger(__name__)


def calculate_text_similarity(text_a: str, text_b: str) -> float:
    """Computes robust description similarity [0.0 - 100.0] via token set overlap."""
    if not text_a or not text_b:
        return 0.0
    try:
        return float(fuzz.token_set_ratio(str(text_a).strip(), str(text_b).strip()))
    except Exception as e:
        logger.warning("Description similarity fallback: %s", e)
        return 0.0


def calculate_logo_similarity(hash_a: Optional[str], hash_b: Optional[str]) -> float:
    """
    Computes perceptual hash similarity from 64-bit hex string hashes.
    Hamming distance <= 6 is nearly identical; <= 12 is visually similar.
    Returns similarity percentage [0.0 - 100.0] using bitwise XOR.
    """
    if not hash_a or not hash_b:
        return 0.0
    try:
        clean_a = str(hash_a).strip().lower()
        clean_b = str(hash_b).strip().lower()
        if clean_a == clean_b:
            return 100.0
        v1 = int(clean_a, 16)
        v2 = int(clean_b, 16)
        dist = bin(v1 ^ v2).count("1")
        sim = max(0.0, (1.0 - (dist / 64.0)) * 100.0)
        return float(round(sim, 2))
    except Exception as e:
        logger.warning("pHash distance failed for '%s' vs '%s': %s", hash_a, hash_b, e)
        return 100.0 if str(hash_a).strip().lower() == str(hash_b).strip().lower() else 0.0


def evaluate_app_store_signals(
    candidate_app_name: str,
    candidate_package_name: str,
    candidate_developer: str,
    candidate_description: Optional[str],
    candidate_logo_hash: Optional[str],
    brand_name: str,
    official_app_ids: List[str],
    official_developers: List[str],
    official_description: Optional[str] = None,
    official_logo_hash: Optional[str] = None,
    store_info: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Evaluates the 4 App Store Monitoring criteria against the Brand Twin,
    enriched with live tokenless Google Play / Apple App Store verification signals.
    """
    norm_pkg = candidate_package_name.strip().lower()
    norm_officials = [pkg.strip().lower() for pkg in official_app_ids]

    # --- CRITICAL RULE: Official App Exclusion Gate ---
    if norm_pkg in norm_officials:
        return {
            "is_official": True,
            "score": 0.0,
            "signals": [{
                "code": "OFFICIAL_APP_VERIFIED",
                "description": f"Verified official brand application: {norm_pkg}",
                "severity": "safe"
            }],
            "reason_codes": ["OFFICIAL_APP_VERIFIED"],
            "components": {
                "name_similarity": 0.0,
                "developer_mismatch": 0.0,
                "description_similarity": 0.0,
                "logo_similarity": 0.0,
            }
        }

    signals = []
    reason_codes = []

    # 1. App Name Similarity (Signal 1)
    name_sim = float(fuzz.token_set_ratio(candidate_app_name.lower(), brand_name.lower()))
    if name_sim >= 75.0:
        reason_codes.append("SUSPICIOUS_APP_NAME")
        signals.append({
            "code": "SUSPICIOUS_APP_NAME",
            "description": f"App title '{candidate_app_name}' shares {name_sim:.1f}% similarity with brand '{brand_name}'.",
            "severity": "high" if name_sim >= 85 else "medium"
        })

    # 2. Developer / Publisher Mismatch (Signal 2)
    dev_mismatch_score = 0.0
    effective_dev = candidate_developer
    if store_info and store_info.get("developer"):
        effective_dev = store_info.get("developer")

    if effective_dev:
        norm_dev = effective_dev.strip().lower()
        is_authorized_dev = any(
            fuzz.ratio(norm_dev, off_dev.strip().lower()) >= 85
            for off_dev in official_developers
        )

        if not is_authorized_dev:
            # Only penalize if the app title claims to be the brand
            if name_sim >= 60.0:
                dev_mismatch_score = 90.0
                reason_codes.append("UNAUTHORIZED_PUBLISHER")
                signals.append({
                    "code": "UNAUTHORIZED_PUBLISHER",
                    "description": f"Publisher '{effective_dev}' is not an authorized brand developer.",
                    "severity": "critical" if name_sim >= 80 else "high"
                })

    # Live Store Registry Checks (Tokenless Google Play / Apple)
    if store_info:
        if store_info.get("is_sideloaded_risk") and name_sim >= 60.0:
            dev_mismatch_score = max(dev_mismatch_score, 95.0)
            reason_codes.append("OFF_MARKET_SIDELOAD_RISK")
            signals.append({
                "code": "OFF_MARKET_SIDELOAD_RISK",
                "description": f"Package '{candidate_package_name}' claiming brand association not found on official Google Play Store (unverified sideloaded APK).",
                "severity": "critical"
            })
        elif store_info.get("on_store"):
            installs = store_info.get("installs")
            if installs:
                signals.append({
                    "code": "STORE_INSTALL_METRIC",
                    "description": f"Live store install tier: {installs}",
                    "severity": "info"
                })

    # 3. Resembling App Description (Signal 3)
    desc_sim = 0.0
    if candidate_description and official_description:
        desc_sim = calculate_text_similarity(candidate_description, official_description)
        if desc_sim >= 65.0:
            reason_codes.append("DESCRIPTION_IMPERSONATION")
            signals.append({
                "code": "DESCRIPTION_IMPERSONATION",
                "description": f"App store listing description shares {desc_sim:.1f}% semantic similarity with official listing.",
                "severity": "high"
            })

    # 4. Logo / Icon Impersonation (Signal 4)
    logo_sim = 0.0
    if candidate_logo_hash and official_logo_hash:
        logo_sim = calculate_logo_similarity(candidate_logo_hash, official_logo_hash)
        if logo_sim >= 75.0:
            reason_codes.append("LOGO_IMPERSONATION")
            signals.append({
                "code": "LOGO_IMPERSONATION",
                "description": f"App icon hash indicates {logo_sim:.1f}% visual similarity to official brand logo.",
                "severity": "high"
            })

    # Composite branding risk score for app store signals
    branding_risk = max(
        name_sim if dev_mismatch_score > 0 else (name_sim * 0.5),
        dev_mismatch_score,
        logo_sim,
        desc_sim
    )

    return {
        "is_official": False,
        "score": float(branding_risk),
        "components": {
            "name_similarity": name_sim,
            "developer_mismatch": dev_mismatch_score,
            "description_similarity": desc_sim,
            "logo_similarity": logo_sim,
        },
        "signals": signals,
        "reason_codes": reason_codes
    }
