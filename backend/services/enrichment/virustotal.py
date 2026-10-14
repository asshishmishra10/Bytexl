"""
VirusTotal v3 Multi-Engine Threat Intelligence Client — AegisShield
====================================================================
Submits look-alike domains and file hashes to 70+ commercial antivirus engines
(Kaspersky, CrowdStrike, Sophos, Microsoft Defender) for consensus threat classification.
Requires VIRUSTOTAL_API_KEY from .env (500 queries/day free).
"""

import os
import logging
from typing import Dict, Any
import requests

logger = logging.getLogger(__name__)

VT_BASE = "https://www.virustotal.com/api/v3"
DEFAULT_TIMEOUT = 1.5


def check_virustotal_domain(domain: str, timeout: float = DEFAULT_TIMEOUT) -> Dict[str, Any]:
    """
    Query VirusTotal v3 for multi-engine domain reputation.
    Non-blocking with graceful fallback if unconfigured or timed out.
    """
    clean_domain = domain.strip().lower()
    result = {
        "domain": clean_domain,
        "configured": False,
        "checked": False,
        "malicious_count": 0,
        "suspicious_count": 0,
        "total_engines": 0,
        "is_flagged": False,
        "error": None,
    }

    api_key = os.getenv("VIRUSTOTAL_API_KEY", "").strip()
    if not api_key:
        return result

    result["configured"] = True

    if not clean_domain or "." not in clean_domain:
        return result

    headers = {
        "x-apikey": api_key,
        "Accept": "application/json",
    }

    try:
        url = f"{VT_BASE}/domains/{clean_domain}"
        resp = requests.get(url, headers=headers, timeout=timeout)
        if resp.status_code == 200:
            data = resp.json().get("data", {})
            attributes = data.get("attributes", {})
            stats = attributes.get("last_analysis_stats", {})
            malicious = int(stats.get("malicious", 0))
            suspicious = int(stats.get("suspicious", 0))
            harmless = int(stats.get("harmless", 0))
            undetected = int(stats.get("undetected", 0))

            total = malicious + suspicious + harmless + undetected
            result["checked"] = True
            result["malicious_count"] = malicious
            result["suspicious_count"] = suspicious
            result["total_engines"] = total
            result["is_flagged"] = (malicious >= 2)
        elif resp.status_code == 404:
            # Domain not previously analyzed by VirusTotal
            result["checked"] = True
            result["is_flagged"] = False
        elif resp.status_code == 429:
            result["error"] = "VirusTotal rate limit exceeded (4 req/min)"
        else:
            result["error"] = f"VirusTotal responded with HTTP {resp.status_code}"
    except requests.exceptions.Timeout:
        result["error"] = "VirusTotal request timed out"
    except Exception as e:
        result["error"] = f"VirusTotal exception: {str(e)}"

    return result
