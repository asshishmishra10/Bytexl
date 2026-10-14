"""
AbuseIPDB Threat Intelligence Client — AegisShield
===================================================
Enriches resolved IP addresses with crowdsourced abuse reports,
confidence scores (0-100%), and hosting provider attribution.
Requires ABUSEIPDB_API_KEY from .env (1,000 checks/day free).
"""

import os
import logging
from typing import Dict, Any, Optional
import requests

logger = logging.getLogger(__name__)

ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"
DEFAULT_TIMEOUT = 1.5


def check_ip_reputation(ip_address: str, timeout: float = DEFAULT_TIMEOUT) -> Dict[str, Any]:
    """
    Query AbuseIPDB v2 for IP reputation and malicious confidence score.
    Non-blocking with graceful fallback if unconfigured or timed out.
    """
    clean_ip = ip_address.strip()
    result = {
        "ip": clean_ip,
        "configured": False,
        "checked": False,
        "abuse_score": 0,
        "total_reports": 0,
        "country": None,
        "isp": None,
        "is_malicious": False,
        "error": None,
    }

    api_key = os.getenv("ABUSEIPDB_API_KEY", "").strip()
    if not api_key:
        return result

    result["configured"] = True

    if not clean_ip or clean_ip in ("127.0.0.1", "0.0.0.0", "localhost"):
        return result

    headers = {
        "Key": api_key,
        "Accept": "application/json",
        "User-Agent": "AegisShield-ThreatIntelligence/1.0",
    }
    params = {
        "ipAddress": clean_ip,
        "maxAgeInDays": 90,
        "verbose": False,
    }

    try:
        resp = requests.get(ABUSEIPDB_URL, headers=headers, params=params, timeout=timeout)
        if resp.status_code == 200:
            data = resp.json().get("data", {})
            score = int(data.get("abuseConfidenceScore", 0))
            result["checked"] = True
            result["abuse_score"] = score
            result["total_reports"] = int(data.get("totalReports", 0))
            result["country"] = data.get("countryCode")
            result["isp"] = data.get("isp")
            result["is_malicious"] = score >= 50
        elif resp.status_code == 429:
            result["error"] = "AbuseIPDB rate limit exceeded (1,000/day)"
        else:
            result["error"] = f"AbuseIPDB responded with HTTP {resp.status_code}"
    except requests.exceptions.Timeout:
        result["error"] = "AbuseIPDB request timed out"
    except Exception as e:
        result["error"] = f"AbuseIPDB exception: {str(e)}"

    return result
