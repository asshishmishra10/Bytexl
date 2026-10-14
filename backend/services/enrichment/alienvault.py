"""
AlienVault OTX (Open Threat Exchange) Client — AegisShield
===========================================================
Correlates look-alike domains and IP addresses against community
Threat Pulses, malware actor campaigns, and known threat infrastructure.
Requires ALIENVAULT_OTX_KEY from .env (Unlimited free community tier).
"""

import os
import logging
from typing import Dict, Any
import requests

logger = logging.getLogger(__name__)

OTX_BASE = "https://otx.alienvault.com/api/v1/indicators"
DEFAULT_TIMEOUT = 1.5


def check_alienvault_domain(domain: str, timeout: float = DEFAULT_TIMEOUT) -> Dict[str, Any]:
    """
    Query AlienVault OTX for domain threat indicators and active pulses.
    Non-blocking with graceful fallback if unconfigured or timed out.
    """
    clean_domain = domain.strip().lower()
    result = {
        "domain": clean_domain,
        "configured": False,
        "checked": False,
        "pulse_count": 0,
        "tags": [],
        "is_threat": False,
        "error": None,
    }

    api_key = os.getenv("ALIENVAULT_OTX_KEY", "").strip()
    if not api_key:
        return result

    result["configured"] = True

    if not clean_domain or "." not in clean_domain:
        return result

    headers = {
        "X-OTX-API-KEY": api_key,
        "Accept": "application/json",
        "User-Agent": "AegisShield-ThreatIntelligence/1.0",
    }

    try:
        url = f"{OTX_BASE}/domain/{clean_domain}/general"
        resp = requests.get(url, headers=headers, timeout=timeout)
        if resp.status_code == 200:
            data = resp.json()
            pulse_info = data.get("pulse_info", {})
            count = int(pulse_info.get("count", 0))
            result["checked"] = True
            result["pulse_count"] = count
            result["is_threat"] = count > 0

            # Collect unique tags from pulses
            tags = set()
            for pulse in pulse_info.get("pulses", [])[:5]:
                for t in pulse.get("tags", []):
                    tags.add(t)
            result["tags"] = list(tags)
        else:
            result["error"] = f"AlienVault OTX responded with HTTP {resp.status_code}"
    except requests.exceptions.Timeout:
        result["error"] = "AlienVault OTX request timed out"
    except Exception as e:
        result["error"] = f"AlienVault OTX exception: {str(e)}"

    return result
