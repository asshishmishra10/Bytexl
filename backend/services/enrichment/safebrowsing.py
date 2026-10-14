"""
Google Safe Browsing Threat Intelligence Client — AegisShield
==============================================================
Validates suspicious candidate URLs and look-alike domains against
Google Chrome's official Safe Browsing blacklist (phishing & malware).
Requires GOOGLE_SAFE_BROWSING_API_KEY from .env (10,000 lookups/day free).
"""

import os
import logging
from typing import List, Dict, Any, Union
import requests

logger = logging.getLogger(__name__)

SAFEBROWSING_ENDPOINT = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
DEFAULT_TIMEOUT = 1.5


def check_google_safe_browsing(targets: Union[str, List[str]], timeout: float = DEFAULT_TIMEOUT) -> Dict[str, Any]:
    """
    Query Google Safe Browsing v4 for phishing / malware blacklisting.
    Non-blocking with graceful fallback if unconfigured or timed out.
    """
    if isinstance(targets, str):
        target_list = [targets.strip()]
    else:
        target_list = [t.strip() for t in targets if t.strip()]

    result = {
        "configured": False,
        "checked": False,
        "blacklisted": False,
        "threat_types": [],
        "matches": [],
        "error": None,
    }

    api_key = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY", "").strip()
    if not api_key:
        return result

    result["configured"] = True

    if not target_list:
        return result

    # Format entries as URLs
    entries = []
    for t in target_list:
        url_cand = t if t.startswith("http") else f"http://{t}"
        entries.append({"url": url_cand})

    payload = {
        "client": {
            "clientId": "aegisshield-core",
            "clientVersion": "1.0.0"
        },
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": entries[:50]
        }
    }

    headers = {"Content-Type": "application/json"}

    try:
        resp = requests.post(
            f"{SAFEBROWSING_ENDPOINT}?key={api_key}",
            json=payload,
            headers=headers,
            timeout=timeout
        )

        if resp.status_code == 200:
            result["checked"] = True
            data = resp.json()
            matches = data.get("matches", [])
            if matches:
                result["blacklisted"] = True
                result["matches"] = matches
                result["threat_types"] = list(set(m.get("threatType") for m in matches if m.get("threatType")))
        else:
            result["error"] = f"Safe Browsing responded with HTTP {resp.status_code}"
    except requests.exceptions.Timeout:
        result["error"] = "Safe Browsing request timed out"
    except Exception as e:
        result["error"] = f"Safe Browsing exception: {str(e)}"

    return result
