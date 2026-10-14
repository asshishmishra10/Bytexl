"""
Certificate Transparency (CT) Log Intelligence — AegisShield
==============================================================
Queries the public, tokenless Sectigo crt.sh CT Log API to verify
active TLS/SSL certificates issued for typosquatted or candidate domains.
Presence of an active certificate indicates weaponized web hosting (phishing landing page).
"""

import logging
from typing import Dict, Any, List
from datetime import datetime, timezone
import requests

logger = logging.getLogger(__name__)

CRTSH_ENDPOINT = "https://crt.sh"
DEFAULT_TIMEOUT = 1.5


def lookup_crtsh_certificates(domain: str, timeout: float = DEFAULT_TIMEOUT) -> Dict[str, Any]:
    """
    Search Certificate Transparency logs for issued SSL/TLS certificates.
    Tokenless, public, keyless API.
    """
    clean = domain.strip().lower()
    result = {
        "domain": clean,
        "has_tls_cert": False,
        "cert_count": 0,
        "latest_issuer": None,
        "latest_entry_timestamp": None,
        "is_recent_cert": False,    # Issued in last 30 days
        "source": "crt.sh",
        "error": None,
    }

    if not clean or "." not in clean:
        result["error"] = "Invalid domain format"
        return result

    headers = {
        "User-Agent": "AegisShield-ThreatIntelligence/1.0 (+https://github.com/aegisshield)",
        "Accept": "application/json",
    }

    try:
        resp = requests.get(
            CRTSH_ENDPOINT,
            params={"q": clean, "output": "json"},
            headers=headers,
            timeout=timeout,
        )

        if resp.status_code == 200:
            entries = resp.json()
            if isinstance(entries, list) and len(entries) > 0:
                result["has_tls_cert"] = True
                result["cert_count"] = len(entries)
                first = entries[0]
                result["latest_issuer"] = first.get("issuer_name")
                entry_time_str = first.get("entry_timestamp") or first.get("not_before")
                result["latest_entry_timestamp"] = entry_time_str

                if entry_time_str:
                    try:
                        clean_time = entry_time_str.split(".")[0].replace("T", " ")
                        cert_dt = datetime.fromisoformat(clean_time).replace(tzinfo=timezone.utc)
                        now_utc = datetime.now(timezone.utc)
                        age_days = (now_utc - cert_dt).days
                        result["is_recent_cert"] = age_days <= 30
                    except Exception:
                        pass
        elif resp.status_code == 404:
            result["has_tls_cert"] = False
        else:
            result["error"] = f"crt.sh responded with HTTP {resp.status_code}"

    except requests.exceptions.Timeout:
        result["error"] = "crt.sh request timed out"
    except requests.exceptions.RequestException as e:
        result["error"] = f"crt.sh request error: {str(e)}"
    except Exception as e:
        result["error"] = f"Unexpected crt.sh exception: {str(e)}"

    return result
