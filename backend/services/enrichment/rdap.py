"""
RDAP Domain Registration & Age Intelligence — AegisShield
===========================================================
Queries the open, tokenless ICANN RDAP standard protocol (via rdap.org)
to determine domain creation date and compute domain age in days.
Newly registered domains (< 14 days) represent high-probability weaponized phishing.
"""

import logging
from typing import Dict, Any, Optional
from datetime import datetime, timezone
import requests

logger = logging.getLogger(__name__)

RDAP_GATEWAY = "https://rdap.org/domain"
DEFAULT_TIMEOUT = 1.2


def lookup_rdap_domain_age(domain: str, timeout: float = DEFAULT_TIMEOUT) -> Dict[str, Any]:
    """
    Look up domain registration timestamp and calculate domain age in days.
    Tokenless, 100% free, unlimited public IETF/ICANN standard.
    """
    clean = domain.strip().lower()
    result = {
        "domain": clean,
        "registered": False,
        "age_days": None,
        "registration_date": None,
        "is_newly_registered": False,   # < 14 days
        "is_suspicious_age": False,     # < 60 days
        "registrar": None,
        "source": "rdap.org",
        "error": None,
    }

    if not clean or "." not in clean:
        result["error"] = "Invalid domain format"
        return result

    headers = {
        "User-Agent": "AegisShield-ThreatIntelligence/1.0 (+https://github.com/aegisshield)",
        "Accept": "application/rdap+json, application/json",
    }

    try:
        resp = requests.get(
            f"{RDAP_GATEWAY}/{clean}",
            headers=headers,
            timeout=timeout,
            allow_redirects=True,
        )

        if resp.status_code == 200:
            data = resp.json()
            result["registered"] = True

            # Extract registration date from events array
            events = data.get("events", [])
            reg_date_str = None
            for ev in events:
                action = str(ev.get("eventAction", "")).lower()
                if action in ("registration", "registered", "created"):
                    reg_date_str = ev.get("eventDate")
                    break

            if reg_date_str:
                result["registration_date"] = reg_date_str
                try:
                    # Normalize ISO 8601 timestamps
                    clean_ts = reg_date_str.replace("Z", "+00:00")
                    reg_dt = datetime.fromisoformat(clean_ts)
                    now_utc = datetime.now(timezone.utc)
                    age_days = (now_utc - reg_dt).days
                    result["age_days"] = max(0, age_days)
                    result["is_newly_registered"] = result["age_days"] < 14
                    result["is_suspicious_age"] = result["age_days"] < 60
                except Exception as parse_err:
                    logger.debug("Failed parsing RDAP eventDate '%s': %s", reg_date_str, parse_err)

            # Extract registrar name if available
            entities = data.get("entities", [])
            for ent in entities:
                roles = ent.get("roles", [])
                if "registrar" in roles:
                    vcard = ent.get("vcardArray", [])
                    if len(vcard) > 1 and isinstance(vcard[1], list):
                        for prop in vcard[1]:
                            if len(prop) > 3 and prop[0] == "fn":
                                result["registrar"] = str(prop[3])
                                break

        elif resp.status_code == 404:
            # Domain is unregistered / available
            result["registered"] = False
        else:
            result["error"] = f"RDAP responded with HTTP {resp.status_code}"

    except requests.exceptions.Timeout:
        result["error"] = "RDAP request timed out"
    except requests.exceptions.RequestException as e:
        result["error"] = f"RDAP request error: {str(e)}"
    except Exception as e:
        result["error"] = f"Unexpected RDAP exception: {str(e)}"

    return result
