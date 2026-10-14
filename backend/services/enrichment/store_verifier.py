"""
Live App Store & Repository Verifier — AegisShield
===================================================
Validates mobile application packages against official live store registries:
1. Google Play Store (Web registry lookup) — Detects verified publisher, install tiers, or off-market sideloads.
2. Apple iTunes Search API (Official Apple REST API) — Verifies iOS bundles, official seller names, and track status.
Tokenless, zero-key, non-blocking with strict timeouts.
"""

import logging
import re
from typing import Dict, Any, Optional
import requests
from bs4 import BeautifulSoup

logger = logging.getLogger(__name__)

GOOGLE_PLAY_BASE = "https://play.google.com/store/apps/details"
ITUNES_SEARCH_BASE = "https://itunes.apple.com/search"
ITUNES_LOOKUP_BASE = "https://itunes.apple.com/lookup"
DEFAULT_TIMEOUT = 1.5


def verify_google_play_package(package_name: str, timeout: float = DEFAULT_TIMEOUT) -> Dict[str, Any]:
    """
    Check if an Android package exists on Google Play and extract verified publisher signals.
    Tokenless, public, keyless.
    """
    clean_pkg = package_name.strip()
    result = {
        "package_name": clean_pkg,
        "on_store": False,
        "store": "google_play",
        "title": None,
        "developer": None,
        "installs": None,
        "score": None,
        "icon_url": None,
        "is_sideloaded_risk": False,
        "error": None,
    }

    if not clean_pkg or "." not in clean_pkg:
        result["error"] = "Invalid package format"
        return result

    headers = {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        ),
        "Accept-Language": "en-US,en;q=0.9",
    }

    try:
        resp = requests.get(
            GOOGLE_PLAY_BASE,
            params={"id": clean_pkg, "hl": "en"},
            headers=headers,
            timeout=timeout,
        )

        if resp.status_code == 200:
            result["on_store"] = True
            soup = BeautifulSoup(resp.text, "html.parser")

            # Extract Title (h1)
            h1 = soup.find("h1")
            if h1:
                result["title"] = h1.get_text(strip=True)

            # Extract Developer name
            dev_elem = soup.find("a", href=re.compile(r"/store/apps/developer\?id="))
            if dev_elem:
                result["developer"] = dev_elem.get_text(strip=True)
            else:
                # Fallback search for developer link
                dev_elem = soup.find("a", href=re.compile(r"/store/apps/dev\?id="))
                if dev_elem:
                    result["developer"] = dev_elem.get_text(strip=True)

            # Extract Installs / Downloads bracket (e.g. 5M+ downloads, 100K+)
            text_all = resp.text
            installs_match = re.search(r"(\d+[\d,]*\+?)\s*(?:downloads|installs)", text_all, re.IGNORECASE)
            if installs_match:
                result["installs"] = installs_match.group(1)

            # Extract Icon URL
            icon_meta = soup.find("meta", property="og:image")
            if icon_meta and icon_meta.get("content"):
                result["icon_url"] = icon_meta["content"]

        elif resp.status_code == 404:
            # Package does not exist on official Google Play Store
            result["on_store"] = False
            result["is_sideloaded_risk"] = True
        else:
            result["error"] = f"Google Play returned HTTP {resp.status_code}"

    except requests.exceptions.Timeout:
        result["error"] = "Google Play check timed out"
    except requests.exceptions.RequestException as e:
        result["error"] = f"Google Play request error: {str(e)}"
    except Exception as e:
        result["error"] = f"Unexpected Google Play verification exception: {str(e)}"

    return result


def verify_apple_itunes_app(identifier_or_name: str, timeout: float = DEFAULT_TIMEOUT) -> Dict[str, Any]:
    """
    Search Apple iTunes / App Store for verified applications.
    Tokenless, public official Apple REST API.
    """
    clean_id = identifier_or_name.strip()
    result = {
        "query": clean_id,
        "on_store": False,
        "store": "apple_app_store",
        "title": None,
        "bundle_id": None,
        "developer": None,
        "seller_name": None,
        "primary_genre": None,
        "price": None,
        "error": None,
    }

    headers = {"User-Agent": "AegisShield-ThreatIntelligence/1.0"}

    try:
        # Check if bundle ID lookup or text search
        if "." in clean_id and not clean_id.startswith("http"):
            # Try bundle lookup
            resp = requests.get(
                ITUNES_LOOKUP_BASE,
                params={"bundleId": clean_id},
                headers=headers,
                timeout=timeout,
            )
        else:
            resp = requests.get(
                ITUNES_SEARCH_BASE,
                params={"term": clean_id, "entity": "software", "limit": 1},
                headers=headers,
                timeout=timeout,
            )

        if resp.status_code == 200:
            data = resp.json()
            results = data.get("results", [])
            if results and len(results) > 0:
                item = results[0]
                result["on_store"] = True
                result["title"] = item.get("trackName")
                result["bundle_id"] = item.get("bundleId")
                result["developer"] = item.get("artistName")
                result["seller_name"] = item.get("sellerName")
                result["primary_genre"] = item.get("primaryGenreName")
                result["price"] = item.get("price")
            else:
                result["on_store"] = False

    except requests.exceptions.Timeout:
        result["error"] = "Apple App Store check timed out"
    except requests.exceptions.RequestException as e:
        result["error"] = f"Apple App Store request error: {str(e)}"
    except Exception as e:
        result["error"] = f"Unexpected Apple App Store verification exception: {str(e)}"

    return result
