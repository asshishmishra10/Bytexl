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

logger = logging.getLogger(__name__)

GOOGLE_PLAY_BASE = "https://play.google.com/store/apps/details"
ITUNES_SEARCH_BASE = "https://itunes.apple.com/search"
ITUNES_LOOKUP_BASE = "https://itunes.apple.com/lookup"
DEFAULT_TIMEOUT = 1.5


def _strip_html(fragment: str) -> str:
    """Strip nested markup and collapse whitespace from an HTML fragment."""
    text = re.sub(r"<[^>]+>", " ", fragment)
    return re.sub(r"\s+", " ", text).strip()


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
            html = resp.text

            # Extract Title (first h1)
            title_match = re.search(r"<h1[^>]*>(.*?)</h1>", html, re.DOTALL | re.IGNORECASE)
            if title_match:
                result["title"] = _strip_html(title_match.group(1)) or None

            # Extract Developer name from the store developer link
            dev_match = re.search(
                r"<a[^>]+href=[\"'][^\"']*/store/apps/developer\?id=[^\"']*[\"'][^>]*>(.*?)</a>",
                html,
                re.DOTALL | re.IGNORECASE,
            ) or re.search(
                # Fallback search for developer link
                r"<a[^>]+href=[\"'][^\"']*/store/apps/dev\?id=[^\"']*[\"'][^>]*>(.*?)</a>",
                html,
                re.DOTALL | re.IGNORECASE,
            )
            if dev_match:
                result["developer"] = _strip_html(dev_match.group(1)) or None

            # Extract Installs / Downloads bracket (e.g. 5M+ downloads, 100K+)
            installs_match = re.search(r"(\d+[\d,]*\+?)\s*(?:downloads|installs)", html, re.IGNORECASE)
            if installs_match:
                result["installs"] = installs_match.group(1)

            # Extract Icon URL from og:image meta tag
            icon_match = re.search(
                r"<meta[^>]+property=[\"']og:image[\"'][^>]*content=[\"']([^\"']+)[\"']",
                html,
                re.IGNORECASE,
            ) or re.search(
                r"<meta[^>]+content=[\"']([^\"']+)[\"'][^>]*property=[\"']og:image[\"']",
                html,
                re.IGNORECASE,
            )
            if icon_match:
                result["icon_url"] = icon_match.group(1)

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
