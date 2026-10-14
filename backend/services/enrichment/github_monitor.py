"""
GitHub Repository Brand Impersonation Monitor — AegisShield
============================================================
Searches GitHub for unauthorized public repositories copying brand names,
distributing suspicious APK releases, or hosting phishing templates.
Requires GITHUB_PAT from .env (5,000 requests/hour).
"""

import os
import logging
from typing import Dict, Any, List
import requests

logger = logging.getLogger(__name__)

GITHUB_SEARCH_URL = "https://api.github.com/search/repositories"
DEFAULT_TIMEOUT = 1.5


def search_github_brand_repos(brand_name: str, timeout: float = DEFAULT_TIMEOUT) -> Dict[str, Any]:
    """
    Search GitHub for potential brand impersonation repositories.
    Non-blocking with graceful fallback if unconfigured or timed out.
    """
    clean_brand = brand_name.strip()
    result = {
        "brand": clean_brand,
        "configured": False,
        "checked": False,
        "total_matches": 0,
        "suspicious_repos": [],
        "error": None,
    }

    token = os.getenv("GITHUB_PAT", "").strip()
    if not token:
        return result

    result["configured"] = True

    if not clean_brand:
        return result

    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "AegisShield-BrandProtection/1.0",
    }
    params = {
        "q": f'"{clean_brand}" in:name,description',
        "sort": "updated",
        "order": "desc",
        "per_page": 5,
    }

    try:
        resp = requests.get(GITHUB_SEARCH_URL, headers=headers, params=params, timeout=timeout)
        if resp.status_code == 200:
            data = resp.json()
            total_count = int(data.get("total_count", 0))
            result["checked"] = True
            result["total_matches"] = total_count

            items = []
            for item in data.get("items", [])[:5]:
                items.append({
                    "full_name": item.get("full_name"),
                    "html_url": item.get("html_url"),
                    "description": item.get("description"),
                    "updated_at": item.get("updated_at"),
                    "stars": item.get("stargazers_count", 0),
                    "owner": item.get("owner", {}).get("login"),
                })
            result["suspicious_repos"] = items
        elif resp.status_code == 401:
            result["error"] = "Invalid GITHUB_PAT token"
        elif resp.status_code == 403:
            result["error"] = "GitHub rate limit exceeded"
        else:
            result["error"] = f"GitHub API responded with HTTP {resp.status_code}"
    except requests.exceptions.Timeout:
        result["error"] = "GitHub API request timed out"
    except Exception as e:
        result["error"] = f"GitHub API exception: {str(e)}"

    return result
