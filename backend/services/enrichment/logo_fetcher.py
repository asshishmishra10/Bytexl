"""
Brand Logo Perceptual Hash Extractor — AegisShield
===================================================
Fetches official brand logos from the tokenless Clearbit Logo API
and computes 64-bit perceptual image hashes (pHash) for automated Brand Digital Twin onboarding.
"""

import io
import logging
from typing import Optional
import requests
from PIL import Image
from utils.hasher import compute_image_hash

logger = logging.getLogger(__name__)

CLEARBIT_LOGO_BASE = "https://logo.clearbit.com"
DEFAULT_TIMEOUT = 1.5


def fetch_clearbit_logo_hash(domain: str, timeout: float = DEFAULT_TIMEOUT) -> Optional[str]:
    """
    Download official brand logo from Clearbit and compute 16-hex perceptual hash (pHash).
    Tokenless, public, 100% free.
    """
    clean_domain = domain.strip().lower()
    if not clean_domain or "." not in clean_domain:
        return None

    # Strip protocols if present
    if "://" in clean_domain:
        clean_domain = clean_domain.split("://")[1].split("/")[0]

    url = f"{CLEARBIT_LOGO_BASE}/{clean_domain}"
    headers = {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        )
    }

    # 1. Try Clearbit Logo API
    try:
        resp = requests.get(url, headers=headers, timeout=timeout)
        if resp.status_code == 200 and resp.content:
            img = Image.open(io.BytesIO(resp.content))
            if img.mode not in ("RGB", "L"):
                img = img.convert("RGB")
            phash_val = compute_image_hash(img)
            logger.info("Derived logo pHash '%s' from Clearbit for '%s'", phash_val, clean_domain)
            return phash_val
    except Exception as e:
        logger.debug("Clearbit logo fetch failed for %s: %s", clean_domain, e)

    # 2. Resilient Fallback: Google 128px High-Res Favicon CDN
    try:
        google_url = f"https://www.google.com/s2/favicons?domain={clean_domain}&sz=128"
        resp = requests.get(google_url, headers=headers, timeout=timeout)
        if resp.status_code == 200 and resp.content:
            img = Image.open(io.BytesIO(resp.content))
            if img.mode not in ("RGB", "L"):
                img = img.convert("RGB")
            phash_val = compute_image_hash(img)
            logger.info("Derived logo pHash '%s' from Google Favicon CDN for '%s'", phash_val, clean_domain)
            return phash_val
    except Exception as e:
        logger.debug("Google favicon fetch failed for %s: %s", clean_domain, e)

    return None

