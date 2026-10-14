"""
Model Loaders and Scoring Utilities — AegisShield
==================================================
Handles loading and inference for all ML models:
1. Social Profile Impersonation (social_xgb_model.json)
2. Rogue / Malicious Mobile App Detection (mobile_xgb_model.json)
3. URL / Domain Classifier (url_model.pkl)
"""

import json
import os
from typing import Dict, Any, List, Union
import numpy as np

try:
    from xgboost import XGBClassifier
except ImportError:
    XGBClassifier = None

try:
    import joblib
except ImportError:
    joblib = None

from models.pure_engine import (
    get_pure_social_ensemble,
    get_pure_mobile_ensemble,
    get_pure_url_ensemble,
)

MODEL_DIR = os.path.dirname(__file__)

_url_model = None
_social_model = None
_mobile_model = None

# Load persisted 215 mobile feature names schema
MOBILE_FEATURES_PATH = os.path.join(MODEL_DIR, "mobile_feature_names.json")
if os.path.exists(MOBILE_FEATURES_PATH):
    with open(MOBILE_FEATURES_PATH, "r", encoding="utf-8") as _f:
        MOBILE_FEATURE_NAMES: List[str] = json.load(_f)
else:
    MOBILE_FEATURE_NAMES: List[str] = []


# ---------------- 1. URL Model ----------------
URL_FEATURE_NAMES = [
    "url_length",
    "domain_length",
    "num_subdomains",
    "has_ip_address",
    "has_at_symbol",
    "has_hyphen",
    "num_digits",
    "digit_ratio",
    "shannon_entropy",
    "suspicious_keyword_count",
    "suspicious_tld",
    "brand_homoglyph_count",
]


def extract_url_features_dict(url_or_domain: str) -> Dict[str, float]:
    """Extract lexical and entropy features from URL for XGBoost inference."""
    import re
    import math
    from urllib.parse import urlparse

    raw = str(url_or_domain).strip().lower()
    parsed = urlparse(raw if "://" in raw else f"https://{raw}")
    netloc = parsed.netloc or parsed.path.split("/")[0]
    domain = netloc.split(":")[0]

    is_ip = 1.0 if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", domain) else 0.0
    parts = domain.split(".")
    tld = parts[-1] if len(parts) > 1 else ""
    num_subs = max(0, len(parts) - 2)

    has_at = 1.0 if "@" in raw else 0.0
    has_hyphen = 1.0 if "-" in domain else 0.0

    digits = sum(c.isdigit() for c in domain)
    digit_ratio = (digits / len(domain)) if len(domain) > 0 else 0.0

    # Shannon entropy
    entropy = 0.0
    if domain:
        prob = [float(domain.count(c)) / len(domain) for c in set(domain)]
        entropy = -sum(p * math.log2(p) for p in prob)

    suspicious_kws = [
        "login", "secure", "verify", "account", "banking", "update", "signin",
        "auth", "support", "token", "wallet", "recovery", "password", "service",
        "billing", "confirm", "security", "portal", "alert", "access"
    ]
    kw_count = sum(1 for kw in suspicious_kws if kw in raw)

    susp_tlds = {"xyz", "top", "buzz", "work", "click", "rest", "surf", "cfd", "gq", "ml", "tk", "ga", "cf"}
    susp_tld = 1.0 if tld in susp_tlds else 0.0

    homoglyphs = 0
    clean_domain = domain.replace(f".{tld}", "")
    for k in ['0', '1', '3', '4', '5', '8', 'vv', 'rn']:
        if k in clean_domain:
            homoglyphs += clean_domain.count(k)

    return {
        "url_length": float(len(raw)),
        "domain_length": float(len(domain)),
        "num_subdomains": float(num_subs),
        "has_ip_address": is_ip,
        "has_at_symbol": has_at,
        "has_hyphen": has_hyphen,
        "num_digits": float(digits),
        "digit_ratio": round(digit_ratio, 4),
        "shannon_entropy": round(entropy, 4),
        "suspicious_keyword_count": float(kw_count),
        "suspicious_tld": susp_tld,
        "brand_homoglyph_count": float(homoglyphs),
    }


def get_url_model():
    """Load URL phishing detection XGBoost model."""
    global _url_model
    if _url_model is None:
        xgb_path = os.path.join(MODEL_DIR, "url_xgb_model.json")
        if os.path.exists(xgb_path) and XGBClassifier:
            model = XGBClassifier()
            model.load_model(xgb_path)
            _url_model = model
        elif joblib:
            pkl_path = os.path.join(MODEL_DIR, "url_model.pkl")
            if os.path.exists(pkl_path):
                _url_model = joblib.load(pkl_path)
    return _url_model


def predict_url(url_or_features: Union[str, Dict[str, float]]) -> float:
    """Return URL phishing risk probability in [0.0, 1.0]."""
    if isinstance(url_or_features, str):
        feats = extract_url_features_dict(url_or_features)
    else:
        feats = url_or_features

    vec = [float(feats.get(k, 0.0)) for k in URL_FEATURE_NAMES]
    model = get_url_model()
    if model is not None and hasattr(model, "predict_proba"):
        try:
            arr = np.array([vec], dtype=float)
            proba = model.predict_proba(arr)
            return float(proba[0][1])
        except Exception:
            pass

    return get_pure_url_ensemble().predict_proba(vec)


# ---------------- 2. Social Profile Model ----------------
def get_social_model():
    """Load trained social profile fake detection XGBoost model."""
    global _social_model
    if _social_model is None:
        path = os.path.join(MODEL_DIR, "social_xgb_model.json")
        if os.path.exists(path) and XGBClassifier:
            model = XGBClassifier()
            model.load_model(path)
            _social_model = model
    return _social_model


# Standard feature ordering expected by social_xgb_model
SOCIAL_FEATURE_KEYS = [
    "profile pic",
    "nums/length username",
    "fullname words",
    "nums/length fullname",
    "name==username",
    "description length",
    "external URL",
    "private",
    "#posts",
    "#followers",
    "#follows",
]


def predict_social_profile(features: Dict[str, Any]) -> float:
    """
    Score a social profile given dict of features.
    Returns probability of account being fake/impersonator [0.0, 1.0].
    """
    vec = [float(features.get(k, 0)) for k in SOCIAL_FEATURE_KEYS]
    model = get_social_model()
    if model is not None and hasattr(model, "predict_proba"):
        try:
            arr = np.array([vec])
            proba = model.predict_proba(arr)
            return float(proba[0][1])
        except Exception:
            pass

    return get_pure_social_ensemble().predict_proba(vec)


# ---------------- 3. Mobile App Model ----------------
def get_mobile_model():
    """Load trained mobile rogue app detection XGBoost model."""
    global _mobile_model
    if _mobile_model is None:
        path = os.path.join(MODEL_DIR, "mobile_xgb_model.json")
        if os.path.exists(path) and XGBClassifier:
            model = XGBClassifier()
            model.load_model(path)
            _mobile_model = model
    return _mobile_model


def _normalize_perm_string(p: str) -> str:
    s = p.strip()
    if s.startswith("android.permission."):
        return s[len("android.permission."):]
    return s


def manifest_to_vector(permissions: Union[List[str], Dict[str, Any], set]) -> List[float]:
    """
    Convert a list or set of Android permission / API strings into
    the exact 215-element binary feature vector expected by mobile_xgb_model.
    Normalizes 'android.permission.' prefixes to handle real-world APK manifests.
    """
    if isinstance(permissions, dict):
        clean_dict = {}
        for k, v in permissions.items():
            if isinstance(k, str):
                clean_dict[k] = v
                clean_dict[_normalize_perm_string(k)] = v
        return [float(clean_dict.get(name, 0)) for name in MOBILE_FEATURE_NAMES]
    
    raw_list = list(permissions) if isinstance(permissions, (list, tuple, set)) else []
    perm_set = set()
    for p in raw_list:
        if isinstance(p, str):
            perm_set.add(p.strip())
            perm_set.add(_normalize_perm_string(p))

    return [1.0 if name in perm_set else 0.0 for name in MOBILE_FEATURE_NAMES]


def predict_mobile_app(features: Union[List[Any], Dict[str, Any], set]) -> float:
    """
    Score a mobile app. Features can be:
    - A list/set of string permissions (e.g. ['SEND_SMS', 'INTERNET', 'CAMERA'])
    - A dictionary of {permission_name: 0/1}
    - A pre-computed numeric feature vector of length 215
    Returns probability of app being rogue/malicious (Class S) [0.0, 1.0].
    """
    if (
        isinstance(features, list)
        and len(features) == len(MOBILE_FEATURE_NAMES)
        and (not features or isinstance(features[0], (int, float)))
    ):
        vec = [float(x) for x in features]
    else:
        vec = manifest_to_vector(features)

    model = get_mobile_model()
    if model is not None and hasattr(model, "predict_proba"):
        try:
            arr = np.array([vec], dtype=float)
            proba = model.predict_proba(arr)
            return float(proba[0][1])
        except Exception:
            pass

    return get_pure_mobile_ensemble().predict_proba(vec)

