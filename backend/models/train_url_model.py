"""
URL Phishing & Malicious Domain XGBoost Classifier Trainer — AegisShield
========================================================================
Extracts 12 lexical, entropy, and typosquat features from URLs and domains,
trains an XGBoost binary classifier (Benign vs Malicious Phishing),
and saves `url_xgb_model.json` along with `url_feature_names.json`.
"""

import json
import math
import os
import re
from pathlib import Path
from typing import Dict, List, Tuple
from urllib.parse import urlparse

import numpy as np
from xgboost import XGBClassifier

MODEL_DIR = Path(__file__).resolve().parent

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

SUSPICIOUS_KEYWORDS = [
    "login", "secure", "verify", "account", "banking", "update", "signin",
    "auth", "support", "token", "wallet", "recovery", "password", "service",
    "billing", "confirm", "security", "portal", "alert", "access"
]

SUSPICIOUS_TLDS = {
    "xyz", "top", "buzz", "work", "click", "rest", "surf", "cfd", "gq", "ml", "tk", "ga", "cf"
}

HOMOGLYPH_MAP = {
    '0': 'o', '1': 'l', '3': 'e', '4': 'a', '5': 's', '8': 'b', 'vv': 'w', 'rn': 'm'
}


def compute_shannon_entropy(s: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not s:
        return 0.0
    prob = [float(s.count(c)) / len(s) for c in set(s)]
    return -sum(p * math.log2(p) for p in prob)


def extract_url_features(url_or_domain: str, brand_name: str = "apex") -> Dict[str, float]:
    """Extract 12 lexical, structural, and semantic features from a URL or domain."""
    raw = str(url_or_domain).strip().lower()
    parsed = urlparse(raw if "://" in raw else f"https://{raw}")
    netloc = parsed.netloc or parsed.path.split("/")[0]
    domain = netloc.split(":")[0]

    # Check for IP address in netloc
    is_ip = 1.0 if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", domain) else 0.0

    # Parts and subdomains
    parts = domain.split(".")
    tld = parts[-1] if len(parts) > 1 else ""
    num_subs = max(0, len(parts) - 2)

    has_at = 1.0 if "@" in raw else 0.0
    has_hyphen = 1.0 if "-" in domain else 0.0

    digits = sum(c.isdigit() for c in domain)
    digit_ratio = (digits / len(domain)) if len(domain) > 0 else 0.0

    entropy = compute_shannon_entropy(domain)

    # Keywords count
    full_text = raw.lower()
    kw_count = sum(1 for kw in SUSPICIOUS_KEYWORDS if kw in full_text)

    # Suspicious TLD
    susp_tld = 1.0 if tld in SUSPICIOUS_TLDS else 0.0

    # Homoglyphs / brand mutations
    homoglyphs = 0
    clean_domain = domain.replace(f".{tld}", "")
    for k in HOMOGLYPH_MAP:
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


def generate_training_data() -> Tuple[np.ndarray, np.ndarray]:
    """Create a balanced training dataset with representative benign and phishing domains."""
    benign_samples = [
        "https://apexbank.com", "https://apexbank.net", "https://apexbank.com/about",
        "https://google.com", "https://apple.com", "https://microsoft.com",
        "https://chase.com", "https://amazon.com", "https://github.com",
        "https://bankofamerica.com", "https://wellsfargo.com", "https://citi.com",
        "https://fidelity.com", "https://schwab.com", "https://paypal.com",
        "https://stripe.com", "https://stackoverflow.com", "https://bloomberg.com",
        "https://wsj.com", "https://reuters.com", "https://linkedin.com",
        "https://twitter.com", "https://cloudflare.com", "https://fastly.com",
        "https://apexbank.com/personal-banking", "https://apexbank.com/commercial",
        "https://apexbank.net/login/status", "https://apexbank.com/careers",
        "https://developer.apple.com", "https://docs.github.com", "https://cloud.google.com",
        "https://aws.amazon.com", "https://portal.azure.com", "https://login.salesforce.com"
    ]

    phishing_samples = [
        "https://apex-bank-secure-login.com",
        "https://apexbank-verify-account.xyz",
        "https://secure-apexbank.top/auth/login",
        "https://update-apexbank-billing.click",
        "http://192.168.1.105/apex/login.php",
        "https://apexbank.online-auth.ru/verify",
        "https://apexba-nk.com/signin",
        "https://apexb0nk-support.com",
        "https://apexbank-auth-token.xyz",
        "https://recovery-apexbank.net.work",
        "https://apexbank-security-alert.buzz",
        "https://login.apexbank.secure-portal-update.com",
        "https://apex-banking-service-verify.cfd",
        "https://apexbank-customer-access.tk",
        "https://confirm-apexbank-id.xyz",
        "http://104.244.42.1/apex/passwords",
        "https://apexbank-wallet-recovery.com",
        "https://apex-security-verification-portal.com",
        "https://apex-bank-official-support-2026.net",
        "https://secure-login-apexbank-account.top",
        "https://apex-pass-verify-auth.xyz/index.html",
        "https://apexbank-update-myaccount.click",
        "https://portal-apexbank-security-service.buzz",
        "https://apex-fraud-alert-confirmation.com"
    ]

    rows = []
    labels = []

    for url in benign_samples:
        feats = extract_url_features(url)
        rows.append([feats[k] for k in URL_FEATURE_NAMES])
        labels.append(0)

    for url in phishing_samples:
        feats = extract_url_features(url)
        rows.append([feats[k] for k in URL_FEATURE_NAMES])
        labels.append(1)

    X = np.array(rows, dtype=float)
    y = np.array(labels, dtype=int)
    return X, y


def train_and_save_model():
    print("Generating URL training dataset...")
    X, y = generate_training_data()

    model = XGBClassifier(
        n_estimators=100,
        max_depth=3,
        learning_rate=0.1,
        objective="binary:logistic",
        eval_metric="logloss",
        random_state=42,
    )

    print("Fitting XGBoost URL Phishing model...")
    model.fit(X, y)

    # Save model and feature names
    model_path = MODEL_DIR / "url_xgb_model.json"
    model.save_model(str(model_path))

    names_path = MODEL_DIR / "url_feature_names.json"
    with open(names_path, "w", encoding="utf-8") as f:
        json.dump(URL_FEATURE_NAMES, f, indent=2)

    print(f"URL XGBoost Model successfully saved at:\n{model_path}")
    print(f"Features saved at:\n{names_path}")


if __name__ == "__main__":
    train_and_save_model()
