"""
Explainable AI (XAI) Engine — AegisShield
==========================================
Computes native tree feature contributions (Tree SHAP) for both:
1. Social Profile Impersonation Classifier (`social_xgb_model.json`)
2. Rogue Mobile Permissions Classifier (`mobile_xgb_model.json`)

Identifies the top-N driving factors behind every machine-learning verdict,
enabling SOC analysts to inspect WHY a candidate was flagged.
"""

import logging
from typing import Dict, Any, List, Union
import numpy as np

try:
    import xgboost as xgb
except ImportError:
    xgb = None

from models.loader import (
    get_social_model,
    SOCIAL_FEATURE_KEYS,
    get_mobile_model,
    MOBILE_FEATURE_NAMES,
    manifest_to_vector,
    get_url_model,
    URL_FEATURE_NAMES,
    extract_url_features_dict,
)

logger = logging.getLogger(__name__)


def explain_social_prediction(features: Dict[str, Any], top_n: int = 5) -> Dict[str, float]:
    """
    Computes feature contributions (SHAP values) for a social profile prediction.
    Returns the top-N features pushing the classification toward fake/impersonator.
    """
    model = get_social_model()
    if model is None or xgb is None:
        return {}

    try:
        vec = [float(features.get(k, 0)) for k in SOCIAL_FEATURE_KEYS]
        arr = np.array([vec], dtype=float)
        dmat = xgb.DMatrix(arr, feature_names=SOCIAL_FEATURE_KEYS)
        
        contribs = model.get_booster().predict(dmat, pred_contribs=True)[0][:-1]
        
        # Pair feature names with their contribution values
        paired = [(name, float(val)) for name, val in zip(SOCIAL_FEATURE_KEYS, contribs)]
        
        # Sort by magnitude of positive contribution (pushing toward threat)
        paired.sort(key=lambda x: x[1], reverse=True)
        
        # Return top N positive contributors (or top features overall)
        return {name: round(val, 4) for name, val in paired[:top_n]}
    except Exception as e:
        logger.warning(f"Error computing social feature contributions: {e}", exc_info=True)
        return {}


def explain_mobile_prediction(
    permissions: Union[List[str], Dict[str, Any], set],
    top_n: int = 5
) -> Dict[str, float]:
    """
    Computes permission contributions (SHAP values) for a mobile app prediction.
    Returns the top-N anomalous permissions driving the rogue app probability.
    """
    model = get_mobile_model()
    if model is None or xgb is None:
        return {}

    try:
        vec = manifest_to_vector(permissions)
        arr = np.array([vec], dtype=float)
        dmat = xgb.DMatrix(arr, feature_names=MOBILE_FEATURE_NAMES)
        
        contribs = model.get_booster().predict(dmat, pred_contribs=True)[0][:-1]
        
        # Filter for active permissions requested by this app
        active_indices = [i for i, v in enumerate(vec) if v > 0]
        
        if active_indices:
            paired = [(MOBILE_FEATURE_NAMES[i], float(contribs[i])) for i in active_indices]
        else:
            paired = [(MOBILE_FEATURE_NAMES[i], float(contribs[i])) for i in range(len(MOBILE_FEATURE_NAMES))]
            
        # Sort by positive contribution to malware classification
        paired.sort(key=lambda x: x[1], reverse=True)
        
        return {name: round(val, 4) for name, val in paired[:top_n]}
    except Exception as e:
        logger.warning(f"Error computing mobile permission contributions: {e}", exc_info=True)
        return {}


def explain_url_prediction(
    url_or_features: Union[str, Dict[str, float]],
    top_n: int = 5
) -> Dict[str, float]:
    """
    Computes lexical and entropy feature contributions (Tree SHAP) for a URL / domain prediction.
    Returns the top-N driving factors behind why a domain was flagged as malicious phishing.
    """
    model = get_url_model()
    if model is None or xgb is None:
        return {}

    try:
        if isinstance(url_or_features, str):
            feats = extract_url_features_dict(url_or_features)
        else:
            feats = url_or_features

        vec = [float(feats.get(k, 0.0)) for k in URL_FEATURE_NAMES]
        arr = np.array([vec], dtype=float)
        dmat = xgb.DMatrix(arr, feature_names=URL_FEATURE_NAMES)

        contribs = model.get_booster().predict(dmat, pred_contribs=True)[0][:-1]
        paired = [(URL_FEATURE_NAMES[i], float(contribs[i])) for i in range(len(URL_FEATURE_NAMES))]
        paired.sort(key=lambda x: x[1], reverse=True)

        return {name: round(val, 4) for name, val in paired[:top_n]}
    except Exception as e:
        logger.warning(f"Error computing URL feature contributions: {e}", exc_info=True)
        return {}

