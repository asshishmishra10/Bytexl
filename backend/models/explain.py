"""
Explainable AI (XAI) Engine — Aegis
===================================
Computes feature contributions (Tree SHAP) for:
1. Social Profile Impersonation Classifier (social_xgb_model.json)
2. Rogue Mobile Permissions Classifier (mobile_xgb_model.json)
3. URL / Domain Classifier (url_xgb_model.json)

Supports native XGBoost when installed, with seamless fallback to
PureTreeEnsemble on lightweight serverless runtimes like Vercel.
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
from models.pure_engine import (
    get_pure_social_ensemble,
    get_pure_mobile_ensemble,
    get_pure_url_ensemble,
)

logger = logging.getLogger(__name__)


def explain_social_prediction(features: Dict[str, Any], top_n: int = 5) -> Dict[str, float]:
    """Computes feature contributions (SHAP values) for a social profile prediction."""
    vec = [float(features.get(k, 0)) for k in SOCIAL_FEATURE_KEYS]
    model = get_social_model()
    if model is not None and xgb is not None:
        try:
            arr = np.array([vec], dtype=float)
            dmat = xgb.DMatrix(arr, feature_names=SOCIAL_FEATURE_KEYS)
            contribs = model.get_booster().predict(dmat, pred_contribs=True)[0][:-1]
            paired = [(name, float(val)) for name, val in zip(SOCIAL_FEATURE_KEYS, contribs)]
            paired.sort(key=lambda x: x[1], reverse=True)
            return {name: round(val, 4) for name, val in paired[:top_n]}
        except Exception as e:
            logger.debug("Native XGBoost explain error, using pure tree engine: %s", e)

    return get_pure_social_ensemble().explain(vec, top_n=top_n)


def explain_mobile_prediction(
    permissions: Union[List[str], Dict[str, Any], set],
    top_n: int = 5
) -> Dict[str, float]:
    """Computes permission contributions (SHAP values) for a mobile app prediction."""
    vec = manifest_to_vector(permissions)
    model = get_mobile_model()
    if model is not None and xgb is not None:
        try:
            arr = np.array([vec], dtype=float)
            dmat = xgb.DMatrix(arr, feature_names=MOBILE_FEATURE_NAMES)
            contribs = model.get_booster().predict(dmat, pred_contribs=True)[0][:-1]
            active_indices = [i for i, v in enumerate(vec) if v > 0]
            if active_indices:
                paired = [(MOBILE_FEATURE_NAMES[i], float(contribs[i])) for i in active_indices]
            else:
                paired = [(MOBILE_FEATURE_NAMES[i], float(contribs[i])) for i in range(len(MOBILE_FEATURE_NAMES))]
            paired.sort(key=lambda x: x[1], reverse=True)
            return {name: round(val, 4) for name, val in paired[:top_n]}
        except Exception as e:
            logger.debug("Native XGBoost explain error, using pure tree engine: %s", e)

    return get_pure_mobile_ensemble().explain(vec, top_n=top_n)


def explain_url_prediction(
    url_or_features: Union[str, Dict[str, float]],
    top_n: int = 5
) -> Dict[str, float]:
    """Computes lexical and entropy feature contributions for a URL / domain prediction."""
    if isinstance(url_or_features, str):
        feats = extract_url_features_dict(url_or_features)
    else:
        feats = url_or_features

    vec = [float(feats.get(k, 0.0)) for k in URL_FEATURE_NAMES]
    model = get_url_model()
    if model is not None and xgb is not None:
        try:
            arr = np.array([vec], dtype=float)
            dmat = xgb.DMatrix(arr, feature_names=URL_FEATURE_NAMES)
            contribs = model.get_booster().predict(dmat, pred_contribs=True)[0][:-1]
            paired = [(URL_FEATURE_NAMES[i], float(contribs[i])) for i in range(len(URL_FEATURE_NAMES))]
            paired.sort(key=lambda x: x[1], reverse=True)
            return {name: round(val, 4) for name, val in paired[:top_n]}
        except Exception as e:
            logger.debug("Native XGBoost explain error, using pure tree engine: %s", e)

    return get_pure_url_ensemble().explain(vec, top_n=top_n)
