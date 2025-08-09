import pandas as pd
import numpy as np
from typing import Dict, Tuple
from .features import FeatureEncoder

def fit_if_needed(model, encoder: FeatureEncoder, df_hist: pd.DataFrame):
    feats = encoder.transform(df_hist)
    try:
        # Will raise before fit on some sklearn versions
        _ = model.decision_function(feats)
    except Exception:
        model.fit(feats)
    return model

def _sigmoid(x: float, k: float = 5.0) -> float:
    """
    Map IsolationForest decision_function (higher=more normal) to [0,1] threat score.
    Negative raw -> high threat, positive raw -> low threat.
    k controls steepness; k=5 works well for typical IF ranges.
    """
    # threat_score = 1 / (1 + exp(k * raw_score))
    # raw << 0 -> ~1.0 (threat); raw >> 0 -> ~0.0 (normal)
    return float(1.0 / (1.0 + np.exp(k * x)))

def score_event(
    model,
    encoder: FeatureEncoder,
    summary: Dict,
    threshold: float = 0.75
) -> Tuple[Dict, float, bool]:
    """
    Returns: (summary_with_scores, threat_score in [0,1], is_anomaly bool)
    """
    df = pd.DataFrame([summary])
    feats = encoder.transform(df)

    # 1) Raw IF score: higher = more normal, lower (negative) = more anomalous
    try:
        raw = float(model.decision_function(feats)[0])
    except Exception:
        # Fit quickly on a duplicated tiny batch if needed
        tmp = pd.concat([feats] * 10, ignore_index=True)
        model.fit(tmp)
        raw = float(model.decision_function(feats)[0])

    # 2) Convert to threat score in [0,1] with a sigmoid centered ~0
    threat_score = _sigmoid(raw, k=5.0)

    # 3) Binary decision (two ways): model.predict and threshold on threat_score
    #    model.predict: -1 = anomaly, 1 = normal
    try:
        pred = int(model.predict(feats)[0])
        is_anom_by_model = (pred == -1)
    except Exception:
        is_anom_by_model = False

    is_anomaly = bool(is_anom_by_model or (threat_score >= threshold))

    # 4) Attach to the event
    summary["threat_score"] = threat_score
    summary["is_anomaly"] = is_anomaly

    return summary, threat_score, is_anomaly
