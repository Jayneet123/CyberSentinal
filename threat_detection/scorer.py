import pandas as pd
import numpy as np
from typing import Dict, Tuple
from .features import FeatureEncoder

# Load known bad IP list (could be from a CSV in future)
BAD_IPS = {
    "103.70.115.121", "42.0.129.10", "204.44.110.203", "15.235.151.18",
    "107.175.62.236", "146.59.45.160", "117.86.57.177", "42.0.129.145",
    "140.237.86.152", "42.0.129.182", "171.211.48.35", "175.165.144.206",
    "118.120.230.109", "42.6.176.117", "121.232.99.179", "34.85.112.44",
    "103.149.28.83", "103.149.28.174", "42.0.129.83", "103.149.29.13",
    "172.233.115.32", "42.6.177.92", "34.146.250.104", "23.226.136.178",
    "160.191.52.44"
}

# Suspicious action keywords
SUSPICIOUS_KEYWORDS = [
    "failed password", "multiple failed sudo", "unauthorized database access",
    "brute force", "sql injection", "malware"
]

def fit_if_needed(model, encoder: FeatureEncoder, df_hist: pd.DataFrame):
    feats = encoder.transform(df_hist)
    try:
        _ = model.decision_function(feats)
    except Exception:
        model.fit(feats)
    return model

def _sigmoid(x: float, k: float = 5.0) -> float:
    return float(1.0 / (1.0 + np.exp(k * x)))

def score_event(
    model,
    encoder: FeatureEncoder,
    summary: Dict,
    threshold: float = 0.75
) -> Tuple[Dict, float, bool]:
    ip = summary.get("ip_address", "").strip().lower()
    action = summary.get("action", "").lower()
    msg = summary.get("message_summary", "").lower()

    # 1. Immediate blocklist match
    if ip in BAD_IPS:
        summary["threat_score"] = 1.0
        summary["is_anomaly"] = True
        summary["anomaly_reason"] = "Known malicious IP"
        return summary, 1.0, True

    # 2. Hard keyword rules (raise base score)
    rule_bonus = 0.0
    for keyword in SUSPICIOUS_KEYWORDS:
        if keyword in action or keyword in msg:
            rule_bonus = max(rule_bonus, 0.25)

    # 3. ML scoring
    df = pd.DataFrame([summary])
    feats = encoder.transform(df)

    try:
        raw = float(model.decision_function(feats)[0])
    except Exception:
        tmp = pd.concat([feats] * 10, ignore_index=True)
        model.fit(tmp)
        raw = float(model.decision_function(feats)[0])

    threat_score = _sigmoid(raw, k=5.0)
    final_score = min(1.0, threat_score + rule_bonus)

    try:
        pred = int(model.predict(feats)[0])
        is_anom_by_model = (pred == -1)
    except Exception:
        is_anom_by_model = False

    is_anomaly = bool(is_anom_by_model or (final_score >= threshold))

    summary["threat_score"] = final_score
    summary["is_anomaly"] = is_anomaly
    return summary, final_score, is_anomaly
