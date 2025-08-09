import joblib
from pathlib import Path
from sklearn.ensemble import IsolationForest

def load_or_new_model(model_path: str, contamination: float = 0.15):
    p = Path(model_path)
    if p.exists():
        try:
            return joblib.load(p)
        except Exception:
            pass
    return IsolationForest(contamination=contamination, random_state=42)

def save_model(model, model_path: str):
    joblib.dump(model, model_path)
