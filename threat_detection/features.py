import numpy as np
import pandas as pd
from sklearn.preprocessing import LabelEncoder

class FeatureEncoder:
    def __init__(self):
        self.enc_username = LabelEncoder()
        self.enc_ip = LabelEncoder()
        self._fitted = False

    def fit(self, df: pd.DataFrame):
        df = df.copy()
        df["username"] = df["username"].fillna("unknown")
        df["ip_address"] = df["ip_address"].fillna("0.0.0.0")
        self.enc_username.fit(df["username"])
        self.enc_ip.fit(df["ip_address"])
        self._fitted = True
        return self

    def _safe_transform(self, enc: LabelEncoder, series: pd.Series):
        # allow unseen labels by extending classes_
        new_vals = [v for v in series.unique() if v not in enc.classes_]
        if new_vals:
            enc.classes_ = np.concatenate([enc.classes_, np.array(new_vals, dtype=enc.classes_.dtype)])
        return enc.transform(series)

    def transform(self, df: pd.DataFrame) -> pd.DataFrame:
        if not self._fitted:
            self.fit(df)

        df = df.copy()
        df["action"] = df.get("action", "").fillna("")
        df["username"] = df.get("username", "").fillna("unknown")
        df["ip_address"] = df.get("ip_address", "").fillna("0.0.0.0")

        df["is_failed_action"] = df["action"].str.lower().str.contains("fail|denied|unauthorized").astype(int)
        ip_counts = df["ip_address"].value_counts().to_dict()
        user_counts = df["username"].value_counts().to_dict()
        df["ip_frequency"] = df["ip_address"].map(ip_counts).fillna(0)
        df["user_frequency"] = df["username"].map(user_counts).fillna(0)

        df["username_encoded"] = self._safe_transform(self.enc_username, df["username"])
        df["ip_encoded"] = self._safe_transform(self.enc_ip, df["ip_address"])

        feats = df[["is_failed_action","ip_frequency","user_frequency","username_encoded","ip_encoded"]].astype(float)
        return feats
