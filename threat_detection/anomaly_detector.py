import json
import os
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import LabelEncoder
import numpy as np

# === Load log summaries ===
with open("../llm_log_parser/output/summarized_logs.json", "r") as f:
    logs = json.load(f)

# === Create DataFrame ===
df = pd.DataFrame(logs)

# === Feature Engineering ===

# Treat common actions as low-risk
df["is_failed_action"] = df["action"].str.lower().str.contains("fail|denied|unauthorized").astype(int)

# Frequency of each IP (rare IPs might be anomalous)
ip_counts = df["ip_address"].value_counts().to_dict()
df["ip_frequency"] = df["ip_address"].map(ip_counts)

# Frequency of usernames
user_counts = df["username"].value_counts().to_dict()
df["user_frequency"] = df["username"].map(user_counts)

# Encode username and IP address
enc_username = LabelEncoder()
enc_ip = LabelEncoder()
df["username_encoded"] = enc_username.fit_transform(df["username"].fillna("unknown"))
df["ip_encoded"] = enc_ip.fit_transform(df["ip_address"].fillna("0.0.0.0"))

# Final feature set
features = df[["is_failed_action", "ip_frequency", "user_frequency", "username_encoded", "ip_encoded"]].fillna(0)

# === Train Isolation Forest ===
model = IsolationForest(contamination=0.15, random_state=42)
model.fit(features)
df["anomaly_score"] = -model.decision_function(features)  # lower = more anomalous


# Normalize anomaly score (0 to 1)
min_score = df["anomaly_score"].min()
max_score = df["anomaly_score"].max()
df["threat_score"] = (df["anomaly_score"] - min_score) / (max_score - min_score)
df["is_anomaly"] = df["threat_score"] > 0.6  # threshold for alert

# === Save model (optional) ===
import joblib
joblib.dump(model, "threat_model.pkl")

# === Output scored logs ===
output = logs
for i, entry in enumerate(output):
    entry["threat_score"] = float(df.loc[i, "threat_score"])
    entry["is_anomaly"] = bool(df.loc[i, "is_anomaly"])

with open("scored_logs.json", "w") as f:
    json.dump(output, f, indent=2)

print(f"✅ Scored {len(df)} log entries. Saved to scored_logs.json.")
