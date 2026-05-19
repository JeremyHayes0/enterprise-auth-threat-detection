
import pandas as pd
from sklearn.ensemble import IsolationForest


def run_pipeline(df):
    """
    Run enterprise authentication threat detection pipeline.

    Adds:
    - threat_score
    - risk_level
    - MITRE ATT&CK mapping
    - anomaly detection labels
    - behavioral risk features
    """

    df = df.copy()

    # -------------------------
    # Defensive cleanup
    # -------------------------
    df["result"] = df["result"].fillna("").str.lower()
    df["source_user"] = df["source_user"].fillna("unknown")

    if "timestamp" in df.columns:
        df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
        df["hour"] = df["timestamp"].dt.hour.fillna(12)
    else:
        df["hour"] = 12

    # -------------------------
    # Base threat scoring
    # -------------------------
    df["threat_score"] = 0

    # Failed authentication
    df.loc[df["result"] == "failure", "threat_score"] += 25

    # Suspicious account names
    suspicious_user = df["source_user"].str.contains(
        "admin|svc|service|machine",
        case=False,
        na=False
    )
    df.loc[suspicious_user, "threat_score"] += 15

    # After-hours activity
    df["after_hours"] = df["hour"].between(0, 5)
    df.loc[df["after_hours"], "threat_score"] += 10

    # User failed login count
    df["user_failure_count"] = df.groupby("source_user")["result"].transform(
        lambda x: (x == "failure").sum()
    )
    df.loc[df["user_failure_count"] >= 10, "threat_score"] += 20

    # Unique machines accessed
    if "source_computer" in df.columns:
        df["unique_machines_accessed"] = df.groupby("source_user")[
            "source_computer"
        ].transform("nunique")

        df.loc[df["unique_machines_accessed"] >= 3, "threat_score"] += 15
    else:
        df["unique_machines_accessed"] = 0

    # Country risk signal
    if "country" in df.columns:
        df["country"] = df["country"].fillna("Unknown")
        df.loc[
            df["country"].isin(["Unknown", "Germany", "Brazil"]),
            "threat_score"
        ] += 10

    # Attack campaign scoring
    if "attack_campaign" in df.columns:
        df["attack_campaign"] = df["attack_campaign"].fillna("Normal Activity")

        df.loc[df["attack_campaign"] == "Brute Force Campaign", "threat_score"] += 30
        df.loc[df["attack_campaign"] == "Lateral Movement", "threat_score"] += 35
        df.loc[df["attack_campaign"] == "Service Account Abuse", "threat_score"] += 25
        df.loc[df["attack_campaign"] == "Foreign Login Anomaly", "threat_score"] += 20
    else:
        df["attack_campaign"] = "Unknown"

    # -------------------------
    # MITRE ATT&CK mapping
    # -------------------------
    def map_mitre(row):
        campaign = str(row.get("attack_campaign", "")).lower()
        user = str(row.get("source_user", "")).lower()
        result = str(row.get("result", "")).lower()

        if "brute force" in campaign:
            return "T1110 - Brute Force"
        if "lateral movement" in campaign:
            return "T1021 - Remote Services"
        if "service account" in campaign:
            return "T1078 - Valid Accounts"
        if "foreign login" in campaign:
            return "T1078 - Valid Accounts"
        if result == "failure" and row.get("user_failure_count", 0) >= 10:
            return "T1110 - Brute Force"
        if "admin" in user:
            return "T1078.002 - Domain Accounts"
        if "svc" in user or "service" in user:
            return "T1078 - Valid Accounts"
        if row.get("unique_machines_accessed", 0) >= 3:
            return "T1021 - Remote Services"

        return "Normal Activity"

    df["mitre_attack"] = df.apply(map_mitre, axis=1)

    # -------------------------
    # Dynamic risk levels
    # -------------------------
    medium = df["threat_score"].quantile(0.70)
    high = df["threat_score"].quantile(0.85)
    critical = df["threat_score"].quantile(0.95)

    def label_risk(score):
        if score >= critical:
            return "CRITICAL"
        elif score >= high:
            return "HIGH"
        elif score >= medium:
            return "MEDIUM"
        return "LOW"

    df["risk_level"] = df["threat_score"].apply(label_risk)

    # -------------------------
    # ML anomaly detection
    # -------------------------
    features = df[
        [
            "threat_score",
            "user_failure_count",
            "unique_machines_accessed",
            "hour"
        ]
    ].fillna(0)

    model = IsolationForest(
        contamination=0.05,
        random_state=42
    )

    df["anomaly_raw"] = model.fit_predict(features)

    df["anomaly"] = df["anomaly_raw"].map({
        1: "Normal",
        -1: "Anomalous"
    })

    df["anomaly_score"] = model.decision_function(features)

    return df
