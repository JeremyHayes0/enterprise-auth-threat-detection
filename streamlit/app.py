
import streamlit as st
import pandas as pd
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.append(str(ROOT))

from src.pipeline import run_pipeline

st.set_page_config(
    page_title="SOC Threat Detection",
    layout="wide"
)

csv_path = ROOT / "data" / "logs.csv"

df = pd.read_csv(csv_path)
df = run_pipeline(df)

st.sidebar.title("SOC Navigation")

page = st.sidebar.radio(
    "Go to",
    [
        "Overview",
        "Executive Summary",
        "Threat Analysis",
        "Anomaly Detection",
        "Attack Campaign Analysis",
        "User Investigation",
        "Machine Investigation",
        "Incident Timeline",
        "Geo/IP Analysis",
        "MITRE ATT&CK",
        "Raw Logs"
    ]
)

st.title("🛡️ Enterprise Authentication Threat Detection Platform")

if page == "Overview":
    col1, col2, col3, col4, col5 = st.columns(5)

    col1.metric("Total Events", len(df))
    col2.metric("Failed Logins", (df["result"] == "failure").sum())
    col3.metric("Critical Events", (df["risk_level"] == "CRITICAL").sum())
    col4.metric("Anomalies", (df["anomaly"] == "Anomalous").sum())
    col5.metric("Unique Users", df["source_user"].nunique())

    st.subheader("Risk Distribution")
    st.bar_chart(df["risk_level"].value_counts())

    st.subheader("Anomaly Distribution")
    st.bar_chart(df["anomaly"].value_counts())

    st.subheader("Attack Campaign Distribution")
    st.bar_chart(df["attack_campaign"].value_counts())

elif page == "Executive Summary":
    st.subheader("Executive SOC Summary")

    total_events = len(df)
    failed_logins = (df["result"] == "failure").sum()
    critical_events = (df["risk_level"] == "CRITICAL").sum()
    anomalies = (df["anomaly"] == "Anomalous").sum()

    col1, col2, col3, col4 = st.columns(4)

    col1.metric("Total Events", total_events)
    col2.metric("Failed Logins", failed_logins)
    col3.metric("Critical Events", critical_events)
    col4.metric("ML Anomalies", anomalies)

    failure_rate = round((failed_logins / total_events) * 100, 2)
    critical_rate = round((critical_events / total_events) * 100, 2)
    anomaly_rate = round((anomalies / total_events) * 100, 2)

    highest_risk_user = df.groupby("source_user")["threat_score"].max().idxmax()
    highest_risk_country = df.groupby("country")["threat_score"].max().idxmax()

    st.subheader("Key Risk Indicators")

    st.write(f"""
    - Failure rate: **{failure_rate}%**
    - Critical event rate: **{critical_rate}%**
    - Anomaly rate: **{anomaly_rate}%**
    - Highest-risk user: **{highest_risk_user}**
    - Highest-risk country: **{highest_risk_country}**
    - Detection model: **Rule-based scoring + Isolation Forest anomaly detection**
    """)

    st.subheader("Top Risky Users")
    st.bar_chart(
        df.groupby("source_user")["threat_score"]
        .max()
        .sort_values(ascending=False)
        .head(10)
    )

    st.subheader("Top Attack Campaigns")
    st.bar_chart(df["attack_campaign"].value_counts())

elif page == "Threat Analysis":
    st.subheader("Top High-Risk Events")

    high_risk = df[df["risk_level"].isin(["HIGH", "CRITICAL"])]

    st.dataframe(
        high_risk.sort_values("threat_score", ascending=False),
        use_container_width=True
    )

    st.subheader("Top Failed Login Users")
    failed_users = (
        df[df["result"] == "failure"]["source_user"]
        .value_counts()
        .head(10)
    )
    st.bar_chart(failed_users)

    st.subheader("Top Threat Scores by User")
    st.bar_chart(
        df.groupby("source_user")["threat_score"]
        .max()
        .sort_values(ascending=False)
        .head(10)
    )

elif page == "Anomaly Detection":
    st.subheader("ML-Based Anomaly Detection")

    anomalies = df[df["anomaly"] == "Anomalous"]

    col1, col2, col3 = st.columns(3)

    col1.metric("Total Anomalies", len(anomalies))
    col2.metric("Anomaly Rate", f"{round((len(anomalies) / len(df)) * 100, 2)}%")
    col3.metric(
        "Max Threat Score",
        int(anomalies["threat_score"].max()) if not anomalies.empty else 0
    )

    st.subheader("Anomalous Events")
    st.dataframe(
        anomalies.sort_values("threat_score", ascending=False),
        use_container_width=True
    )

    st.subheader("Anomalies by User")
    st.bar_chart(anomalies["source_user"].value_counts().head(10))

    st.subheader("Anomalies by Campaign")
    st.bar_chart(anomalies["attack_campaign"].value_counts())

    csv = anomalies.to_csv(index=False)

    st.download_button(
        "Download Anomaly Report",
        csv,
        "anomaly_report.csv",
        "text/csv"
    )

elif page == "Attack Campaign Analysis":
    st.subheader("Attack Campaign Intelligence")

    st.subheader("Campaign Distribution")
    st.bar_chart(df["attack_campaign"].value_counts())

    selected_campaign = st.selectbox(
        "Select Campaign",
        sorted(df["attack_campaign"].unique())
    )

    campaign_df = df[df["attack_campaign"] == selected_campaign]

    col1, col2, col3, col4 = st.columns(4)

    col1.metric("Campaign Events", len(campaign_df))
    col2.metric("Failures", (campaign_df["result"] == "failure").sum())
    col3.metric("Anomalies", (campaign_df["anomaly"] == "Anomalous").sum())
    col4.metric("Max Threat Score", int(campaign_df["threat_score"].max()))

    st.subheader("Campaign Events")
    st.dataframe(
        campaign_df.sort_values("threat_score", ascending=False),
        use_container_width=True
    )

    st.subheader("Campaign MITRE Mapping")
    st.bar_chart(campaign_df["mitre_attack"].value_counts())

    csv = campaign_df.to_csv(index=False)

    st.download_button(
        "Download Campaign Report",
        csv,
        "campaign_report.csv",
        "text/csv"
    )

elif page == "User Investigation":
    st.subheader("User Investigation Mode")

    selected_user = st.selectbox(
        "Select a user",
        sorted(df["source_user"].unique())
    )

    user_df = df[df["source_user"] == selected_user]

    col1, col2, col3, col4 = st.columns(4)

    col1.metric("User Events", len(user_df))
    col2.metric("Failures", (user_df["result"] == "failure").sum())
    col3.metric("Max Threat Score", int(user_df["threat_score"].max()))
    col4.metric("Anomalies", (user_df["anomaly"] == "Anomalous").sum())

    st.dataframe(
        user_df.sort_values("threat_score", ascending=False),
        use_container_width=True
    )

    st.subheader("User Threat Score Timeline")

    timeline = user_df[["timestamp", "threat_score"]].copy()
    timeline["timestamp"] = pd.to_datetime(timeline["timestamp"], errors="coerce")
    timeline = timeline.dropna().sort_values("timestamp")

    if not timeline.empty:
        st.line_chart(timeline.set_index("timestamp")["threat_score"])
    else:
        st.info("No valid timestamp data available for this user.")

elif page == "Machine Investigation":
    st.subheader("Machine Investigation Mode")

    selected_machine = st.selectbox(
        "Select a source machine",
        sorted(df["source_computer"].unique())
    )

    machine_df = df[df["source_computer"] == selected_machine]

    col1, col2, col3, col4 = st.columns(4)

    col1.metric("Machine Events", len(machine_df))
    col2.metric("Failures", (machine_df["result"] == "failure").sum())
    col3.metric("Max Threat Score", int(machine_df["threat_score"].max()))
    col4.metric("Anomalies", (machine_df["anomaly"] == "Anomalous").sum())

    st.subheader("Machine Events")
    st.dataframe(
        machine_df.sort_values("threat_score", ascending=False),
        use_container_width=True
    )

    st.subheader("Destination Computers Accessed")
    st.bar_chart(machine_df["destination_computer"].value_counts())

    st.subheader("Users Seen on This Machine")
    st.bar_chart(machine_df["source_user"].value_counts())

elif page == "Incident Timeline":
    st.subheader("Threat Activity Timeline")

    timeline_df = df.copy()
    timeline_df["timestamp"] = pd.to_datetime(timeline_df["timestamp"], errors="coerce")
    timeline_df = timeline_df.dropna(subset=["timestamp"])

    if not timeline_df.empty:
        st.subheader("Average Threat Score Over Time")
        threat_timeline = (
            timeline_df
            .set_index("timestamp")
            .resample("h")["threat_score"]
            .mean()
        )
        st.line_chart(threat_timeline)

        st.subheader("Critical Events Over Time")
        critical_timeline = (
            timeline_df[timeline_df["risk_level"] == "CRITICAL"]
            .set_index("timestamp")
            .resample("h")
            .size()
        )
        st.line_chart(critical_timeline)

        st.subheader("Failed Logins Over Time")
        failure_timeline = (
            timeline_df[timeline_df["result"] == "failure"]
            .set_index("timestamp")
            .resample("h")
            .size()
        )
        st.line_chart(failure_timeline)

        st.subheader("Anomalies Over Time")
        anomaly_timeline = (
            timeline_df[timeline_df["anomaly"] == "Anomalous"]
            .set_index("timestamp")
            .resample("h")
            .size()
        )
        st.line_chart(anomaly_timeline)

elif page == "Geo/IP Analysis":
    st.subheader("Country and IP Risk Analysis")

    st.subheader("Top Countries by Event Volume")
    st.bar_chart(df["country"].value_counts())

    st.subheader("Top IP Addresses by Threat Score")
    ip_risk = (
        df.groupby("ip_address")["threat_score"]
        .max()
        .sort_values(ascending=False)
        .head(10)
    )
    st.bar_chart(ip_risk)

    st.subheader("Geo/IP High-Risk Events")

    geo_cols = [
        "timestamp",
        "source_user",
        "ip_address",
        "country",
        "auth_type",
        "logon_type",
        "attack_campaign",
        "anomaly",
        "risk_level",
        "threat_score"
    ]

    st.dataframe(
        df[geo_cols].sort_values("threat_score", ascending=False),
        use_container_width=True
    )

elif page == "MITRE ATT&CK":
    st.subheader("MITRE ATT&CK Technique Mapping")

    mitre_counts = df["mitre_attack"].value_counts()
    st.bar_chart(mitre_counts)

    display_cols = [
        "source_user",
        "result",
        "attack_campaign",
        "threat_score",
        "risk_level",
        "anomaly",
        "mitre_attack"
    ]

    st.dataframe(
        df[display_cols].sort_values("threat_score", ascending=False),
        use_container_width=True
    )

elif page == "Raw Logs":
    st.subheader("Raw Processed Logs")

    risk_filter = st.multiselect(
        "Filter by risk level",
        options=sorted(df["risk_level"].unique()),
        default=sorted(df["risk_level"].unique())
    )

    anomaly_filter = st.multiselect(
        "Filter by anomaly status",
        options=sorted(df["anomaly"].unique()),
        default=sorted(df["anomaly"].unique())
    )

    campaign_filter = st.multiselect(
        "Filter by attack campaign",
        options=sorted(df["attack_campaign"].unique()),
        default=sorted(df["attack_campaign"].unique())
    )

    filtered = df[
        df["risk_level"].isin(risk_filter)
        & df["anomaly"].isin(anomaly_filter)
        & df["attack_campaign"].isin(campaign_filter)
    ]

    st.dataframe(filtered, use_container_width=True)

    csv = filtered.to_csv(index=False)

    st.download_button(
        "Download Filtered Threat Report",
        csv,
        "threat_report.csv",
        "text/csv"
    )
