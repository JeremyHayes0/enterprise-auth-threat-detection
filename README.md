# 🛡️ Enterprise Authentication Threat Detection Platform

![Python](https://img.shields.io/badge/Python-3.12-blue)
![Streamlit](https://img.shields.io/badge/Streamlit-Deployed-red)
![Machine Learning](https://img.shields.io/badge/ML-IsolationForest-green)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK-orange)

A production-style SOC/SIEM cybersecurity analytics dashboard built with Python, Streamlit, Pandas, and machine learning concepts.

This project simulates enterprise authentication telemetry and detects suspicious login activity, brute force behavior, service account abuse, lateral movement, foreign login anomalies, and anomalous authentication patterns.

---

# 🚀 Live Demo

https://enterprise-app-threat-detection-8mxncfvnrm8xwfzk5v8ejh.streamlit.app/

---

# 🖼️ Platform Preview

![Platform Banner](images/Screenshot%202026-05-19%20003636.png)

---

# 📌 Project Overview

This project demonstrates:

- Authentication log analytics
- Detection engineering
- SOC dashboard development
- ML-assisted anomaly detection
- MITRE ATT&CK mapping
- Threat hunting workflows
- Attack campaign simulation
- Streamlit Cloud deployment
- Production-style GitHub project organization
- Cybersecurity analytics engineering
- SIEM-style investigation workflows
- Security-focused data analysis

---

# 🧠 Core Features

## Threat Detection Engine

- Failed login detection
- After-hours authentication monitoring
- Suspicious admin/service account monitoring
- User failure-count tracking
- Multi-machine access detection
- Country/IP-based risk signals
- Attack campaign scoring
- Dynamic threat severity classification

---

## ML Anomaly Detection

Uses Isolation Forest to identify unusual authentication behavior based on:

- threat score
- failed login counts
- unique machines accessed
- login hour
- behavioral anomalies

---

## MITRE ATT&CK Mapping

| Behavior | MITRE Technique |
|---|---|
| Brute force failures | T1110 - Brute Force |
| Service account abuse | T1078 - Valid Accounts |
| Admin account activity | T1078.002 - Domain Accounts |
| Lateral movement | T1021 - Remote Services |

---

# ⚔️ Attack Campaign Simulation

The dataset includes realistic simulated attack scenarios:

- Normal Activity
- Brute Force Campaign
- Lateral Movement
- Service Account Abuse
- Foreign Login Anomaly

This allows the platform to simulate real SOC investigation workflows and enterprise attack telemetry analysis.

---

# 📊 Dashboard Pages

- Overview
- Executive Summary
- Threat Analysis
- Anomaly Detection
- Attack Campaign Analysis
- User Investigation
- Machine Investigation
- Incident Timeline
- Geo/IP Analysis
- MITRE ATT&CK
- Raw Logs

---

# 🖼️ Dashboard Screenshots

## Overview Dashboard

![Overview](images/Screenshot%202026-05-19%20003636.png)

---

## Executive Summary

![Executive Summary](images/Screenshot%202026-05-19%20003730.png)

---

## Threat Analysis

![Threat Analysis](images/Screenshot%202026-05-19%20003801.png)

---

## Anomaly Detection

![Anomaly Detection](images/Screenshot%202026-05-19%20003843.png)

---

## Attack Campaign Analysis

![Attack Campaigns](images/Screenshot%202026-05-19%20003914.png)

---

## MITRE ATT&CK Mapping

![MITRE](images/Screenshot%202026-05-19%20004003.png)

---

## Incident Timeline

![Timeline](images/Screenshot%202026-05-19%20004114.png)

---

# 🏗️ Architecture

```text
Synthetic Enterprise Authentication Logs
                ↓
Detection Pipeline
                ↓
Rule-Based Threat Scoring
                ↓
ML Anomaly Detection
                ↓
MITRE ATT&CK Mapping
                ↓
Streamlit SOC Dashboard
                ↓
Downloadable Incident Reports
```

---

# 🧪 Tech Stack

| Technology | Purpose |
|---|---|
| Python | Core development |
| Pandas | Data processing |
| NumPy | Synthetic data generation |
| Scikit-learn | ML anomaly detection |
| Streamlit | Dashboard application |
| GitHub | Version control |
| Streamlit Cloud | Deployment |

---

# 📂 Project Structure

```text
enterprise-auth-threat-detection/
│
├── data/
│   └── logs.csv
│
├── src/
│   ├── __init__.py
│   └── pipeline.py
│
├── streamlit/
│   └── app.py
│
├── notebooks/
├── models/
├── utils/
├── images/
│
├── requirements.txt
├── README.md
└── .gitignore
```

---

# ⚙️ Run Locally

Clone the repository:

```bash
git clone https://github.com/JeremyHayes0/enterprise-auth-threat-detection.git
```

Move into the project:

```bash
cd enterprise-auth-threat-detection
```

Install dependencies:

```bash
pip install -r requirements.txt
```

Run the Streamlit dashboard:

```bash
streamlit run streamlit/app.py
```

---

# 🎯 Portfolio Value

This project demonstrates practical cybersecurity engineering skills across:

- Detection engineering
- Security analytics
- SOC workflows
- Authentication security monitoring
- Machine learning anomaly detection
- Threat hunting
- Streamlit dashboard engineering
- Production deployment
- GitHub project organization
- Blue team analytics
- Cybersecurity automation
- SIEM-style investigation workflows

---

# 🚧 Future Improvements

- Real Windows Event Log ingestion
- Azure AD / Okta / AWS CloudTrail log simulation
- Graph-based user-machine relationship analysis
- Kafka real-time streaming
- Elastic/Splunk SIEM integration
- GeoIP enrichment
- Threat intelligence feed integration
- Modular detection rules engine
- Automated incident response workflows
- Threat hunting query engine
- Real-time dashboard updates
- Detection-as-code architecture

---

# 👨‍💻 Author

Jeremy Hayes

GitHub:
https://github.com/JeremyHayes0

---

# 📜 License

This project is for educational and portfolio purposes.
