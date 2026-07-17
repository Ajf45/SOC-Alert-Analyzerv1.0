# SOC Alert Analyzerv1.0

A rule-based Security Operations Center (SOC) alert analysis platform that ingests security logs, enriches alerts with threat intelligence context, maps activity to the MITRE ATT&CK framework, and generates analyst-ready incident reports.

Built to simulate real-world SOC workflows including alert triage, severity classification, KPI tracking, and shift-handover reporting.

---

## Overview

SOC teams often spend significant time manually reviewing alerts, determining severity, documenting incidents, and preparing handover reports between analyst shifts.

SOC Alert Analyzer automates these repetitive tasks by transforming raw security logs into actionable incident insights.

The platform provides:

* Automated alert severity classification
* MITRE ATT&CK technique mapping
* Risk scoring and prioritization
* SOC KPI visualization
* Downloadable incident reports for shift handovers

The project aims to replicate the day-to-day workflow of an L1/L2 SOC analyst while demonstrating practical incident response and detection engineering concepts.

---

## Why This Project Exists

Security analysts frequently encounter:

* High alert volumes
* Manual triage processes
* Inconsistent incident documentation
* Difficulty prioritizing critical alerts
* Lack of standardized reporting

SOC Alert Analyzer was created to address these challenges by providing a lightweight and extensible alert triage solution that can serve as:

* A SOC analyst training platform
* A portfolio project for cybersecurity professionals
* A foundation for future SOAR automation workflows
* A simplified simulation of enterprise SOC operations

---

## Features

### Log Ingestion

Supports importing security events from:

* CSV files
* JSON files

Example log sources include:

* Firewall logs
* Authentication logs
* Endpoint alerts
* Network traffic events
* IDS/IPS alerts

---

### Rule-Based Detection Engine

Automatically detects suspicious behaviors such as:

* Brute-force login attempts
* Multiple failed authentications
* Suspicious PowerShell execution
* Connections to known malicious IPs
* Privilege escalation attempts
* Unusual process execution

---

### Severity Classification

Alerts are automatically categorized into:

* Critical
* High
* Medium
* Low
* Informational

Classification is based on:

* Detection rule triggered
* Asset sensitivity
* Event frequency
* Risk score

---

### MITRE ATT&CK Mapping

Detected activities are mapped to MITRE ATT&CK techniques to provide threat context.

Example mappings include:

| Activity          | ATT&CK Technique |
| ----------------- | ---------------- |
| Brute Force Login | T1110            |
| PowerShell Abuse  | T1059.001        |
| Command Execution | T1059            |
| Credential Access | T1003            |
| Remote Services   | T1021            |

---

### Risk Scoring Engine

Generates a numerical risk score based on:

* Alert severity
* Frequency of occurrence
* Technique criticality
* Detection confidence

This enables analysts to prioritize incidents more effectively.

---

### Interactive SOC Dashboard

Built using Streamlit and Plotly.

Dashboard capabilities include:

* Real-time KPI metrics
* Alert distribution charts
* Severity trends
* MITRE ATT&CK coverage statistics
* Incident timelines
* Top triggered detections

---

### Incident Reporting

Generate analyst-ready HTML incident reports with a single click.

Reports include:

* Incident summary
* Severity level
* Timeline of events
* Indicators of compromise (IOCs)
* MITRE ATT&CK mapping
* Recommended remediation actions

Designed to replicate SOC shift-handover documentation workflows.

---

## Architecture

The platform follows a modular design consisting of five decoupled components:

```text
SOC Alert Analyzer
│
├── Parser Module
│   ├── CSV ingestion
│   └── JSON ingestion
│
├── Detection Engine
│   ├── Detection rules
│   └── MITRE mappings
│
├── Risk Scoring Engine
│   └── Severity calculations
│
├── Dashboard Module
│   ├── KPIs
│   ├── Metrics
│   └── Visualizations
│
└── Reporting Module
    └── HTML report generation
```

This architecture allows easy extension with new detection rules, log sources, or reporting formats.

---

## Tech Stack

| Category             | Technologies |
| -------------------- | ------------ |
| Programming Language | Python       |
| Data Processing      | Pandas       |
| Dashboard            | Streamlit    |
| Visualization        | Plotly       |
| Reporting            | Jinja2       |
| Threat Framework     | MITRE ATT&CK |

---

## Example Workflow

```text
CSV/JSON Logs
        ↓
Parser Module
        ↓
Detection Rules
        ↓
Severity Classification
        ↓
MITRE ATT&CK Mapping
        ↓
Risk Scoring
        ↓
Dashboard Visualization
        ↓
HTML Incident Report
```

---

## Future Improvements

Planned enhancements include:

* Sigma rule support
* YARA integration
* Threat intelligence enrichment
* VirusTotal API integration
* Email alerting
* SOAR playbook automation
* Elasticsearch support


Installation
git clone https://github.com/Ajf45/SOC_Alert_Analyzerv1.0.git

cd SOC_Alert_Analyzer

python3 -m venv venv

source venv/bin/activate

pip install -r requirements.txt

streamlit run app.py
Sample Logs


Examples:

Windows Event Log (.evtx) support
Sigma rule integration
VirusTotal IP enrichment
GeoIP mapping
Email notifications
User authentication
Incident history with SQLite
