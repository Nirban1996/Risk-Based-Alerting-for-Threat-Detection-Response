# An Open-Source Risk-Based Alerting (RBA) Framework for Effective Threat Detection and Response

[![Python](https://img.shields.io/badge/Python-3.10+-blue.svg)](https://www.python.org/)
[![OpenSearch](https://img.shields.io/badge/OpenSearch-2.x-orange.svg)](https://opensearch.org/)
[![Wazuh](https://img.shields.io/badge/Wazuh-4.14-blueviolet.svg)](https://wazuh.com/)
[![Streamlit](https://img.shields.io/badge/Streamlit-1.25+-red.svg)](https://streamlit.io/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

An enterprise-grade, fully open-source **Risk-Based Alerting (RBA)** framework designed to eliminate Security Operations Center (SOC) alert fatigue, suppress false positives by up to **98%**, and aggregate low-fidelity security telemetry into high-fidelity entity risk profiles.

> **Academic Reference:**  
> Developed as part of the *Professional Masters in Information and Cyber Security (PMICS)* degree program at the **Department of Computer Science and Engineering, University of Dhaka**.  
> **Authors:** Shafayet Ahmed & Mohd. Billal Hossain Bipu  
> **Supervisor:** Md. Samiul Islam  

---

## 📌 Table of Contents
- [Executive Overview](#-executive-overview)
- [The Problem: SOC Alert Fatigue & SIEM Limitations](#-the-problem-soc-alert-fatigue--siem-limitations)
- [Core Concept & Architectural Philosophy](#-core-concept--architectural-philosophy)
- [System Architecture & Data Flow](#-system-architecture--data-flow)
- [Mathematical Framework](#-mathematical-framework)
  - [1. Entity-Centric Risk Aggregation & Temporal Decay](#1-entity-centric-risk-aggregation--temporal-decay)
  - [2. Robust Statistical Baselines (MAD & Trimming)](#2-robust-statistical-baselines-mad--trimming)
  - [3. Adaptive Thresholding & Self-Healing](#3-adaptive-thresholding--self-healing)
  - [4. Multi-Gate Alert Logic & Velocity Gating](#4-multi-gate-alert-logic--velocity-gating)
- [Repository Structure](#-repository-structure)
- [Key Components](#-key-components)
  - [RBA Compute Engine](#1-rba-compute-engine-rba_compute_snapshot_and_alert_oncepy)
  - [RBA Control Center Dashboard](#2-rba-control-center-dashboard-rba_dashboardpy)
- [Configuration Guide (`.env`)](#-configuration-guide-env)
- [Getting Started & Installation](#-getting-started--installation)
- [Empirical Evaluation & Results](#-empirical-evaluation--results)
- [MITRE ATT&CK Alignment & Explainability](#-mitre-attck-alignment--explainability)
- [Limitations & Future Roadmap](#-limitations--future-roadmap)
- [License & Citation](#-license--citation)

---

## 📑 Executive Overview

Modern Security Operations Centers (SOCs) face an unprecedented operational crisis: traditional Security Information and Event Management (SIEM) systems generate tens of thousands of atomic, binary alerts per day. Industry studies highlight the severity of this issue:
* **56%** of large enterprises ingest over 1,000 alerts per analyst daily.
* **83%** of generated security alerts are classified as false positives.
* **62%** of SOC alerts are ignored due to analyst bandwidth constraints and cognitive overload.

This framework transforms threat detection by shifting from **event-level matching** to **entity-level behavioral risk aggregation**. By maintaining continuous sliding temporal windows with exponential risk decay and calculating dynamic, entity-specific thresholds, the platform suppresses routine operational noise while providing clear, explainable, and actionable detection for multi-stage threat campaigns.

---

## 🚨 The Problem: SOC Alert Fatigue & SIEM Limitations

### 1. The Precision-Recall Dilemma
Traditional rule-based SIEMs tune detection rules for high recall ($Recall = \frac{TP}{TP + FN}$) to prevent missed breaches. However, this creates a catastrophic drop in precision ($Precision = \frac{TP}{TP + FP}$), flooding analysts with false alarms.

### 2. Static Threshold Asymmetry
Static global risk thresholds ($\theta_{static}$) fail to account for behavioral heterogeneity across organizational roles:
* **System Administrator:** Baseline daily risk score $R = 75$ (due to privileged access and service creation). A static threshold of $\theta_{static} = 80$ triggers frequent **false positives** during normal administration.
* **Standard User:** Baseline daily risk score $R = 10$. An anomalous risk jump to $R = 50$ (indicating credential compromise) remains undetected as a **false negative** because it does not cross $\theta_{static} = 80$.

```
Static Threshold (θ_static = 80)
   |
   |---- Standard User Baseline (μ=10)
   |                                 |---- SysAdmin Baseline (μ=75)
   |                                 |             |\
  / \                               / \            | \ False Positives
 /   \     Anomalous User (R=50)   /   \           |  \ (Normal Admin)
/_____\          ●                /_____\__________|___\_______
  10            50                  75             80     100
             Risk Score
```

### 3. Fragility of Whitelisting
Static allowlists create dangerous security blind spots. Compromised administrative accounts or white-listed scripts allow adversaries to operate with complete immunity.

---

## 💡 Core Concept & Architectural Philosophy

The Risk-Based Alerting (RBA) model replaces binary "rule match = alert" logic with a continuous mathematical risk model based on four core pillars:

1. **Entity-Centric Modeling:** All security telemetry is attributed to discrete entities (e.g., `host:004` or `user:admin`). Risk score accumulation happens per entity.
2. **Temporal Decay:** Older security events naturally lose relevance over time through exponential mathematical decay ($e^{-\lambda t}$).
3. **Adaptive Thresholding:** Dynamic risk thresholds ($\theta_e$) are derived continuously from each entity's historical baseline ($\mu_e + k \cdot \sigma_e$) using robust statistics.
4. **Multi-Gate Alerting:** An alert is generated only when an entity breaches its adaptive threshold **AND** demonstrates a significant rate of change ($\Delta R > \delta$).

---

## 🏗️ System Architecture & Data Flow

The system is built on top of an open-source SIEM stack comprising **Wazuh**, **OpenSearch**, **Python Compute Engine**, and **Streamlit Dashboard**.

```
+-------------------+      +-------------------+      +-------------------------+
|  Telemetry Logs   | ---> |   Wazuh Manager   | ---> |       OpenSearch        |
| (Win/Linux Agents)|      | Ingestion Engine  |      | (wazuh-alerts-YYYY.MM)  |
+-------------------+      +-------------------+      +-------------------------+
                                                                   |
                                                                   v
+-------------------+      +-------------------+      +-------------------------+
| RBA Control Center| <--- |   OpenSearch RBA  | <--- |   Python RBA Engine     |
| Streamlit UI      |      | Derived Indices   |      | (Temporal Decay, MAD,   |
+-------------------+      +-------------------+      |  Adaptive Thresholding) |
                                                      +-------------------------+
```

### Data Pipeline Flow:
1. **Log Collection:** Wazuh Agents collect Windows Event Channel, Auditd, and Sysmon logs from endpoints.
2. **Indexing:** Wazuh Manager normalizes and indexes telemetry into OpenSearch under `wazuh-alerts-*`.
3. **Risk Compute Pipeline:** The Python RBA engine (`rba_compute_snapshot_and_alert_once.py`) queries OpenSearch over a sliding temporal window ($T_w$), calculates entity risk with decay, applies robust statistics, and evaluates alert gating logic.
4. **Derived Indices Written:**
   * `rba-entity-state`: Current real-time risk profile, baseline stats, and contributor rule buffer per entity.
   * `rba-risk-snapshots-YYYY.MM.DD`: Historical time-series metrics ($R$, $\theta$, $\mu$, $\sigma$, $z$, $ratio$) for analytics.
   * `rba-alerts-YYYY.MM.DD`: High-fidelity, gated security alerts enriched with top contributor rules.
   * `rba-cases`: Lightweight case tracking and analyst triage records.
5. **Analyst Workflow:** Security analysts interact with the Streamlit RBA Control Center dashboard to triage alerts, inspect contributor rules, view MITRE ATT&CK coverage, and track cases.

---

## 📐 Mathematical Framework

### 1. Entity-Centric Risk Aggregation & Temporal Decay

Let $E$ be the set of all tracked entities. For a given entity $e \in E$ at time $t$, over a sliding window $T_w$, the cumulative risk score $R(e,t)$ is formulated as:

$$R(e,t) = \sum_{i \in \text{Events}(e, t-T_w, t)} w_i \cdot R_i \cdot e^{-\lambda (t - t_i)}$$

Where:
* $R_i$: Risk score increment of event $i$, mapped from rule severity (e.g., $R_i = 2^{\text{rule.level}}$).
* $w_i$: Confidence and weight factor for the event.
* $t_i$: Timestamp of occurrence for event $i$.
* $\lambda$: Exponential decay factor derived from the configured half-life $H$ (in seconds):

$$\lambda = \frac{\ln(2)}{H}$$

### 2. Robust Statistical Baselines (MAD & Trimming)

To prevent baseline distortion caused by extreme risk spikes or security incidents, the engine calculates baseline statistics using **Median Absolute Deviation (MAD)** and **trimmed statistics**:

$$\text{MAD} = \text{median}\left( | X_i - \text{median}(X) | \right)$$

$$\sigma_{\text{robust}} = 1.4826 \times \text{MAD}$$

For larger sample histories ($n \ge 20$), a 10% trimmed mean ($\mu_{\text{trimmed}}$) and trimmed standard deviation ($\sigma_{\text{trimmed}}$) are computed by excluding extreme top and bottom percentiles.

### 3. Adaptive Thresholding & Self-Healing

The adaptive risk threshold $\theta_e$ for entity $e$ is calculated dynamically:

$$\theta_{\text{cand}} = \mu_e + k \cdot \sigma_{\text{capped}}$$

Where:
* $k$: Sensitivity multiplier (`RBA_K_SIGMA`, typically $2.0 - 3.0$).
* $\sigma_{\text{capped}}$: Sigma cap preventing excessive thresholds during volatile periods:

$$\sigma_{\text{capped}} = \min\left(\sigma_e, \text{MAX\_SIGMA\_MULTIPLIER} \times \max(\mu_e, 1.0)\right)$$

* **Self-Healing Mechanism:** To prevent thresholds from remaining permanently elevated after a major incident, a dynamic threshold decay function is applied:

$$\theta_e = \min\left( \theta_{\text{cand}}, \max\left(\mu_e, \theta_{e, \text{prev}} \cdot \text{DECAY\_FACTOR}\right) \right)$$

### 4. Multi-Gate Alert Logic & Velocity Gating

To guarantee high alert precision, four distinct logical conditions must evaluate to `TRUE` for an RBA alert to fire:

$$\text{Alert}(e,t) = \begin{cases} 1 & \text{if } (n \ge n_{\min}) \land (R(e,t) \ge \theta_e) \land (\Delta R(e,t) > \delta) \land (\text{not in cooldown}) \\ 0 & \text{otherwise} \end{cases}$$

Where:
* $n \ge n_{\min}$: Ensures sufficient baseline snapshots exist before alerting (`RBA_BASELINE_MIN_SNAPSHOTS`).
* $R(e,t) \ge \theta_e$: Cumulative risk breaches the adaptive threshold.
* $\Delta R(e,t) > \delta$: Risk velocity condition ($\Delta R = R(e,t) - R(e, t-1)$) ensuring rapid risk acceleration rather than minor slow drift (`RBA_DELTA_MIN`).
* **Cooldown Check:** Prevents duplicate alert spamming within a configurable time window (`RBA_ALERT_COOLDOWN_MINUTES`).

### Standardized Ranking Metrics:

$$\text{z-score} = \frac{R(e,t) - \mu_e}{\sigma_{\text{capped}}}, \qquad \text{ratio} = \frac{R(e,t)}{\theta_e}$$

---

## 📁 Repository Structure

```
.
├── rba_compute_snapshot_and_alert_once.py  # Core RBA calculation engine
├── rba_dashboard.py                        # Streamlit RBA Control Center UI
├── .env                                    # Central environment & hyperparameter config
├── requirements.txt                        # Python dependencies
└── README.md                               # Project documentation
```

---

## ⚙️ Key Components

### 1. RBA Compute Engine (`rba_compute_snapshot_and_alert_once.py`)
Executes periodic or on-demand risk calculations:
* Queries Wazuh raw events from OpenSearch (`wazuh-alerts-*`).
* Applies temporal decay and entity risk aggregation.
* Generates historical snapshots (`rba-risk-snapshots-*`).
* Evaluates dynamic baselines and alert gating logic.
* Writes high-confidence alerts (`rba-alerts-*`) and updates state (`rba-entity-state`).

### 2. RBA Control Center Dashboard (`rba_dashboard.py`)
Streamlit-based SOC management console providing six operational modules:
1. **Overview:** High-level KPIs, raw event vs. RBA alert volume comparisons, noise reduction percentages, and timeline histograms.
2. **Risk Posture:** Entity ranking (by ratio, z-score, or risk), risk buckets (*Above Threshold*, *Near Threshold $\ge 80\%$*, *Fast Risers*), and historical entity trend graphs.
3. **Alert Triage:** Actionable alert list with gate validation indicators, top contributor rule breakdowns (counts, maximum rule level, descriptions), and direct links to cases.
4. **Investigation:** Guided deep-dive view into specific entities, raw event timeline density, MITRE ATT&CK technique breakdown, and CSV data export.
5. **Raw Events & Rule Lookup:** Searchable event logs and rule aggregation inspector for tuning detection logic.
6. **Case Management:** Lightweight Kanban workflow (*New*, *Investigating*, *Benign*, *Escalated*, *Closed*) integrated with OpenSearch backend.

---

## 🔧 Configuration Guide (`.env`)

All engine parameters and connections are managed via `.env`:

```env
# ===================================
# OpenSearch Connection Settings
# ===================================
OS_HOST=localhost
OS_PORT=9200
OS_USER=admin
OS_PASS=YourSecurePasswordHere
OS_SSL=True
OS_VERIFY_CERTS=False
OS_TIMEOUT=30

# ===================================
# RBA Core Hyperparameters
# ===================================
# Sliding window for raw event aggregation (hours)
RBA_TIME_WINDOW_HOURS=24.0

# Temporal decay half-life (minutes)
RBA_HALF_LIFE_MINUTES=60.0

# Historical window for baseline calculation (hours)
RBA_BASELINE_WINDOW_HOURS=168.0

# Minimum historical snapshots required to compute baseline
RBA_BASELINE_MIN_SNAPSHOTS=5

# Dynamic threshold multiplier (k * sigma)
RBA_K_SIGMA=2.0

# Minimum risk velocity change required to fire an alert
RBA_DELTA_MIN=50.0

# Alert suppression cooldown period (minutes)
RBA_ALERT_COOLDOWN_MINUTES=30
```

---

## 🚀 Getting Started & Installation

### Prerequisites
* **Python:** `3.10` or higher
* **OpenSearch Cluster:** `2.x` running locally or remotely
* **Wazuh Manager:** `4.x` with active Windows/Linux agents sending telemetry to OpenSearch

### 1. Clone the Repository
```bash
git clone https://github.com/Nirban1996/Risk-Based-Alerting-for-Threat-Detection-Response.git
cd Risk-Based-Alerting-for-Threat-Detection-Response
```

### 2. Set Up Virtual Environment
```bash
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

### 4. Configure Environment
Copy and edit the `.env` configuration file:
```bash
cp .env.example .env  # Adjust OS_HOST, OS_PASS, etc.
```

### 5. Execute RBA Compute Engine
Run the engine script to perform snapshot calculations and alert generation:
```bash
python rba_compute_snapshot_and_alert_once.py
```
*(Tip: Set up a cron job or systemd timer to execute this script every 1 to 5 minutes for real-time monitoring).*

### 6. Launch the Control Center Dashboard
Start the Streamlit UI:
```bash
streamlit run rba_dashboard.py
```
Open your browser and navigate to `http://localhost:8501`.

---

## 📊 Empirical Evaluation & Results

The framework was evaluated in a controlled lab environment using a Linux server (Wazuh Manager + OpenSearch) and a Windows endpoint (`Victim-1` / `host:004`) running active workloads over matching 1-hour time windows.

### Summary Results (1-Hour Horizon)

| Test Environment Window | Raw Wazuh Events | Generated RBA Alerts | Alert Reduction Rate (%) | Primary Operational Outcome |
| :--- | :---: | :---: | :---: | :--- |
| **Benign Baseline Window** | 164 | **0** | **100.0%** | All routine background operational noise suppressed. Zero false alarms. |
| **Attack Simulation Window** | 297 | **6** | **98.0%** | Victim entity (`host:004`) breached adaptive threshold ($\theta$). Surfaced high-fidelity alerts. |

```
      Raw Events vs. RBA Alerts (Attack Window)
      
      Raw Events  [==================================================] 297
      RBA Alerts  [=] 6  (98.0% Alert Suppression)
```

### Key Triage Metrics for Compromised Entity (`Victim-1 / host:004`):
* **Cumulative Risk Score ($R$):** `1544.26`
* **Adaptive Threshold ($\theta$):** `1354.41`
* **Risk Ratio ($R/\theta$):** `1.14` (Threshold breached)
* **Risk Velocity ($\Delta R$):** `452.93` (Exceeded $\delta = 50.0$)
* **Top Contributing Rules:**
  * `111302` (Level 15): *Suspicious service execution (`sc.exe` manipulation)*
  * `60107` (Level 5): *Failed attempt to perform privileged operation*
  * `61104` (Level 5): *Service startup type modification*
  * `67027` (Level 3): *Routine process creation events*

---

## 🔍 MITRE ATT&CK Alignment & Explainability

Unlike black-box machine learning detection models, this framework provides complete **explainability** for every generated alert:

```
+-----------------------------------------------------------------+
|                       RBA Alert Generated                       |
|          Entity: host:004 | Risk: 1544.26 | Threshold: 1354.41   |
+-----------------------------------------------------------------+
                                |
                                v
+-----------------------------------------------------------------+
|                  Top Contributor Rule Breakdown                 |
|  - Rule 111302 (Level 15): Service manipulation (sc.exe)        |
|  - Rule 60107  (Level 5): Privilege execution failure           |
|  - Rule 61104  (Level 5): Service startup change                |
+-----------------------------------------------------------------+
                                |
                                v
+-----------------------------------------------------------------+
|                    MITRE ATT&CK Mapping                         |
|  - Tactic: Persistence / Privilege Escalation                   |
|  - Technique: T1078 (Valid Accounts), T1543 (Create/Modify Svc) |
+-----------------------------------------------------------------+
```

---

## 🛡️ Limitations & Future Roadmap

### Current Limitations
1. **Lab Baseline Scale:** Baseline depth in lab environments is smaller than multi-year enterprise production histories.
2. **Simplified Risk Mapping:** Risk increments currently map from Wazuh rule levels ($2^{\text{level}}$) rather than asset criticality weights.
3. **SOAR Integration:** Closed-loop automated response orchestration (e.g., automated host isolation via Shuffle SOAR) is architected but not enabled in the current release.

### Future Roadmap
* [ ] **Production SOAR Integration:** Connect alert outputs to Shuffle SOAR playbooks for automated host isolation and active directory user suspension.
* [ ] **Asset Criticality Weighting:** Incorporate CMDB asset tags (e.g., Domain Controllers vs. test VMs) directly into entity risk formulas.
* [ ] **Extended Data Normalization:** Expand ingestion parsers to natively map Elastic Common Schema (ECS) and Open Cybersecurity Schema Framework (OCSF).

---

## 📄 License & Citation

This project is licensed under the **MIT License**.

### Citation
If you use this project or framework in academic research or technical implementations, please cite:

```bibtex
@mastersthesis{ahmed_hossain_rba_2026,
  author       = {Shafayet Ahmed and Mohd. Billal Hossain Bipu},
  title        = {An Open-Source Risk-Based Alerting Framework for Effective Threat Detection and Response},
  school       = {Department of Computer Science and Engineering, University of Dhaka},
  degree       = {Professional Masters in Information and Cyber Security (PMICS)},
  year         = {2026},
  month        = {February},
  advisor      = {Md. Samiul Islam}
}
```