<h1 align="center">🚨 SSH Threat Analysis — Log Set 02</h1>
<h3 align="center">Brute Force Detection &nbsp;·&nbsp; Real-Time Alert &nbsp;·&nbsp; Compromised Account Identification &nbsp;·&nbsp; Dashboard</h3>

<p align="center">
  <img src="https://img.shields.io/badge/Splunk-SSH%20Brute%20Force-FF5733?style=for-the-badge&logo=splunk&logoColor=white" />
  <img src="https://img.shields.io/badge/Log%20Source-JSON%20SSH%20Logs-0078D6?style=for-the-badge" />
  <img src="https://img.shields.io/badge/Phase-02B%20SSH%20LOG02-3fb950?style=for-the-badge" />
  <img src="https://img.shields.io/badge/Status-Analysed-22c55e?style=for-the-badge" />
</p>

<p align="center">
  <b>Advanced SSH threat investigation using a structured JSON log dataset — detected brute force attackers, identified a compromised account (10.0.1.8), configured a real-time Splunk alert, built visualisations, and created a dedicated SSH monitoring dashboard.</b>
</p>

---

## 📖 Table of Contents

- [Project Context](#-project-context)
- [Log File Overview](#-log-file-overview)
- [Ingestion — Steps 1 to 9](#ingestion--steps-1-to-9)
- [SPL 1 — Validate Ingestion](#spl-1--validate-ingestion)
- [SPL 2 — Source IPs Behind Failed Logins](#spl-2--source-ips-behind-failed-logins)
- [SPL 3 — Bar Chart: Failed Logins per IP](#spl-3--bar-chart-failed-logins-per-ip)
- [SPL 4 — Detect Repeated Failures (Brute Force)](#spl-4--detect-repeated-failures-brute-force)
- [SPL 5 — Bar Chart: Multiple Failure Attempts](#spl-5--bar-chart-multiple-failure-attempts)
- [Alert — Real-Time Brute Force Alert](#alert--real-time-brute-force-alert)
- [SPL 6 — Compromised Account Detection](#spl-6--compromised-account-detection)
- [Dashboard — Successful Logins Panel](#dashboard--successful-logins-panel)
- [SPL 7 — Unauthenticated Connections](#spl-7--unauthenticated-connections)
- [SPL 8 — Timechart Visualisation](#spl-8--timechart-visualisation)
- [Key Findings](#-key-findings)

---

## 🧠 Project Context

This investigation used a **JSON-formatted SSH log** (`ssh_logs.json`) with richer structured fields than the Zeek tab-separated format in Log Set 01. Each event includes explicit `event_type`, `auth_success`, `auth_attempts`, source/destination IPs, and packet metadata — enabling more precise SPL queries and statistical analysis.

The investigation escalated from basic event counting to **identifying a compromised account** by correlating failed login history with subsequent successful logins from the same source IP.

| Log Field | Example | Description |
|-----------|---------|-------------|
| `id.orig_h` | `10.0.0.43` | Source IP |
| `id.resp_h` | `10.0.1.6` | Target server IP |
| `auth_success` | `true` / `false` | Whether auth succeeded |
| `auth_attempts` | `8` | Number of attempts in this connection |
| `event_type` | `Multiple Failed Authentication Attempts` | Pre-classified event label |
| `conn_state` | `SF` | Connection state |

---

## Ingestion — Steps 1 to 9

The JSON log file was ingested using the same **Search & Reporting → Add Data → Upload** workflow as Log Set 01.

<img src="Images/02 SSH Threat Analysis In Splunk/SSH_LOG02/01 Click Search & Reporting App To Upload the Logs and Analyze.png" width="700"/>

<img src="Images/02 SSH Threat Analysis In Splunk/SSH_LOG02/02 Click Add Data .png" width="700"/>

<img src="Images/02 SSH Threat Analysis In Splunk/SSH_LOG02/03 Click Upload .png" width="700"/>

<img src="Images/02 SSH Threat Analysis In Splunk/SSH_LOG02/04 Select The Log File And Click Next .png" width="700"/>

<img src="Images/02 SSH Threat Analysis In Splunk/SSH_LOG02/05 Select the Default or as Custom and Click Save As .png" width="700"/>

<img src="Images/02 SSH Threat Analysis In Splunk/SSH_LOG02/06 And Give a Name for the Source and Description and Click Save.png" width="700"/>

<img src="Images/02 SSH Threat Analysis In Splunk/SSH_LOG02/07 Create a New Index and Give it a Name and Then Click Review.png" width="700"/>

A new index was created specifically for this JSON SSH dataset — keeping it separate from the Zeek log set from Log Set 01.

<img src="Images/02 SSH Threat Analysis In Splunk/SSH_LOG02/08 And Then Submit the Source .png" width="700"/>

<img src="Images/02 SSH Threat Analysis In Splunk/SSH_LOG02/09 Click Start Searching to Investigate the Logs.png" width="700"/>

---

## SPL 1 — Validate Ingestion

After ingestion, a validation search confirmed all events were loaded correctly and the JSON fields were parsed properly.

```spl
index=ssh_logs2
| stats count by event_type
| sort -count
```

<img src="Images/02 SSH Threat Analysis In Splunk/SSH_LOG02/10 validation Search of Events.png" width="700"/>

This confirmed three event types were present in the dataset:
- `Successful SSH Login`
- `Failed SSH Login`
- `Multiple Failed Authentication Attempts`

---

## SPL 2 — Source IPs Behind Failed Logins

Identified which source IPs were generating failed login attempts — the starting point for any brute force investigation.

```spl
index=ssh_logs2
| search event_type="Failed SSH Login" OR event_type="Multiple Failed Authentication Attempts"
| stats count as failed_attempts by id.orig_h
| sort -failed_attempts
| rename id.orig_h as "Source IP", failed_attempts as "Failed Attempts"
```

<img src="Images/02 SSH Threat Analysis In Splunk/SSH_LOG02/11 The Source IPs generating failed logins..png" width="700"/>

This ranked every attacker IP by total failed login count — immediately showing which sources were most aggressively probing the environment.

---

## SPL 3 — Bar Chart: Failed Logins per IP

The same query was visualised as a **bar chart** to make the attacker ranking immediately visible.

```spl
index=ssh_logs2
| search event_type="Failed SSH Login" OR event_type="Multiple Failed Authentication Attempts"
| stats count as failed_attempts by id.orig_h
| sort -failed_attempts
| rename id.orig_h as "Source IP", failed_attempts as "Failed Attempts"
```

<img src="Images/02 SSH Threat Analysis In Splunk/SSH_LOG02/12 A bar chart visualization for failed login attempts per source IP.png" width="700"/>

The bar chart format makes the outlier IPs immediately obvious — the longest bars represent the most persistent attackers.

---

## SPL 4 — Detect Repeated Failures (Brute Force)

Specifically targeted the `Multiple Failed Authentication Attempts` event type — the most direct indicator of brute force activity where `auth_attempts > 1` in a single connection.

```spl
index=ssh_logs2
| search event_type="Multiple Failed Authentication Attempts"
| stats count as brute_force_events, sum(auth_attempts) as total_attempts by id.orig_h
| sort -total_attempts
| rename id.orig_h as "Attacker IP",
         brute_force_events as "Brute Force Events",
         total_attempts as "Total Auth Attempts"
```

<img src="Images/02 SSH Threat Analysis In Splunk/SSH_LOG02/13 Detect repeated failures.png" width="700"/>

---

## SPL 5 — Bar Chart: Multiple Failure Attempts

The brute force detection results were visualised as a bar chart — confirming which IPs were running sustained authentication attacks.

```spl
index=ssh_logs2
| search event_type="Multiple Failed Authentication Attempts"
| stats count by id.orig_h
| sort -count
```

<img src="Images/02 SSH Threat Analysis In Splunk/SSH_LOG02/14 A bar chart visualization for Detected Multiple Failure attempts.png" width="700"/>

---

## Alert — Real-Time Brute Force Alert

A **real-time Splunk alert** was configured to trigger automatically when any source IP attempts more than **5 logins within 10 minutes** — without requiring an analyst to be watching the dashboard.

```spl
index=ssh_logs2
| search event_type="Failed SSH Login" OR event_type="Multiple Failed Authentication Attempts"
| bucket _time span=10m
| stats count as attempts by id.orig_h, _time
| where attempts > 5
```

**Alert Configuration:**

| Setting | Value |
|---------|-------|
| **Alert Name** | `SSH Brute Force — Threshold Exceeded` |
| **Alert Type** | Real-Time |
| **Trigger Condition** | Number of Results > 0 |
| **Throttle** | 60 minutes per source IP |
| **Severity** | High |

<img src="Images/02 SSH Threat Analysis In Splunk/SSH_LOG02/15 Creating an Alert in splunk like Trigger when any IP attempts more than 5 logins within 10 minutes.png" width="700"/>

<img src="Images/02 SSH Threat Analysis In Splunk/SSH_LOG02/16 Created an Real Time Alert .png" width="700"/>

The alert was successfully created and is shown as active in the Alerts list — it will fire automatically whenever the threshold is breached in incoming log data.

---

## SPL 6 — Compromised Account Detection

The most critical finding of this investigation — compared successful logins against prior failed attempts from the same source IP. Any IP that had **both failures and successes** indicates a brute force attack that eventually found valid credentials — a **compromised account**.

```spl
index=ssh_logs2
| eval status = if(auth_success="true", "Success", "Failure")
| stats count(eval(status="Failure")) as failures,
        count(eval(status="Success"))  as successes
  by id.orig_h
| where failures > 0 AND successes > 0
| eval verdict = "⚠️ LIKELY COMPROMISED"
| sort -failures
| rename id.orig_h as "Source IP"
```

<img src="Images/02 SSH Threat Analysis In Splunk/SSH_LOG02/17 Compare successful logins against prior failed attempts (to detect compromised accounts) therefore the 10.0.1.8 is compromised.png" width="700"/>

> **🔴 Finding: IP `10.0.1.8` is compromised** — this host had prior failed authentication attempts followed by a successful login, indicating the attacker found valid credentials and gained access.

---

## Dashboard — Successful Logins Panel

A dashboard panel showing **top source IPs for successful logins** was created to provide ongoing visibility into who is successfully authenticating to the environment.

```spl
index=ssh_logs2
| search event_type="Successful SSH Login"
| stats count as successful_logins by id.orig_h
| sort -successful_logins
| rename id.orig_h as "Source IP", successful_logins as "Successful Logins"
```

<img src="Images/02 SSH Threat Analysis In Splunk/SSH_LOG02/18 Creating a dashboard panel showing top source IPs for successful logins..png" width="700"/>

The dashboard was named **"Successful Logins"** and saved as a standalone panel.

<img src="Images/02 SSH Threat Analysis In Splunk/SSH_LOG02/19 Named the Dashboard as Succesful Logins.png" width="700"/>

<img src="Images/02 SSH Threat Analysis In Splunk/SSH_LOG02/20 A Seperate dashboard is Created.png" width="700"/>

---

## SPL 7 — Unauthenticated Connections

Identified connections where no authentication was attempted — reconnaissance/scanning activity from hosts probing the SSH port without authenticating.

```spl
index=ssh_logs2
| search auth_success="false" auth_attempts=0
| stats count as probe_count by id.orig_h, id.resp_h
| sort -probe_count
| rename id.orig_h as "Scanner IP", id.resp_h as "Target", probe_count as "Probe Count"
```

<img src="Images/02 SSH Threat Analysis In Splunk/SSH_LOG02/21 Unauthenticated SSH connections.png" width="700"/>

---

## SPL 8 — Timechart Visualisation

A **timechart** was created to visualise unauthenticated and failed SSH events over time — revealing attack patterns, peak times, and whether attacks were sustained or burst-based.

```spl
index=ssh_logs2
| eval status = case(
    auth_success="true",  "Successful",
    auth_attempts=0,      "Unauthenticated",
    true(),               "Failed"
  )
| timechart count by status
```

<img src="Images/02 SSH Threat Analysis In Splunk/SSH_LOG02/22 Created a timechart visualization to monitor such events over time.png" width="700"/>

The timechart visualisation showed the temporal distribution of all three SSH event types — enabling identification of attack burst periods versus sustained campaigns.

---

## 🔍 Key Findings

| Finding | Detail |
|---------|--------|
| **Compromised Account** | IP `10.0.1.8` — failed attempts followed by successful login confirms credential compromise |
| **Brute Force IPs** | Multiple source IPs detected with `Multiple Failed Authentication Attempts` event type |
| **Real-Time Alert** | Configured to fire when any IP exceeds 5 login attempts in 10 minutes |
| **Unauthenticated Probes** | Reconnaissance activity detected — attackers scanning before attempting auth |
| **Dashboard Created** | Standalone "Successful Logins" dashboard panel built for ongoing monitoring |
| **Timechart** | Attack timeline visualised — confirmed burst attack pattern |

---

## 🔗 Navigation

⬅️ **[Phase 02A — SSH Threat Analysis LOG01](./02_SSH_Threat_Analysis_LOG01.md)** &nbsp;&nbsp;|&nbsp;&nbsp; ➡️ **[Phase 03 — DNS Anomaly Detection](./04_DNS_Anomaly_Detection.md)**

---

<p align="center">
  <b>Umar Ahmed</b> · Cybersecurity Student · Security Automation & SIEM Enthusiast<br/>
  <a href="https://github.com/User-Umar-Ahamed">
    <img src="https://img.shields.io/badge/GitHub-User--Umar--Ahamed-181717?style=for-the-badge&logo=github" />
  </a>
</p>
