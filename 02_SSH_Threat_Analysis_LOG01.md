<h1 align="center">🔐 SSH Threat Analysis — Log Set 01</h1>
<h3 align="center">Zeek SSH Logs &nbsp;·&nbsp; Event Classification &nbsp;·&nbsp; Success / Failure / Unauthenticated Detection</h3>

<p align="center">
  <img src="https://img.shields.io/badge/Splunk-SSH%20Analysis-FF5733?style=for-the-badge&logo=splunk&logoColor=white" />
  <img src="https://img.shields.io/badge/Log%20Source-Zeek%20SSH%20Log-0078D6?style=for-the-badge" />
  <img src="https://img.shields.io/badge/Phase-02A%20SSH%20LOG01-3fb950?style=for-the-badge" />
  <img src="https://img.shields.io/badge/Status-Analysed-22c55e?style=for-the-badge" />
</p>

<p align="center">
  <b>First SSH threat analysis investigation — a Zeek-generated SSH log was ingested into Splunk, indexed, and analysed using SPL to classify every connection as a successful login, failed login, or unauthenticated connection attempt.</b>
</p>

---

## 📖 Table of Contents

- [Project Context](#-project-context)
- [Log File Overview](#-log-file-overview)
- [Step 1 — Open Search & Reporting](#step-1--open-search--reporting)
- [Step 2 — Add Data](#step-2--add-data)
- [Step 3 — Upload the Log File](#step-3--upload-the-log-file)
- [Step 4 — Select the Log File](#step-4--select-the-log-file)
- [Step 5 — Set Source Type](#step-5--set-source-type)
- [Step 6 — Name the Source](#step-6--name-the-source)
- [Step 7 — Create Index](#step-7--create-index)
- [Step 8 — Submit & Ingest](#step-8--submit--ingest)
- [Step 9 — Start Searching](#step-9--start-searching)
- [SPL Query 1 — Classify All Events](#spl-query-1--classify-all-events)
- [SPL Query 2 — Successful Logins](#spl-query-2--successful-logins)
- [SPL Query 3 — Failed Logins](#spl-query-3--failed-logins)
- [SPL Query 4 — Unauthenticated Connections](#spl-query-4--unauthenticated-connections)
- [Key Findings](#-key-findings)

---

## 🧠 Project Context

This investigation used a **Zeek-generated SSH log** (`ssh.log`) — a tab-separated file capturing SSH connection metadata across a network. Unlike auth.log which records authentication messages, Zeek's SSH log records connection-level data including source/destination IPs, ports, auth result, and client/server SSH version strings.

The goal was to ingest this log into Splunk and write SPL to classify every SSH connection event into one of three categories:

| Category | Zeek Field Value | Meaning |
|----------|-----------------|---------|
| **Successful Login** | `auth_success=true` or result=`success` | SSH session fully established |
| **Failed Login** | result=`failure` | Authentication was attempted but rejected |
| **Unauthenticated** | result=`undetermined` | Connection made but no auth was attempted (scanner/probe) |

---

## 📄 Log File Overview

**File:** `ssh.log` (Zeek tab-separated format)

Sample fields in the log:

| Field | Example | Description |
|-------|---------|-------------|
| `ts` | `1331901011.84` | Unix timestamp |
| `id.orig_h` | `192.168.202.68` | Source IP (attacker) |
| `id.orig_p` | `53633` | Source port |
| `id.resp_h` | `192.168.28.254` | Destination IP (target) |
| `id.resp_p` | `22` | Destination port (SSH) |
| `auth_success` | `failure` | Authentication result |
| `direction` | `INBOUND` | Connection direction |
| `client` | `SSH-2.0-OpenSSH_5.0` | Client SSH version |
| `server` | `SSH-1.99-Cisco-1.25` | Server SSH version |

---

## Step 1 — Open Search & Reporting

Navigated to the **Search & Reporting** app from the Splunk Home screen — this is the primary workspace for uploading logs and running SPL queries throughout this project.

<img src="Images/02 SSH Threat Analysis In Splunk/SSH_LOG01/01 Click Search & Reporting App To Upload the Logs and Analyze.png" width="700"/>

---

## Step 2 — Add Data

Clicked **Add Data** from within the Search & Reporting app to begin the log ingestion wizard.

<img src="Images/02 SSH Threat Analysis In Splunk/SSH_LOG01/02 Click Add Data .png" width="700"/>

---

## Step 3 — Upload

Selected **Upload** as the ingestion method — used for one-time log file analysis rather than continuous monitoring.

<img src="Images/02 SSH Threat Analysis In Splunk/SSH_LOG01/03 Click Upload .png" width="700"/>

---

## Step 4 — Select the Log File

Selected the `ssh.log` file and clicked **Next** to proceed to source type configuration.

<img src="Images/02 SSH Threat Analysis In Splunk/SSH_LOG01/04 Select The Log File And Click Next .png" width="700"/>

---

## Step 5 — Set Source Type

Configured the source type — either accepted Splunk's auto-detection or set it manually to match the Zeek SSH log format. Saved the source type for reuse.

<img src="Images/02 SSH Threat Analysis In Splunk/SSH_LOG01/05 Select the Default or as Custom and Click Save As .png" width="700"/>

---

## Step 6 — Name the Source

Gave the data source a descriptive name and description so it can be identified easily in future searches.

<img src="Images/02 SSH Threat Analysis In Splunk/SSH_LOG01/06 And Give a Name for the Source and Description and Click Save.png" width="700"/>

---

## Step 7 — Create Index

Created a **new custom index** to store this SSH log data separately from other log types — keeping data organised and allowing targeted SPL searches.

<img src="Images/02 SSH Threat Analysis In Splunk/SSH_LOG01/07 Create a New Index and Give it a Name and Then Click Review.png" width="700"/>

A dedicated index was created and named (e.g., `ssh_logs`) rather than using the default `main` index — best practice for keeping different data sources clean and searchable independently.

---

## Step 8 — Submit & Ingest

Reviewed all settings and submitted the upload. Splunk ingested the log file and indexed all events.

<img src="Images/02 SSH Threat Analysis In Splunk/SSH_LOG01/08 And Then Submit the Source .png" width="700"/>

---

## Step 9 — Start Searching

After ingestion, clicked **Start Searching** to open the Search & Reporting workspace with the new index pre-populated and ready for SPL queries.

<img src="Images/02 SSH Threat Analysis In Splunk/SSH_LOG01/09 Click Start Searching to Investigate the Logs.png" width="700"/>

---

## SPL Query 1 — Classify All Events

The first query classified every SSH log entry into one of three event types based on keywords in the raw log text — displayed as a clean single-column output.

```spl
index=ssh_logs
| eval event_type=case(
    match(_raw, "(?i)success"),          "Successful Login",
    match(_raw, "(?i)failure"),          "Failed Login",
    match(_raw, "(?i)undetermined"),     "Unauthenticated Connection",
    true(),                              "Unknown"
  )
| table event_type
```

<img src="Images/02 SSH Threat Analysis In Splunk/SSH_LOG01/10 SPL Query which searches SSH logs, categorizes each log entry as a successful login, failed login, or unauthenticated connection based on keywords in the raw log text, and displays only the event type column.png" width="700"/>

This classification query is the foundation — it confirmed the log was ingested correctly and that all three connection types were present in the dataset.

---

## SPL Query 2 — Successful Logins

Filtered the log to show only **successful SSH login events** — identifying which source IPs successfully authenticated to target systems.

```spl
index=ssh_logs
| search auth_success=true OR result=success OR match(_raw, "(?i)success")
| table _time, id.orig_h, id.resp_h, client, server
```

<img src="Images/02 SSH Threat Analysis In Splunk/SSH_LOG01/11 SPL Query Which Searches for Success Logs.png" width="700"/>

Successful logins are critical to track because:
- They may represent **legitimate access** (baseline normal behaviour)
- Or **attacker access** after a successful brute force attempt
- Any success from an unexpected source IP warrants investigation

---

## SPL Query 3 — Failed Logins

Filtered to show only **failed authentication events** — the primary brute force detection signal.

```spl
index=ssh_logs
| search match(_raw, "(?i)failure")
| table _time, id.orig_h, id.resp_h, id.orig_p, client
```

<img src="Images/02 SSH Threat Analysis In Splunk/SSH_LOG01/12 SPL Query Which Searches For Failure Logs.png" width="700"/>

Failed login events reveal:
- Which source IPs are attempting authentication
- Which target servers they are attacking
- The SSH client version being used (can fingerprint attacker tools)

---

## SPL Query 4 — Unauthenticated Connections

Filtered to show **unauthenticated connections** — connections where no authentication was even attempted. This is the signature of **port scanners and probes** (e.g., Nmap, Shodan crawlers).

```spl
index=ssh_logs
| search match(_raw, "(?i)undetermined")
| table _time, id.orig_h, id.resp_h, client, server
```

<img src="Images/02 SSH Threat Analysis In Splunk/SSH_LOG01/13 SPL Query Which Searches for unauthenticated connection.png" width="700"/>

Unauthenticated connections indicate **reconnaissance activity** — the attacker is probing which hosts are running SSH before launching authentication attacks. Notably, Nmap SSH version scan clients (`SSH-2.0-Nmap-SSH2-Hostkey`, `SSH-1.5-Nmap-SSH1-Hostkey`) appeared in these records — a direct fingerprint of active scanning.

---

## 🔍 Key Findings

| Finding | Detail |
|---------|--------|
| **Log Format** | Zeek tab-separated SSH log with connection-level auth metadata |
| **Three Event Types** | Successfully classified: success, failure, undetermined |
| **Scanner Activity** | Nmap SSH client strings detected in unauthenticated connection events |
| **Attack Pattern** | Source IPs with `failure` records also appeared in `undetermined` — indicating scan-then-attack behaviour |
| **Client Fingerprinting** | SSH client version strings in each event allow attacker tool identification |

---

## 🔗 Navigation

⬅️ **[Phase 01 — Splunk Installation](./01_Splunk_Installation.md)** &nbsp;&nbsp;|&nbsp;&nbsp; ➡️ **[Phase 02B — SSH Threat Analysis Log Set 2](./03_SSH_Threat_Analysis_LOG02.md)**

---

<p align="center">
  <b>Umar Ahmed</b> · Cybersecurity Student · Security Automation & SIEM Enthusiast<br/>
  <a href="https://github.com/User-Umar-Ahamed">
    <img src="https://img.shields.io/badge/GitHub-User--Umar--Ahamed-181717?style=for-the-badge&logo=github" />
  </a>
</p>
