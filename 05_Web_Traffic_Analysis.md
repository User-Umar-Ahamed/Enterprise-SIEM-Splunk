<h1 align="center">🌍 Web Traffic Analysis</h1>
<h3 align="center">HTTP Log Analysis &nbsp;·&nbsp; Server Errors &nbsp;·&nbsp; Scripted Attacks &nbsp;·&nbsp; Large Transfers &nbsp;·&nbsp; Suspicious URIs</h3>

<p align="center">
  <img src="https://img.shields.io/badge/Splunk-Web%20Traffic%20Analysis-FF5733?style=for-the-badge&logo=splunk&logoColor=white" />
  <img src="https://img.shields.io/badge/Log%20Source-HTTP%20JSON%20Logs-0078D6?style=for-the-badge" />
  <img src="https://img.shields.io/badge/Phase-04%20Web%20Traffic-3fb950?style=for-the-badge" />
  <img src="https://img.shields.io/badge/Events-3%2C000-f59e0b?style=for-the-badge" />
</p>

<p align="center">
  <b>HTTP traffic investigation — 3,000 web server log events were ingested into Splunk and analysed to identify top traffic endpoints, server errors, scripted attack user-agents, large file transfers, and suspicious URI patterns including admin panel probing and credential path scanning.</b>
</p>

---

## 📖 Table of Contents

- [Project Context](#-project-context)
- [Log File Overview](#-log-file-overview)
- [Ingestion — Steps 1 to 6](#ingestion--steps-1-to-6)
- [SPL 1 — Event Count Validation](#spl-1--event-count-validation)
- [SPL 2 — Top 10 Traffic Endpoints](#spl-2--top-10-traffic-endpoints)
- [SPL 3 — Server Error Count (HTTP 500)](#spl-3--server-error-count-http-500)
- [SPL 4 — Scripted Attack User-Agents](#spl-4--scripted-attack-user-agents)
- [SPL 5 — Large File Transfers (> 500 KB)](#spl-5--large-file-transfers--500-kb)
- [SPL 6 — Suspicious URIs](#spl-6--suspicious-uris)
- [Key Findings](#-key-findings)

---

## 🧠 Project Context

Web server logs are a **primary attack surface** — HTTP traffic reveals brute force attempts against login pages, directory traversal, admin panel probing, vulnerability scanning, and data exfiltration via large transfers.

This investigation analysed a **structured JSON HTTP log** (`http_logs.json`) containing 3,000 events from a web server environment. The analysis moved through five escalating detection scenarios:

| Detection Scenario | What It Reveals |
|-------------------|----------------|
| Top traffic endpoints | Which pages receive the most requests — normal baseline |
| HTTP 500 errors | Server-side failures — application errors or attack side-effects |
| Suspicious user-agents | Automated scanners, exploit frameworks, headless browsers |
| Large file transfers | Potential data exfiltration or malware payload delivery |
| Suspicious URIs | Admin panel access, credential file probing, path traversal |

---

## 📄 Log File Overview

**File:** `http_logs.json` (JSON format, one event per line)

| Field | Example | Description |
|-------|---------|-------------|
| `id.orig_h` | `10.0.0.49` | Client IP |
| `id.resp_h` | `10.0.1.6` | Web server IP |
| `method` | `GET` / `POST` | HTTP method |
| `uri` | `/index.html` | Requested URI path |
| `status_code` | `200` / `500` / `404` | HTTP response code |
| `user_agent` | `Mozilla/5.0...` | Browser or tool identifier |
| `resp_body_len` | `1958305` | Response body size in bytes |
| `event_type` | `Large Transfer` | Pre-classified event label |

---

## Ingestion — Steps 1 to 6

<img src="Images/04 Web Traffic Analysis Splunk/01 Click Search & Reporting App To Upload the Logs and Analyze.png" width="700"/>

<img src="Images/04 Web Traffic Analysis Splunk/02 Click Add Data .png" width="700"/>

<img src="Images/04 Web Traffic Analysis Splunk/03 Click Upload .png" width="700"/>

<img src="Images/04 Web Traffic Analysis Splunk/04 Logs uploaded.png" width="700"/>

<img src="Images/04 Web Traffic Analysis Splunk/05 Save as http_logs.png" width="700"/>

The source was saved as **`http_logs`** for identification in SPL queries.

<img src="Images/04 Web Traffic Analysis Splunk/06 Create Index and name as http_logs.png" width="700"/>

A dedicated **`http_logs`** index was created — separating web traffic data from SSH and DNS log sets for clean targeted analysis.

---

## SPL 1 — Event Count Validation

```spl
index=http_logs
| stats count
```

<img src="Images/04 Web Traffic Analysis Splunk/07 There are 3000 Events in this Particular http Log.png" width="700"/>

**3,000 HTTP events** confirmed — the largest dataset in this project. All JSON fields parsed correctly and available for SPL queries.

---

## SPL 2 — Top 10 Endpoints Generating Web Traffic

Identified which server endpoints (destination IPs or URIs) received the most HTTP requests — establishing the traffic baseline for anomaly detection.

```spl
index=http_logs
| stats count as request_count by id.resp_h, uri
| sort -request_count
| head 10
| rename id.resp_h as "Server", uri as "URI", request_count as "Request Count"
```

<img src="Images/04 Web Traffic Analysis Splunk/08 the top 10 endpoints generating web traffic.png" width="700"/>

The top endpoints reveal:
- Which pages are legitimately popular (index pages, API endpoints)
- Any endpoint receiving **disproportionately high traffic** — potential scanning or DoS
- Unusual endpoints in the top 10 that shouldn't be heavily accessed

---

## SPL 3 — Server Error Count (HTTP 500)

Counted the total number of **HTTP 500 server errors** — application-side failures that can indicate:
- A web application being probed with malformed requests
- An exploit attempt triggering an unhandled exception
- Genuine application bugs under load

```spl
index=http_logs
| search status_code=500
| stats count as server_errors by id.orig_h, uri
| sort -server_errors
| rename id.orig_h as "Source IP", uri as "URI", server_errors as "500 Errors"
```

<img src="Images/04 Web Traffic Analysis Splunk/09 Count the number of server errors (500) observed.png" width="700"/>

A single client IP generating many HTTP 500 errors across multiple URIs is a strong indicator of **automated vulnerability scanning** — the scanner is submitting malformed payloads and triggering exceptions.

---

## SPL 4 — Scripted Attack User-Agents

Identified **User-Agent strings associated with automated attack tools** — scanners, exploit frameworks, headless browsers, and custom scripts that don't present as normal browser clients.

```spl
index=http_logs
| stats count as requests by user_agent, id.orig_h
| sort -requests
| where NOT match(user_agent, "(?i)(Mozilla|Chrome|Safari|Firefox|Edge|Opera)")
| rename user_agent as "User Agent", id.orig_h as "Source IP", requests as "Requests"
```

<img src="Images/04 Web Traffic Analysis Splunk/10 Identified User-Agents associated with possible scripted attacks.png" width="700"/>

Non-browser user-agents to flag:

| User-Agent Pattern | Tool | Threat |
|-------------------|------|--------|
| `python-requests` | Python requests library | Custom attack scripts |
| `curl/` | cURL | Manual or scripted probing |
| `Nikto` | Nikto web scanner | Vulnerability scanning |
| `sqlmap` | SQLMap | SQL injection automation |
| `Nmap Scripting Engine` | Nmap NSE | Network/web scanning |
| `Go-http-client` | Golang HTTP | Custom scanner/exploiter |
| `masscan` | Masscan | Port/service scanning |

---

## SPL 5 — Large File Transfers (> 500 KB)

Identified HTTP responses larger than **500 KB** — potential data exfiltration, malware payload delivery, or backup file exposure.

```spl
index=http_logs
| where resp_body_len > 500000
| eval size_kb = round(resp_body_len / 1024, 2)
| stats count as transfers, sum(size_kb) as total_kb by id.orig_h, uri, method
| sort -total_kb
| rename id.orig_h as "Recipient IP", uri as "URI",
         method as "Method", transfers as "Transfers",
         total_kb as "Total KB Transferred"
```

<img src="Images/04 Web Traffic Analysis Splunk/11 Finded large file transfers (greater than 500 KB).png" width="700"/>

Large transfer investigation priorities:
- **POST requests** with large bodies → data being sent **out** (exfiltration)
- **GET requests** returning large files → database dumps, backup files, archive downloads being pulled
- **Unusual URIs** serving large content → hidden or sensitive files being accessed

---

## SPL 6 — Suspicious URIs

Detected access attempts to **sensitive paths** — admin panels, credential files, configuration files, and common vulnerability probe targets.

```spl
index=http_logs
| search match(uri, "(?i)(admin|passwd|password|\.env|config|backup|\.git|wp-admin|phpmyadmin|shell|cmd|eval|base64)")
| stats count as hits by id.orig_h, uri, status_code
| sort -hits
| rename id.orig_h as "Source IP", uri as "Suspicious URI",
         status_code as "HTTP Response", hits as "Attempts"
```

<img src="Images/04 Web Traffic Analysis Splunk/12 Detected suspicious URIs accessed such admin and psswd and all.png" width="700"/>

**Suspicious URI categories detected:**

| URI Pattern | What It Indicates |
|-------------|-----------------|
| `/admin`, `/administrator` | Admin panel brute force or probing |
| `/passwd`, `/password` | Credential file exposure attempt |
| `/.env` | Environment file theft (contains DB credentials, API keys) |
| `/backup`, `/backup.zip` | Backup file exposure |
| `/.git` | Source code repository exposure |
| `/wp-admin`, `/phpmyadmin` | CMS and database admin probing |
| `/cmd`, `/shell`, `/eval` | Web shell access or command injection |

Any **HTTP 200 response** on these URIs is a confirmed security incident — the file was successfully accessed.

---

## 🔍 Key Findings

| Finding | Detail |
|---------|--------|
| **Total Events** | 3,000 HTTP events — largest dataset in this project |
| **Top Endpoints** | Top 10 traffic destinations identified — baseline established |
| **Server Errors** | HTTP 500 errors counted and ranked by source IP — automated scanning suspected |
| **Scripted Agents** | Non-browser user-agents identified — automated attack tools detected |
| **Large Transfers** | Transfers >500 KB identified — exfiltration and payload delivery risk |
| **Suspicious URIs** | Admin panels, credential paths, and config files probed — confirmed scanning activity |

---

## 🔗 Navigation

⬅️ **[Phase 03 — DNS Anomaly Detection](./04_DNS_Anomaly_Detection.md)** &nbsp;&nbsp;|&nbsp;&nbsp; ➡️ **[Phase 05 — Cloudflare Log Monitoring](./06_Cloudflare_Log_Monitoring.md)**

---

<p align="center">
  <b>Umar Ahmed</b> · Cybersecurity Student · Security Automation & SIEM Enthusiast<br/>
  <a href="https://github.com/User-Umar-Ahamed">
    <img src="https://img.shields.io/badge/GitHub-User--Umar--Ahamed-181717?style=for-the-badge&logo=github" />
  </a>
</p>
