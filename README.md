<h1 align="center">🔵 Enterprise-SIEM-Splunk</h1>
<h3 align="center">Built a fully operational Splunk SIEM — real log ingestion, live threat detection, and custom SOC dashboards</h3>

<p align="center">
  <img src="https://img.shields.io/badge/Splunk-Enterprise%20SIEM-FF5733?style=for-the-badge&logo=splunk&logoColor=white" />
  <img src="https://img.shields.io/badge/Investigations-8%20Log%20Sources-0078D6?style=for-the-badge" />
  <img src="https://img.shields.io/badge/Attacks%20Detected-Brute%20Force%20%7C%20SQLi%20%7C%20XSS%20%7C%20LFI-dc2626?style=for-the-badge" />
  <img src="https://img.shields.io/badge/Dashboards-3%20Live%20Dashboards-22c55e?style=for-the-badge" />
  <img src="https://img.shields.io/badge/License-MIT-8b5cf6?style=for-the-badge" />
</p>

<p align="center">
  <b>Deployed Splunk Enterprise from scratch, ingested eight distinct real-world log datasets, built targeted SPL detections across SSH brute force, DNS anomalies, web traffic threats, and Cloudflare edge attacks — then visualised everything in three live SOC monitoring dashboards.</b>
</p>

---

## 📖 Table of Contents

- [Project Overview](#-project-overview)
- [Log Sources Analysed](#-log-sources-analysed)
- [Project Phases](#-project-phases)
- [Detections Built](#-detections-built)
- [Key Findings](#-key-findings)
- [SPL Quick Reference](#-spl-quick-reference)
- [Skills Demonstrated](#-skills-demonstrated)
- [Author](#-author)

---

## 🧠 Project Overview

This project is a **fully deployed Splunk SIEM investigation platform** — a working system built on real log data, with real threat detections, real alerts, and three live analyst dashboards.

| Phase | Investigation | Threat Category |
|-------|--------------|----------------|
| 01 | Splunk Installation | Infrastructure |
| 02A | SSH Analysis LOG01 | Scanner Detection, Login Classification |
| 02B | SSH Analysis LOG02 | Brute Force, Compromised Account, Real-Time Alert |
| 03 | DNS Anomaly Detection | C2 Baseline, DGA Framework, High-Volume IPs |
| 04 | Web Traffic Analysis | Server Errors, Scripted Agents, LFI, Suspicious URIs |
| 05 | Cloudflare Log Monitoring | SQLi, XSS, LFI, Brute Force, Admin Scanning |
| 06 | SSH Security Dashboard | Live SSH Monitoring Dashboard |
| 07 | Web Traffic Dashboard | HTTP Response Dashboard + Geo Map |
| 08 | Cloudflare Dashboard | WAF Challenge/Block Monitoring Dashboard |

---

---

## 📂 Log Sources Analysed

| Index | Source File | Format | Events |
|-------|------------|--------|--------|
| `ssh_logs` | `ssh.log` | Zeek TSV | — |
| `ssh_logs2` | `ssh_logs.json` | JSON | — |
| `dns_logs` | `dns_logs.json` | JSON | 1,200 |
| `http_logs` | `http_logs.json` | JSON | 3,000 |
| `Cloudflare_http_logs` | `cloudflare_http_requests_full_.json` | JSON | — |

---

## 📋 Project Phases

| # | Phase | Document |
|---|-------|---------|
| 01 | Splunk Installation | [01_Splunk_Installation.md](./01_Splunk_Installation.md) |
| 02A | SSH Threat Analysis — LOG01 | [02_SSH_Threat_Analysis_LOG01.md](./02_SSH_Threat_Analysis_LOG01.md) |
| 02B | SSH Threat Analysis — LOG02 | [03_SSH_Threat_Analysis_LOG02.md](./03_SSH_Threat_Analysis_LOG02.md) |
| 03 | DNS Anomaly Detection | [04_DNS_Anomaly_Detection.md](./04_DNS_Anomaly_Detection.md) |
| 04 | Web Traffic Analysis | [05_Web_Traffic_Analysis.md](./05_Web_Traffic_Analysis.md) |
| 05 | Cloudflare Log Monitoring | [06_Cloudflare_Log_Monitoring.md](./06_Cloudflare_Log_Monitoring.md) |
| 06 | SSH Security Dashboard | [07_SSH_Log_Dashboard.md](./07_SSH_Log_Dashboard.md) |
| 07 | Web Traffic Dashboard | [08_Web_Traffic_Dashboard.md](./08_Web_Traffic_Dashboard.md) |
| 08 | Cloudflare Security Dashboard | [09_Cloudflare_Dashboard.md](./09_Cloudflare_Dashboard.md) |

---

## 🎯 Detections Built

| Detection | Log Source | Severity |
|-----------|-----------|---------|
| SSH Login Classification | `ssh.log` | — |
| Brute Force Source IPs | `ssh_logs.json` | 🔴 High |
| **Compromised Account (10.0.1.8)** | `ssh_logs.json` | 🔴 Critical |
| Real-Time Brute Force Alert | `ssh_logs.json` | 🔴 High |
| Unauthenticated SSH Probes | `ssh_logs.json` | 🟡 Medium |
| DNS Top Queried Domains | `dns_logs.json` | — |
| High-Volume DNS Sources | `dns_logs.json` | 🟡 Medium |
| HTTP 500 Server Errors | `http_logs.json` | 🟡 Medium |
| Scripted Attack User-Agents | `http_logs.json` | 🟠 High |
| Large File Transfers (>500KB) | `http_logs.json` | 🟠 High |
| Suspicious URI Access | `http_logs.json` | 🔴 High |
| Cloudflare Brute Force | Cloudflare logs | 🔴 High |
| SQL Injection (SQLi) | Cloudflare logs | 🔴 High |
| Cross-Site Scripting (XSS) | Cloudflare logs | 🔴 High |
| LFI / Directory Traversal | Cloudflare logs | 🔴 High |
| Admin Path Scanning | Cloudflare logs | 🟠 High |
| WAF Challenges | Cloudflare logs | 🟡 Medium |
| WAF Blocks | Cloudflare logs | 🔴 High |

---

## 🔍 Key Findings

| Finding | Detail |
|---------|--------|
| **🔴 Compromised Account** | IP `10.0.1.8` — brute force success, credentials confirmed compromised |
| **🔴 Nmap Scanning** | Nmap SSH client strings detected in unauthenticated connections |
| **🔴 Web Attack Campaign** | SQLi, XSS, LFI, and admin scanning all detected in Cloudflare logs |
| **🔴 WAF Blocks Active** | Cloudflare WAF blocking confirmed malicious traffic at the edge |
| **🟠 Scripted Agents** | Non-browser user-agents in HTTP traffic — automated attack tools confirmed |
| **🟡 DNS Baseline Built** | Top domains and active IPs profiled for anomaly detection framework |

---

## 📝 SPL Quick Reference

```spl
-- SSH Event Classification
index=ssh_logs
| eval event_type=case(match(_raw,"(?i)success"),"Successful Login",
    match(_raw,"(?i)failure"),"Failed Login",
    match(_raw,"(?i)undetermined"),"Unauthenticated",true(),"Unknown")
| stats count by event_type

-- Brute Force Detection
index=ssh_logs2 | search event_type="Failed SSH Login"
| stats count as attempts by id.orig_h | where attempts > 5 | sort -attempts

-- Compromised Account
index=ssh_logs2
| eval s=if(auth_success="true","Win","Fail")
| stats count(eval(s="Fail")) as fails, count(eval(s="Win")) as wins by id.orig_h
| where fails>0 AND wins>0

-- DNS Top Domains
index=dns_logs | stats count by query | sort -count | head 20

-- HTTP Server Errors
index=http_logs | search status_code=500
| stats count by id.orig_h, uri | sort -count

-- Cloudflare SQLi
index=Cloudflare_http_logs
| search match(ClientRequestURI,"(?i)(union.*select|sleep\(|or.*1=1)")
| stats count by ClientIP, ClientRequestURI

-- WAF Blocks
index=Cloudflare_http_logs | search WAFAction=block
| stats count by ClientIP, WAFRuleID | sort -count

-- Geo Map
index=http_logs | iplocation id.orig_h
| stats count by Country, lat, lon | geostats latfield=lat longfield=lon count
```

---

## 🧠 Skills Demonstrated

| Category | Skills |
|----------|--------|
| **SIEM Deployment** | Splunk Enterprise install, index architecture, source type config |
| **Log Ingestion** | Upload workflow, custom index creation, multi-format log parsing |
| **SPL Query Writing** | `stats`, `eval`, `timechart`, `iplocation`, `geostats`, `rex`, `where` |
| **Threat Detection** | Brute force, SQLi, XSS, LFI, WAF analysis, compromised account ID |
| **Alert Engineering** | Real-time alert, threshold tuning, throttle configuration |
| **Dashboard Building** | Classic Dashboard XML, time tokens, panels, colour thresholds, geo maps |
| **Cloudflare/WAF** | Edge log analysis, WAF rule interpretation, challenge vs block analysis |

---

## 👨‍💻 Author

<p align="center">
  <b>Umar Ahmed</b><br/>
  Cybersecurity Student &nbsp;·&nbsp; Security Automation & SIEM Enthusiast<br/><br/>
  <a href="https://github.com/User-Umar-Ahamed">
    <img src="https://img.shields.io/badge/GitHub-User--Umar--Ahamed-181717?style=for-the-badge&logo=github" />
  </a>
</p>
