<h1 align="center">🌐 DNS Anomaly Detection</h1>
<h3 align="center">DNS Log Analysis &nbsp;·&nbsp; Top Queried Domains &nbsp;·&nbsp; Active IPs &nbsp;·&nbsp; Query Type Breakdown</h3>

<p align="center">
  <img src="https://img.shields.io/badge/Splunk-DNS%20Analysis-FF5733?style=for-the-badge&logo=splunk&logoColor=white" />
  <img src="https://img.shields.io/badge/Log%20Source-DNS%20JSON%20Logs-0078D6?style=for-the-badge" />
  <img src="https://img.shields.io/badge/Phase-03%20DNS%20Detection-3fb950?style=for-the-badge" />
  <img src="https://img.shields.io/badge/Events-1%2C200-f59e0b?style=for-the-badge" />
</p>

<p align="center">
  <b>DNS anomaly investigation — 1,200 DNS log events were ingested into Splunk and analysed to identify the most frequently queried domains, the most active source IPs generating DNS traffic, and the breakdown of query types (A, AAAA, CNAME, PTR) for threat hunting and anomaly detection.</b>
</p>

---

## 📖 Table of Contents

- [Project Context](#-project-context)
- [Log File Overview](#-log-file-overview)
- [Ingestion — Steps 1 to 6](#ingestion--steps-1-to-6)
- [SPL 1 — Event Count Validation](#spl-1--event-count-validation)
- [SPL 2 — Most Frequently Queried Domains](#spl-2--most-frequently-queried-domains)
- [SPL 3 — Most Active IPs Generating DNS Traffic](#spl-3--most-active-ips-generating-dns-traffic)
- [SPL 4 — DNS Query Type Breakdown](#spl-4--dns-query-type-breakdown)
- [Key Findings](#-key-findings)
- [Why DNS Analysis Matters](#-why-dns-analysis-matters)

---

## 🧠 Project Context

DNS is one of the most overlooked but **richest sources of threat intelligence** in any network. Attackers rely on DNS for:
- **C2 communication** (malware beaconing to command-and-control servers)
- **DNS tunnelling** (data exfiltration hidden in DNS queries)
- **Domain generation algorithms (DGA)** (malware generating random domains to evade blocklists)
- **Reconnaissance** (querying internal hostnames to map the network)

This investigation analysed a **Zeek-generated DNS log** (`dns_logs.json`) containing 1,200 events to establish baseline DNS behaviour and identify anomalies.

---

## 📄 Log File Overview

**File:** `dns_logs.json` (JSON format, one event per line)

| Field | Example | Description |
|-------|---------|-------------|
| `id.orig_h` | `192.168.1.12` | Client IP making the DNS query |
| `id.resp_h` | `192.168.1.1` | DNS server responding |
| `query` | `google.com` | Domain name queried |
| `qtype` | `A` | Query type (A, AAAA, CNAME, PTR, MX, TXT) |
| `rcode` | `NOERROR` | Response code |
| `answers` | `142.250.80.46` | Resolved IP or record value |
| `rtt` | `0.397` | Round-trip time in seconds |
| `rejected` | `false` | Whether query was rejected by server |

---

## Ingestion — Steps 1 to 6

The DNS log was ingested using the standard **Add Data → Upload** workflow.

<img src="Images/03 DNS Anomaly Detection Splunk/01 Click Search & Reporting App To Upload the Logs and Analyze.png" width="700"/>

<img src="Images/03 DNS Anomaly Detection Splunk/02 Click Add Data .png" width="700"/>

<img src="Images/03 DNS Anomaly Detection Splunk/03 Click Upload .png" width="700"/>

<img src="Images/03 DNS Anomaly Detection Splunk/04 Logs Uploaded.png" width="700"/>

The file was uploaded successfully and Splunk confirmed receipt of the log data.

<img src="Images/03 DNS Anomaly Detection Splunk/05 Saved as DNS Logs.png" width="700"/>

The source was saved with the name **DNS Logs** for easy identification in future searches.

<img src="Images/03 DNS Anomaly Detection Splunk/06 Create New Index and name it as dns_logs.png" width="700"/>

A dedicated **`dns_logs`** index was created — isolating DNS data from SSH and other log sources for clean, targeted analysis.

---

## SPL 1 — Event Count Validation

After ingestion, a validation search confirmed the total event count and that the JSON fields were parsed correctly.

```spl
index=dns_logs
| stats count
```

<img src="Images/03 DNS Anomaly Detection Splunk/07 There are 1200 Events in this Particular Log.png" width="700"/>

**1,200 DNS events** confirmed — all events ingested successfully. The JSON structure was parsed cleanly with individual fields (`query`, `qtype`, `id.orig_h`, etc.) available for SPL queries.

---

## SPL 2 — Most Frequently Queried Domains

Identified the top domain names by query frequency — the foundation of DNS anomaly detection. Legitimate networks have predictable, recognisable top domains. Unusual or random-looking domains at the top of this list signal potential DGA malware or C2 beaconing.

```spl
index=dns_logs
| stats count as query_count by query
| sort -query_count
| head 20
| rename query as "Domain", query_count as "Query Count"
```

<img src="Images/03 DNS Anomaly Detection Splunk/08 Identified the most frequently queried domain names.png" width="700"/>

This query produces a ranked list of every domain queried — immediately highlighting:
- **High-frequency legitimate domains** (google.com, microsoft.com, etc.) — expected baseline
- **Unknown high-frequency domains** — potential C2 or DGA activity
- **Internal hostnames** (fileserver.local, backup.local) — internal network DNS traffic

---

## SPL 3 — Most Active IPs Generating DNS Traffic

Identified which source IPs were generating the most DNS queries — high-volume DNS from a single host can indicate automated beaconing, scanning, or DGA malware running on that machine.

```spl
index=dns_logs
| stats count as dns_queries, dc(query) as unique_domains by id.orig_h
| sort -dns_queries
| rename id.orig_h as "Source IP",
         dns_queries as "Total DNS Queries",
         unique_domains as "Unique Domains Queried"
```

<img src="Images/03 DNS Anomaly Detection Splunk/09 Finding the most active user IPs generating DNS traffic.png" width="700"/>

The combination of **total queries** and **unique domains** per IP is key:
- **High queries + few unique domains** → beaconing to a fixed C2 server
- **High queries + many unique domains** → DGA malware generating random domains
- **Moderate queries + expected domains** → normal user browsing behaviour

---

## SPL 4 — DNS Query Type Breakdown

Analysed the distribution of DNS query types (A, AAAA, CNAME, PTR, MX, TXT) across all events — unusual query type distributions can reveal specific attacker techniques.

```spl
index=dns_logs
| stats count as query_count by qtype
| sort -query_count
| rename qtype as "Query Type", query_count as "Count"
```

<img src="Images/03 DNS Anomaly Detection Splunk/10 Breakdown of DNS query types (A, AAAA, CNAME, PTR).png" width="700"/>

**Query type threat relevance:**

| Query Type | Normal Use | Threat Relevance |
|-----------|-----------|-----------------|
| `A` | Resolve domain to IPv4 | Most common — baseline |
| `AAAA` | Resolve domain to IPv6 | Elevated volume can indicate IPv6 tunnelling |
| `CNAME` | Domain aliasing | Normal — used heavily by CDNs |
| `PTR` | Reverse DNS lookup | High volume from one IP suggests network scanning |
| `TXT` | Text records | **DNS tunnelling** commonly abuses TXT records for data exfiltration |
| `MX` | Mail server lookup | Bulk MX queries can indicate spam infrastructure reconnaissance |

Any significant spike in `TXT` or `PTR` queries from a single source warrants immediate investigation.

---

## 🔍 Key Findings

| Finding | Detail |
|---------|--------|
| **Total Events** | 1,200 DNS events successfully ingested and parsed |
| **Top Domains** | Most queried domains identified — baseline established |
| **Active IPs** | Source IPs ranked by DNS query volume — outliers flagged |
| **Query Type Mix** | A, AAAA, CNAME, PTR distribution analysed |
| **Anomaly Indicators** | Framework established for detecting DGA, tunnelling, and C2 beaconing |

---

## 🌐 Why DNS Analysis Matters

```
Normal DNS:     User → DNS Server → Legitimate Domain → IP Response
                Fast, low volume, recognisable domains

C2 Beaconing:   Malware → DNS Server → attacker-domain.com → C2 IP
                Periodic, same domain, may look legitimate

DNS Tunnelling: Malware → DNS Server → data.exfil.attacker.com → TXT
                High TXT query volume, very long subdomain strings

DGA Malware:    Malware → DNS Server → xk3jd82k.com (random)
                Many unique NXDOMAIN responses, random-looking domains
```

The SPL queries built in this investigation establish the **baseline** needed to detect all three patterns — any deviation from the top domain list, any IP with abnormal query volume, or any unusual TXT record query spike now has a detection framework.

---

## 🔗 Navigation

⬅️ **[Phase 02B — SSH Threat Analysis LOG02](./03_SSH_Threat_Analysis_LOG02.md)** &nbsp;&nbsp;|&nbsp;&nbsp; ➡️ **[Phase 04 — Web Traffic Analysis](./05_Web_Traffic_Analysis.md)**

---

<p align="center">
  <b>Umar Ahmed</b> · Cybersecurity Student · Security Automation & SIEM Enthusiast<br/>
  <a href="https://github.com/User-Umar-Ahamed">
    <img src="https://img.shields.io/badge/GitHub-User--Umar--Ahamed-181717?style=for-the-badge&logo=github" />
  </a>
</p>
