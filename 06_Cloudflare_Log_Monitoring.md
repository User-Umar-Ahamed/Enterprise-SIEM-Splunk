<h1 align="center">☁️ Cloudflare Log Monitoring & Web Attack Detection</h1>
<h3 align="center">Brute Force &nbsp;·&nbsp; SQL Injection &nbsp;·&nbsp; XSS &nbsp;·&nbsp; LFI &nbsp;·&nbsp; Admin Path Scanning</h3>

<p align="center">
  <img src="https://img.shields.io/badge/Splunk-Cloudflare%20Monitoring-FF5733?style=for-the-badge&logo=splunk&logoColor=white" />
  <img src="https://img.shields.io/badge/Log%20Source-Cloudflare%20HTTP%20Requests-F6821F?style=for-the-badge&logo=cloudflare&logoColor=white" />
  <img src="https://img.shields.io/badge/Phase-05%20Cloudflare-3fb950?style=for-the-badge" />
  <img src="https://img.shields.io/badge/Status-Analysed-22c55e?style=for-the-badge" />
</p>

<p align="center">
  <b>Cloudflare edge log analysis — ingested Cloudflare HTTP request logs into Splunk and built five targeted SPL detections covering brute force login attempts, SQL injection, cross-site scripting (XSS), local file inclusion (LFI), and reconnaissance/admin path scanning.</b>
</p>

---

## 📖 Table of Contents

- [Project Context](#-project-context)
- [Log File Overview](#-log-file-overview)
- [Ingestion — Steps 1 to 6](#ingestion--steps-1-to-6)
- [Detection 1 — Brute Force Login Attempts](#detection-1--brute-force-login-attempts)
- [Detection 2 — SQL Injection (SQLi) Attempts](#detection-2--sql-injection-sqli-attempts)
- [Detection 3 — Cross-Site Scripting (XSS)](#detection-3--cross-site-scripting-xss)
- [Detection 4 — Local File Inclusion (LFI) / Directory Traversal](#detection-4--local-file-inclusion-lfi--directory-traversal)
- [Detection 5 — Recon & Admin Path Scanning](#detection-5--recon--admin-path-scanning)
- [Key Findings](#-key-findings)

---

## 🧠 Project Context

Cloudflare sits at the **edge of a web infrastructure** — every HTTP request to a protected domain passes through Cloudflare before reaching the origin server. Cloudflare logs therefore capture the full attack surface: automated scanners, injection attempts, brute force campaigns, and reconnaissance activity from across the internet.

This investigation built five production-ready **OWASP-aligned detections** directly from Cloudflare log data:

| Detection | OWASP Category | Attacker Goal |
|-----------|---------------|--------------|
| Brute Force | A07:2021 Auth Failures | Gain account access |
| SQL Injection | A03:2021 Injection | Dump database, bypass auth |
| XSS | A03:2021 Injection | Steal sessions, deface, redirect |
| LFI / Directory Traversal | A01:2021 Broken Access Control | Read sensitive server files |
| Admin Path Scanning | A05:2021 Security Misconfiguration | Find exposed admin panels |

---

## 📄 Log File Overview

**File:** `cloudflare_http_requests_full_.json` (JSON array format)

| Field | Example | Description |
|-------|---------|-------------|
| `ClientIP` | `203.0.113.23` | Client IP address |
| `ClientRequestMethod` | `POST` | HTTP method |
| `ClientRequestURI` | `/login` | Requested path |
| `ClientRequestUserAgent` | `python-requests/2.28` | Client user agent |
| `EdgeResponseStatus` | `200` / `403` / `404` | HTTP response code from Cloudflare edge |
| `ClientRequestReferer` | `https://example.com` | Referring URL |
| `ClientCountry` | `CN` | Client country code |
| `WAFAction` | `block` / `allow` | Cloudflare WAF decision |
| `ClientRequestHost` | `example.com` | Target hostname |

---

## Ingestion — Steps 1 to 6

<img src="Images/05 Cloudflare Log Monitoring Splunk/01 Click Search & Reporting App To Upload the Logs and Analyze.png" width="700"/>

<img src="Images/05 Cloudflare Log Monitoring Splunk/02 Click Add Data .png" width="700"/>

<img src="Images/05 Cloudflare Log Monitoring Splunk/03 Click Upload .png" width="700"/>

<img src="Images/05 Cloudflare Log Monitoring Splunk/04 Logs uploaded.png" width="700"/>

<img src="Images/05 Cloudflare Log Monitoring Splunk/05 Save as http_logs.png" width="700"/>

<img src="Images/05 Cloudflare Log Monitoring Splunk/06 Create Index and name as Cloudflare_http_logs.png" width="700"/>

A dedicated **`Cloudflare_http_logs`** index was created — keeping Cloudflare edge data separate from the direct HTTP server logs analysed in Phase 04.

---

## Detection 1 — Brute Force Login Attempts

Identified source IPs making **repeated POST requests to login endpoints** — the signature of automated credential stuffing or brute force attacks against web authentication.

```spl
index=Cloudflare_http_logs
| search ClientRequestMethod=POST
| search match(ClientRequestURI, "(?i)(login|signin|auth|session|wp-login|account)")
| stats count as login_attempts by ClientIP, ClientRequestURI, EdgeResponseStatus
| where login_attempts > 5
| sort -login_attempts
| rename ClientIP as "Attacker IP",
         ClientRequestURI as "Target Endpoint",
         EdgeResponseStatus as "HTTP Response",
         login_attempts as "Login Attempts"
```

<img src="Images/05 Cloudflare Log Monitoring Splunk/07 Brute Force Login Attempts.png" width="700"/>

**Brute force indicators in Cloudflare logs:**
- High POST volume to `/login` from a single IP
- Repeated `401` or `403` responses (failed auth)
- Non-browser user-agents (`python-requests`, `curl`, `Go-http-client`)
- Same IP from multiple countries in a short window (credential stuffing using proxy networks)

---

## Detection 2 — SQL Injection (SQLi) Attempts

Detected SQL injection attack patterns in URI query strings — attackers attempting to manipulate backend database queries to dump data, bypass authentication, or execute commands.

```spl
index=Cloudflare_http_logs
| search match(ClientRequestURI, "(?i)(union.*select|select.*from|insert.*into|drop.*table|exec\(|execute\(|'.*or.*'|1=1|--\s|;--|\bor\b.*=|cast\(|convert\(|sleep\(|benchmark\(|xp_cmdshell|information_schema)")
| stats count as sqli_attempts by ClientIP, ClientRequestURI, EdgeResponseStatus
| sort -sqli_attempts
| rename ClientIP as "Attacker IP",
         ClientRequestURI as "Injection Payload URI",
         EdgeResponseStatus as "HTTP Response",
         sqli_attempts as "Attempts"
```

<img src="Images/05 Cloudflare Log Monitoring Splunk/08 SQL Injection (SQLi) Attempts.png" width="700"/>

**SQLi payload patterns detected:**

| Pattern | Technique |
|---------|-----------|
| `UNION SELECT` | Union-based data extraction |
| `' OR '1'='1` | Auth bypass |
| `; DROP TABLE` | Destructive query injection |
| `SLEEP(5)` | Blind time-based SQLi |
| `xp_cmdshell` | MSSQL OS command execution |
| `information_schema` | Database schema enumeration |

---

## Detection 3 — Cross-Site Scripting (XSS)

Identified XSS payload injection attempts in URIs — attackers attempting to inject JavaScript that executes in the browsers of other users visiting the affected page.

```spl
index=Cloudflare_http_logs
| search match(ClientRequestURI, "(?i)(<script|javascript:|onerror=|onload=|alert\(|document\.cookie|eval\(|src=.*javascript|<img.*onerror|<svg.*onload|%3Cscript|%3C%2Fscript%3E)")
| stats count as xss_attempts by ClientIP, ClientRequestURI, EdgeResponseStatus
| sort -xss_attempts
| rename ClientIP as "Attacker IP",
         ClientRequestURI as "XSS Payload URI",
         EdgeResponseStatus as "HTTP Response",
         xss_attempts as "Attempts"
```

<img src="Images/05 Cloudflare Log Monitoring Splunk/09 Cross-Site Scripting (XSS).png" width="700"/>

**XSS payload types detected:**

| Payload | Type | Goal |
|---------|------|------|
| `<script>alert(1)</script>` | Reflected XSS proof-of-concept | Confirm vulnerability |
| `document.cookie` | Session hijacking | Steal session tokens |
| `onerror=fetch(...)` | Exfiltration XSS | Send data to attacker server |
| `<img src=x onerror=...>` | DOM XSS | Execute via broken image |
| URL-encoded variants (`%3Cscript`) | Encoded bypass | Evade basic WAF rules |

---

## Detection 4 — Local File Inclusion (LFI) / Directory Traversal

Detected attempts to traverse the server's directory structure to read sensitive files — attackers trying to access `/etc/passwd`, SSH keys, application configs, or environment files.

```spl
index=Cloudflare_http_logs
| search match(ClientRequestURI, "(?i)(\.\.\/|\.\.\\\\|%2e%2e%2f|%2e%2e\/|\/etc\/passwd|\/etc\/shadow|\/proc\/self|\/var\/log|boot\.ini|win\.ini|system32|\.\.%2f|%252e%252e)")
| stats count as lfi_attempts by ClientIP, ClientRequestURI, EdgeResponseStatus
| sort -lfi_attempts
| rename ClientIP as "Attacker IP",
         ClientRequestURI as "Traversal Payload",
         EdgeResponseStatus as "HTTP Response",
         lfi_attempts as "Attempts"
```

<img src="Images/05 Cloudflare Log Monitoring Splunk/10 Local File Inclusion (LFI) or Directory Traversal.png" width="700"/>

**LFI/Path Traversal targets:**

| Target Path | Sensitive Data |
|-------------|---------------|
| `/../../../etc/passwd` | Linux user accounts |
| `/../../../etc/shadow` | Password hashes |
| `/../../../proc/self/environ` | Environment variables (may contain secrets) |
| `/../../../var/log/auth.log` | Authentication logs |
| `/../../../.env` | Application secrets, database credentials |
| `/../../../.ssh/id_rsa` | Private SSH keys |
| `\..\..\windows\win.ini` | Windows system file (confirms Windows server) |

Any **HTTP 200 response** to a traversal URI means the file was successfully read — an immediate critical incident.

---

## Detection 5 — Recon & Admin Path Scanning

Detected systematic scanning for **admin panels, hidden paths, and management interfaces** — the reconnaissance phase before a targeted attack.

```spl
index=Cloudflare_http_logs
| search match(ClientRequestURI, "(?i)(\/admin|\/administrator|\/wp-admin|\/phpmyadmin|\/cpanel|\/plesk|\/manager|\/console|\/dashboard|\/panel|\/control|\/backend|\/cms|\/moderator|\/root|\/user\/login|\/api\/v1\/admin|\/actuator|\/swagger|\.bak|\.old|\.backup|robots\.txt|sitemap\.xml)")
| stats count as scan_hits,
        dc(ClientRequestURI) as unique_paths_probed,
        values(EdgeResponseStatus) as responses
  by ClientIP
| sort -unique_paths_probed
| rename ClientIP as "Scanner IP",
         scan_hits as "Total Hits",
         unique_paths_probed as "Unique Paths Probed"
```

<img src="Images/05 Cloudflare Log Monitoring Splunk/11 Recon & Admin Path Scanning.png" width="700"/>

**Scanning behaviour patterns:**

| Pattern | Indicator |
|---------|----------|
| One IP probing 50+ unique paths | Automated directory scanner (DirBuster, Gobuster, ffuf) |
| Sequential URI patterns (`/admin1`, `/admin2`) | Wordlist-based scanning |
| Many `404` responses from one IP | Path bruteforce — probing for hidden endpoints |
| `robots.txt` + `sitemap.xml` request | Passive recon — reading site map before active scanning |
| `/actuator`, `/swagger` requests | Framework-specific probe (Spring Boot, API docs) |

The `dc(ClientRequestURI)` (distinct count of unique paths) is the key metric — a high unique path count from one IP is the scanner fingerprint regardless of response codes.

---

## 🔍 Key Findings

| Detection | Status | Key Indicator |
|-----------|--------|--------------|
| **Brute Force** | ✅ Detected | High POST volume to login endpoints from single IPs |
| **SQL Injection** | ✅ Detected | UNION SELECT, SLEEP(), OR 1=1 patterns in URIs |
| **XSS** | ✅ Detected | `<script>`, `onerror=`, `document.cookie` in requests |
| **LFI / Path Traversal** | ✅ Detected | `../../../etc/passwd` and encoded variants |
| **Admin Path Scanning** | ✅ Detected | IPs probing 50+ unique admin and hidden paths |

All five OWASP-aligned web attack categories were successfully detected from Cloudflare edge logs using targeted SPL queries.

---

## 🔗 Navigation

⬅️ **[Phase 04 — Web Traffic Analysis](./05_Web_Traffic_Analysis.md)** &nbsp;&nbsp;|&nbsp;&nbsp; ➡️ **[Phase 06 — SSH Log Dashboard](./07_SSH_Log_Dashboard.md)**

---

<p align="center">
  <b>Umar Ahmed</b> · Cybersecurity Student · Security Automation & SIEM Enthusiast<br/>
  <a href="https://github.com/User-Umar-Ahamed">
    <img src="https://img.shields.io/badge/GitHub-User--Umar--Ahamed-181717?style=for-the-badge&logo=github" />
  </a>
</p>
