<h1 align="center">☁️ Cloudflare Security Dashboard</h1>
<h3 align="center">WAF Monitoring &nbsp;·&nbsp; Threat Blocking &nbsp;·&nbsp; Web Stats &nbsp;·&nbsp; Top IPs &nbsp;·&nbsp; Geo Traffic Map</h3>

<p align="center">
  <img src="https://img.shields.io/badge/Splunk-Cloudflare%20Dashboard-FF5733?style=for-the-badge&logo=splunk&logoColor=white" />
  <img src="https://img.shields.io/badge/Cloudflare-WAF%20Monitoring-F6821F?style=for-the-badge&logo=cloudflare&logoColor=white" />
  <img src="https://img.shields.io/badge/Phase-08%20Cloudflare%20Dashboard-3fb950?style=for-the-badge" />
  <img src="https://img.shields.io/badge/Status-Built%20%26%20Live-22c55e?style=for-the-badge" />
</p>

<p align="center">
  <b>Built a live Cloudflare security monitoring dashboard in Splunk — ingested Cloudflare edge logs, created a Classic Dashboard with panels covering web activity summary, successful responses, WAF challenges, WAF blocks, web stats, top IPs, and a geographic traffic map.</b>
</p>

---

## 📖 Table of Contents

- [Project Context](#-project-context)
- [Ingestion — Steps 1 to 7](#ingestion--steps-1-to-7)
- [Step 8 — Create New Dashboard](#step-8--create-new-dashboard)
- [Step 9 — Add Time, Submit & Panels](#step-9--add-time-submit--panels)
- [Panel — Quick Summary of Web Activity](#panel--quick-summary-of-web-activity)
- [Panel — Successful Responses](#panel--successful-responses)
- [Panel — WAF Challenges](#panel--waf-challenges)
- [Panel — WAF Blocks](#panel--waf-blocks)
- [Panel — Web Stats](#panel--web-stats)
- [Panel — Top Users by IP Address](#panel--top-users-by-ip-address)
- [Panel — Web Traffic by Client IP (Geo Map)](#panel--web-traffic-by-client-ip-geo-map)
- [Full Dashboard View](#full-dashboard-view)

---

## 🧠 Project Context

The Cloudflare threat detection SPL queries from Phase 05 identified SQLi, XSS, LFI, brute force, and recon activity. This phase converts those detections into a **live Cloudflare security dashboard** — adding WAF monitoring panels that show in real time what Cloudflare is challenging and blocking at the edge before threats reach the origin server.

The dashboard is split into two halves:
- **Traffic health** — legitimate request volume, response code distribution
- **Security posture** — WAF challenges, WAF blocks, top attacking IPs, geographic threat origins

---

## Ingestion — Steps 1 to 7

<img src="Images/08 Cloudflare Dashboard Splunk/01 Click Search & Reporting App To Upload the Logs and Analyze.png" width="700"/>

<img src="Images/08 Cloudflare Dashboard Splunk/02 Click Add Data .png" width="700"/>

<img src="Images/08 Cloudflare Dashboard Splunk/03 Click Upload .png" width="700"/>

<img src="Images/08 Cloudflare Dashboard Splunk/04 Select The Log File And Click Next .png" width="700"/>

<img src="Images/08 Cloudflare Dashboard Splunk/05 Select the Default or as Custom and Click Save As .png" width="700"/>

<img src="Images/08 Cloudflare Dashboard Splunk/06 Named the Host as splunk.png" width="700"/>

The host was named **"splunk"** to identify the Cloudflare log source in all dashboard panels.

<img src="Images/08 Cloudflare Dashboard Splunk/07 After Submitting the File Click Start Searching.png" width="700"/>

---

## Step 8 — Create New Dashboard

Navigated to **Dashboards** → **Create New Dashboard** to begin the Cloudflare dashboard build.

<img src="Images/08 Cloudflare Dashboard Splunk/08 Create a new dashboard.png" width="700"/>

---

## Step 9 — Add Time, Submit & Panels

Added the **Time Range** input, **Submit** button, and began adding panels — all configured to use the shared `$time_tok$` token.

<img src="Images/08 Cloudflare Dashboard Splunk/09 Add Time and Submit Button and Then Panels.png" width="700"/>

---

## Panel — Quick Summary of Web Activity

KPI panel showing the overall Cloudflare traffic breakdown — total requests, allowed, challenged, and blocked — giving an instant security posture overview.

```spl
index=Cloudflare_http_logs $time_tok$
| stats count as total,
        count(eval(WAFAction="allow"))     as allowed,
        count(eval(WAFAction="challenge")) as challenged,
        count(eval(WAFAction="block"))     as blocked
```

<img src="Images/08 Cloudflare Dashboard Splunk/10 quick summary of Web activity..png" width="700"/>

---

## Panel — Successful Responses

Volume of HTTP 2xx successful responses passing through Cloudflare — confirms legitimate traffic is flowing normally alongside the security monitoring.

```spl
index=Cloudflare_http_logs $time_tok$
| search EdgeResponseStatus>=200 EdgeResponseStatus<300
| timechart count span=1h
```

<img src="Images/08 Cloudflare Dashboard Splunk/11 Successful Responces.png" width="700"/>

---

## Panel — WAF Challenges

Requests that Cloudflare's Web Application Firewall flagged as suspicious and issued a **challenge** (CAPTCHA, JS challenge) — these are potential attacks that Cloudflare is testing before deciding to block.

```spl
index=Cloudflare_http_logs $time_tok$
| search WAFAction=challenge
| stats count as challenges by ClientIP, ClientRequestURI, ClientCountry
| sort -challenges
| rename ClientIP as "Source IP", ClientRequestURI as "URI",
         ClientCountry as "Country", challenges as "Challenges"
```

<img src="Images/08 Cloudflare Dashboard Splunk/12 Web application firewall Challenges .png" width="700"/>

A high challenge count from a single IP indicates Cloudflare is actively engaging with a persistent attacker — the attacker has not yet been fully blocked.

---

## Panel — WAF Blocks

Requests that Cloudflare **hard-blocked** — confirmed malicious traffic stopped at the edge before reaching the origin server.

```spl
index=Cloudflare_http_logs $time_tok$
| search WAFAction=block
| stats count as blocks by ClientIP, ClientRequestURI, ClientCountry, WAFRuleID
| sort -blocks
| rename ClientIP as "Blocked IP", ClientRequestURI as "Blocked URI",
         ClientCountry as "Country", WAFRuleID as "WAF Rule", blocks as "Blocks"
```

<img src="Images/08 Cloudflare Dashboard Splunk/13 WAF Block.png" width="700"/>

WAF block data reveals:
- Which IPs are being blocked (confirmed attackers)
- Which WAF rules are firing most (identifies the primary attack vectors)
- Which URIs are being targeted (attack surface visibility)

---

## Panel — Web Stats

Aggregate web statistics panel — bytes transferred, average response time, request method distribution, and edge response status breakdown.

```spl
index=Cloudflare_http_logs $time_tok$
| stats count as requests,
        sum(EdgeResponseBytes) as total_bytes,
        avg(OriginResponseTime) as avg_response_ms
        by ClientRequestMethod
| eval total_mb = round(total_bytes/1048576, 2)
| eval avg_response_ms = round(avg_response_ms, 0)
| rename ClientRequestMethod as "Method", requests as "Requests",
         total_mb as "Data (MB)", avg_response_ms as "Avg Response (ms)"
```

<img src="Images/08 Cloudflare Dashboard Splunk/14 Web Stats.png" width="700"/>

---

## Panel — Top Users by IP Address

Ranked list of the most active client IPs across all Cloudflare-proxied requests — flags both heavy legitimate users and automated attack sources.

```spl
index=Cloudflare_http_logs $time_tok$
| stats count as requests by ClientIP, ClientCountry, WAFAction
| sort -requests
| head 15
| rename ClientIP as "Client IP", ClientCountry as "Country",
         WAFAction as "WAF Decision", requests as "Requests"
```

<img src="Images/08 Cloudflare Dashboard Splunk/15 Top Users by IP Address.png" width="700"/>

---

## Panel — Web Traffic by Client IP (Geo Map)

Geographic map plotting the origin of all Cloudflare-proxied requests — immediately reveals nation-state attack campaigns, coordinated botnets, and unexpected geographic traffic spikes.

```spl
index=Cloudflare_http_logs $time_tok$
| iplocation ClientIP
| stats count by Country, lat, lon
| geostats latfield=lat longfield=lon count
```

<img src="Images/08 Cloudflare Dashboard Splunk/16 Web Traffic by Client IP Addresses.png" width="700"/>

---

## Full Dashboard View

The completed Cloudflare Security Dashboard — all panels live with time controls showing the full edge security picture.

<img src="Images/08 Cloudflare Dashboard Splunk/17 The Cloudfalre Dashbaord.png" width="700"/>

The dashboard delivers complete Cloudflare edge visibility:
- **Summary KPIs** — total traffic, allowed vs challenged vs blocked
- **Successful Responses** — legitimate traffic volume trending
- **WAF Challenges** — suspicious requests under active evaluation
- **WAF Blocks** — confirmed blocked attacks with rule IDs
- **Web Stats** — method distribution, data volume, response times
- **Top IPs** — most active clients with WAF decision overlay
- **Geo Map** — global attack and traffic origin mapping

---

## 🔗 Navigation

⬅️ **[Phase 07 — Web Traffic Dashboard](./08_Web_Traffic_Dashboard.md)** &nbsp;&nbsp;|&nbsp;&nbsp; ➡️ **[Back to Project Overview](./README.md)**

---

<p align="center">
  <b>Umar Ahmed</b> · Cybersecurity Student · Security Automation & SIEM Enthusiast<br/>
  <a href="https://github.com/User-Umar-Ahamed">
    <img src="https://img.shields.io/badge/GitHub-User--Umar--Ahamed-181717?style=for-the-badge&logo=github" />
  </a>
</p>
