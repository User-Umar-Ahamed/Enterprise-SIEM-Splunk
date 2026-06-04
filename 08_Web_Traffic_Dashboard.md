<h1 align="center">🌍 Web Traffic Monitoring Dashboard</h1>
<h3 align="center">HTTP Log Dashboard &nbsp;·&nbsp; Response Codes &nbsp;·&nbsp; Top URIs &nbsp;·&nbsp; Top IPs &nbsp;·&nbsp; Geo Map</h3>

<p align="center">
  <img src="https://img.shields.io/badge/Splunk-Web%20Traffic%20Dashboard-FF5733?style=for-the-badge&logo=splunk&logoColor=white" />
  <img src="https://img.shields.io/badge/Type-Classic%20Dashboard-8b5cf6?style=for-the-badge" />
  <img src="https://img.shields.io/badge/Phase-07%20Web%20Dashboard-3fb950?style=for-the-badge" />
  <img src="https://img.shields.io/badge/Status-Built%20%26%20Live-22c55e?style=for-the-badge" />
</p>

<p align="center">
  <b>Built a live web traffic monitoring dashboard in Splunk — ingested HTTP logs, created a Classic Dashboard with time and submit controls, and added panels covering web activity summary, successful responses, client errors, server errors, top URIs, top IPs, and a geo-location map of client traffic.</b>
</p>

---

## 📖 Table of Contents

- [Project Context](#-project-context)
- [Ingestion — Steps 1 to 7](#ingestion--steps-1-to-7)
- [Step 8 — Create New Dashboard](#step-8--create-new-dashboard)
- [Step 9 — Dashboard Name & Type](#step-9--dashboard-name--type)
- [Step 10 — Add Time & Submit Button](#step-10--add-time--submit-button)
- [Step 11 — Time Range Settings](#step-11--time-range-settings)
- [Panel — Quick Summary of Web Activity](#panel--quick-summary-of-web-activity)
- [Panel — Successful Responses (2xx)](#panel--successful-responses-2xx)
- [Panel — Client Side Errors (4xx)](#panel--client-side-errors-4xx)
- [Panel — Server Side Errors (5xx)](#panel--server-side-errors-5xx)
- [Panel — Top Requested URIs](#panel--top-requested-uris)
- [Panel — Top Users by IP Address](#panel--top-users-by-ip-address)
- [Panel — Geo Location Map](#panel--geo-location-map)
- [Full Dashboard View](#full-dashboard-view)

---

## 🧠 Project Context

The web traffic SPL analysis from Phase 04 identified threats through direct queries. This phase converts those detections into a **live persistent dashboard** — giving any analyst an instant overview of web server health, attack surface, and traffic origins without running a single query.

The dashboard covers the full HTTP response code spectrum (2xx success, 4xx client errors, 5xx server errors) alongside top endpoint rankings and geographic traffic mapping.

---

## Ingestion — Steps 1 to 7

<img src="Images/07 Dashboard for Web Traffic Logs/01 Click Search & Reporting App To Upload the Logs and Analyze.png" width="700"/>

<img src="Images/07 Dashboard for Web Traffic Logs/02 Click Add Data .png" width="700"/>

<img src="Images/07 Dashboard for Web Traffic Logs/03 Click Upload .png" width="700"/>

<img src="Images/07 Dashboard for Web Traffic Logs/04 Select The Log File And Click Next .png" width="700"/>

<img src="Images/07 Dashboard for Web Traffic Logs/05 Select the Default or as Custom and Click Save As .png" width="700"/>

<img src="Images/07 Dashboard for Web Traffic Logs/06 Named the Host as webServer.png" width="700"/>

The host was named **"webServer"** to identify the web server endpoint in all dashboard panels.

<img src="Images/07 Dashboard for Web Traffic Logs/07 After Submitting the File Click Start Searching.png" width="700"/>

---

## Step 8 — Create New Dashboard

Navigated to **Dashboards** → **Create New Dashboard**.

<img src="Images/07 Dashboard for Web Traffic Logs/08 Click Dashboard and Click Create New Dashbaord.png" width="700"/>

---

## Step 9 — Dashboard Name & Type

<img src="Images/07 Dashboard for Web Traffic Logs/09 Dashboard Name and Choice.png" width="700"/>

| Setting | Value |
|---------|-------|
| **Dashboard Name** | Web Traffic Monitoring |
| **Type** | Classic Dashboards |
| **Permissions** | Shared in App |

---

## Step 10 — Add Time & Submit Button

Added a **Time Range** input and a **Submit** button — analysts select their time window and click submit to refresh all panels.

<img src="Images/07 Dashboard for Web Traffic Logs/10 Add the Time and Submit Button.png" width="700"/>

---

## Step 11 — Time Range Settings

Configured the time input token and default range so panels load with a sensible window on open.

<img src="Images/07 Dashboard for Web Traffic Logs/11 Time range Settings.png" width="700"/>

---

## Panel — Quick Summary of Web Activity

A summary panel giving an instant count of total HTTP events, broken down by method and response code — the analyst's first view when opening the dashboard.

```spl
index=http_logs $time_tok$
| stats count as total_requests,
        count(eval(status_code>=200 AND status_code<300)) as successful,
        count(eval(status_code>=400 AND status_code<500)) as client_errors,
        count(eval(status_code>=500)) as server_errors
```

<img src="Images/07 Dashboard for Web Traffic Logs/12 quick summary of Web activity..png" width="700"/>

---

## Panel — Successful Responses (2xx)

Visualisation of all HTTP 2xx successful responses — confirming legitimate traffic volume and identifying peak usage periods.

```spl
index=http_logs $time_tok$
| search status_code>=200 status_code<300
| timechart count span=1h
```

<img src="Images/07 Dashboard for Web Traffic Logs/13 Successful Response.png" width="700"/>

---

## Panel — Client Side Errors (4xx)

HTTP 4xx errors — client-side failures including 401 (Unauthorized), 403 (Forbidden), and 404 (Not Found). High 401/403 volume from a single IP indicates brute force or unauthorised access attempts.

```spl
index=http_logs $time_tok$
| search status_code>=400 status_code<500
| stats count as error_count by id.orig_h, uri, status_code
| sort -error_count
| rename id.orig_h as "Source IP", uri as "URI",
         status_code as "Error Code", error_count as "Count"
```

<img src="Images/07 Dashboard for Web Traffic Logs/14 Client Side Error.png" width="700"/>

---

## Panel — Server Side Errors (5xx)

HTTP 5xx server errors — application-side failures. Clusters of 500 errors from one IP often indicate automated vulnerability scanning triggering unhandled exceptions.

```spl
index=http_logs $time_tok$
| search status_code>=500
| stats count as server_errors by id.orig_h, uri
| sort -server_errors
| rename id.orig_h as "Source IP", uri as "URI", server_errors as "500 Errors"
```

<img src="Images/07 Dashboard for Web Traffic Logs/15 Server Side Error.png" width="700"/>

---

## Panel — Bar Chart: Top Requested URIs

Horizontal bar chart ranking the most-requested URIs — reveals which endpoints receive the most traffic and flags any unexpected high-traffic paths.

```spl
index=http_logs $time_tok$
| stats count as requests by uri
| sort -requests
| head 10
| rename uri as "URI", requests as "Requests"
```

<img src="Images/07 Dashboard for Web Traffic Logs/16 Bar Chart Top Requested URIs.png" width="700"/>

---

## Panel — Bar Chart: Top Users by IP Address

Horizontal bar chart ranking source IPs by total request count — immediately shows the most active clients, which may be legitimate heavy users or automated attack tools.

```spl
index=http_logs $time_tok$
| stats count as requests by id.orig_h
| sort -requests
| head 10
| rename id.orig_h as "Client IP", requests as "Requests"
```

<img src="Images/07 Dashboard for Web Traffic Logs/17 Bar Chart Top Users by IP Address.png" width="700"/>

---

## Panel — Geo Location Map

Geographic map of web traffic origin — plots every client IP on a world map using Splunk's built-in `iplocation` command, making geographic attack patterns and unexpected traffic origins immediately visible.

```spl
index=http_logs $time_tok$
| iplocation id.orig_h
| stats count by Country, lat, lon
| geostats latfield=lat longfield=lon count
```

<img src="Images/07 Dashboard for Web Traffic Logs/18 Geo location of Web Traffic by Client IP Addresses.png" width="700"/>

---

## Full Dashboard View

The completed Web Traffic Monitoring Dashboard — all panels live with time controls.

<img src="Images/07 Dashboard for Web Traffic Logs/18 The DashBoard of Web Traffic.png" width="700"/>

The dashboard provides complete web server visibility:
- **Summary KPIs** — total requests, success, client errors, server errors
- **2xx Trend** — legitimate traffic volume over time
- **4xx Panel** — unauthorised and forbidden access attempts
- **5xx Panel** — server errors indicating scanning or application issues
- **Top URIs** — most-requested endpoints
- **Top IPs** — most-active clients
- **Geo Map** — geographic traffic origin

---

## 🔗 Navigation

⬅️ **[Phase 06 — SSH Dashboard](./07_SSH_Log_Dashboard.md)** &nbsp;&nbsp;|&nbsp;&nbsp; ➡️ **[Phase 08 — Cloudflare Dashboard](./09_Cloudflare_Dashboard.md)**

---

<p align="center">
  <b>Umar Ahmed</b> · Cybersecurity Student · Security Automation & SIEM Enthusiast<br/>
  <a href="https://github.com/User-Umar-Ahamed">
    <img src="https://img.shields.io/badge/GitHub-User--Umar--Ahamed-181717?style=for-the-badge&logo=github" />
  </a>
</p>
