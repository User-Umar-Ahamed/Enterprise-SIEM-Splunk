<h1 align="center">📊 SSH Security Monitoring Dashboard</h1>
<h3 align="center">Classic Dashboard &nbsp;·&nbsp; Time Range Input &nbsp;·&nbsp; Live Panels &nbsp;·&nbsp; Visualisations &nbsp;·&nbsp; Full Dashboard View</h3>

<p align="center">
  <img src="https://img.shields.io/badge/Splunk-SOC%20Dashboard-FF5733?style=for-the-badge&logo=splunk&logoColor=white" />
  <img src="https://img.shields.io/badge/Type-Classic%20Dashboard-8b5cf6?style=for-the-badge" />
  <img src="https://img.shields.io/badge/Phase-06%20SSH%20Dashboard-3fb950?style=for-the-badge" />
  <img src="https://img.shields.io/badge/Status-Built%20%26%20Live-22c55e?style=for-the-badge" />
</p>

<p align="center">
  <b>Built a live SSH security monitoring dashboard in Splunk — ingested SSH logs, created a Classic Dashboard with a time range input, added analytical panels for failed logins, successful logins, unauthenticated connections, and brute force — with custom colour formatting and a full dashboard view.</b>
</p>

---

## 📖 Table of Contents

- [Project Context](#-project-context)
- [Ingestion — Steps 1 to 7](#ingestion--steps-1-to-7)
- [Step 8 — Create New Dashboard](#step-8--create-new-dashboard)
- [Step 9 — Name & Select Dashboard Type](#step-9--name--select-dashboard-type)
- [Step 10 — Add Time Range Input](#step-10--add-time-range-input)
- [Step 11 — Configure Time Range Token](#step-11--configure-time-range-token)
- [Step 12 — Add Panels](#step-12--add-panels)
- [Step 13 — Custom Colour Formatting](#step-13--custom-colour-formatting)
- [Panel — Failed SSH Logins](#panel--failed-ssh-logins)
- [Panel — Unauthenticated Connections](#panel--unauthenticated-connections)
- [Panel — Possible Brute Force](#panel--possible-brute-force)
- [Panel — Successful SSH Logins](#panel--successful-ssh-logins)
- [Panel — Brute Force Statistics Table](#panel--brute-force-statistics-table)
- [Full Dashboard View](#full-dashboard-view)
- [Dashboard XML Reference](#-dashboard-xml-reference)

---

## 🧠 Project Context

The SPL queries built in the SSH Threat Analysis phases produced results in the search bar — this phase converts them into a **persistent live dashboard** that any analyst can open for instant SSH threat visibility without writing a single query.

---

## Ingestion — Steps 1 to 7

<img src="Images/06 SSH_LOG_DASHBOARD/01 Click Search & Reporting App To Upload the Logs and Analyze.png" width="700"/>

<img src="Images/06 SSH_LOG_DASHBOARD/02 Click Add Data .png" width="700"/>

<img src="Images/06 SSH_LOG_DASHBOARD/03 Click Upload .png" width="700"/>

<img src="Images/06 SSH_LOG_DASHBOARD/04 Select The Log File And Click Next .png" width="700"/>

<img src="Images/06 SSH_LOG_DASHBOARD/05 Select the Default or as Custom and Click Save As .png" width="700"/>

<img src="Images/06 SSH_LOG_DASHBOARD/06 Named the Host as Server.png" width="700"/>

The host was named **"Server"** to represent the SSH target endpoint in dashboard filters.

<img src="Images/06 SSH_LOG_DASHBOARD/07 After Submitting the File Click Start Searching.png" width="700"/>

---

## Step 8 — Create New Dashboard

Navigated to **Dashboards** → **Create New Dashboard**.

<img src="Images/06 SSH_LOG_DASHBOARD/08 Click Dashboard and Click Create New Dashbaord.png" width="700"/>

---

## Step 9 — Name & Select Dashboard Type

<img src="Images/06 SSH_LOG_DASHBOARD/09 Set name and Select Classic Dashboard and Create .png" width="700"/>

| Setting | Value |
|---------|-------|
| **Dashboard Name** | SSH Security Monitoring |
| **Type** | Classic Dashboards |
| **Permissions** | Shared in App |

---

## Step 10 — Add Time Range Input

Added a **Time Range** input — one control adjusts every panel simultaneously.

<img src="Images/06 SSH_LOG_DASHBOARD/10 Adding Time Range in Dashboard.png" width="700"/>

---

## Step 11 — Configure Time Range Token

Clicked **Edit** on the time input to set the token name `$time_tok$` and default value (`-24h` to `now`).

<img src="Images/06 SSH_LOG_DASHBOARD/11 After Adding Time Range Click Edit and Edit the Field as above.png" width="700"/>

---

## Step 12 — Add Panels

Panels were added via **Add Panel** — each powered by SPL from the SSH Threat Analysis investigations.

<img src="Images/06 SSH_LOG_DASHBOARD/12 Adding the Panel .png" width="700"/>

---

## Step 13 — Custom Colour Formatting

Applied colour thresholds so threat severity is immediately visible without reading numbers.

<img src="Images/06 SSH_LOG_DASHBOARD/13 Colors Can Be Changed.png" width="700"/>

---

## Panel — Failed SSH Logins

Visualisation showing failed SSH login attempts over time — the primary brute force detection signal.

```spl
index=ssh_logs $time_tok$
| search event_type="Failed SSH Login"
| timechart count span=1h
```

<img src="Images/06 SSH_LOG_DASHBOARD/14 Visualising the Failed ssh logins .png" width="700"/>

---

## Panel — Unauthenticated Connections

Visualisation of unauthenticated SSH connections — reconnaissance/scanning activity with no auth attempt.

```spl
index=ssh_logs $time_tok$
| search auth_attempts=0
| stats count by id.orig_h
| sort -count
```

<img src="Images/06 SSH_LOG_DASHBOARD/15 Visualising the Connection without Authentication .png" width="700"/>

---

## Panel — Possible Brute Force

Visualisation highlighting IPs flagged as possible brute force sources based on repeated failure counts.

```spl
index=ssh_logs $time_tok$
| search event_type="Multiple Failed Authentication Attempts"
| stats count as attempts by id.orig_h
| where attempts > 5
| sort -attempts
```

<img src="Images/06 SSH_LOG_DASHBOARD/16 Visualising Possible Brute Force .png" width="700"/>

---

## Panel — Successful SSH Logins

Visualisation of successful SSH logins — cross-referenced against failure history to flag compromised accounts.

```spl
index=ssh_logs $time_tok$
| search auth_success=true
| stats count by id.orig_h, id.resp_h
| sort -count
```

<img src="Images/06 SSH_LOG_DASHBOARD/16 Visualising the Successfull ssh logins .png" width="700"/>

---

## Panel — Brute Force Statistics Table

A statistics table showing the full brute force breakdown per attacker IP — event count, unique targets, and auth attempts.

```spl
index=ssh_logs $time_tok$
| search event_type="Multiple Failed Authentication Attempts"
| stats count as events, sum(auth_attempts) as total_attempts, dc(id.resp_h) as targets by id.orig_h
| sort -total_attempts
| rename id.orig_h as "Attacker IP", events as "Events", total_attempts as "Total Attempts", targets as "Targets"
```

<img src="Images/06 SSH_LOG_DASHBOARD/17 Visualising the Brute Force in Statistic Table .png" width="700"/>

---

## Full Dashboard View

The completed SSH Security Monitoring Dashboard — all panels live, time-controlled, and colour-coded.

<img src="Images/06 SSH_LOG_DASHBOARD/18 The DashBoard of SSH Logs.png" width="700"/>

The dashboard consolidates all SSH threat signals into one view:
- **Failed Logins** panel — attack volume trending
- **Unauthenticated Connections** — scanner/probe activity
- **Possible Brute Force** — ranked attacker IPs
- **Successful Logins** — post-attack access monitoring
- **Brute Force Table** — full statistics per attacker

---

## 📋 Dashboard XML Reference

```xml
<dashboard>
  <label>SSH Security Monitoring</label>
  <fieldset submitButton="false" autoRun="true">
    <input type="time" token="time_tok">
      <label>Time Range</label>
      <default><earliest>-24h@h</earliest><latest>now</latest></default>
    </input>
  </fieldset>
  <row>
    <panel>
      <single>
        <title>Failed SSH Logins</title>
        <search><query>index=ssh_logs $time_tok$ | search event_type="Failed SSH Login" | stats count</query></search>
        <option name="colorBy">value</option>
        <option name="rangeColors">["0x3fb950","0xf59e0b","0xff0040"]</option>
        <option name="rangeValues">[10,50]</option>
      </single>
    </panel>
  </row>
  <row>
    <panel>
      <chart>
        <title>Failed Logins Over Time</title>
        <search><query>index=ssh_logs $time_tok$ | search event_type="Failed SSH Login" | timechart count span=1h</query></search>
        <option name="charting.chart">line</option>
      </chart>
    </panel>
  </row>
  <row>
    <panel>
      <table>
        <title>Brute Force — Top Attackers</title>
        <search><query>index=ssh_logs $time_tok$ | search event_type="Multiple Failed Authentication Attempts" | stats count by id.orig_h | sort -count | head 10</query></search>
      </table>
    </panel>
  </row>
</dashboard>
```

---

## 🔗 Navigation

⬅️ **[Phase 05 — Cloudflare Log Monitoring](./06_Cloudflare_Log_Monitoring.md)** &nbsp;&nbsp;|&nbsp;&nbsp; ➡️ **[Phase 07 — Web Traffic Dashboard](./08_Web_Traffic_Dashboard.md)**

---

<p align="center">
  <b>Umar Ahmed</b> · Cybersecurity Student · Security Automation & SIEM Enthusiast<br/>
  <a href="https://github.com/User-Umar-Ahamed">
    <img src="https://img.shields.io/badge/GitHub-User--Umar--Ahamed-181717?style=for-the-badge&logo=github" />
  </a>
</p>
