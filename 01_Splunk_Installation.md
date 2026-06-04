<h1 align="center">🔵 Splunk SIEM — Installation & Setup</h1>
<h3 align="center">Ubuntu Server &nbsp;·&nbsp; Splunk Enterprise &nbsp;·&nbsp; System Prep &nbsp;·&nbsp; First Login</h3>

<p align="center">
  <img src="https://img.shields.io/badge/Splunk-Enterprise-FF5733?style=for-the-badge&logo=splunk&logoColor=white" />
  <img src="https://img.shields.io/badge/Platform-Ubuntu%20Server-0078D6?style=for-the-badge&logo=linux&logoColor=white" />
  <img src="https://img.shields.io/badge/Phase-01%20Installation-3fb950?style=for-the-badge" />
  <img src="https://img.shields.io/badge/Status-Deployed-22c55e?style=for-the-badge" />
</p>

<p align="center">
  <b>The foundation of the entire SIEM project — Splunk Enterprise was installed on an Ubuntu server from the ground up, covering system preparation, package download, installation, boot-start configuration, and first login.</b>
</p>

---

## 📖 Table of Contents

- [Project Context](#-project-context)
- [Step 1 — System Updates & Upgrades](#step-1--system-updates--upgrades)
- [Step 2 — Downloading Splunk Enterprise](#step-2--downloading-splunk-enterprise)
- [Step 3 — Installing Splunk Enterprise](#step-3--installing-splunk-enterprise)
- [Step 4 — License Agreement & Boot-Start](#step-4--license-agreement--boot-start)
- [Step 5 — Splunk Login](#step-5--splunk-login)
- [Key Decisions](#-key-decisions)

---

## 🧠 Project Context

Before any log analysis or threat detection could begin, a stable Splunk Enterprise instance needed to be deployed. This phase covers the complete installation on an Ubuntu server — the platform that all subsequent SSH analysis, DNS monitoring, web traffic inspection, and Cloudflare log investigations run on.

| Component | Detail |
|-----------|--------|
| **Platform** | Splunk Enterprise (Free Developer Licence) |
| **OS** | Ubuntu Server (LTS) |
| **Web UI Port** | 8000 |
| **Install Path** | `/opt/splunk` |
| **Ingest Limit** | 500 MB/day (free licence) |

---

## Step 1 — System Updates & Upgrades

Before installing any software, the server's packages were fully updated to avoid dependency conflicts and ensure the latest security patches were applied.

```bash
sudo apt-get update && sudo apt-get upgrade -y
```

<img src="Images/01 Splunk Installation/01 Updates and Upgrades of The Splunk Server.png" width="700"/>

All packages were updated successfully before proceeding to the Splunk download.

---

## Step 2 — Downloading Splunk Enterprise

Splunk Enterprise was downloaded directly from the official Splunk portal using `wget`. The `.deb` package was used for Ubuntu compatibility.

```bash
wget -O splunk-enterprise.deb \
  "https://download.splunk.com/products/splunk/releases/9.x.x/linux/splunk-9.x.x-linux-amd64.deb"
```

<img src="Images/01 Splunk Installation/02 Downloading Splunk Enterprise .png" width="700"/>

The download was verified for integrity before proceeding to installation.

---

## Step 3 — Installing Splunk Enterprise

The downloaded `.deb` package was installed using `dpkg`, which extracted all Splunk binaries and configuration templates into `/opt/splunk`.

```bash
sudo dpkg -i splunk-enterprise.deb
```

<img src="Images/01 Splunk Installation/03 Installing The Splunk Enterprise.png" width="700"/>

Installation placed the following in `/opt/splunk/`:

| Directory | Purpose |
|-----------|---------|
| `bin/` | Splunk executables (`splunk`, `splunkd`) |
| `etc/system/local/` | All custom configuration files |
| `etc/apps/` | Installed Splunk apps and add-ons |
| `var/log/splunk/` | Splunk internal logs |
| `var/lib/splunk/` | Index data storage |

---

## Step 4 — License Agreement & Boot-Start

Splunk was started for the first time, the licence agreement was accepted, admin credentials were set, and boot-start was enabled so Splunk automatically restarts after any server reboot.

```bash
# Start Splunk, accept licence, set admin credentials
sudo /opt/splunk/bin/splunk start --accept-license

# Enable Splunk to start automatically on boot
sudo /opt/splunk/bin/splunk enable boot-start -user splunk
```

<img src="Images/01 Splunk Installation/04 Accept the license agreement and enable Splunk at boot.png" width="700"/>

Boot-start registers Splunk as a `systemd` service named `Splunkd`. From this point, the SIEM platform survives server reboots without manual intervention — a critical requirement for any production monitoring system.

```bash
# Useful service management commands post-installation
sudo systemctl start Splunkd
sudo systemctl stop Splunkd
sudo systemctl restart Splunkd
sudo systemctl status Splunkd
```

---

## Step 5 — Splunk Login

With Splunk running, the Web UI was accessed at `http://SERVER_IP:8000` and the admin credentials set during installation were used to log in for the first time.

<img src="Images/01 Splunk Installation/05 Splunk Login.png" width="700"/>

The Splunk Home screen confirmed the platform was fully operational. From here, all subsequent log ingestion, SPL queries, dashboards, and alerts were built.

Key areas used throughout this project:

| UI Area | Purpose |
|---------|---------|
| **Search & Reporting** | All SPL queries and log analysis |
| **Settings → Add Data** | Uploading log files for each investigation |
| **Settings → Indexes** | Creating custom indexes per log type |
| **Dashboards** | Building the SSH monitoring dashboard |
| **Alerts** | Configuring real-time brute force notifications |

---

## 🔑 Key Decisions

| Decision | Rationale |
|----------|-----------|
| Ubuntu Server as the host OS | Most common OS in production SOC environments, best Splunk support |
| `.deb` package install | Clean integration with Ubuntu's package manager and systemd |
| Boot-start enabled immediately | A SIEM that requires manual restart after reboots is unreliable |
| Free developer licence | 500 MB/day is sufficient for all log files analysed in this project |

---

## 🔗 Next Phase

➡️ **[Phase 02 — SSH Threat Analysis (Log Set 1)](./02_SSH_Threat_Analysis_LOG01.md)**

---

<p align="center">
  <b>Umar Ahmed</b> · Cybersecurity Student · Security Automation & SIEM Enthusiast<br/>
  <a href="https://github.com/User-Umar-Ahamed">
    <img src="https://img.shields.io/badge/GitHub-User--Umar--Ahamed-181717?style=for-the-badge&logo=github" />
  </a>
</p>
