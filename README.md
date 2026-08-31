# 🪤 SHADOW-TRAP

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.10%2B-blue?style=for-the-badge&logo=python&logoColor=white" alt="Python Version">
  <img src="https://img.shields.io/badge/Platform-Windows%20%7C%20Linux-green?style=for-the-badge&logo=linux&logoColor=white" alt="Platform Support">
  <img src="https://img.shields.io/badge/Security-Honeypot%20%26%20Active%20Defense-red?style=for-the-badge" alt="Security Domain">
  <img src="https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge" alt="License">
</p>

**SHADOW-TRAP** is a lightweight, modular Low-Interaction Honeypot engineered for active cyber-defense, threat telemetry gathering, and automated attacker mitigation.

The honeypot emulates common exposed services, captures unauthorized access attempts, brute-force attacks, and port scans, evaluates malicious intent using a scoring model, and dynamically isolates threat actors at the firewall layer (Windows Firewall / Linux `iptables`).

---

## ⚡ Key Features

- **Multi-Service Trap Emulation:**
  - **SSH (Port 22):** Intercepts credential brute-force attempts (user/password pairs).
  - **FTP (Port 21):** Emulates `vsFTPd 3.0.3` capturing authentication handshakes (`USER` / `PASS`).
  - **HTTP (Port 80):** Decoy administrator login portal with payload extraction and URL decoding for incoming POST requests.
  - **MySQL (Port 3306):** Traps reconnaissance sweeps and network probes.
- **Active Defense & IPS:**
  - Dynamic threat scoring model based on attacker actions.
  - Automated IP blocking once the cumulative threshold (`THREAT_LIMIT`) is reached.
  - Cross-platform firewall integration (PowerShell NetFirewall for Windows / `iptables` for Linux).
  - Protection against duplicate firewall rules and exclusion for private/loopback subnets (RFC 1918).
- **Threat Intelligence & GeoIP:**
  - Resolves geolocation (Country) and ISP metadata for external threats.
  - Thread-safe in-memory GeoIP caching to mitigate network latency and third-party rate limits.
- **Security Dashboard:**
  - Standalone SOC-style dark dashboard powered by TailwindCSS and Chart.js.
  - Full output sanitization to prevent Stored XSS from captured malicious payloads.
  - Graphical breakdown of attack vectors and geographical origins.
- **Storage:**
  - Thread-safe SQLite persistence (`shadow_trap.db`).

---

## 📁 Repository Structure

```text
SHADOW-TRAP/
├── config.py           # Configuration: ports, banners, scoring, and whitelists
├── main.py             # Multithreaded honeypot orchestrator and socket listener
├── deception.py        # Protocol emulation logic and payload capture
├── threat_intel.py     # Threat scoring engine, GeoIP resolution, SQLite logger
├── firewall.py         # Cross-platform automated firewall blocking module
├── dashboard.py        # Threat report generator (HTML + Charts)
├── dashboard.html      # Generated interactive security dashboard
├── client_test.py      # Local testing client for SSH verification
└── shadow_trap.db      # SQLite database storing raw incident logs
```

---

## 🚀 Getting Started

### 1. Prerequisites
* Python `3.10` or higher.
* **Administrator** (Windows) or **Root** (Linux) privileges are required to bind to privileged low ports (<1024) and manage system firewall rules.

### 2. Installation & Run

```bash
git clone https://github.com/d3fuse99/SHADOW-TRAP.git
cd SHADOW-TRAP
```

**Run on Windows (PowerShell as Administrator):**
```powershell
python main.py
```

**Run on Linux (Root):**
```bash
sudo python3 main.py
```

---

## 🧪 Testing Deployed Traps

Open a secondary terminal to test the active listeners:

* **SSH Trap (Port 22):**
  ```bash
  python client_test.py
  ```
* **HTTP Decoy (Port 80):**
  Open `http://localhost` in your browser and submit test credentials.
* **FTP Trap (Port 21):**
  ```bash
  curl ftp://127.0.0.1:21
  ```

---

## 📊 Generating the Threat Dashboard

Generate a fresh intelligence report based on captured incidents:

```bash
python dashboard.py
```

Open `dashboard.html` in your default browser:
- **Windows:** `start dashboard.html`
- **Linux:** `xdg-open dashboard.html`

---

## ⚙️ Configuration (`config.py`)

Core threat parameters can be fine-tuned in `config.py`:

```python
DB_FILE = "shadow_trap.db"    # Incident database file
THREAT_LIMIT = 10              # Threat score threshold required to trigger a block
MAX_TRACKED_IPS = 1000         # Maximum number of concurrently tracked IP scores

WHITELIST_IPS = [              # IPs exempt from scoring and firewall blocking
    "127.0.0.1",
    "::1"
]
```

---

## ⚠️ Disclaimer

This tool is developed solely for educational purposes, security research, and defensive infrastructure monitoring in controlled environments. The author assumes no liability for misuse or damage caused by this software.
