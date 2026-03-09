# HoneyWatch

A lightweight, production-ready honeypot for **Ubuntu 24.04 LTS** on DigitalOcean (or any VPS). Captures attacker credentials across nine services, maps their origins, checks IPs against threat intel databases, and displays everything on a live web dashboard at `http://your-ip:5000`.

![Dashboard preview](docs/screenshot.png)

---

## Features

| Feature | Details |
|---|---|
| **9 honeypot services** | SSH, HTTP, Telnet, FTP, SMTP, RDP, MySQL, Redis, SMB |
| **Geo-location** | Every attacker IP resolved to country/city via ip-api.com |
| **Threat intel** | Optional AbuseIPDB integration flags known-bad IPs |
| **Live dashboard** | Real-time web UI with world map, charts, and event feed |
| **Server-Sent Events** | Dashboard updates instantly without polling |
| **CSV / JSON export** | Filter by service, date range, and row limit — download from the UI |
| **Weekly email alerts** | Automated summary email with top IPs, passwords, and service breakdown |
| **SQLite storage** | All events persisted locally — no external DB needed |
| **Systemd service** | Auto-starts on boot, restarts on crash |
| **One-command updates** | `./update.sh` pulls latest code, upgrades deps, restarts the service |
| **Optional auth** | HTTP basic auth for the dashboard |

---

## Quick Start (DigitalOcean)

### 1. Create a Droplet

- **Image**: Ubuntu 24.04 LTS x64
- **Size**: Basic $6/month (1 vCPU / 1 GB) is sufficient
- **Region**: Anywhere

> ⚠️ Use a **dedicated droplet**. Do not run this on a server with sensitive data.

### 2. Deploy

```bash
git clone https://github.com/netplayz/honeywatch.git
cd honeywatch
chmod +x ./update.sh
sudo bash install.sh
```

The installer will:
- Configure UFW firewall (keeps port 22 open for your real SSH)
- Create a dedicated `honeypot` system user
- Install Python dependencies in a virtualenv
- Install and start the `honeywatch` systemd service

### 3. Open the Dashboard

Navigate to `http://YOUR_DROPLET_IP:5000` in your browser.

### 4. Updating

```bash
./update.sh
```

Pulls the latest code from `main`, upgrades dependencies, runs a syntax check on all Python files, and restarts the service. If the syntax check fails the service is left running on the old code.

```bash
./update.sh --no-restart          # pull + install only, don't bounce the service
./update.sh --branch dev          # pull from a different branch
```

---

## Configuration

Edit `/etc/honeywatch/env` after installation:

```bash
# Honeypot ports
SSH_PORT=2222
HTTP_PORT=8080
TELNET_PORT=2323
FTP_PORT=2121
SMTP_PORT=2525
RDP_PORT=3389
MYSQL_PORT=3306
REDIS_PORT=6379
SMB_PORT=445

# Dashboard
DASHBOARD_PORT=5000
DASHBOARD_HOST=0.0.0.0

# Optional: HTTP basic auth on the dashboard
DASHBOARD_USER=admin
DASHBOARD_PASS=yourpassword

# Optional: AbuseIPDB threat intelligence (free API key)
# https://www.abuseipdb.com/register
ABUSEIPDB_API_KEY=your_key_here

# Optional: weekly summary email
ALERT_SMTP_HOST=smtp.gmail.com
ALERT_SMTP_PORT=587
ALERT_SMTP_USER=you@gmail.com
ALERT_SMTP_PASS=app-password
ALERT_EMAIL_TO=you@gmail.com
# Set ALERT_SMTP_TLS=0 to disable STARTTLS (not recommended)
```

After editing:

```bash
sudo systemctl restart honeywatch
```

---

## Honeypot Services

| Service | Default Port | What it captures |
|---|---|---|
| SSH | 2222 | Username + password from every auth attempt |
| HTTP | 8080 | Credentials submitted to a fake admin login panel |
| Telnet | 2323 | Username + password |
| FTP | 2121 | Username + password (ProFTPD banner) |
| SMTP | 2525 | AUTH LOGIN credentials, MAIL FROM/RCPT TO, mail body snippet |
| RDP | 3389 | RDP cookie (`mstshash` username), X.224 negotiation blob |
| MySQL | 3306 | Login request username + password hash (MySQL 5.7 handshake) |
| Redis | 6379 | AUTH password, command attempts (INFO, KEYS, CONFIG, etc.) |
| SMB | 445 | SMB2 negotiate packet, SESSION_SETUP NTLMSSP blob |

> Ports 3389, 3306, 6379, and 445 are standard — scanners will hit them without any advertising. Use environment variables to remap any port if there are conflicts.

---

## Dashboard

| Panel | What it shows |
|---|---|
| **World map** | Each attacker plotted — amber = unknown, red = known threat |
| **Stat bar** | Total events / last hour / last 24 h / known threat IPs |
| **Service chart** | Event breakdown by honeypot type |
| **Top countries** | Where attacks originate |
| **Top usernames / passwords** | Most commonly attempted credentials |
| **Live event stream** | Real-time table with geo + threat data |

### Exporting Threat Intel

The export bar sits above the event stream. Select a service filter, optional start date, format (CSV or JSON), and row limit, then click **Export**. The file downloads directly without leaving the dashboard.

You can also hit the endpoint directly:

```bash
# All SSH events since Jan 1
curl "http://localhost:5000/api/export?format=csv&service=SSH&since=2025-01-01T00:00:00Z" \
  -o ssh_events.csv

# Full JSON dump, last 50 000 rows
curl "http://localhost:5000/api/export?format=json&limit=50000" \
  -o honeywatch_dump.json
```

---

## Weekly Email Alerts

When `ALERT_SMTP_HOST` is set, HoneyWatch emails a summary once per week containing:

- All-time, last 24 h, and last hour event counts
- Known-bad IP count
- Top 5 attacking IPs with country and threat status
- Top 5 passwords attempted
- Event breakdown by service

The email sends as both plain text and HTML. Any SMTP provider works — Gmail app passwords, SendGrid, Postmark, etc.

---

## Service Management

```bash
# Status
sudo systemctl status honeywatch

# Follow logs
sudo journalctl -u honeywatch -f

# Restart
sudo systemctl restart honeywatch

# Raw log file
tail -f /var/log/honeypot/honeypot.log

# Query the database directly
sqlite3 /var/lib/honeypot/events.db \
  "SELECT timestamp, src_ip, service, username, password, country \
   FROM events ORDER BY timestamp DESC LIMIT 20;"
```

---

## File Layout

```
honeywatch/
├── main.py            — Entrypoint, starts all services
├── services.py        — All nine honeypot implementations
├── database.py        — SQLite storage, geo/threat enrichment, email alerts
├── app.py             — Flask dashboard, SSE stream, /api/export
├── index.html         — Dashboard UI
├── requirements.txt
├── install.sh         — One-shot installer
├── update.sh          — Pull latest, upgrade deps, restart service
└── honeywatch.service — Systemd unit file
```

---

## Security Notes

- **Never** run this on a machine with sensitive data or production workloads
- The honeypot **always rejects** credentials — it never grants real access
- Dashboard port 5000 is open by default; lock it down with `DASHBOARD_USER`/`DASHBOARD_PASS` or via UFW:
  ```bash
  ufw allow from YOUR_IP to any port 5000
  ```
- RDP (3389), MySQL (3306), Redis (6379), and SMB (445) are standard ports — expect inbound connections immediately after deployment
- The service runs as a locked-down `honeypot` system user with minimal filesystem access

---

## Extending

| Want to add... | Where to look |
|---|---|
| More honeypot ports | `services.py` — copy the pattern from `FTPHoneypot` |
| HTTPS on dashboard | Put nginx in front with `proxy_pass http://localhost:5000` |
| Slack / webhook alerts | `database.py` — add to `_maybe_send_weekly_alert()` |
| Grafana integration | Point Grafana's SQLite plugin at `/var/lib/honeypot/events.db` |

---

## Legal

Deploying a honeypot is legal in most jurisdictions when you own the server. You are passively recording connection attempts made to your own system. Always review local laws before deployment. Do not use honeypot data to actively attack or harass any IP.

---

## License

MIT — do whatever you want, but please don't use it maliciously.
