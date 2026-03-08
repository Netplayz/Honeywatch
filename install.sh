#!/usr/bin/env bash
# ============================================================
#  HoneyWatch — DigitalOcean Ubuntu 24.04 LTS installer
#  Usage: sudo bash install.sh
# ============================================================
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
log()  { echo -e "${GREEN}[✔]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }
err()  { echo -e "${RED}[✘]${NC} $*"; exit 1; }

[[ $EUID -eq 0 ]] || err "Run as root: sudo bash install.sh"

INSTALL_DIR="/opt/honeywatch"
ENV_FILE="/etc/honeywatch/env"
SERVICE="honeywatch"

# ── 1. System deps ──────────────────────────────────────────
log "Updating system packages…"
apt-get update -qq
apt-get install -y -qq python3 python3-pip python3-venv git ufw curl

# ── 2. Firewall ─────────────────────────────────────────────
log "Configuring UFW firewall…"
ufw --force reset
# Keep real SSH on 22 open
ufw allow 22/tcp   comment "Real SSH"
ufw allow 5000/tcp comment "HoneyWatch Dashboard"
ufw allow 2222/tcp comment "SSH Honeypot"
ufw allow 8080/tcp comment "HTTP Honeypot"
ufw allow 2323/tcp comment "Telnet Honeypot"
ufw allow 2121/tcp comment "FTP Honeypot"
ufw --force enable
log "Firewall configured."

# ── 3. Honeypot user ────────────────────────────────────────
if ! id honeypot &>/dev/null; then
  useradd -r -s /usr/sbin/nologin -d "$INSTALL_DIR" honeypot
  log "Created system user 'honeypot'."
fi

# ── 4. Install files ────────────────────────────────────────
log "Installing HoneyWatch to $INSTALL_DIR…"
mkdir -p "$INSTALL_DIR"
cp -r . "$INSTALL_DIR/"
chown -R honeypot:honeypot "$INSTALL_DIR"

# ── 5. Python venv ──────────────────────────────────────────
log "Creating Python virtual environment…"
python3 -m venv "$INSTALL_DIR/venv"
"$INSTALL_DIR/venv/bin/pip" install --quiet --upgrade pip
"$INSTALL_DIR/venv/bin/pip" install --quiet \
  asyncssh \
  flask \
  requests

log "Python dependencies installed."

# ── 6. Data dirs ────────────────────────────────────────────
mkdir -p /var/lib/honeypot /var/log/honeypot
chown -R honeypot:honeypot /var/lib/honeypot /var/log/honeypot

# ── 7. Environment config ───────────────────────────────────
mkdir -p /etc/honeywatch
if [[ ! -f "$ENV_FILE" ]]; then
cat > "$ENV_FILE" <<EOF
# HoneyWatch environment configuration
# Edit this file to customise your deployment

HONEYPOT_DB=/var/lib/honeypot/events.db
HONEYPOT_LOGS=/var/log/honeypot

# Dashboard
DASHBOARD_PORT=5000
DASHBOARD_HOST=0.0.0.0
# Uncomment and set to require HTTP basic auth on the dashboard:
# DASHBOARD_USER=admin
# DASHBOARD_PASS=changeme

# Honeypot ports (change if port conflicts)
SSH_PORT=2222
HTTP_PORT=8080
TELNET_PORT=2323
FTP_PORT=2121

# Optional: AbuseIPDB API key for threat intelligence
# Get a free key at https://www.abuseipdb.com/
# ABUSEIPDB_API_KEY=your_key_here
EOF
  log "Created env file at $ENV_FILE"
else
  warn "Env file already exists at $ENV_FILE — not overwriting."
fi
chmod 640 "$ENV_FILE"
chown root:honeypot "$ENV_FILE"

# ── 8. Systemd service ──────────────────────────────────────
log "Installing systemd service…"
cp "$INSTALL_DIR/honeywatch.service" /etc/systemd/system/
systemctl daemon-reload
systemctl enable "$SERVICE"
systemctl restart "$SERVICE"

# ── 9. Done ─────────────────────────────────────────────────
DROPLET_IP=$(curl -s --max-time 3 http://169.254.169.254/metadata/v1/interfaces/public/0/ipv4/address 2>/dev/null || hostname -I | awk '{print $1}')

echo ""
echo -e "${CYAN}╔══════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║         HoneyWatch installed successfully!       ║${NC}"
echo -e "${CYAN}╚══════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "  Dashboard:  ${GREEN}http://${DROPLET_IP}:5000${NC}"
echo ""
echo -e "  Honeypot ports:"
echo -e "    SSH     → ${YELLOW}${DROPLET_IP}:2222${NC}"
echo -e "    HTTP    → ${YELLOW}${DROPLET_IP}:8080${NC}"
echo -e "    Telnet  → ${YELLOW}${DROPLET_IP}:2323${NC}"
echo -e "    FTP     → ${YELLOW}${DROPLET_IP}:2121${NC}"
echo ""
echo -e "  Config:    ${CYAN}$ENV_FILE${NC}"
echo -e "  Logs:      ${CYAN}/var/log/honeypot/honeypot.log${NC}"
echo -e "  Database:  ${CYAN}/var/lib/honeypot/events.db${NC}"
echo ""
echo -e "  Service:   ${CYAN}systemctl status $SERVICE${NC}"
echo ""
warn "Add your AbuseIPDB key to $ENV_FILE for threat intelligence!"
echo ""
