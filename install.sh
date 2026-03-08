#!/usr/bin/env bash
# ============================================================
#  HoneyWatch - Installer for Ubuntu 24.04 LTS
#  https://github.com/netplayz/honeywatch
#
#  Usage: sudo bash install.sh
# ============================================================
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

log()     { echo -e "${GREEN}[✔]${NC} $*"; }
warn()    { echo -e "${YELLOW}[!]${NC} $*"; }
err()     { echo -e "${RED}[✘]${NC} $*"; exit 1; }
section() { echo -e "\n${BOLD}${CYAN}━━━ $* ━━━${NC}"; }
ask()     { echo -ne "${CYAN}[?]${NC} $1 "; }

[[ $EUID -eq 0 ]] || err "Run as root: sudo bash install.sh"

# ── Banner ────────────────────────────────────────────────────
clear
echo -e "${CYAN}"
cat << 'BANNER'
  ██╗  ██╗ ██████╗ ███╗   ██╗███████╗██╗   ██╗
  ██║  ██║██╔═══██╗████╗  ██║██╔════╝╚██╗ ██╔╝
  ███████║██║   ██║██╔██╗ ██║█████╗   ╚████╔╝
  ██╔══██║██║   ██║██║╚██╗██║██╔══╝    ╚██╔╝
  ██║  ██║╚██████╔╝██║ ╚████║███████╗   ██║
  ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝╚══════╝   ╚═╝
BANNER
echo -e "${NC}"
echo -e "  ${BOLD}HoneyWatch Installer${NC} — Ubuntu 24.04 LTS"
echo -e "  ${YELLOW}⚠  Deploy on a dedicated server only. Never on production.${NC}"
echo ""

# ── Interactive config ────────────────────────────────────────
section "Configuration"
echo ""

# Ports
ask "SSH honeypot port [2222]:"
read -r SSH_PORT;    SSH_PORT="${SSH_PORT:-2222}"

ask "HTTP honeypot port [8080]:"
read -r HTTP_PORT;   HTTP_PORT="${HTTP_PORT:-8080}"

ask "Telnet honeypot port [2323]:"
read -r TELNET_PORT; TELNET_PORT="${TELNET_PORT:-2323}"

ask "FTP honeypot port [2121]:"
read -r FTP_PORT;    FTP_PORT="${FTP_PORT:-2121}"

ask "Dashboard port [5000]:"
read -r DASH_PORT;   DASH_PORT="${DASH_PORT:-5000}"

# Dashboard auth
echo ""
ask "Password-protect the dashboard? [y/N]:"
read -r WANT_AUTH
DASH_USER="" DASH_PASS=""
if [[ "${WANT_AUTH,,}" == "y" ]]; then
  ask "  Username:"
  read -r DASH_USER
  ask "  Password:"
  read -rs DASH_PASS
  echo ""
  [[ -n "$DASH_USER" && -n "$DASH_PASS" ]] || err "Username and password cannot be empty."
  log "Dashboard auth configured."
fi

# AbuseIPDB
echo ""
ask "AbuseIPDB API key for threat intel? (Enter to skip):"
read -r ABUSE_KEY

# Confirm
echo ""
echo -e "${BOLD}Configuration summary:${NC}"
echo -e "  SSH honeypot    : ${YELLOW}:${SSH_PORT}${NC}"
echo -e "  HTTP honeypot   : ${YELLOW}:${HTTP_PORT}${NC}"
echo -e "  Telnet honeypot : ${YELLOW}:${TELNET_PORT}${NC}"
echo -e "  FTP honeypot    : ${YELLOW}:${FTP_PORT}${NC}"
echo -e "  Dashboard        : ${YELLOW}:${DASH_PORT}${NC}"
if [[ -n "$DASH_USER" ]]; then
  echo -e "  Dashboard auth  : ${GREEN}enabled (user: ${DASH_USER})${NC}"
else
  echo -e "  Dashboard auth  : disabled"
fi
if [[ -n "$ABUSE_KEY" ]]; then
  echo -e "  AbuseIPDB key   : ${GREEN}provided${NC}"
else
  echo -e "  AbuseIPDB key   : ${YELLOW}not set${NC}"
fi
echo ""
ask "Proceed with installation? [Y/n]:"
read -r CONFIRM
[[ "${CONFIRM,,}" != "n" ]] || { echo "Aborted."; exit 0; }

# ── System packages ───────────────────────────────────────────
section "System packages"
apt-get update -qq
apt-get install -y -qq python3 python3-pip python3-venv git ufw curl
log "Packages installed."

# ── Firewall ──────────────────────────────────────────────────
section "Firewall"
if ! ufw status | grep -q "Status: active"; then
  ufw --force reset
  ufw default deny incoming
  ufw default allow outgoing
fi
ufw allow 22/tcp              comment "Real SSH — do not remove"
ufw allow "${DASH_PORT}"/tcp  comment "HoneyWatch Dashboard"
ufw allow "${SSH_PORT}"/tcp   comment "SSH Honeypot"
ufw allow "${HTTP_PORT}"/tcp  comment "HTTP Honeypot"
ufw allow "${TELNET_PORT}"/tcp comment "Telnet Honeypot"
ufw allow "${FTP_PORT}"/tcp   comment "FTP Honeypot"
ufw --force enable
log "Firewall configured."

# ── System user ───────────────────────────────────────────────
section "System user"
if ! id honeywatch &>/dev/null; then
  useradd --system --no-create-home --shell /usr/sbin/nologin honeywatch
  log "Created system user 'honeywatch'."
else
  log "User 'honeywatch' already exists."
fi

# ── Clone / update repo ───────────────────────────────────────
section "Installing HoneyWatch"
INSTALL_DIR="/opt/honeywatch"
if [[ -d "$INSTALL_DIR/.git" ]]; then
  log "Existing install found — updating..."
  git -C "$INSTALL_DIR" fetch origin
  git -C "$INSTALL_DIR" reset --hard origin/main
else
  log "Cloning https://github.com/netplayz/honeywatch ..."
  git clone https://github.com/netplayz/honeywatch "$INSTALL_DIR"
fi
chown -R honeywatch:honeywatch "$INSTALL_DIR"
log "Code installed at $INSTALL_DIR."

# ── Python venv ───────────────────────────────────────────────
section "Python environment"
python3 -m venv "$INSTALL_DIR/venv"
"$INSTALL_DIR/venv/bin/pip" install --quiet --upgrade pip
"$INSTALL_DIR/venv/bin/pip" install --quiet -r "$INSTALL_DIR/requirements.txt"
chown -R honeywatch:honeywatch "$INSTALL_DIR/venv"
log "Dependencies installed."

# ── Data dirs ─────────────────────────────────────────────────
section "Data directories"
mkdir -p /var/lib/honeypot /var/log/honeypot
chown -R honeywatch:honeywatch /var/lib/honeypot /var/log/honeypot
log "Directories ready."

# ── Write env file ────────────────────────────────────────────
section "Writing config"
ENV_FILE="/etc/honeywatch/env"
mkdir -p /etc/honeywatch

# Build the file line by line (avoids heredoc quoting issues)
{
  echo "# HoneyWatch config — generated by install.sh"
  echo "# Edit then run: sudo systemctl restart honeywatch"
  echo ""
  echo "HONEYPOT_DB=/var/lib/honeypot/events.db"
  echo "HONEYPOT_LOGS=/var/log/honeypot"
  echo ""
  echo "DASHBOARD_HOST=0.0.0.0"
  echo "DASHBOARD_PORT=${DASH_PORT}"
  echo ""
  echo "SSH_PORT=${SSH_PORT}"
  echo "HTTP_PORT=${HTTP_PORT}"
  echo "TELNET_PORT=${TELNET_PORT}"
  echo "FTP_PORT=${FTP_PORT}"
  if [[ -n "$DASH_USER" ]]; then
    echo ""
    echo "DASHBOARD_USER=${DASH_USER}"
    echo "DASHBOARD_PASS=${DASH_PASS}"
  fi
  if [[ -n "$ABUSE_KEY" ]]; then
    echo ""
    echo "ABUSEIPDB_API_KEY=${ABUSE_KEY}"
  fi
} > "$ENV_FILE"

chmod 640 "$ENV_FILE"
chown root:honeywatch "$ENV_FILE"
log "Config written to $ENV_FILE"

# ── Systemd service ───────────────────────────────────────────
section "Systemd service"
cp "$INSTALL_DIR/honeywatch.service" /etc/systemd/system/
systemctl daemon-reload
systemctl enable honeywatch
systemctl restart honeywatch
log "Service installed and started."

# ── Verify ────────────────────────────────────────────────────
sleep 3
if ! systemctl is-active --quiet honeywatch; then
  echo ""
  warn "Service failed to start. Last 30 log lines:"
  journalctl -u honeywatch -n 30 --no-pager
  err "Installation failed — check the logs above."
fi

# ── Done ──────────────────────────────────────────────────────
IP=$(curl -s --max-time 3 http://169.254.169.254/metadata/v1/interfaces/public/0/ipv4/address 2>/dev/null \
  || curl -s --max-time 3 https://api.ipify.org 2>/dev/null \
  || hostname -I | awk '{print $1}')

echo ""
echo -e "${CYAN}╔════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║     HoneyWatch installed successfully! 🍯          ║${NC}"
echo -e "${CYAN}╚════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "  Dashboard  →  ${GREEN}http://${IP}:${DASH_PORT}${NC}"
echo ""
echo -e "  Honeypots:"
echo -e "    SSH    → ${YELLOW}${IP}:${SSH_PORT}${NC}"
echo -e "    HTTP   → ${YELLOW}${IP}:${HTTP_PORT}${NC}"
echo -e "    Telnet → ${YELLOW}${IP}:${TELNET_PORT}${NC}"
echo -e "    FTP    → ${YELLOW}${IP}:${FTP_PORT}${NC}"
echo ""
echo -e "  Config   → ${CYAN}/etc/honeywatch/env${NC}"
echo -e "  Logs     → ${CYAN}journalctl -u honeywatch -f${NC}"
echo ""
[[ -z "$ABUSE_KEY" ]] && warn "No AbuseIPDB key set — threat intel disabled."
echo ""
