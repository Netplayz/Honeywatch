#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# HoneyWatch — update.sh
# Pull latest code, install/upgrade dependencies, restart the service.
#
# Usage:  ./update.sh [--no-restart] [--branch <name>]
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

BLUE='\033[0;34m'; GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'; NC='\033[0m'
info()    { echo -e "${BLUE}[»]${NC} $*"; }
success() { echo -e "${GREEN}[✔]${NC} $*"; }
warn()    { echo -e "${YELLOW}[!]${NC} $*"; }
die()     { echo -e "${RED}[✘]${NC} $*" >&2; exit 1; }

# ── Defaults ──────────────────────────────────────────────────────────────────
RESTART=true
BRANCH="main"
SERVICE_NAME="honeywatch"

# ── Arg parsing ───────────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
  case "$1" in
    --no-restart) RESTART=false ;;
    --branch)     BRANCH="$2"; shift ;;
    -h|--help)
      echo "Usage: $0 [--no-restart] [--branch <name>]"
      exit 0 ;;
    *) die "Unknown option: $1" ;;
  esac
  shift
done

# ── Resolve project root (directory this script lives in) ─────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"
info "Working directory: $SCRIPT_DIR"

# ── Sanity checks ─────────────────────────────────────────────────────────────
command -v git  >/dev/null 2>&1 || die "git not found"
command -v python3 >/dev/null 2>&1 || die "python3 not found"

# ── Git pull ──────────────────────────────────────────────────────────────────
info "Fetching latest code from origin/${BRANCH}…"
git fetch origin
LOCAL=$(git rev-parse HEAD)
REMOTE=$(git rev-parse "origin/${BRANCH}")

if [[ "$LOCAL" == "$REMOTE" ]]; then
  warn "Already up-to-date ($(git rev-parse --short HEAD)). Continuing anyway."
else
  git pull --ff-only origin "$BRANCH" \
    || die "git pull failed — resolve conflicts manually then re-run."
  success "Updated $(git rev-parse --short "$LOCAL")  →  $(git rev-parse --short HEAD)"
fi

# ── Virtual-env & dependencies ────────────────────────────────────────────────
VENV_DIR="$SCRIPT_DIR/.venv"

if [[ ! -d "$VENV_DIR" ]]; then
  info "Creating virtual environment…"
  python3 -m venv "$VENV_DIR"
fi

info "Upgrading pip and installing requirements…"
"$VENV_DIR/bin/pip" install --quiet --upgrade pip
"$VENV_DIR/bin/pip" install --quiet --upgrade -r requirements.txt
success "Dependencies up-to-date."

# ── Syntax check before restart ───────────────────────────────────────────────
info "Running syntax check…"
FAIL=false
for f in main.py app.py services.py database.py; do
  if "$VENV_DIR/bin/python" -c "import ast, sys; ast.parse(open('$f').read())" 2>/dev/null; then
    echo -e "  ${GREEN}✔${NC} $f"
  else
    echo -e "  ${RED}✘${NC} $f — syntax error"
    FAIL=true
  fi
done
$FAIL && die "Syntax errors found — aborting restart. Fix the errors and re-run."
success "All files pass syntax check."

# ── Service restart ───────────────────────────────────────────────────────────
if $RESTART; then
  if systemctl is-active --quiet "$SERVICE_NAME" 2>/dev/null; then
    info "Restarting systemd service '${SERVICE_NAME}'…"
    sudo systemctl restart "$SERVICE_NAME"
    sleep 2
    if systemctl is-active --quiet "$SERVICE_NAME"; then
      success "Service '${SERVICE_NAME}' is running."
    else
      die "Service '${SERVICE_NAME}' failed to start. Check: journalctl -u ${SERVICE_NAME} -n 50"
    fi
  else
    warn "Systemd service '${SERVICE_NAME}' not found or not active."
    warn "To start manually:  $VENV_DIR/bin/python main.py"
    warn "To install service: sudo cp honeywatch.service /etc/systemd/system/ && sudo systemctl enable --now honeywatch"
  fi
else
  warn "--no-restart passed; skipping service restart."
  warn "Run 'sudo systemctl restart ${SERVICE_NAME}' when ready."
fi

# ── Done ──────────────────────────────────────────────────────────────────────
echo ""
success "HoneyWatch update complete — $(git rev-parse --short HEAD) on ${BRANCH}."
