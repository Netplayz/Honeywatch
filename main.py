#!/usr/bin/env python3
"""
HoneyWatch — Main entrypoint
Starts SSH, HTTP, Telnet, FTP honeypots + web dashboard
"""

import asyncio
import logging
import os
import sys
import threading
from pathlib import Path

# ── Logging setup ──────────────────────────────────────────────────────────────
log_dir = Path(os.environ.get("HONEYPOT_LOGS", "/var/log/honeypot"))
log_dir.mkdir(parents=True, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-8s %(name)s — %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(log_dir / "honeypot.log"),
    ],
)
logger = logging.getLogger("honeypot.main")

# Ensure the project root is on sys.path so subpackages resolve correctly
_ROOT = Path(__file__).resolve().parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from honeypot.services import HTTPHoneypot, TelnetHoneypot, FTPHoneypot, start_ssh_honeypot


def start_dashboard():
    from dashboard.app import app
    port = int(os.environ.get("DASHBOARD_PORT", 5000))
    host = os.environ.get("DASHBOARD_HOST", "0.0.0.0")
    logger.info(f"Dashboard starting on {host}:{port}")
    app.run(host=host, port=port, threaded=True, debug=False, use_reloader=False)


async def main():
    logger.info("=" * 60)
    logger.info("  HoneyWatch starting up")
    logger.info("=" * 60)

    # Start thread-based honeypots
    for svc_cls, port, env in [
        (HTTPHoneypot,   8080, "HTTP_PORT"),
        (TelnetHoneypot, 2323, "TELNET_PORT"),
        (FTPHoneypot,    2121, "FTP_PORT"),
    ]:
        p = int(os.environ.get(env, port))
        svc = svc_cls(port=p)
        svc.start()

    # Start dashboard in thread
    t = threading.Thread(target=start_dashboard, daemon=True)
    t.start()

    # SSH honeypot (async)
    ssh_port = int(os.environ.get("SSH_PORT", 2222))
    await start_ssh_honeypot(port=ssh_port)

    logger.info("All services running. Ctrl+C to stop.")
    await asyncio.Event().wait()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("Shutting down.")
