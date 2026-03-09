#!/usr/bin/env python3
"""
HoneyWatch - Main entrypoint
Starts SSH, HTTP, Telnet, FTP honeypots + web dashboard
"""

import asyncio
import logging
import os
import sys
import threading
from pathlib import Path

# Always resolve imports relative to this file's directory
ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

# ── Logging ────────────────────────────────────────────────────────────────────
log_dir = Path(os.environ.get("HONEYPOT_LOGS", "/var/log/honeypot"))
log_dir.mkdir(parents=True, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-8s %(name)s - %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(str(log_dir / "honeypot.log")),
    ],
)
logger = logging.getLogger("main")

# ── Import services after path is set ─────────────────────────────────────────
from services import HTTPHoneypot, TelnetHoneypot, FTPHoneypot, start_ssh_honeypot  # noqa: E402


def start_dashboard():
    """Run Flask dashboard in a background thread."""
    from app import app
    host = os.environ.get("DASHBOARD_HOST", "0.0.0.0")
    port = int(os.environ.get("DASHBOARD_PORT", "5000"))
    logger.info("Dashboard starting on %s:%s", host, port)
    app.run(host=host, port=port, threaded=True, debug=False, use_reloader=False)


async def main():
    logger.info("=" * 50)
    logger.info("  HoneyWatch starting up")
    logger.info("=" * 50)

    # Start thread-based honeypots
    thread_services = [
        (HTTPHoneypot, int(os.environ.get("HTTP_PORT", "8080"))),
        (TelnetHoneypot, int(os.environ.get("TELNET_PORT", "2323"))),
        (FTPHoneypot, int(os.environ.get("FTP_PORT", "2121"))),
    ]
    for cls, port in thread_services:
        cls(port=port).start()

    # Start dashboard in its own thread
    threading.Thread(target=start_dashboard, daemon=True).start()

    # Start async SSH honeypot (blocks until cancelled)
    ssh_port = int(os.environ.get("SSH_PORT", "2222"))
    await start_ssh_honeypot(port=ssh_port)

    logger.info("All services running. Press Ctrl+C to stop.")
    await asyncio.Event().wait()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("Shutting down.")
