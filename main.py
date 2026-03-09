#!/usr/bin/env python3
"""
HoneyWatch - Main entrypoint
Starts SSH, HTTP, Telnet, FTP, SMTP, RDP, MySQL, Redis, SMB honeypots + web dashboard
"""

import asyncio
import logging
import os
import sys
import threading
import signal
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
try:
    from services import (  # noqa: E402
        HTTPHoneypot, TelnetHoneypot, FTPHoneypot,
        SMTPHoneypot, RDPHoneypot, MySQLHoneypot, RedisHoneypot, SMBHoneypot,
        start_ssh_honeypot,
    )
except ImportError as e:
    logger.error("Failed to import services: %s", e)
    sys.exit(1)


def start_dashboard():
    """Run Flask dashboard in a background thread."""
    from app import app
    host = os.environ.get("DASHBOARD_HOST", "0.0.0.0")
    port = int(os.environ.get("DASHBOARD_PORT", "5000"))
    logger.info("Dashboard starting on %s:%s", host, port)
    # use_reloader=False is critical when running in a thread
    app.run(host=host, port=port, threaded=True, debug=False, use_reloader=False)


async def main():
    logger.info("=" * 50)
    logger.info("  HoneyWatch starting up")
    logger.info("=" * 50)

    # 1. Start thread-based honeypots
    thread_services = [
        (HTTPHoneypot, int(os.environ.get("HTTP_PORT", "8080"))),
        (TelnetHoneypot, int(os.environ.get("TELNET_PORT", "2323"))),
        (FTPHoneypot, int(os.environ.get("FTP_PORT", "2121"))),
        (SMTPHoneypot, int(os.environ.get("SMTP_PORT", "2525"))),
        (RDPHoneypot, int(os.environ.get("RDP_PORT", "3389"))),
        (MySQLHoneypot, int(os.environ.get("MYSQL_PORT", "3306"))),
        (RedisHoneypot, int(os.environ.get("REDIS_PORT", "6379"))),
        (SMBHoneypot, int(os.environ.get("SMB_PORT", "445"))),
    ]

    for cls, port in thread_services:
        logger.info("Starting %s on port %s", cls.__name__, port)
        try:
            cls(port=port).start()
        except Exception as e:
            logger.error("Failed to start %s on port %s: %s", cls.__name__, port, e)

    # 2. Start dashboard in its own thread
    threading.Thread(target=start_dashboard, daemon=True).start()

    # 3. Start async SSH honeypot
    ssh_port = int(os.environ.get("SSH_PORT", "2222"))
    await start_ssh_honeypot(port=ssh_port)

    logger.info("All services running. Press Ctrl+C to stop.")

    # 4. KEEP ALIVE 
    # This prevents the script from exiting and shutting down the service.
    # We use an Event to wait until the process is interrupted.
    stop_event = asyncio.Event()

    # Define a clean shutdown for signals (SIGTERM/SIGINT)
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, stop_event.set)

    # The script stays here until a signal is received
    await stop_event.wait()
    logger.info("Shutdown signal received. Closing HoneyWatch.")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except Exception as e:
        logger.critical("HoneyWatch crashed with a fatal error: %s", e)
        sys.exit(1)
