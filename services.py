"""
Honeypot Services: SSH, HTTP, FTP, Telnet traps
Logs all connection attempts with metadata
"""

import asyncio
import socket
import threading
import logging
import json
import time
import os
import re
from datetime import datetime, timezone
from pathlib import Path

import asyncssh
from honeypot.database import log_event

logger = logging.getLogger(__name__)

# ─── SSH Honeypot ────────────────────────────────────────────────────────────

class FakeSSHServer(asyncssh.SSHServer):
    def __init__(self, client_addr):
        self._client_addr = client_addr

    def connection_made(self, conn):
        self._conn = conn
        ip, port = self._client_addr
        log_event(
            src_ip=ip,
            src_port=port,
            service="SSH",
            event_type="connection",
            payload=None,
            username=None,
            password=None
        )
        logger.info(f"SSH connection from {ip}:{port}")

    def begin_auth(self, username):
        self._username = username
        return True  # Always require auth

    def password_auth_requested(self):
        return True

    def validate_password(self, username, password):
        ip, port = self._client_addr
        log_event(
            src_ip=ip,
            src_port=port,
            service="SSH",
            event_type="auth_attempt",
            payload=None,
            username=username,
            password=password
        )
        logger.info(f"SSH auth attempt {ip} user={username} pass={password}")
        return False  # Always reject

    def public_key_auth_requested(self):
        return False


async def start_ssh_honeypot(host="0.0.0.0", port=2222):
    """Start the SSH honeypot on the given port."""
    key = asyncssh.generate_private_key("ssh-rsa")

    async def create_server():
        return FakeSSHServer((None, None))

    # We need the peer address — use a wrapper
    async def handle_client(process):
        pass

    class TrackedSSHServer(asyncssh.SSHServer):
        def connection_made(self, conn):
            self._conn = conn
            peer = conn.get_extra_info("peername")
            ip = peer[0] if peer else "unknown"
            port_r = peer[1] if peer else 0
            self._peer_ip = ip
            self._peer_port = port_r
            log_event(src_ip=ip, src_port=port_r, service="SSH",
                      event_type="connection", payload=None,
                      username=None, password=None)

        def begin_auth(self, username):
            self._username = username
            return True

        def password_auth_requested(self):
            return True

        def validate_password(self, username, password):
            log_event(src_ip=self._peer_ip, src_port=self._peer_port,
                      service="SSH", event_type="auth_attempt",
                      payload=None, username=username, password=password)
            return False

        def public_key_auth_requested(self):
            return False

    await asyncssh.create_server(
        TrackedSSHServer,
        host=host,
        port=port,
        server_host_keys=[key],
        process_factory=handle_client,
    )
    logger.info(f"SSH honeypot listening on {host}:{port}")


# ─── HTTP Honeypot ────────────────────────────────────────────────────────────

class HTTPHoneypot(threading.Thread):
    """Fake HTTP server that logs all requests."""

    BANNER = b"""\
HTTP/1.1 200 OK\r
Server: Apache/2.4.41 (Ubuntu)\r
Content-Type: text/html\r
Connection: close\r
\r
<!DOCTYPE html>
<html><head><title>Login</title></head>
<body>
<h2>Admin Panel</h2>
<form method="POST" action="/login">
  <input name="username" placeholder="Username"><br>
  <input name="password" type="password" placeholder="Password"><br>
  <button type="submit">Login</button>
</form>
</body></html>
"""

    def __init__(self, host="0.0.0.0", port=8080):
        super().__init__(daemon=True)
        self.host = host
        self.port = port

    def run(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind((self.host, self.port))
            srv.listen(50)
            logger.info(f"HTTP honeypot listening on {self.host}:{self.port}")
            while True:
                try:
                    conn, addr = srv.accept()
                    t = threading.Thread(
                        target=self._handle, args=(conn, addr), daemon=True
                    )
                    t.start()
                except Exception as e:
                    logger.error(f"HTTP accept error: {e}")

    def _handle(self, conn, addr):
        ip, port = addr
        try:
            data = conn.recv(4096).decode(errors="replace")
            # Parse method, path, headers
            lines = data.split("\r\n")
            first = lines[0] if lines else ""
            parts = first.split(" ")
            method = parts[0] if len(parts) > 0 else ""
            path = parts[1] if len(parts) > 1 else "/"

            # Extract POST body (credentials)
            body = ""
            if "\r\n\r\n" in data:
                body = data.split("\r\n\r\n", 1)[1]

            username = None
            password = None
            if body:
                m = re.search(r"username=([^&]*)", body)
                if m:
                    username = m.group(1)
                m = re.search(r"password=([^&]*)", body)
                if m:
                    password = m.group(1)

            log_event(
                src_ip=ip,
                src_port=port,
                service="HTTP",
                event_type="request",
                payload=f"{method} {path}",
                username=username,
                password=password,
            )
            conn.sendall(self.BANNER)
        except Exception as e:
            logger.error(f"HTTP handler error: {e}")
        finally:
            conn.close()


# ─── Telnet Honeypot ──────────────────────────────────────────────────────────

class TelnetHoneypot(threading.Thread):
    BANNER = b"Ubuntu 24.04 LTS\r\nlogin: "

    def __init__(self, host="0.0.0.0", port=2323):
        super().__init__(daemon=True)
        self.host = host
        self.port = port

    def run(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind((self.host, self.port))
            srv.listen(50)
            logger.info(f"Telnet honeypot listening on {self.host}:{self.port}")
            while True:
                try:
                    conn, addr = srv.accept()
                    t = threading.Thread(
                        target=self._handle, args=(conn, addr), daemon=True
                    )
                    t.start()
                except Exception as e:
                    logger.error(f"Telnet accept error: {e}")

    def _handle(self, conn, addr):
        ip, port = addr
        try:
            conn.sendall(self.BANNER)
            username = conn.recv(256).decode(errors="replace").strip()
            conn.sendall(b"Password: ")
            password = conn.recv(256).decode(errors="replace").strip()
            log_event(
                src_ip=ip,
                src_port=port,
                service="Telnet",
                event_type="auth_attempt",
                payload=None,
                username=username,
                password=password,
            )
            conn.sendall(b"\r\nLogin incorrect\r\n")
        except Exception as e:
            logger.error(f"Telnet handler error: {e}")
        finally:
            conn.close()


# ─── FTP Honeypot ─────────────────────────────────────────────────────────────

class FTPHoneypot(threading.Thread):
    def __init__(self, host="0.0.0.0", port=2121):
        super().__init__(daemon=True)
        self.host = host
        self.port = port

    def run(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind((self.host, self.port))
            srv.listen(50)
            logger.info(f"FTP honeypot listening on {self.host}:{self.port}")
            while True:
                try:
                    conn, addr = srv.accept()
                    t = threading.Thread(
                        target=self._handle, args=(conn, addr), daemon=True
                    )
                    t.start()
                except Exception as e:
                    logger.error(f"FTP accept error: {e}")

    def _handle(self, conn, addr):
        ip, port = addr
        try:
            conn.sendall(b"220 ProFTPD 1.3.6 Server ready.\r\n")
            username = None
            password = None
            for _ in range(10):
                data = conn.recv(256).decode(errors="replace").strip()
                if not data:
                    break
                if data.upper().startswith("USER "):
                    username = data[5:]
                    conn.sendall(b"331 Password required.\r\n")
                elif data.upper().startswith("PASS "):
                    password = data[5:]
                    log_event(
                        src_ip=ip,
                        src_port=port,
                        service="FTP",
                        event_type="auth_attempt",
                        payload=None,
                        username=username,
                        password=password,
                    )
                    conn.sendall(b"530 Login incorrect.\r\n")
                    break
                elif data.upper() == "QUIT":
                    break
        except Exception as e:
            logger.error(f"FTP handler error: {e}")
        finally:
            conn.close()
