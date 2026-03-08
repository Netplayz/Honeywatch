"""
HoneyWatch - Honeypot services
SSH, HTTP, Telnet and FTP traps that log every connection attempt.
"""

import logging
import re
import socket
import threading

import asyncssh

# database is in the same directory; main.py puts ROOT on sys.path
import database

logger = logging.getLogger(__name__)


# ── SSH honeypot ───────────────────────────────────────────────────────────────

async def start_ssh_honeypot(host: str = "0.0.0.0", port: int = 2222):
    """Start a fake SSH server that logs every auth attempt."""

    host_key = asyncssh.generate_private_key("ssh-rsa")

    class _Server(asyncssh.SSHServer):
        def connection_made(self, conn):
            self._conn = conn
            peer = conn.get_extra_info("peername") or ("unknown", 0)
            self._ip, self._port = peer[0], peer[1]
            database.log_event(
                src_ip=self._ip, src_port=self._port,
                service="SSH", event_type="connection",
                payload=None, username=None, password=None,
            )
            logger.info("SSH connection from %s:%s", self._ip, self._port)

        def begin_auth(self, username):
            self._username = username
            return True  # always require authentication

        def password_auth_requested(self):
            return True

        def validate_password(self, username, password):
            database.log_event(
                src_ip=self._ip, src_port=self._port,
                service="SSH", event_type="auth_attempt",
                payload=None, username=username, password=password,
            )
            logger.info("SSH auth from %s  user=%s  pass=%s",
                        self._ip, username, password)
            return False  # always deny

        def public_key_auth_requested(self):
            return False

    async def _noop(process):
        pass

    await asyncssh.create_server(
        _Server,
        host=host,
        port=port,
        server_host_keys=[host_key],
        process_factory=_noop,
    )
    logger.info("SSH honeypot listening on %s:%s", host, port)


# ── Base class for thread-based honeypots ──────────────────────────────────────

class _BaseHoneypot(threading.Thread):
    SERVICE = "unknown"
    DEFAULT_PORT = 9999

    def __init__(self, host: str = "0.0.0.0", port: int = None):
        super().__init__(daemon=True)
        self.host = host
        self.port = port if port is not None else self.DEFAULT_PORT

    def run(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind((self.host, self.port))
            srv.listen(50)
            logger.info("%s honeypot listening on %s:%s",
                        self.SERVICE, self.host, self.port)
            while True:
                try:
                    conn, addr = srv.accept()
                    threading.Thread(
                        target=self._handle, args=(conn, addr), daemon=True
                    ).start()
                except Exception as exc:
                    logger.error("%s accept error: %s", self.SERVICE, exc)

    def _handle(self, conn: socket.socket, addr: tuple):
        raise NotImplementedError


# ── HTTP honeypot ──────────────────────────────────────────────────────────────

class HTTPHoneypot(_BaseHoneypot):
    SERVICE = "HTTP"
    DEFAULT_PORT = 8080

    _RESPONSE = (
        b"HTTP/1.1 200 OK\r\n"
        b"Server: Apache/2.4.41 (Ubuntu)\r\n"
        b"Content-Type: text/html; charset=utf-8\r\n"
        b"Connection: close\r\n"
        b"\r\n"
        b"<!DOCTYPE html><html><head><title>Admin Login</title></head>"
        b"<body><h2>Admin Panel</h2>"
        b"<form method='POST' action='/login'>"
        b"<label>Username <input name='username'></label><br>"
        b"<label>Password <input name='password' type='password'></label><br>"
        b"<button type='submit'>Login</button>"
        b"</form></body></html>"
    )

    def _handle(self, conn: socket.socket, addr: tuple):
        ip, port = addr
        try:
            raw = conn.recv(4096).decode(errors="replace")
            # Parse request line
            first_line = raw.split("\r\n", 1)[0]
            parts = first_line.split(" ")
            method = parts[0] if len(parts) > 0 else ""
            path = parts[1] if len(parts) > 1 else "/"
            # Parse POST body for credentials
            body = raw.split("\r\n\r\n", 1)[1] if "\r\n\r\n" in raw else ""
            username = password = None
            if body:
                m = re.search(r"(?:^|&)username=([^&]*)", body)
                if m:
                    username = m.group(1)
                m = re.search(r"(?:^|&)password=([^&]*)", body)
                if m:
                    password = m.group(1)
            database.log_event(
                src_ip=ip, src_port=port,
                service="HTTP", event_type="request",
                payload=f"{method} {path}",
                username=username, password=password,
            )
            conn.sendall(self._RESPONSE)
        except Exception as exc:
            logger.debug("HTTP handler error from %s: %s", ip, exc)
        finally:
            conn.close()


# ── Telnet honeypot ────────────────────────────────────────────────────────────

class TelnetHoneypot(_BaseHoneypot):
    SERVICE = "Telnet"
    DEFAULT_PORT = 2323

    def _handle(self, conn: socket.socket, addr: tuple):
        ip, port = addr
        try:
            conn.sendall(b"Ubuntu 24.04 LTS\r\nlogin: ")
            username = conn.recv(256).decode(errors="replace").strip()
            conn.sendall(b"Password: ")
            password = conn.recv(256).decode(errors="replace").strip()
            database.log_event(
                src_ip=ip, src_port=port,
                service="Telnet", event_type="auth_attempt",
                payload=None, username=username, password=password,
            )
            conn.sendall(b"\r\nLogin incorrect\r\n")
        except Exception as exc:
            logger.debug("Telnet handler error from %s: %s", ip, exc)
        finally:
            conn.close()


# ── FTP honeypot ───────────────────────────────────────────────────────────────

class FTPHoneypot(_BaseHoneypot):
    SERVICE = "FTP"
    DEFAULT_PORT = 2121

    def _handle(self, conn: socket.socket, addr: tuple):
        ip, port = addr
        username = None
        try:
            conn.sendall(b"220 ProFTPD 1.3.6 Server ready.\r\n")
            for _ in range(20):
                line = conn.recv(256).decode(errors="replace").strip()
                if not line:
                    break
                upper = line.upper()
                if upper.startswith("USER "):
                    username = line[5:].strip()
                    conn.sendall(b"331 Password required.\r\n")
                elif upper.startswith("PASS "):
                    password = line[5:].strip()
                    database.log_event(
                        src_ip=ip, src_port=port,
                        service="FTP", event_type="auth_attempt",
                        payload=None, username=username, password=password,
                    )
                    conn.sendall(b"530 Login incorrect.\r\n")
                    break
                elif upper == "QUIT":
                    conn.sendall(b"221 Goodbye.\r\n")
                    break
                else:
                    conn.sendall(b"500 Unknown command.\r\n")
        except Exception as exc:
            logger.debug("FTP handler error from %s: %s", ip, exc)
        finally:
            conn.close()
