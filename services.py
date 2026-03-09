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


# ── SMTP honeypot ──────────────────────────────────────────────────────────────

class SMTPHoneypot(_BaseHoneypot):
    """Fake SMTP server — captures EHLO hostname, AUTH credentials, and mail data."""
    SERVICE = "SMTP"
    DEFAULT_PORT = 2525  # use 25 in prod (requires root); 587 for submission

    def _handle(self, conn: socket.socket, addr: tuple):
        ip, port = addr
        username = password = mail_from = rcpt_to = None
        payload_lines = []
        try:
            conn.sendall(b"220 mail.corp-internal.local ESMTP Postfix\r\n")
            for _ in range(50):
                line = conn.recv(1024).decode(errors="replace").strip()
                if not line:
                    break
                upper = line.upper()
                if upper.startswith("EHLO") or upper.startswith("HELO"):
                    payload_lines.append(line)
                    conn.sendall(
                        b"250-mail.corp-internal.local\r\n"
                        b"250-SIZE 10240000\r\n"
                        b"250-AUTH LOGIN PLAIN\r\n"
                        b"250 OK\r\n"
                    )
                elif upper.startswith("AUTH LOGIN"):
                    conn.sendall(b"334 VXNlcm5hbWU6\r\n")  # "Username:"
                    import base64
                    u_b64 = conn.recv(256).decode(errors="replace").strip()
                    try:
                        username = base64.b64decode(u_b64).decode(errors="replace")
                    except Exception:
                        username = u_b64
                    conn.sendall(b"334 UGFzc3dvcmQ6\r\n")  # "Password:"
                    p_b64 = conn.recv(256).decode(errors="replace").strip()
                    try:
                        password = base64.b64decode(p_b64).decode(errors="replace")
                    except Exception:
                        password = p_b64
                    database.log_event(
                        src_ip=ip, src_port=port,
                        service="SMTP", event_type="auth_attempt",
                        payload=" ".join(payload_lines) or None,
                        username=username, password=password,
                    )
                    conn.sendall(b"535 5.7.8 Authentication credentials invalid\r\n")
                    break
                elif upper.startswith("MAIL FROM"):
                    mail_from = line
                    conn.sendall(b"250 OK\r\n")
                elif upper.startswith("RCPT TO"):
                    rcpt_to = line
                    conn.sendall(b"250 OK\r\n")
                elif upper == "DATA":
                    conn.sendall(b"354 End data with <CR><LF>.<CR><LF>\r\n")
                    body = conn.recv(8192).decode(errors="replace")
                    database.log_event(
                        src_ip=ip, src_port=port,
                        service="SMTP", event_type="mail_data",
                        payload=f"{mail_from} -> {rcpt_to}\n{body[:500]}",
                        username=None, password=None,
                    )
                    conn.sendall(b"550 5.1.1 User unknown\r\n")
                    break
                elif upper == "QUIT":
                    conn.sendall(b"221 Bye\r\n")
                    break
                else:
                    conn.sendall(b"502 Command not implemented\r\n")
        except Exception as exc:
            logger.debug("SMTP handler error from %s: %s", ip, exc)
        finally:
            conn.close()


# ── RDP honeypot ───────────────────────────────────────────────────────────────

class RDPHoneypot(_BaseHoneypot):
    """
    Fake RDP banner — logs every connection and records the initial
    Client X.224 Connection Request PDU (contains the cookie / username).
    """
    SERVICE = "RDP"
    DEFAULT_PORT = 3389

    # Minimal X.224 Connection Confirm — tells the client to proceed in plain
    # (not NLA/TLS), so scanners that check banners will keep sending data.
    _CC_PDU = bytes([
        0x03, 0x00, 0x00, 0x13,          # TPKT header (length 19)
        0x0e,                             # TPDU length
        0xd0,                             # X.224 CC
        0x00, 0x00,                       # dst reference
        0x00, 0x00,                       # src reference
        0x00,                             # class / options
        # RDP Negotiation Response — PROTOCOL_RDP (0)
        0x02, 0x00, 0x08, 0x00,
        0x00, 0x00, 0x00, 0x00,
    ])

    def _handle(self, conn: socket.socket, addr: tuple):
        ip, port = addr
        try:
            data = conn.recv(1024)
            # RDP cookies look like "Cookie: mstshash=USERNAME\r\n"
            username = None
            try:
                text = data.decode(errors="replace")
                import re as _re
                m = _re.search(r"mstshash=([^\r\n]+)", text)
                if m:
                    username = m.group(1).strip()
            except Exception:
                pass
            database.log_event(
                src_ip=ip, src_port=port,
                service="RDP", event_type="connection",
                payload=data.hex()[:200],
                username=username, password=None,
            )
            conn.sendall(self._CC_PDU)
            # Grab one more packet (CredSSP / NLA client hello) if it arrives
            try:
                conn.settimeout(3)
                extra = conn.recv(2048)
                if extra:
                    database.log_event(
                        src_ip=ip, src_port=port,
                        service="RDP", event_type="negotiation",
                        payload=extra.hex()[:200],
                        username=None, password=None,
                    )
            except Exception:
                pass
        except Exception as exc:
            logger.debug("RDP handler error from %s: %s", ip, exc)
        finally:
            conn.close()


# ── MySQL honeypot ─────────────────────────────────────────────────────────────

class MySQLHoneypot(_BaseHoneypot):
    """
    Sends a real-looking MySQL 5.7 Server Greeting, then captures the
    client's Login Request (contains username + hashed password).
    """
    SERVICE = "MySQL"
    DEFAULT_PORT = 3306

    # Hand-crafted MySQL Initial Handshake Packet (protocol v10)
    _GREETING = (
        b"\x4a\x00\x00\x00"          # packet length = 74, seq = 0
        b"\x0a"                       # protocol version 10
        b"5.7.38-log\x00"            # server version string
        b"\x01\x00\x00\x00"          # connection id = 1
        b"\x3e\x4b\x7c\x21\x32\x5f\x62\x41\x00"  # auth-plugin-data part 1 (8 bytes + NUL)
        b"\xff\xf7"                   # capability flags low
        b"\x21"                       # charset utf8
        b"\x02\x00"                   # status flags: autocommit
        b"\xff\xff"                   # capability flags high
        b"\x15"                       # auth-plugin-data length = 21
        b"\x00" * 10                  # reserved
        b"\x28\x60\x43\x5e\x72\x3a\x71\x42\x4e\x35\x37\x21\x00"  # auth-data part 2
        b"mysql_native_password\x00"
    )

    _ERR = (
        b"\x31\x00\x00\x02"          # packet length, seq = 2
        b"\xff"                       # ERR packet
        b"\x15\x04"                   # error code 1045
        b"#28000"                     # SQL state
        b"Access denied for user (using password: YES)"
    )

    def _handle(self, conn: socket.socket, addr: tuple):
        ip, port = addr
        try:
            conn.sendall(self._GREETING)
            data = conn.recv(4096)
            # MySQL Login Request: skip 4-byte header + 32-byte capabilities etc.
            username = password_hash = None
            try:
                # After header (4) + capability (4) + max_packet (4) + charset (1)
                # + reserved (23) = offset 36
                payload = data[4:]
                null_idx = payload.index(b"\x00", 32)
                username = payload[32:null_idx].decode(errors="replace")
                # Next byte is hash length
                hash_len = payload[null_idx + 1]
                password_hash = payload[null_idx + 2: null_idx + 2 + hash_len].hex()
            except Exception:
                pass
            database.log_event(
                src_ip=ip, src_port=port,
                service="MySQL", event_type="auth_attempt",
                payload=None,
                username=username, password=password_hash,
            )
            conn.sendall(self._ERR)
        except Exception as exc:
            logger.debug("MySQL handler error from %s: %s", ip, exc)
        finally:
            conn.close()


# ── Redis honeypot ─────────────────────────────────────────────────────────────

class RedisHoneypot(_BaseHoneypot):
    """
    Mimics an unauthenticated Redis 7.x instance.
    Logs AUTH attempts and any commands sent before disconnect.
    """
    SERVICE = "Redis"
    DEFAULT_PORT = 6379

    def _handle(self, conn: socket.socket, addr: tuple):
        ip, port = addr
        try:
            conn.settimeout(10)
            for _ in range(30):
                data = conn.recv(1024).decode(errors="replace").strip()
                if not data:
                    break
                upper = data.upper()
                # RESP inline: AUTH <password>  or  *2\r\n$4\r\nAUTH\r\n...
                if "AUTH" in upper:
                    parts = data.split()
                    password = parts[-1] if len(parts) >= 2 else data
                    database.log_event(
                        src_ip=ip, src_port=port,
                        service="Redis", event_type="auth_attempt",
                        payload=data[:200],
                        username=None, password=password,
                    )
                    conn.sendall(b"-ERR invalid password\r\n")
                    break
                elif any(cmd in upper for cmd in ("INFO", "CONFIG", "KEYS", "DBSIZE")):
                    database.log_event(
                        src_ip=ip, src_port=port,
                        service="Redis", event_type="command",
                        payload=data[:200],
                        username=None, password=None,
                    )
                    conn.sendall(b"-NOAUTH Authentication required\r\n")
                elif upper.startswith("PING"):
                    conn.sendall(b"+PONG\r\n")
                else:
                    database.log_event(
                        src_ip=ip, src_port=port,
                        service="Redis", event_type="command",
                        payload=data[:200],
                        username=None, password=None,
                    )
                    conn.sendall(b"-NOAUTH Authentication required\r\n")
        except Exception as exc:
            logger.debug("Redis handler error from %s: %s", ip, exc)
        finally:
            conn.close()


# ── SMB honeypot ───────────────────────────────────────────────────────────────

class SMBHoneypot(_BaseHoneypot):
    """
    Responds to SMB NEGOTIATE with a minimal SMB2 Negotiate Response,
    then captures the SMB2 SESSION_SETUP request containing the NTLMSSP
    negotiate blob — includes workstation name, domain, and OS details.
    """
    SERVICE = "SMB"
    DEFAULT_PORT = 445

    # SMB2 Negotiate Response — dialect 0x0202 (SMB 2.0.2), no signing required
    _NEG_RESP = bytes.fromhex(
        "000000900000000000000000"         # NetBIOS session header (len=0x90)
        "fe534d42"                         # SMB2 magic
        "40000000" "00000000" "00000000"   # structure, credit, status, command(0=neg)
        "0100" "0000"                      # credits, flags
        "00000000" "0000000000000000"      # chain, msg-id
        "fffe0000" "01000000"              # tree, session
        # Negotiate response body (minimal)
        "41000100" "02020000"              # structure size=65, dialect 0x0202
        + "00" * 100                       # pad to size
    )

    def _handle(self, conn: socket.socket, addr: tuple):
        ip, port = addr
        try:
            data = conn.recv(4096)
            if not data:
                return
            # Log the raw negotiate — NTLMSSP info lives in the session setup packet
            database.log_event(
                src_ip=ip, src_port=port,
                service="SMB", event_type="negotiate",
                payload=data.hex()[:300],
                username=None, password=None,
            )
            try:
                conn.sendall(self._NEG_RESP)
                conn.settimeout(5)
                session_data = conn.recv(4096)
                if session_data:
                    # Extract workstation from NTLMSSP if present
                    username = None
                    try:
                        text = session_data.decode("utf-16-le", errors="ignore")
                        import re as _re
                        m = _re.search(r"([A-Za-z0-9\-_]{2,30})", text)
                        if m:
                            username = m.group(1)
                    except Exception:
                        pass
                    database.log_event(
                        src_ip=ip, src_port=port,
                        service="SMB", event_type="session_setup",
                        payload=session_data.hex()[:300],
                        username=username, password=None,
                    )
            except Exception:
                pass
        except Exception as exc:
            logger.debug("SMB handler error from %s: %s", ip, exc)
        finally:
            conn.close()
