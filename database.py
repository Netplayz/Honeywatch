"""
HoneyWatch - Database layer
SQLite storage with background geo and threat-intel enrichment.
"""

import ipaddress
import logging
import os
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path

import requests

logger = logging.getLogger(__name__)

# ── Database path ──────────────────────────────────────────────────────────────
DB_PATH = Path(os.environ.get("HONEYPOT_DB", "/var/lib/honeypot/events.db"))
DB_PATH.parent.mkdir(parents=True, exist_ok=True)

# Each thread gets its own connection (SQLite requirement)
_thread_local = threading.local()

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp    TEXT    NOT NULL,
    src_ip       TEXT    NOT NULL,
    src_port     INTEGER,
    service      TEXT    NOT NULL,
    event_type   TEXT    NOT NULL,
    username     TEXT,
    password     TEXT,
    payload      TEXT,
    country      TEXT,
    city         TEXT,
    latitude     REAL,
    longitude    REAL,
    isp          TEXT,
    is_known_bad INTEGER NOT NULL DEFAULT 0,
    threat_tags  TEXT    NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_ts     ON events (timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_ip     ON events (src_ip);
CREATE INDEX IF NOT EXISTS idx_svc    ON events (service);
"""

# Simple in-memory caches so we don't hammer external APIs
_geo_cache: dict = {}
_geo_lock = threading.Lock()

_threat_cache: dict = {}
_threat_lock = threading.Lock()


# ── Connection helper ──────────────────────────────────────────────────────────

def _get_conn() -> sqlite3.Connection:
    if not hasattr(_thread_local, "conn"):
        conn = sqlite3.connect(str(DB_PATH), check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.executescript(SCHEMA)
        conn.commit()
        _thread_local.conn = conn
    return _thread_local.conn


# ── IP helpers ─────────────────────────────────────────────────────────────────

def _is_routable(ip: str) -> bool:
    """Return True only for public, routable IPs worth looking up."""
    try:
        addr = ipaddress.ip_address(ip)
        return not (addr.is_private or addr.is_loopback or addr.is_link_local
                    or addr.is_multicast or addr.is_unspecified)
    except ValueError:
        return False


# ── Geo lookup ─────────────────────────────────────────────────────────────────

def _geo_lookup(ip: str) -> dict:
    """Look up geo info via ip-api.com (free, no key required)."""
    if not _is_routable(ip):
        return {}

    with _geo_lock:
        if ip in _geo_cache:
            return _geo_cache[ip]

    result = {}
    try:
        resp = requests.get(
            f"http://ip-api.com/json/{ip}",
            params={"fields": "status,country,city,lat,lon,isp,org"},
            timeout=4,
        )
        if resp.status_code == 200:
            data = resp.json()
            if data.get("status") == "success":
                result = {
                    "country": data.get("country"),
                    "city": data.get("city"),
                    "latitude": data.get("lat"),
                    "longitude": data.get("lon"),
                    "isp": data.get("org") or data.get("isp"),
                }
    except Exception as exc:
        logger.debug("Geo lookup failed for %s: %s", ip, exc)

    with _geo_lock:
        _geo_cache[ip] = result
    return result


# ── Threat lookup ──────────────────────────────────────────────────────────────

def _threat_lookup(ip: str) -> dict:
    """Check AbuseIPDB if ABUSEIPDB_API_KEY is set in the environment."""
    api_key = os.environ.get("ABUSEIPDB_API_KEY", "")
    if not api_key or not _is_routable(ip):
        return {"is_known_bad": 0, "threat_tags": ""}

    with _threat_lock:
        if ip in _threat_cache:
            return _threat_cache[ip]

    result = {"is_known_bad": 0, "threat_tags": ""}
    try:
        resp = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": api_key, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90},
            timeout=5,
        )
        if resp.status_code == 200:
            data = resp.json().get("data", {})
            score = data.get("abuseConfidenceScore", 0)
            usage = data.get("usageType", "")
            tags = f"score={score}"
            if usage:
                tags += f",type={usage}"
            result = {
                "is_known_bad": 1 if score >= 25 else 0,
                "threat_tags": tags,
            }
    except Exception as exc:
        logger.debug("Threat lookup failed for %s: %s", ip, exc)

    with _threat_lock:
        _threat_cache[ip] = result
    return result


# ── Public API ─────────────────────────────────────────────────────────────────

def log_event(
    src_ip: str,
    src_port: int,
    service: str,
    event_type: str,
    payload,
    username,
    password,
):
    """
    Persist a honeypot event.
    Geo and threat enrichment happens in a background thread.
    """
    timestamp = datetime.now(timezone.utc).isoformat()

    def _insert():
        geo = _geo_lookup(src_ip)
        threat = _threat_lookup(src_ip)
        conn = _get_conn()
        conn.execute(
            """
            INSERT INTO events (
                timestamp, src_ip, src_port, service, event_type,
                username, password, payload,
                country, city, latitude, longitude, isp,
                is_known_bad, threat_tags
            ) VALUES (
                ?, ?, ?, ?, ?,
                ?, ?, ?,
                ?, ?, ?, ?, ?,
                ?, ?
            )
            """,
            (
                timestamp, src_ip, src_port, service, event_type,
                username, password, payload,
                geo.get("country"), geo.get("city"),
                geo.get("latitude"), geo.get("longitude"), geo.get("isp"),
                threat["is_known_bad"], threat["threat_tags"],
            ),
        )
        conn.commit()
        _maybe_send_weekly_alert()

    threading.Thread(target=_insert, daemon=True).start()


def get_recent_events(limit: int = 200) -> list:
    conn = _get_conn()
    rows = conn.execute(
        "SELECT * FROM events ORDER BY timestamp DESC LIMIT ?", (limit,)
    ).fetchall()
    return [dict(r) for r in rows]


def get_stats() -> dict:
    conn = _get_conn()

    def scalar(sql, *params):
        return conn.execute(sql, params).fetchone()[0]

    def rows(sql, *params):
        return [dict(r) for r in conn.execute(sql, params).fetchall()]

    return {
        "total": scalar("SELECT COUNT(*) FROM events"),
        "last_hour": scalar(
            "SELECT COUNT(*) FROM events WHERE timestamp >= datetime('now','-1 hour')"
        ),
        "last_24h": scalar(
            "SELECT COUNT(*) FROM events WHERE timestamp >= datetime('now','-24 hours')"
        ),
        "known_bad_count": scalar(
            "SELECT COUNT(DISTINCT src_ip) FROM events WHERE is_known_bad = 1"
        ),
        "by_service": rows(
            "SELECT service, COUNT(*) AS cnt FROM events GROUP BY service ORDER BY cnt DESC"
        ),
        "top_ips": rows(
            "SELECT src_ip, COUNT(*) AS cnt, country, city, is_known_bad "
            "FROM events GROUP BY src_ip ORDER BY cnt DESC LIMIT 20"
        ),
        "top_countries": rows(
            "SELECT country, COUNT(*) AS cnt FROM events "
            "WHERE country IS NOT NULL GROUP BY country ORDER BY cnt DESC LIMIT 15"
        ),
        "top_passwords": rows(
            "SELECT password, COUNT(*) AS cnt FROM events "
            "WHERE password IS NOT NULL GROUP BY password ORDER BY cnt DESC LIMIT 15"
        ),
        "top_usernames": rows(
            "SELECT username, COUNT(*) AS cnt FROM events "
            "WHERE username IS NOT NULL GROUP BY username ORDER BY cnt DESC LIMIT 15"
        ),
        "geo_points": rows(
            "SELECT src_ip, latitude, longitude, country, city, COUNT(*) AS cnt "
            "FROM events WHERE latitude IS NOT NULL "
            "GROUP BY src_ip ORDER BY cnt DESC LIMIT 500"
        ),
    }


# ── Weekly email alert ─────────────────────────────────────────────────────────

import smtplib
import email.mime.text as _mime_text
import email.mime.multipart as _mime_multi
import time as _time

_last_weekly_alert: dict = {"ts": 0.0}
_WEEK_SECONDS = 7 * 24 * 3600


def _should_send_weekly() -> bool:
    """Returns True once per week; resets the internal timestamp."""
    now = _time.time()
    if now - _last_weekly_alert["ts"] >= _WEEK_SECONDS:
        _last_weekly_alert["ts"] = now
        return True
    return False


def _send_weekly_email():
    """
    Compose and send a weekly summary email using SMTP credentials from env.

    Required env vars:
        ALERT_SMTP_HOST    — SMTP server hostname (e.g. smtp.gmail.com)
        ALERT_SMTP_PORT    — SMTP port (default 587)
        ALERT_SMTP_USER    — login username / sender address
        ALERT_SMTP_PASS    — login password or app-password
        ALERT_EMAIL_TO     — recipient address (comma-separated for multiple)

    Optional:
        ALERT_SMTP_TLS     — set to "0" to disable STARTTLS (not recommended)
    """
    host = os.environ.get("ALERT_SMTP_HOST", "")
    if not host:
        return  # alerts not configured — skip silently

    port      = int(os.environ.get("ALERT_SMTP_PORT", "587"))
    user      = os.environ.get("ALERT_SMTP_USER", "")
    password  = os.environ.get("ALERT_SMTP_PASS", "")
    to_raw    = os.environ.get("ALERT_EMAIL_TO", user)
    use_tls   = os.environ.get("ALERT_SMTP_TLS", "1") != "0"
    recipients = [a.strip() for a in to_raw.split(",") if a.strip()]

    try:
        stats = get_stats()
        top_ips  = stats.get("top_ips",  [])[:5]
        top_pass = stats.get("top_passwords", [])[:5]
        top_svcs = stats.get("by_service", [])

        def _tbl(rows, *keys):
            """Quick plaintext table."""
            lines = []
            for r in rows:
                lines.append("  " + "  |  ".join(str(r.get(k, "")) for k in keys))
            return "\n".join(lines) or "  (none)"

        body_plain = f"""\
HoneyWatch — Weekly Threat Summary
Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}

━━━ Event Counts ━━━━━━━━━━━━━━━━━━━━━━━
  All-time total : {stats.get('total', 0)}
  Last 24 h      : {stats.get('last_24h', 0)}
  Last hour      : {stats.get('last_hour', 0)}
  Known-bad IPs  : {stats.get('known_bad_count', 0)}

━━━ By Service ━━━━━━━━━━━━━━━━━━━━━━━━━
{_tbl(top_svcs, 'service', 'cnt')}

━━━ Top Attacking IPs ━━━━━━━━━━━━━━━━━━
{_tbl(top_ips, 'src_ip', 'cnt', 'country', 'is_known_bad')}

━━━ Top Passwords Tried ━━━━━━━━━━━━━━━
{_tbl(top_pass, 'password', 'cnt')}

— HoneyWatch (automated alert)
"""

        html_rows_svc  = "".join(
            f"<tr><td>{r['service']}</td><td>{r['cnt']}</td></tr>"
            for r in top_svcs
        )
        html_rows_ip   = "".join(
            f"<tr><td>{r['src_ip']}</td><td>{r['cnt']}</td>"
            f"<td>{r.get('country','')}</td>"
            f"<td>{'⚠ Yes' if r.get('is_known_bad') else 'No'}</td></tr>"
            for r in top_ips
        )
        html_rows_pass = "".join(
            f"<tr><td><code>{r['password']}</code></td><td>{r['cnt']}</td></tr>"
            for r in top_pass
        )

        body_html = f"""<!DOCTYPE html>
<html><head><meta charset='utf-8'>
<style>
  body{{font-family:sans-serif;color:#1a1a2e;background:#f5f5f5;padding:20px}}
  h1{{color:#e94560}}
  table{{border-collapse:collapse;width:100%;margin-bottom:16px}}
  th,td{{border:1px solid #ddd;padding:6px 10px;text-align:left}}
  th{{background:#1a1a2e;color:#fff}}
  .badge{{background:#e94560;color:#fff;border-radius:4px;padding:2px 6px;font-size:.85em}}
  .stat{{display:inline-block;background:#fff;border-radius:8px;padding:12px 20px;
         margin:6px;box-shadow:0 1px 4px rgba(0,0,0,.1)}}
</style></head><body>
<h1>🍯 HoneyWatch — Weekly Summary</h1>
<p style='color:#666'>{datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}</p>

<div>
  <span class='stat'><strong>{stats.get('total',0)}</strong><br>All-time events</span>
  <span class='stat'><strong>{stats.get('last_24h',0)}</strong><br>Last 24 h</span>
  <span class='stat'><strong>{stats.get('last_hour',0)}</strong><br>Last hour</span>
  <span class='stat'><strong>{stats.get('known_bad_count',0)}</strong><br>Known-bad IPs</span>
</div>

<h2>Events by Service</h2>
<table><tr><th>Service</th><th>Count</th></tr>{html_rows_svc}</table>

<h2>Top Attacking IPs</h2>
<table><tr><th>IP</th><th>Count</th><th>Country</th><th>Known Bad?</th></tr>
{html_rows_ip}</table>

<h2>Top Passwords Tried</h2>
<table><tr><th>Password</th><th>Count</th></tr>{html_rows_pass}</table>

<p style='color:#aaa;font-size:.8em'>Sent by HoneyWatch automated alert system.</p>
</body></html>"""

        msg = _mime_multi.MIMEMultipart("alternative")
        msg["Subject"] = (
            f"[HoneyWatch] Weekly Report — "
            f"{stats.get('last_24h', 0)} events in last 24 h"
        )
        msg["From"] = user
        msg["To"]   = ", ".join(recipients)
        msg.attach(_mime_text.MIMEText(body_plain, "plain"))
        msg.attach(_mime_text.MIMEText(body_html,  "html"))

        with smtplib.SMTP(host, port, timeout=10) as server:
            if use_tls:
                server.starttls()
            if user and password:
                server.login(user, password)
            server.sendmail(user, recipients, msg.as_string())

        logger.info("Weekly alert email sent to %s", recipients)

    except Exception as exc:
        logger.warning("Failed to send weekly alert email: %s", exc)


def _maybe_send_weekly_alert():
    """Called from the _insert() background thread after each event is persisted."""
    if _should_send_weekly():
        threading.Thread(target=_send_weekly_email, daemon=True).start()
