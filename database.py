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
