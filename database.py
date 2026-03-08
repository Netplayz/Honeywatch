"""
Database layer — SQLite with geo-enrichment and threat intel lookups.
"""

import sqlite3
import threading
import time
import ipaddress
import logging
import os
import json
import requests
from datetime import datetime, timezone
from pathlib import Path

logger = logging.getLogger(__name__)

DB_PATH = Path(os.environ.get("HONEYPOT_DB", "/var/lib/honeypot/events.db"))
DB_PATH.parent.mkdir(parents=True, exist_ok=True)

_local = threading.local()

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp   TEXT    NOT NULL,
    src_ip      TEXT    NOT NULL,
    src_port    INTEGER,
    service     TEXT    NOT NULL,
    event_type  TEXT    NOT NULL,
    username    TEXT,
    password    TEXT,
    payload     TEXT,
    country     TEXT,
    city        TEXT,
    latitude    REAL,
    longitude   REAL,
    isp         TEXT,
    is_known_bad INTEGER DEFAULT 0,
    threat_tags TEXT
);

CREATE INDEX IF NOT EXISTS idx_timestamp ON events (timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_src_ip    ON events (src_ip);
CREATE INDEX IF NOT EXISTS idx_service   ON events (service);
"""

# In-memory geo cache to avoid hammering the API
_geo_cache: dict[str, dict] = {}
_geo_cache_lock = threading.Lock()

# Known-bad IP cache (simple set, refreshed from AbuseIPDB / cached locally)
_bad_ip_cache: dict[str, dict] = {}
_bad_ip_lock = threading.Lock()


def _get_conn() -> sqlite3.Connection:
    if not hasattr(_local, "conn"):
        conn = sqlite3.connect(str(DB_PATH), check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.executescript(SCHEMA)
        conn.commit()
        _local.conn = conn
    return _local.conn


def _geo_lookup(ip: str) -> dict:
    """Free ip-api.com lookup — no key needed, 45 req/min limit."""
    with _geo_cache_lock:
        if ip in _geo_cache:
            return _geo_cache[ip]
    try:
        # Skip private / loopback
        addr = ipaddress.ip_address(ip)
        if addr.is_private or addr.is_loopback:
            return {}
        r = requests.get(
            f"http://ip-api.com/json/{ip}?fields=status,country,city,lat,lon,isp,org,as",
            timeout=4,
        )
        if r.status_code == 200:
            data = r.json()
            if data.get("status") == "success":
                result = {
                    "country": data.get("country"),
                    "city": data.get("city"),
                    "latitude": data.get("lat"),
                    "longitude": data.get("lon"),
                    "isp": data.get("org") or data.get("isp"),
                }
                with _geo_cache_lock:
                    _geo_cache[ip] = result
                return result
    except Exception as e:
        logger.debug(f"Geo lookup failed for {ip}: {e}")
    return {}


def _threat_lookup(ip: str) -> dict:
    """
    Check AbuseIPDB if ABUSEIPDB_API_KEY env var is set.
    Returns dict with is_known_bad and threat_tags.
    """
    api_key = os.environ.get("ABUSEIPDB_API_KEY", "")
    if not api_key:
        return {"is_known_bad": 0, "threat_tags": ""}

    with _bad_ip_lock:
        if ip in _bad_ip_cache:
            return _bad_ip_cache[ip]

    try:
        addr = ipaddress.ip_address(ip)
        if addr.is_private or addr.is_loopback:
            return {"is_known_bad": 0, "threat_tags": ""}

        r = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": api_key, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90},
            timeout=5,
        )
        if r.status_code == 200:
            data = r.json().get("data", {})
            score = data.get("abuseConfidenceScore", 0)
            categories = data.get("usageType", "")
            is_bad = 1 if score >= 25 else 0
            tags = f"score={score}"
            if categories:
                tags += f",type={categories}"
            result = {"is_known_bad": is_bad, "threat_tags": tags}
            with _bad_ip_lock:
                _bad_ip_cache[ip] = result
            return result
    except Exception as e:
        logger.debug(f"Threat lookup failed for {ip}: {e}")
    return {"is_known_bad": 0, "threat_tags": ""}


def log_event(
    src_ip: str,
    src_port: int,
    service: str,
    event_type: str,
    payload: str | None,
    username: str | None,
    password: str | None,
):
    """Insert a honeypot event into the database (non-blocking enrichment)."""
    ts = datetime.now(timezone.utc).isoformat()

    def _insert():
        geo = _geo_lookup(src_ip) if src_ip else {}
        threat = _threat_lookup(src_ip) if src_ip else {}
        conn = _get_conn()
        conn.execute(
            """
            INSERT INTO events
              (timestamp, src_ip, src_port, service, event_type,
               username, password, payload,
               country, city, latitude, longitude, isp,
               is_known_bad, threat_tags)
            VALUES
              (?,?,?,?,?, ?,?,?, ?,?,?,?,?, ?,?)
            """,
            (
                ts, src_ip, src_port, service, event_type,
                username, password, payload,
                geo.get("country"), geo.get("city"),
                geo.get("latitude"), geo.get("longitude"), geo.get("isp"),
                threat.get("is_known_bad", 0), threat.get("threat_tags", ""),
            ),
        )
        conn.commit()

    threading.Thread(target=_insert, daemon=True).start()


# ─── Query helpers ─────────────────────────────────────────────────────────────

def get_recent_events(limit: int = 200) -> list[dict]:
    conn = _get_conn()
    rows = conn.execute(
        "SELECT * FROM events ORDER BY timestamp DESC LIMIT ?", (limit,)
    ).fetchall()
    return [dict(r) for r in rows]


def get_stats() -> dict:
    conn = _get_conn()

    total = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    last_hour = conn.execute(
        "SELECT COUNT(*) FROM events WHERE timestamp >= datetime('now','-1 hour')"
    ).fetchone()[0]
    last_24h = conn.execute(
        "SELECT COUNT(*) FROM events WHERE timestamp >= datetime('now','-24 hours')"
    ).fetchone()[0]

    by_service = conn.execute(
        "SELECT service, COUNT(*) as cnt FROM events GROUP BY service ORDER BY cnt DESC"
    ).fetchall()

    top_ips = conn.execute(
        "SELECT src_ip, COUNT(*) as cnt, country, city, is_known_bad "
        "FROM events GROUP BY src_ip ORDER BY cnt DESC LIMIT 20"
    ).fetchall()

    top_countries = conn.execute(
        "SELECT country, COUNT(*) as cnt FROM events "
        "WHERE country IS NOT NULL GROUP BY country ORDER BY cnt DESC LIMIT 15"
    ).fetchall()

    top_passwords = conn.execute(
        "SELECT password, COUNT(*) as cnt FROM events "
        "WHERE password IS NOT NULL GROUP BY password ORDER BY cnt DESC LIMIT 15"
    ).fetchall()

    top_usernames = conn.execute(
        "SELECT username, COUNT(*) as cnt FROM events "
        "WHERE username IS NOT NULL GROUP BY username ORDER BY cnt DESC LIMIT 15"
    ).fetchall()

    known_bad_count = conn.execute(
        "SELECT COUNT(DISTINCT src_ip) FROM events WHERE is_known_bad=1"
    ).fetchone()[0]

    geo_points = conn.execute(
        "SELECT src_ip, latitude, longitude, country, city, COUNT(*) as cnt "
        "FROM events WHERE latitude IS NOT NULL "
        "GROUP BY src_ip ORDER BY cnt DESC LIMIT 500"
    ).fetchall()

    return {
        "total": total,
        "last_hour": last_hour,
        "last_24h": last_24h,
        "by_service": [dict(r) for r in by_service],
        "top_ips": [dict(r) for r in top_ips],
        "top_countries": [dict(r) for r in top_countries],
        "top_passwords": [dict(r) for r in top_passwords],
        "top_usernames": [dict(r) for r in top_usernames],
        "known_bad_count": known_bad_count,
        "geo_points": [dict(r) for r in geo_points],
    }
