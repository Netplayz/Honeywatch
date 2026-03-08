"""
HoneyWatch - Web dashboard
Flask app with Server-Sent Events for real-time updates.
Served on port 5000 by default.
"""

import json
import logging
import os
import queue
import sys
import threading
from pathlib import Path
from functools import wraps

from flask import Flask, Response, jsonify, request

# Ensure the project root is on sys.path so database.py is importable
ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import database

logger = logging.getLogger(__name__)

app = Flask(__name__)
app.secret_key = os.environ.get("DASHBOARD_SECRET", "honeywatch-change-me")

# ── Optional HTTP basic auth ───────────────────────────────────────────────────

_DASHBOARD_USER = os.environ.get("DASHBOARD_USER", "")
_DASHBOARD_PASS = os.environ.get("DASHBOARD_PASS", "")


def _auth_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not _DASHBOARD_USER:
            return f(*args, **kwargs)
        auth = request.authorization
        if (
            not auth
            or auth.username != _DASHBOARD_USER
            or auth.password != _DASHBOARD_PASS
        ):
            return Response(
                "Authentication required.",
                401,
                {"WWW-Authenticate": 'Basic realm="HoneyWatch"'},
            )
        return f(*args, **kwargs)
    return wrapper


# ── Server-Sent Events broadcaster ────────────────────────────────────────────

_sse_clients: list = []
_sse_lock = threading.Lock()


def _broadcast(data: dict):
    message = "data: " + json.dumps(data) + "\n\n"
    with _sse_lock:
        stale = []
        for q in _sse_clients:
            try:
                q.put_nowait(message)
            except queue.Full:
                stale.append(q)
        for q in stale:
            _sse_clients.remove(q)


# Patch database.log_event so new events are pushed to SSE clients live
_original_log_event = database.log_event


def _patched_log_event(src_ip, src_port, service, event_type,
                        payload, username, password):
    _original_log_event(src_ip, src_port, service, event_type,
                        payload, username, password)
    _broadcast({
        "src_ip":     src_ip,
        "service":    service,
        "event_type": event_type,
    })


database.log_event = _patched_log_event


# ── Routes ─────────────────────────────────────────────────────────────────────

@app.route("/")
@_auth_required
def index():
    html_path = Path(__file__).resolve().parent / "index.html"
    return html_path.read_text(encoding="utf-8")


@app.route("/api/stats")
@_auth_required
def api_stats():
    return jsonify(database.get_stats())


@app.route("/api/events")
@_auth_required
def api_events():
    limit = min(int(request.args.get("limit", 100)), 1000)
    return jsonify(database.get_recent_events(limit))


@app.route("/api/stream")
@_auth_required
def api_stream():
    """Server-Sent Events endpoint — pushes live events to the browser."""
    client_q: queue.Queue = queue.Queue(maxsize=100)
    with _sse_lock:
        _sse_clients.append(client_q)

    def generate():
        try:
            yield "retry: 3000\n\n"
            while True:
                try:
                    yield client_q.get(timeout=25)
                except queue.Empty:
                    yield ": keepalive\n\n"
        except GeneratorExit:
            pass
        finally:
            with _sse_lock:
                if client_q in _sse_clients:
                    _sse_clients.remove(client_q)

    return Response(
        generate(),
        mimetype="text/event-stream",
        headers={
            "Cache-Control":    "no-cache",
            "X-Accel-Buffering": "no",
        },
    )


if __name__ == "__main__":
    host = os.environ.get("DASHBOARD_HOST", "0.0.0.0")
    port = int(os.environ.get("DASHBOARD_PORT", "5000"))
    app.run(host=host, port=port, threaded=True, debug=False)
