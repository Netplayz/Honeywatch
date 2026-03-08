"""
Web dashboard — Flask app served on port 5000.
Real-time updates via SSE; world map via Leaflet.js.
"""

import json
import time
import queue
import threading
import logging
import os
import sys

from flask import Flask, render_template, jsonify, Response, request, abort
from pathlib import Path

# Add parent to path so we can import database
sys.path.insert(0, str(Path(__file__).parent.parent / "honeypot"))
import database as db

logger = logging.getLogger(__name__)

app = Flask(__name__)
app.secret_key = os.environ.get("DASHBOARD_SECRET", "change-me-in-production")

# ─── Optional basic auth ───────────────────────────────────────────────────────

DASHBOARD_USER = os.environ.get("DASHBOARD_USER", "")
DASHBOARD_PASS = os.environ.get("DASHBOARD_PASS", "")


def _check_auth(username, password):
    return username == DASHBOARD_USER and password == DASHBOARD_PASS


def _requires_auth(f):
    from functools import wraps
    from flask import request, Response

    @wraps(f)
    def decorated(*args, **kwargs):
        if not DASHBOARD_USER:  # Auth disabled if no user set
            return f(*args, **kwargs)
        auth = request.authorization
        if not auth or not _check_auth(auth.username, auth.password):
            return Response(
                "Authentication required.",
                401,
                {"WWW-Authenticate": 'Basic realm="Honeypot Dashboard"'},
            )
        return f(*args, **kwargs)

    return decorated


# ─── SSE event broadcaster ─────────────────────────────────────────────────────

_sse_clients: list[queue.Queue] = []
_sse_lock = threading.Lock()


def broadcast_event(event_data: dict):
    msg = f"data: {json.dumps(event_data)}\n\n"
    with _sse_lock:
        dead = []
        for q in _sse_clients:
            try:
                q.put_nowait(msg)
            except queue.Full:
                dead.append(q)
        for q in dead:
            _sse_clients.remove(q)


# Patch database to also broadcast
_orig_log_event = db.log_event


def _patched_log_event(*args, **kwargs):
    _orig_log_event(*args, **kwargs)
    # Broadcast lightweight summary
    payload = {
        "src_ip": kwargs.get("src_ip") or (args[0] if args else ""),
        "service": kwargs.get("service") or (args[2] if len(args) > 2 else ""),
        "event_type": kwargs.get("event_type") or (args[3] if len(args) > 3 else ""),
        "ts": time.time(),
    }
    broadcast_event(payload)


db.log_event = _patched_log_event


# ─── Routes ────────────────────────────────────────────────────────────────────

@app.route("/")
@_requires_auth
def index():
    return render_template("index.html")


@app.route("/api/stats")
@_requires_auth
def api_stats():
    return jsonify(db.get_stats())


@app.route("/api/events")
@_requires_auth
def api_events():
    limit = min(int(request.args.get("limit", 100)), 1000)
    return jsonify(db.get_recent_events(limit))


@app.route("/api/stream")
@_requires_auth
def api_stream():
    """Server-Sent Events endpoint for live updates."""
    q: queue.Queue = queue.Queue(maxsize=50)
    with _sse_lock:
        _sse_clients.append(q)

    def generate():
        try:
            yield "retry: 3000\n\n"
            while True:
                try:
                    msg = q.get(timeout=30)
                    yield msg
                except queue.Empty:
                    yield ": keepalive\n\n"
        except GeneratorExit:
            with _sse_lock:
                if q in _sse_clients:
                    _sse_clients.remove(q)

    return Response(generate(), mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache",
                             "X-Accel-Buffering": "no"})


if __name__ == "__main__":
    port = int(os.environ.get("DASHBOARD_PORT", 5000))
    host = os.environ.get("DASHBOARD_HOST", "0.0.0.0")
    app.run(host=host, port=port, threaded=True, debug=False)
