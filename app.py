"""
HoneyWatch - Flask Web Dashboard
Exposes `app` (a Flask instance) for import by main.py.
"""

import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from flask import Flask, jsonify, render_template_string, request
import database

app = Flask(__name__)

# ── Dashboard HTML ─────────────────────────────────────────────────────────────

_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>HoneyWatch</title>
<style>
  *{box-sizing:border-box;margin:0;padding:0}
  body{background:#0d0d1a;color:#e0e0e0;font-family:'Segoe UI',sans-serif;font-size:14px}
  header{background:#12122a;padding:14px 24px;display:flex;align-items:center;gap:10px;
         border-bottom:2px solid #e94560;position:sticky;top:0;z-index:10}
  header h1{font-size:1.3rem;color:#e94560;letter-spacing:.03em}
  .sub{color:#555;font-size:.8rem;margin-left:auto}
  .grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:14px;padding:20px}
  .card{background:#1a1a2e;border-radius:8px;padding:18px 16px;border:1px solid #252545;text-align:center}
  .card .n{font-size:1.9rem;font-weight:700;color:#e94560}
  .card .l{font-size:.72rem;color:#666;text-transform:uppercase;letter-spacing:.06em;margin-top:4px}
  .panels{display:grid;grid-template-columns:1fr 1fr;gap:14px;padding:0 20px 20px}
  @media(max-width:860px){.panels{grid-template-columns:1fr}}
  .panel{background:#1a1a2e;border-radius:8px;border:1px solid #252545;overflow:hidden}
  .panel h2{padding:12px 16px;font-size:.85rem;color:#8888aa;border-bottom:1px solid #252545;
            text-transform:uppercase;letter-spacing:.06em}
  .panel.wide{grid-column:1/-1}
  table{width:100%;border-collapse:collapse}
  th{background:#12122a;color:#666;text-align:left;padding:7px 14px;font-size:.75rem;
     text-transform:uppercase;letter-spacing:.05em;font-weight:500}
  td{padding:6px 14px;border-top:1px solid #1a1a30;font-size:.82rem;white-space:nowrap;
     overflow:hidden;text-overflow:ellipsis;max-width:260px}
  tr:hover td{background:#1e1e38}
  .scroll{max-height:380px;overflow-y:auto}
  .badge{display:inline-block;padding:1px 7px;border-radius:20px;font-size:.72rem;font-weight:600}
  .red  {background:#e9456015;color:#e94560;border:1px solid #e9456030}
  .blue {background:#2196f315;color:#64b5f6;border:1px solid #2196f330}
  .green{background:#4caf5015;color:#81c784;border:1px solid #4caf5030}
  .amber{background:#ff980015;color:#ffb74d;border:1px solid #ff980030}
  .grey {background:#88888815;color:#aaa;border:1px solid #88888830}
  footer{text-align:center;padding:14px;color:#333;font-size:.72rem}
  #ld{width:8px;height:8px;border-radius:50%;background:#e94560;
      display:inline-block;animation:pulse 2s infinite}
  @keyframes pulse{0%,100%{opacity:1}50%{opacity:.3}}
</style>
</head>
<body>
<header>
  <span>&#x1F36F;</span>
  <h1>HoneyWatch</h1>
  <span id="ld"></span>
  <span class="sub" id="clock"></span>
</header>

<div class="grid">
  <div class="card"><div class="n" id="s-total">—</div><div class="l">Total Events</div></div>
  <div class="card"><div class="n" id="s-24h">—</div><div class="l">Last 24 h</div></div>
  <div class="card"><div class="n" id="s-1h">—</div><div class="l">Last Hour</div></div>
  <div class="card"><div class="n" id="s-bad">—</div><div class="l">Known-Bad IPs</div></div>
</div>

<div class="panels">
  <div class="panel wide">
    <h2>Live Event Feed</h2>
    <div class="scroll"><table>
      <thead><tr><th>Time</th><th>IP</th><th>Service</th><th>Type</th>
        <th>Username</th><th>Password</th><th>Country</th><th>Threat</th></tr></thead>
      <tbody id="feed-body"></tbody>
    </table></div>
  </div>

  <div class="panel"><h2>Events by Service</h2><div class="scroll"><table>
    <thead><tr><th>Service</th><th>Count</th></tr></thead>
    <tbody id="svc-body"></tbody>
  </table></div></div>

  <div class="panel"><h2>Top Attacking IPs</h2><div class="scroll"><table>
    <thead><tr><th>IP</th><th>Hits</th><th>Country</th><th>Bad?</th></tr></thead>
    <tbody id="ip-body"></tbody>
  </table></div></div>

  <div class="panel"><h2>Top Passwords Tried</h2><div class="scroll"><table>
    <thead><tr><th>Password</th><th>Count</th></tr></thead>
    <tbody id="pw-body"></tbody>
  </table></div></div>

  <div class="panel"><h2>Top Usernames Tried</h2><div class="scroll"><table>
    <thead><tr><th>Username</th><th>Count</th></tr></thead>
    <tbody id="un-body"></tbody>
  </table></div></div>

  <div class="panel"><h2>Top Source Countries</h2><div class="scroll"><table>
    <thead><tr><th>Country</th><th>Count</th></tr></thead>
    <tbody id="geo-body"></tbody>
  </table></div></div>
</div>

<footer>HoneyWatch &mdash; auto-refreshes every 10 s</footer>

<script>
const C={SSH:"blue",HTTP:"green",Telnet:"amber",FTP:"grey",
         SMTP:"amber",RDP:"red",MySQL:"blue",Redis:"red",SMB:"amber"};
const b=(t,c)=>`<span class="badge ${c||'grey'}">${t}</span>`;
const e=s=>s==null?"":String(s).replace(/&/g,"&amp;").replace(/</g,"&lt;");
const t=s=>{try{return new Date(s).toLocaleTimeString();}catch{return s;}};

async function refresh(){
  try{
    const [sr,er]=await Promise.all([fetch("/api/stats"),fetch("/api/events?limit=100")]);
    const s=await sr.json(), ev=await er.json();
    document.getElementById("s-total").textContent=(s.total||0).toLocaleString();
    document.getElementById("s-24h").textContent=(s.last_24h||0).toLocaleString();
    document.getElementById("s-1h").textContent=(s.last_hour||0).toLocaleString();
    document.getElementById("s-bad").textContent=(s.known_bad_count||0).toLocaleString();

    document.getElementById("feed-body").innerHTML=ev.map(r=>`<tr>
      <td>${t(r.timestamp)}</td><td>${e(r.src_ip)}</td>
      <td>${b(r.service,C[r.service])}</td><td>${e(r.event_type)}</td>
      <td>${e(r.username)}</td><td>${e(r.password)}</td>
      <td>${e(r.country||"")}</td>
      <td>${r.is_known_bad?b("⚠ Bad","red"):""}</td></tr>`).join("");

    document.getElementById("svc-body").innerHTML=(s.by_service||[]).map(r=>
      `<tr><td>${b(r.service,C[r.service])}</td><td><strong>${r.cnt}</strong></td></tr>`).join("");

    document.getElementById("ip-body").innerHTML=(s.top_ips||[]).map(r=>
      `<tr><td>${e(r.src_ip)}</td><td>${r.cnt}</td><td>${e(r.country||"")}</td>
       <td>${r.is_known_bad?b("⚠","red"):""}</td></tr>`).join("");

    document.getElementById("pw-body").innerHTML=(s.top_passwords||[]).map(r=>
      `<tr><td><code>${e(r.password)}</code></td><td>${r.cnt}</td></tr>`).join("");

    document.getElementById("un-body").innerHTML=(s.top_usernames||[]).map(r=>
      `<tr><td><code>${e(r.username)}</code></td><td>${r.cnt}</td></tr>`).join("");

    document.getElementById("geo-body").innerHTML=(s.top_countries||[]).map(r=>
      `<tr><td>${e(r.country)}</td><td>${r.cnt}</td></tr>`).join("");
  }catch(err){console.error("Refresh error:",err);}
}

setInterval(()=>document.getElementById("clock").textContent=new Date().toUTCString(),1000);
refresh();
setInterval(refresh,10000);
</script>
</body>
</html>"""


# ── Routes ─────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template_string(_HTML)
    

@app.route("/api/stats")
def api_stats():
    return jsonify(database.get_stats())


@app.route("/api/events")
def api_events():
    limit = int(request.args.get("limit", 200))
    return jsonify(database.get_recent_events(limit=limit))


if __name__ == "__main__":
    host = os.environ.get("DASHBOARD_HOST", "0.0.0.0")
    port = int(os.environ.get("DASHBOARD_PORT", "5000"))
    app.run(host=host, port=port, debug=True)
