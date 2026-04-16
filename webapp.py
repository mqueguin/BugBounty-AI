"""
Webapp mobile-first pour piloter BugBounty-AI depuis un téléphone.

- Auth par token (env BUGBOUNTY_WEB_TOKEN)
- Scan launcher (mode pipeline ou autopilot)
- Live status (auto-refresh)
- Findings browser
- Logs et rapports

Lance avec :
    export BUGBOUNTY_WEB_TOKEN=$(python3 -c 'import secrets; print(secrets.token_urlsafe(24))')
    export ANTHROPIC_API_KEY=sk-ant-...
    python3 webapp.py --host 0.0.0.0 --port 5000

Puis sur ton téléphone :
    http://<ip-ou-tunnel>:5000/?token=<TOKEN>
"""

from __future__ import annotations

import argparse
import html
import json
import os
import secrets
import subprocess
import threading
from datetime import datetime
from functools import wraps
from pathlib import Path

from flask import Flask, abort, jsonify, redirect, render_template_string, request, send_file, url_for

ROOT = Path(__file__).resolve().parent
STATE_DIR = ROOT / "state"
FINDINGS_DIR = ROOT / "findings"
RAPPORT_DIR = ROOT / "rapport"
RECON_DIR = ROOT / "recon"
SCOPE_FILE = ROOT / "scope.txt"

app = Flask(__name__)

TOKEN = os.getenv("BUGBOUNTY_WEB_TOKEN")
RUNNING_PROCS: dict[str, subprocess.Popen] = {}
PROC_LOCK = threading.Lock()


BASE_CSS = """
:root { --bg:#0e1116; --panel:#161b22; --border:#30363d; --fg:#e6edf3; --muted:#8b949e; --accent:#58a6ff; --green:#3fb950; --red:#f85149; --yellow:#d29922; }
* { box-sizing: border-box; }
body { margin:0; font-family: -apple-system, BlinkMacSystemFont, "SF Pro Text", "Segoe UI", Roboto, sans-serif; background: var(--bg); color: var(--fg); font-size: 16px; }
header { position: sticky; top: 0; background: var(--panel); border-bottom: 1px solid var(--border); padding: 12px 16px; display: flex; justify-content: space-between; align-items: center; z-index: 10; }
header h1 { margin: 0; font-size: 18px; color: var(--accent); }
nav a { color: var(--fg); margin-left: 12px; text-decoration: none; font-size: 14px; }
nav a:hover { color: var(--accent); }
main { padding: 16px; max-width: 720px; margin: 0 auto; }
.card { background: var(--panel); border: 1px solid var(--border); border-radius: 8px; padding: 16px; margin-bottom: 16px; }
.card h2 { margin: 0 0 12px 0; font-size: 16px; color: var(--accent); }
input, select, textarea, button { font: inherit; padding: 12px; border-radius: 6px; border: 1px solid var(--border); background: var(--bg); color: var(--fg); width: 100%; margin-bottom: 12px; }
button { background: var(--accent); color: white; border: none; font-weight: 600; cursor: pointer; padding: 14px; }
button:hover { opacity: 0.9; }
button.secondary { background: var(--panel); border: 1px solid var(--border); color: var(--fg); }
button.danger { background: var(--red); }
label { display: block; margin: 8px 0 4px; font-size: 14px; color: var(--muted); }
.row { display: flex; gap: 8px; }
.row > * { flex: 1; }
.badge { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 12px; font-weight: 600; }
.badge.running { background: var(--yellow); color: #000; }
.badge.done { background: var(--green); color: #000; }
.badge.error { background: var(--red); color: white; }
.badge.idle { background: var(--border); color: var(--muted); }
pre { background: #0d1117; border: 1px solid var(--border); padding: 12px; border-radius: 6px; overflow-x: auto; font-size: 13px; line-height: 1.4; max-height: 400px; }
.list { list-style: none; padding: 0; margin: 0; }
.list li { padding: 12px; border-bottom: 1px solid var(--border); }
.list li:last-child { border-bottom: none; }
.list a { color: var(--accent); text-decoration: none; font-weight: 600; }
.muted { color: var(--muted); font-size: 13px; }
.empty { text-align: center; padding: 32px 16px; color: var(--muted); }
.toolbar { display: flex; gap: 8px; align-items: center; margin-bottom: 12px; }
.toolbar input { margin: 0; }
"""


HEADER = """
<!doctype html>
<html lang="fr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<meta name="theme-color" content="#0e1116">
<title>{{ title }} — BugBounty-AI</title>
<style>{{ css|safe }}</style>
{% if auto_refresh %}<meta http-equiv="refresh" content="{{ auto_refresh }}">{% endif %}
</head>
<body>
<header>
  <h1>BugBounty-AI</h1>
  <nav>
    <a href="{{ url_for('index', token=token) }}">Scan</a>
    <a href="{{ url_for('findings', token=token) }}">Findings</a>
    <a href="{{ url_for('logs', token=token) }}">Logs</a>
  </nav>
</header>
<main>
"""

FOOTER = "</main></body></html>"


def require_token(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if TOKEN is None:
            abort(503, "BUGBOUNTY_WEB_TOKEN non défini côté serveur")
        provided = request.args.get("token") or request.headers.get("X-Auth-Token")
        if not provided or not secrets.compare_digest(provided, TOKEN):
            abort(401)
        return view(*args, **kwargs)
    return wrapped


def render(template_body: str, title: str, auto_refresh: int | None = None, **ctx) -> str:
    full = HEADER + template_body + FOOTER
    return render_template_string(
        full,
        title=title,
        css=BASE_CSS,
        token=TOKEN,
        auto_refresh=auto_refresh,
        **ctx,
    )


def read_state() -> dict:
    f = STATE_DIR / "current.json"
    if not f.exists():
        return {}
    try:
        return json.loads(f.read_text())
    except json.JSONDecodeError:
        return {}


def is_running() -> bool:
    with PROC_LOCK:
        for sid, proc in list(RUNNING_PROCS.items()):
            if proc.poll() is None:
                return True
            del RUNNING_PROCS[sid]
    return False


def scope_targets() -> list[str]:
    if not SCOPE_FILE.exists():
        return []
    return [
        line.strip()
        for line in SCOPE_FILE.read_text().splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]


@app.route("/")
@require_token
def index():
    state = read_state()
    running = is_running() or state.get("status") == "running"
    body = """
{% if not scope %}
<div class="card">
  <h2>⚠️ scope.txt vide</h2>
  <p class="muted">Ajoute au moins un domaine autorisé ci-dessous (séparés par espace ou retour ligne).</p>
  <form method="post" action="{{ url_for('scope_add', token=token) }}">
    <textarea name="domains" rows="3" placeholder="example.com api.example.com"></textarea>
    <button type="submit">Ajouter au scope</button>
  </form>
</div>
{% else %}
<div class="card">
  <h2>Scope actuel</h2>
  <ul class="list">{% for d in scope %}<li>{{ d }}</li>{% endfor %}</ul>
  <form method="post" action="{{ url_for('scope_add', token=token) }}" style="margin-top:12px;">
    <textarea name="domains" rows="2" placeholder="ajouter d'autres domaines..."></textarea>
    <button type="submit" class="secondary">Ajouter</button>
  </form>
</div>
{% endif %}

<div class="card">
  <h2>Lancer un scan</h2>
  {% if running %}
    <p><span class="badge running">EN COURS</span> sur <strong>{{ state.target }}</strong></p>
    <p class="muted">Itération {{ state.iterations or 0 }} · {{ state.findings|length }} findings écrits</p>
    <form method="post" action="{{ url_for('cancel_scan', token=token) }}">
      <button type="submit" class="danger">Annuler le scan</button>
    </form>
    <p style="margin-top:12px;"><a href="{{ url_for('status', token=token) }}">Voir le live status →</a></p>
  {% else %}
  <form method="post" action="{{ url_for('start_scan', token=token) }}">
    <label>Domaine cible (doit être dans scope.txt)</label>
    <input type="text" name="target" required placeholder="example.com" value="{{ scope[0] if scope else '' }}">
    <label>Mode</label>
    <select name="mode">
      <option value="autopilot">Autopilot (Claude orchestre tout)</option>
      <option value="pipeline">Pipeline classique (recon + analyse)</option>
      <option value="recon">Recon seule (pas de Claude)</option>
    </select>
    <label>Itérations max (autopilot)</label>
    <input type="number" name="max_iterations" value="40" min="5" max="100">
    <button type="submit">Démarrer</button>
  </form>
  {% endif %}
</div>

{% if state %}
<div class="card">
  <h2>Dernier scan</h2>
  <p><strong>{{ state.target }}</strong> ·
     <span class="badge {{ state.status }}">{{ state.status|upper }}</span></p>
  <p class="muted">Démarré : {{ state.started_at }}<br>
     {% if state.finished_at %}Fini : {{ state.finished_at }}<br>{% endif %}
     Itérations : {{ state.iterations or 0 }} ·
     Findings : {{ state.findings|length }} ·
     Probes XSS : {{ state.probe_count or 0 }}</p>
  {% if state.summary %}
  <p><strong>Résumé Claude :</strong></p>
  <pre>{{ state.summary }}</pre>
  {% endif %}
</div>
{% endif %}
"""
    return render(body, "Dashboard", scope=scope_targets(), state=state, running=running)


@app.route("/scope/add", methods=["POST"])
@require_token
def scope_add():
    raw = request.form.get("domains", "")
    new = [d.strip().lower() for d in raw.replace(",", " ").split() if d.strip()]
    existing = scope_targets()
    if not SCOPE_FILE.exists():
        SCOPE_FILE.write_text("# Domaines autorisés. Un par ligne.\n")
    with SCOPE_FILE.open("a") as fh:
        for d in new:
            if d not in existing:
                fh.write(d + "\n")
    return redirect(url_for("index", token=TOKEN))


@app.route("/scan/start", methods=["POST"])
@require_token
def start_scan():
    if is_running():
        abort(409, "Un scan tourne déjà")
    target = request.form.get("target", "").strip().lower()
    mode = request.form.get("mode", "autopilot")
    max_iter = int(request.form.get("max_iterations", 40))
    if target not in scope_targets():
        abort(400, f"Domaine '{target}' absent de scope.txt")

    if mode == "autopilot":
        cmd = ["python3", "-u", "autopilot.py", "--target", target, "--max-iterations", str(max_iter)]
    elif mode == "pipeline":
        cmd = ["python3", "-u", "IABounty.py", "--target", target, "--claude"]
    else:
        cmd = ["python3", "-u", "IABounty.py", "--target", target]

    log_path = STATE_DIR / "stdout.log"
    log_path.parent.mkdir(parents=True, exist_ok=True)
    log_fh = log_path.open("w")
    proc = subprocess.Popen(cmd, cwd=str(ROOT), stdout=log_fh, stderr=subprocess.STDOUT)
    with PROC_LOCK:
        RUNNING_PROCS[str(proc.pid)] = proc
    return redirect(url_for("status", token=TOKEN))


@app.route("/scan/cancel", methods=["POST"])
@require_token
def cancel_scan():
    with PROC_LOCK:
        for sid, proc in list(RUNNING_PROCS.items()):
            if proc.poll() is None:
                proc.terminate()
            del RUNNING_PROCS[sid]
    return redirect(url_for("index", token=TOKEN))


@app.route("/status")
@require_token
def status():
    state = read_state()
    log_path = STATE_DIR / "autopilot.log"
    log_tail = ""
    if log_path.exists():
        lines = log_path.read_text(errors="ignore").splitlines()[-30:]
        log_tail = "\n".join(lines)
    body = """
<div class="card">
  <h2>Live status</h2>
  {% if state %}
    <p><strong>{{ state.target }}</strong> · <span class="badge {{ state.status }}">{{ state.status|upper }}</span></p>
    <p class="muted">Itération {{ state.iterations or 0 }} · {{ state.findings|length }} findings · {{ state.probe_count or 0 }} probes</p>
  {% else %}
    <p class="empty">Aucun scan actif. <a href="{{ url_for('index', token=token) }}">Retour</a></p>
  {% endif %}
</div>
<div class="card">
  <h2>Logs récents</h2>
  <pre>{{ log_tail or 'Pas de logs encore.' }}</pre>
</div>
"""
    refresh = 5 if state.get("status") == "running" else None
    return render(body, "Status", auto_refresh=refresh, state=state, log_tail=log_tail)


@app.route("/findings")
@require_token
def findings():
    confirmed = sorted(FINDINGS_DIR.glob("*.md")) if FINDINGS_DIR.exists() else []
    candidates = sorted((FINDINGS_DIR / "_candidates").glob("*.md")) if (FINDINGS_DIR / "_candidates").exists() else []
    body = """
<div class="card">
  <h2>Confirmed ({{ confirmed|length }})</h2>
  {% if confirmed %}
  <ul class="list">
    {% for f in confirmed %}
    <li><a href="{{ url_for('finding_view', slug=f.stem, token=token) }}">{{ f.stem }}</a></li>
    {% endfor %}
  </ul>
  {% else %}
  <p class="empty">Aucun finding confirmé pour l'instant.</p>
  {% endif %}
</div>

<div class="card">
  <h2>Candidates ({{ candidates|length }})</h2>
  {% if candidates %}
  <ul class="list">
    {% for f in candidates %}
    <li><a href="{{ url_for('finding_view', slug=f.stem, token=token, candidate=1) }}">{{ f.stem }}</a></li>
    {% endfor %}
  </ul>
  {% else %}
  <p class="empty">Aucun candidat.</p>
  {% endif %}
</div>
"""
    return render(body, "Findings", confirmed=confirmed, candidates=candidates)


@app.route("/findings/<slug>")
@require_token
def finding_view(slug: str):
    is_candidate = request.args.get("candidate") == "1"
    folder = FINDINGS_DIR / "_candidates" if is_candidate else FINDINGS_DIR
    target = folder / f"{slug}.md"
    if not target.exists():
        abort(404)
    content = target.read_text(errors="ignore")
    body = """
<div class="card">
  <h2>{{ slug }}{% if is_candidate %} (candidate){% endif %}</h2>
  <pre>{{ content }}</pre>
  <a href="{{ url_for('finding_raw', slug=slug, token=token, candidate=1 if is_candidate else 0) }}">
    <button class="secondary">Télécharger .md</button>
  </a>
</div>
"""
    return render(body, slug, slug=slug, content=content, is_candidate=is_candidate)


@app.route("/findings/<slug>.raw")
@require_token
def finding_raw(slug: str):
    is_candidate = request.args.get("candidate") == "1"
    folder = FINDINGS_DIR / "_candidates" if is_candidate else FINDINGS_DIR
    target = folder / f"{slug}.md"
    if not target.exists():
        abort(404)
    return send_file(str(target), as_attachment=True)


@app.route("/logs")
@require_token
def logs():
    log_path = STATE_DIR / "autopilot.log"
    stdout_path = STATE_DIR / "stdout.log"
    auto_log = log_path.read_text(errors="ignore")[-8000:] if log_path.exists() else "(vide)"
    stdout_log = stdout_path.read_text(errors="ignore")[-8000:] if stdout_path.exists() else "(vide)"
    body = """
<div class="card"><h2>autopilot.log</h2><pre>{{ auto_log }}</pre></div>
<div class="card"><h2>stdout.log</h2><pre>{{ stdout_log }}</pre></div>
"""
    return render(body, "Logs", auto_log=auto_log, stdout_log=stdout_log)


@app.route("/api/state")
@require_token
def api_state():
    return jsonify({"state": read_state(), "running": is_running()})


@app.errorhandler(401)
def unauth(_):
    return ("Token invalide. Ajoute ?token=<TOKEN> à l'URL.", 401)


@app.errorhandler(503)
def cfg_missing(e):
    return (f"503 — {e.description}", 503)


def main():
    # Défaut intelligent : $PORT si défini (Railway/Render/Fly/Heroku), sinon 5000
    default_port = int(os.getenv("PORT", "5000"))
    default_host = os.getenv("HOST", "127.0.0.1")
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default=default_host)
    parser.add_argument("--port", type=int, default=default_port)
    parser.add_argument("--debug", action="store_true")
    args = parser.parse_args()

    global TOKEN
    if TOKEN is None:
        TOKEN = secrets.token_urlsafe(24)
        print(f"[!] BUGBOUNTY_WEB_TOKEN non défini. Token généré : {TOKEN}")
        print(f"[!] ⚠  Configure cette variable d'environnement pour la persister entre redémarrages.")
        print(f"[!] URL locale : http://{args.host}:{args.port}/?token={TOKEN}")
    else:
        print(f"[+] Auth OK. URL : http://{args.host}:{args.port}/?token=<TOKEN>")

    app.run(host=args.host, port=args.port, debug=args.debug)


if __name__ == "__main__":
    main()
