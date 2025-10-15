import os
from flask import Flask, jsonify, request, send_from_directory, abort, redirect, session
import socket
import re
import hashlib
import json

# Import the database helpers in a way that works when running from the repo root
# (python -m backend.app) or when running directly from backend/ (python app.py).
try:
    # Preferred: running as a package from repo root
    from backend.database import get_latest_leaks, leak_to_dict, insert_leak_with_dedupe
    from backend.crawler.pastebin import fetch_and_store as pastebin_fetch
    from backend.crawler.tor_crawler import fetch_and_store as tor_fetch
    import backend.crawler.tor_crawler as tor_module
    from backend.crawler.i2p_crawler import fetch_and_store as i2p_fetch
    import backend.crawler.i2p_crawler as i2p_module
    from backend.assets_db import list_assets, upsert_asset, delete_asset
    from backend.severity import compute_severity_from_entities
    from backend.analytics import get_critical_leaks, risk_summary
except ImportError:
    # Fallback: running directly in the backend/ directory
    from database import get_latest_leaks, leak_to_dict, insert_leak_with_dedupe
    from crawler.pastebin import fetch_and_store as pastebin_fetch
    from crawler.tor_crawler import fetch_and_store as tor_fetch
    import crawler.tor_crawler as tor_module
    from crawler.i2p_crawler import fetch_and_store as i2p_fetch
    import crawler.i2p_crawler as i2p_module
    from assets_db import list_assets, upsert_asset, delete_asset
    from severity import compute_severity_from_entities
    from analytics import get_critical_leaks, risk_summary

# Project root (one level up from backend/) where the frontend files live
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))

# Create Flask app. We won't use the built-in `static_folder` so we can selectively
# serve frontend files and keep API routes under /api.
app = Flask(__name__)

# Aliases used across routing logic
ALIASES = {
    'homepage': 'homepage/homepage.html',
    'dashboard': 'dashboardpage/dashboard.html',
    'resources': 'resourcespage/resources.html',
    'account': 'accountpage/account.html',
    'alerts': 'dashboardpage/alerts.html',
    'risk_analysis': 'dashboardpage/risk_analysis.html',
    'reports': 'dashboardpage/reports.html',
    'leaks': 'dashboardpage/leaks.html',
    'login': 'auth/login.html',
    'register': 'auth/register.html',
}
# Secret key for session management
app.secret_key = 'supersecretkey'  # Change this in production

PUBLIC_ROUTES = [
    '/login', '/register', '/auth/login.html', '/auth/register.html', '/static/', '/favicon.ico', '/dashboard/base.css'
]

@app.before_request
def require_login():
    path = request.path
    # Allow public routes without login
    if path in PUBLIC_ROUTES or any(path.startswith(r) for r in PUBLIC_ROUTES):
        return None
    # Allow /auth/login.html and /auth/register.html without login
    if path in ['/auth/login.html', '/auth/register.html']:
        return None
    if not session.get('logged_in'):
        return redirect('/auth/login.html')
    return None


@app.before_request
def redirect_html_to_clean():
    # If request is for an HTML file directly, redirect to the friendly directory URL
    path = request.path or ''
    if path.endswith('.html'):
        # strip leading slash
        trimmed = path.lstrip('/')
        parts = trimmed.split('/')
        if len(parts) == 2:
            folder, file = parts
            # case: /homepage/homepage.html -> /homepage/
            if file == f"{folder}.html":
                return redirect(f'/{folder}/')
            # case: /dashboardpage/dashboard.html -> /dashboard/
            if folder.endswith('page') and file.endswith('.html'):
                base = folder[:-4]
                return redirect(f'/{base}/')
        # fallback: try to find a matching alias by filename
        fname = os.path.basename(trimmed)
        for key, target in ALIASES.items():
            if target.endswith(fname):
                return redirect(f'/{key}/')


# Root endpoint -- redirect to the homepage HTML so visiting / loads the styled page
@app.route("/")
def home():
    if not session.get('logged_in'):
        return send_from_directory(os.path.join(PROJECT_ROOT, 'auth'), 'register.html')
    return redirect('/dashboard/')


# Small API status endpoint (keeps API root JSON-friendly)
@app.route('/api', methods=['GET'])
def api_status():
    return jsonify({"message": "Dark Web Monitoring API running"})


# Explicit friendly routes for main pages (non-greedy)
@app.route('/homepage')
def homepage_noext():
    return redirect('/homepage/')


@app.route('/homepage/')
def homepage():
    return send_from_directory(os.path.join(PROJECT_ROOT, 'homepage'), 'homepage.html')


@app.route('/dashboard')
def dashboard_noext():
    return redirect('/dashboard/')


@app.route('/dashboard/')
def dashboard():
    return send_from_directory(os.path.join(PROJECT_ROOT, 'dashboardpage'), 'dashboard.html')


@app.route('/resources')
def resources_noext_route():
    return redirect('/resources/')


@app.route('/resources/')
def resources_route():
    return send_from_directory(os.path.join(PROJECT_ROOT, 'resourcespage'), 'resources.html')


@app.route('/account')
def account_noext():
    return redirect('/account/')


@app.route('/account/')
def account():
    return send_from_directory(os.path.join(PROJECT_ROOT, 'accountpage'), 'account.html')

# Alerts page routes
@app.route('/alerts')
def alerts_noext():
    return redirect('/alerts/')


@app.route('/alerts/')
def alerts():
    return send_from_directory(os.path.join(PROJECT_ROOT, 'dashboardpage'), 'alerts.html')


# Risk Analysis page routes
@app.route('/risk_analysis')
def risk_analysis_noext():
    return redirect('/risk_analysis/')


@app.route('/risk_analysis/')
def risk_analysis():
    return send_from_directory(os.path.join(PROJECT_ROOT, 'dashboardpage'), 'risk_analysis.html')


# Reports page routes
@app.route('/reports')
def reports_noext():
    return redirect('/reports/')


@app.route('/reports/')
def reports():
    return send_from_directory(os.path.join(PROJECT_ROOT, 'dashboardpage'), 'reports.html')


# Handle directory-style requests with trailing slash, serving the page file inside the folder
@app.route('/<page>/')
def serve_page_dir(page: str):
    aliases = {
        'homepage': 'homepage/homepage.html',
        'dashboard': 'dashboardpage/dashboard.html',
        'resources': 'resourcespage/resources.html',
        'account': 'accountpage/account.html',
        'alerts': 'dashboardpage/alerts.html',
        'risk_analysis': 'dashboardpage/risk_analysis.html',
        'reports': 'dashboardpage/reports.html',
        'leaks': 'dashboardpage/leaks.html',
        'index': 'homepage/homepage.html',  
        'login': 'auth/login.html',
        'register': 'auth/register.html',
    }

    if page in aliases:
        target = aliases[page]
        rel_dir = os.path.dirname(target)
        file_name = os.path.basename(target)
        return send_from_directory(os.path.join(PROJECT_ROOT, rel_dir or '.'), file_name)

    # Fallback: try folder/index.html or folder/<page>.html
    idx_path = os.path.join(PROJECT_ROOT, page, 'index.html')
    if os.path.isfile(idx_path):
        return send_from_directory(os.path.join(PROJECT_ROOT, page), 'index.html')

    page_html = os.path.join(PROJECT_ROOT, page, f'{page}.html')
    if os.path.isfile(page_html):
        return send_from_directory(os.path.join(PROJECT_ROOT, page), f'{page}.html')

    abort(404)

# Dashboard leaks endpoint
@app.route("/api/leaks", methods=["GET"])
def api_leaks():
    limit = request.args.get("limit", default=10, type=int)
    leaks = get_latest_leaks(limit)
    return jsonify([leak_to_dict(leak) for leak in leaks])

# Alerts (critical leaks only)
@app.route("/api/alerts", methods=["GET"])
def api_alerts():
    limit = request.args.get('limit', default=50, type=int)
    crits = get_critical_leaks(limit=limit)
    return jsonify(crits)

# Risk summary aggregation
@app.route("/api/risk/summary", methods=["GET"])
def api_risk_summary():
    return jsonify(risk_summary())

# Ingest endpoint to support crawler/mock posting leaks now; minimal validation and dedupe
@app.route("/api/leaks", methods=["POST"])
def api_leaks_ingest():
    payload = request.get_json(silent=True) or {}
    source = payload.get('source') or 'unknown'
    url = payload.get('url')
    title = payload.get('title')
    content = payload.get('content') or payload.get('data')
    content_hash = None

    # Accept hash in top-level or inside normalized
    if 'content_hash' in payload:
        content_hash = payload.get('content_hash')
    elif isinstance(payload.get('normalized'), dict):
        content_hash = payload['normalized'].get('content_hash')

    severity = payload.get('severity')
    entities = payload.get('entities') or (payload.get('normalized') or {}).get('entities')

    if not (content or (payload.get('attachments'))):
        return jsonify({"code": "validation_error", "message": "content or attachments required"}), 400

    # Auto-compute severity if not provided and entities exist
    if (not severity) and entities:
        try:
            severity = compute_severity_from_entities(entities)
        except (TypeError, ValueError, KeyError):
            # keep default if any issue computing
            pass

    # Extract fields from payload
    passwords = payload.get('passwords')
    ssn = payload.get('ssn')
    names = payload.get('names')
    phone_numbers = payload.get('phone_numbers')
    physical_addresses = payload.get('physical_addresses')

    leak_id, is_dup = insert_leak_with_dedupe(
        source=source,
        url=url,
        title=title,
        content=content,
        content_hash=content_hash,
        severity=severity,
        entities=entities,
        passwords=json.dumps(passwords) if passwords else None,
        ssn=ssn,
        names=json.dumps(names) if names else None,
        phone_numbers=json.dumps(phone_numbers) if phone_numbers else None,
        physical_addresses=json.dumps(physical_addresses) if physical_addresses else None,
    )

    status = "duplicate" if is_dup else "accepted"
    resp = {"status": status, "id": leak_id}
    return jsonify(resp), 202


# Trigger Pastebin crawler from the web app
@app.route("/api/crawlers/pastebin/run", methods=["POST"])
def api_run_pastebin():
    # Accept optional limit in JSON body
    limit = 10
    if request.is_json:
        body = request.get_json(silent=True) or {}
        try:
            limit = int(body.get('limit', limit))
        except (TypeError, ValueError):
            pass
    try:
        # Our fetch may or may not accept limit; handle both signatures
        try:
            inserted = pastebin_fetch(limit=limit)
        except TypeError:
            inserted = pastebin_fetch() or 0
    except RuntimeError as e:
        return jsonify({"status": "error", "message": str(e)}), 500
    return jsonify({"status": "ok", "inserted": inserted}), 200

# Trigger Tor crawler from the web app
@app.route("/api/crawlers/tor/run", methods=["POST"])
def api_run_tor():
    # Only allow a known-safe .onion endpoint; no arbitrary URL from client
    SAFE_ONION = "http://duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion"
    body = request.get_json(silent=True) or {}
    retries = int(body.get('retries', 3) or 3)
    delay = int(body.get('delay', 10) or 10)
    # Default to Tor Browser's 9150 unless overridden
    port = body.get('port') or 9150
    try:
        tor_module.TOR_PORT = str(port)
        tor_module.TOR_PROXY = {
            "http": f"socks5h://127.0.0.1:{tor_module.TOR_PORT}",
            "https": f"socks5h://127.0.0.1:{tor_module.TOR_PORT}",
        }
        ok = tor_fetch(SAFE_ONION, retries=retries, delay=delay)
    except (TypeError, ValueError, RuntimeError) as e:
        return jsonify({"status": "error", "message": str(e)}), 500
    return jsonify({"status": "ok", "fetched": bool(ok), "url": SAFE_ONION, "port": int(port)}), 200

# ---- Proxy health checks ----
def _tcp_check(host: str, port: int, timeout: float = 1.0) -> bool:
    try:
        with socket.create_connection((host, int(port)), timeout=timeout):
            return True
    except OSError:
        return False

@app.route("/api/proxy/tor/health", methods=["GET"])
def api_tor_health():
    # Default 9150; allow override via query
    port = int(request.args.get('port', 9150))
    ok = _tcp_check('127.0.0.1', port)
    return jsonify({"ok": ok, "port": port}), (200 if ok else 503)

@app.route("/api/proxy/i2p/health", methods=["GET"])
def api_i2p_health():
    # Default 4444; allow override via query
    port = int(request.args.get('port', 4444))
    ok = _tcp_check('127.0.0.1', port)
    return jsonify({"ok": ok, "port": port}), (200 if ok else 503)

# Trigger I2P crawler from the web app
@app.route("/api/crawlers/i2p/run", methods=["POST"])
def api_run_i2p():
    if not request.is_json:
        return jsonify({"status": "error", "message": "JSON body required"}), 400
    body = request.get_json(silent=True) or {}
    url = (body.get('url') or '').strip()
    retries = int(body.get('retries', 3) or 3)
    delay = int(body.get('delay', 10) or 10)
    mock_flag = bool(body.get('mock'))
    # Optional override of I2P HTTP proxy port for this process
    port = int(body.get('port', 4444) or 4444)

    # If mock explicitly requested or proxy not reachable, insert a mock leak
    def insert_mock_leak():
        sample_title = "I2P mock leak"
        sample_content = (
            "This is a mock I2P leak inserted because no I2P router proxy was available. "
            "Contact: security@example.com. Domain: example.com. IP: 203.0.113.5. "
            "BTC: bc1qexampleexampleexampleexamplex0j2z."
        )
        # Simple entity extraction
        email_re = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
        domain_re = re.compile(r"\b(?:(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)\.)+[a-z]{2,}\b", re.I)
        ipv4_re = re.compile(r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(?:\.|$)){4}\b")
        btc_re = re.compile(r"\b(?:bc1|[13])[a-zA-HJ-NP-Z0-9]{25,39}\b")
        emails = sorted(set(email_re.findall(sample_content)))
        domains = sorted(set(domain_re.findall(sample_content)))
        ips = sorted(set(ipv4_re.findall(sample_content)))
        btcs = sorted(set(btc_re.findall(sample_content)))
        entities = {
            "emails": emails,
            "domains": [d.lower() for d in domains],
            "ips": ips,
            "btc_wallets": btcs,
        }
        try:
            sev = compute_severity_from_entities(entities)
        except (TypeError, ValueError, KeyError):
            sev = None
        content_hash = "sha256:" + hashlib.sha256(sample_content.encode("utf-8", errors="ignore")).hexdigest()
        leak_id, is_dup = insert_leak_with_dedupe(
            source="I2P (mock)",
            url=url or "mock://i2p",
            title=sample_title,
            content=sample_content,
            content_hash=content_hash,
            severity=sev,
            entities=entities,
        )
        return {"status": "ok", "fetched": True, "mocked": True, "id": leak_id, "duplicate": is_dup}

    # Mock if asked
    if mock_flag:
        return jsonify(insert_mock_leak()), 200

    # Check proxy
    if not _tcp_check('127.0.0.1', port):
        # Fallback to mock when proxy is unavailable
        return jsonify(insert_mock_leak()), 200

    # Normal I2P fetch path
    try:
        i2p_module.I2P_PROXY = {
            "http": f"http://127.0.0.1:{port}",
            "https": f"http://127.0.0.1:{port}",
        }
        if not url:
            return jsonify({"status": "error", "message": "url is required when proxy is available"}), 400
        ok = i2p_fetch(url, retries=retries, delay=delay)
    except (TypeError, ValueError, RuntimeError) as e:
        return jsonify({"status": "error", "message": str(e)}), 500
    return jsonify({"status": "ok", "fetched": bool(ok), "mocked": False}), 200

# ---- Assets (watchlist) API ----
@app.route("/api/assets", methods=["GET"])  # list all assets
def api_assets_list():
    return jsonify(list_assets())


@app.route("/api/assets", methods=["POST"])  # add an asset
def api_assets_add():
    body = request.get_json(silent=True) or {}
    t = (body.get('type') or '').strip().lower()
    v = (body.get('value') or '').strip().lower()
    if not t or not v:
        return jsonify({"code": "validation_error", "message": "type and value required"}), 400
    try:
        asset_id = upsert_asset(t, v)
    except ValueError as e:
        return jsonify({"code": "validation_error", "message": str(e)}), 400
    return jsonify({"status": "ok", "id": asset_id}), 201


@app.route("/api/assets/<int:asset_id>", methods=["DELETE"])  # delete an asset
def api_assets_delete(asset_id: int):
    ok = delete_asset(asset_id)
    if not ok:
        return jsonify({"code": "not_found", "message": "asset not found"}), 404
    return jsonify({"status": "ok"}), 200


    # moved to backend/severity.py

# Resources endpoint (static for now)
@app.route("/api/resources", methods=["GET"])
def api_resources():
    resources = [
        {"title": "How to Stay Safe Online", "url": "https://www.cyberaware.gov"},
        {"title": "Dark Web Monitoring Guide", "url": "https://www.darkwebguide.com"},
        {"title": "Report a Leak", "url": "https://www.ic3.gov"}
    ]
    return jsonify(resources)

# Account endpoint (mock user profile)
@app.route("/api/account", methods=["GET", "POST"])
def api_account():
    # Mock user profile
    user_profile = {
        "username": "testuser",
        "email": "testuser@example.com",
        "joined": "2025-01-01",
        "settings": {"notifications": True, "theme": "light"}
    }
    if request.method == "POST":
        data = request.json or {}
        # Update mock profile (in real app, update DB)
        user_profile.update(data)
        return jsonify({"status": "updated", "profile": user_profile})
    return jsonify(user_profile)


# v1/events endpoint for crawler ingestion (for compatibility with crawler utils)
@app.route("/v1/events", methods=["POST"])
def v1_events_ingest():
    return api_leaks_ingest()


# Config route to backend
@app.route("/v1/config/org/<int:org_id>")
def get_config(org_id):
    # TODO: Replace with real org-specific logic later
    return jsonify({
        "api": {
            "events_url": "http://127.0.0.1:5000/v1/events"
        },
        "watchlist": {
            "domains": ["example.com", "test.org"],
            "emails": ["admin@example.com"],
            "keywords": ["password", "login", "shadow"]
        },
        "sources": {
            "pastebin": {
                "limit": 5,
                "rate_limit_ms": 500,
                "timeout_sec": 15
            }
        }
    })

# Serve frontend static files (HTML/CSS/JS/images) from project root.
# Only handle paths that map to existing files under the project root and do not
# conflict with API routes (which are all under /api/).
@app.route('/<path:filename>')
def serve_static(filename: str):
    # Avoid serving api routes through this handler
    if filename.startswith('api/'):
        abort(404)

    # Remap requests like 'dashboard/dashboard.css' to 'dashboardpage/dashboard.css'
    # so assets referenced relatively from the served HTML are found.
    alias_dirs = {
        'dashboard': 'dashboardpage',
        'resources': 'resourcespage',
        'account': 'accountpage',
        'homepage': 'homepage'
    }
    parts = filename.split('/', 1)
    if parts and parts[0] in alias_dirs:
        if len(parts) == 1:
            remapped = f"{alias_dirs[parts[0]]}/{parts[0]}"
        else:
            remapped = f"{alias_dirs[parts[0]]}/{parts[1]}"
        remap_path = os.path.join(PROJECT_ROOT, remapped)
        if os.path.isfile(remap_path):
            rel_dir = os.path.dirname(remapped)
            file_name = os.path.basename(remapped)
            return send_from_directory(os.path.join(PROJECT_ROOT, rel_dir or '.'), file_name)

    # Build absolute path and ensure it exists inside project root
    target_path = os.path.join(PROJECT_ROOT, filename)
    if not os.path.isfile(target_path):
        # If requesting a folder like 'homepage/' without a filename, try index
        if filename.endswith('/'):
            index_path = os.path.join(target_path, 'index.html')
            if os.path.isfile(index_path):
                rel_dir = os.path.relpath(os.path.dirname(index_path), PROJECT_ROOT)
                return send_from_directory(os.path.join(PROJECT_ROOT, rel_dir), 'index.html')
        abort(404)

    # Send file relative to project root
    rel_dir = os.path.dirname(filename)
    file_name = os.path.basename(filename)
    return send_from_directory(os.path.join(PROJECT_ROOT, rel_dir or '.'), file_name)


@app.route('/<folder>/<file>')
def redirect_pagefile(folder: str, file: str):
    # Redirect URLs like '/dashboardpage/dashboard.html' to '/dashboard/'
    # Only handle patterns where folder ends with 'page' and file ends with .html
    if folder.endswith('page') and file.endswith('.html'):
        base = folder[:-4]  # 'dashboardpage' -> 'dashboard'
        return redirect(f'/{base}/')
    # Otherwise attempt to serve as static
    return serve_static(f"{folder}/{file}")


# Login route
@app.route("/login", methods=["POST"])
def login():
    data = request.form or request.json or {}
    username = data.get("user_login")
    password = data.get("user_password")
    if username and password:
        session['logged_in'] = True
        session['username'] = username
        return redirect('/dashboard/')
    return redirect('/auth/login.html')

# Logout route
@app.route("/logout", methods=["GET", "POST"])
def logout():
    session.clear()
    return redirect('/auth/login.html')

# Register route
@app.route("/register", methods=["POST"])
def register():
    data = request.form or request.json or {}
    username = data.get("username")
    email = data.get("email")
    password = data.get("password")
    if username and email and password:
        # In real app, insert user into DB
        session['logged_in'] = True
        session['username'] = username
        return redirect('/dashboard/')
    return redirect('/auth/register.html')

if __name__ == "__main__":
    app.run(debug=True)
