import os
from dotenv import load_dotenv
from flask import Flask, jsonify, request, send_from_directory, abort, redirect, session, render_template, flash, g
from flask import current_app as app
import socket
import re
import hashlib
import time
from collections import defaultdict, deque
import json
from backend.utils import get_user_by_api_key
from flask_login import login_required, current_user, LoginManager, login_user
from backend.database import SessionLocal, APIKey, User
import secrets
from datetime import datetime, timedelta

load_dotenv()



# Import the database helpers in a way that works when running from the repo root
# (python -m backend.app) or when running directly from backend/ (python app.py).
try:
    # Preferred: running as a package from repo root
    from backend.database import (get_latest_leaks, leak_to_dict, insert_leak_with_dedupe, 
                                  create_user, authenticate_user, init_db, insert_crawl_run, 
                                  get_crawl_runs_for_user, update_crawl_run_status, 
                                  get_leaks_for_user, leak_to_dict)
    from backend.crawler.pastebin import fetch_and_store as pastebin_fetch
    from backend.crawler.tor_crawler import fetch_and_store as tor_fetch
    import backend.crawler.tor_crawler as tor_module
    from backend.crawler.i2p_crawler import fetch_and_store as i2p_fetch
    import backend.crawler.i2p_crawler as i2p_module
    from backend.database import Asset, SessionLocal, Base, Leak
    from backend.severity import compute_severity_from_entities
    from backend.analytics import get_critical_leaks, risk_summary
except ImportError:
    # Fallback: running directly in the backend/ directory
    from database import (
        get_latest_leaks, leak_to_dict, insert_leak_with_dedupe,
        create_user, authenticate_user, init_db, get_leaks_for_user, leak_to_dict
    )
    from database import insert_crawl_run, get_crawl_runs_for_user, update_crawl_run_status
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

# Create Flask app. Point template_folder at project-level templates directory so
# render_template finds the Jinja2 templates we added under PROJECT_ROOT/templates.
app = Flask(
    __name__,
    template_folder=os.path.join(PROJECT_ROOT, 'templates'),
    static_folder=os.path.join(PROJECT_ROOT, 'static')  # serve project-level static assets
)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "dev-secret-change-me")

# --- Simple in-memory rate limiting (IP based) ---
RATE_LIMIT_WINDOW = 60  # seconds
RATE_LIMIT_MAX = 15     # max attempts per window
_rate_limit_store: dict[str, deque] = defaultdict(deque)


login_manager = LoginManager()
login_manager.login_view = "login"  # redirect here if not logged in
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    session = SessionLocal()
    user = session.get(User, int(user_id))
    session.close()
    return user

@app.before_request
def api_key_auth_middleware():
    # Only apply for /api routes
    if request.path.startswith("/api/"):
        key = request.headers.get("x-api-key")
        if key:
            session = SessionLocal()
            try:
                api_key = session.query(APIKey).filter_by(key=key).first()
                if api_key:
                    g.api_user_id = api_key.user_id
                else:
                    return {"error": "Invalid API key"}, 401
            finally:
                session.close()


def rate_limited(key: str) -> bool:
    now = time.time()
    dq = _rate_limit_store[key]
    # purge old timestamps
    while dq and now - dq[0] > RATE_LIMIT_WINDOW:
        dq.popleft()
    if len(dq) >= RATE_LIMIT_MAX:
        return True
    dq.append(now)
    return False

# --- CSRF token helpers ---
import secrets

def get_csrf_token() -> str:
    token = session.get('_csrf_token')
    if not token:
        token = secrets.token_urlsafe(32)
        session['_csrf_token'] = token
    return token

def validate_csrf(token: str | None) -> bool:
    return token and token == session.get('_csrf_token')

app.jinja_env.globals['csrf_token'] = get_csrf_token

# Ensure database tables exist (idempotent)
try:
    init_db()
except Exception as e:
    print(f"[startup] Failed to initialize database: {e}")

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
    '/login', '/register', '/auth/login.html', '/auth/register.html', '/static/', '/favicon.ico', '/dashboard/base.css', '/api/check_email',
    '/v1/config/',  # allow crawlers to fetch config without session
    '/v1/events'    # allow crawler event ingestion without session; will validate API key inside handler
]

def get_current_user_id():
    # Prefer API key derived identity if middleware set it, else session
    uid = getattr(g, 'current_user_id', None)
    if uid:
        return uid
    return session.get('user_id')


@app.before_request
def check_api_key():
    exempt_paths = ["/login", "/register", "/api/keys/new"]
    if any(request.path.startswith(p) for p in exempt_paths):
        return

    if request.path.startswith("/api/"):
        api_key_str = request.headers.get("x-api-key")
        user_id = get_user_by_api_key(api_key_str) if api_key_str else None

        if user_id == "EXPIRED":
            return jsonify({"error": "Expired API key"}), 401

        # API key takes priority
        if user_id:
            g.current_user_id = user_id
            return

        # Allow session fallback ONLY for safe (GET) routes, not crawler runs
        if request.method == "GET" and session.get("logged_in") and session.get("user_id"):
            g.current_user_id = session["user_id"]
            return

        # No API key and not a safe session fallback → reject
        return jsonify({"error": "Invalid or missing API key"}), 401


@app.before_request
def require_login():
    path = request.path
    # Allow public routes without login
    if path in PUBLIC_ROUTES or any(path.startswith(r) for r in PUBLIC_ROUTES):
        return None
    # Explicitly allow config endpoint (public JSON for crawlers)
    if path.startswith('/v1/config/'):
        return None
    # Allow /auth/login.html and /auth/register.html without login
    if path in ['/auth/login.html', '/auth/register.html']:
        return None
    if path.startswith("/api") and not session.get("logged_in"):
        return redirect("/login")
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
    username = session.get('username', 'User')
    return render_template('homepage.html', username=username)


@app.route('/dashboard')
def dashboard_noext():
    return redirect('/dashboard/')

@app.route('/dashboard/')
@login_required
def dashboard():
    session = SessionLocal()
    try:
        api_key_obj = session.query(APIKey).filter_by(user_id=current_user.id).first()

        # If user doesn't have an API key yet, generate one and store it
        if not api_key_obj:
            new_key = secrets.token_hex(32)
            api_key_obj = APIKey(user_id=current_user.id, key=new_key)
            session.add(api_key_obj)
            session.commit()
            session.refresh(api_key_obj)

        return render_template(
            "dashboard.html",
            username=current_user.username,
            api_key=api_key_obj.key  # Pass the key to the template
        )
    finally:
        session.close()

@app.route('/resources')
def resources_noext_route():
    return redirect('/resources/')


@app.route('/resources/')
def resources_route():
    username = session.get('username', 'User')
    return render_template('resources.html', username=username)


@app.route('/account')
def account_noext():
    return redirect('/account/')


@app.route('/account/')
def account():
    username = session.get('username', 'User')
    return render_template('account.html', username=username)

# Alerts page routes
@app.route('/alerts')
def alerts_noext():
    return redirect('/alerts/')


@app.route('/alerts/')
def alerts():
    username = session.get('username', 'User')
    return render_template('alerts.html', username=username)


# Risk Analysis page routes
@app.route('/risk_analysis')
def risk_analysis_noext():
    return redirect('/risk_analysis/')


@app.route('/risk_analysis/')
def risk_analysis():
    username = session.get('username', 'User')
    return render_template('risk_analysis.html', username=username)


# Reports page routes
@app.route('/reports')
def reports_noext():
    return redirect('/reports/')


@app.route('/reports/')
def reports():
    username = session.get('username', 'User')
    return render_template('reports.html', username=username)

# Leaks page routes
@app.route('/leaks')
def leaks_noext():
    return redirect('/leaks/')

@app.route('/leaks/')
@login_required
def leaks():
    username = session.get('username', 'User')
    # fetch or generate the API key for this user
    session_db = SessionLocal()
    key_obj = session_db.query(APIKey).filter(APIKey.user_id == current_user.id).first()
    session_db.close()
    api_key = key_obj.key if key_obj else None
    return render_template('leaks.html', username=username, api_key=api_key)


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
        # If the page is one we now render via templates, use render_template instead of static send
        template_map = {
            'homepage': 'homepage.html',
            'dashboard': 'dashboard.html',
            'resources': 'resources.html',
            'account': 'account.html',
            'alerts': 'alerts.html',
            'risk_analysis': 'risk_analysis.html',
            'reports': 'reports.html',
            'leaks': 'leaks.html',
        }
        if page in template_map:
            username = session.get('username', 'User')
            return render_template(template_map[page], username=username)
        if page in template_map:
            username = session.get('username', 'User')
            return render_template(template_map[page], username=username)
        # login/register still served as static HTML originals
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
    user_id = get_current_user_id()
    if not user_id:
        return jsonify({"error": "not authenticated"}), 401

    leaks = get_leaks_for_user(user_id)
    limit = request.args.get("limit", default=10, type=int)
    leaks = leaks[:limit]  # trim to requested limit

    return jsonify([leak_to_dict(leak) for leak in leaks])


# Alerts (critical leaks only)
@app.route("/api/alerts", methods=["GET"])
def api_alerts():
    limit = request.args.get('limit', default=50, type=int)
    user_id = session.get("user_id")
    if not user_id:
        return jsonify({"error": "not authenticated"}), 401

    crits = get_critical_leaks(limit=limit, user_id=user_id)
    return jsonify(crits)

# Risk summary aggregation
@app.route("/api/risk/summary", methods=["GET"])
def api_risk_summary():
    user_id = session.get('user_id')
    if not user_id:
        return jsonify({"error": "not authenticated"}), 401

    return jsonify(risk_summary(user_id=user_id))

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

    # Auto-compute severity if not provided (compute even when entities are empty -> 'zero severity')
    if not severity:
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

    user_id = get_current_user_id()
    if not user_id:
        return jsonify({"error": "not authenticated"}), 401

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
        user_id=user_id,
    )

    status = "duplicate" if is_dup else "accepted"
    resp = {"status": status, "id": leak_id}
    return jsonify(resp), 202


# Seed five mock leaks: one per crawler type, covering all entity types across them
@app.route("/api/leaks/mock", methods=["POST"])
def api_leaks_insert_mock():
    uid = get_current_user_id()
    if not uid:
        return jsonify({"error": "not authenticated"}), 401

    # Define 5 mock leaks (pastebin, github, tor, i2p, freenet)
    samples = [
        {
            "source": "pastebin",
            "url": "https://pastebin.com/mock/abc123",
            "title": "Credentials dump for service",
            "content": "Login for alice@example.com password: hunter2\nSome extra lines...",
            "entities": {
                "emails": ["alice@example.com"],
                "domains": ["example.com"],
                "ips": [],
                "btc_wallets": [],
                "ssns": [],
                "phone_numbers": [],
                "passwords": ["hunter2"],
                "physical_addresses": [],
                "names": []
            },
            "passwords": ["hunter2"]
        },
        {
            "source": "github",
            "url": "https://github.com/user/repo/blob/main/config.yml",
            "title": "Config leak with domain and IP",
            "content": "production: domain: example.com\nadmin_ip: 203.0.113.10",
            "entities": {
                "emails": [],
                "domains": ["example.com"],
                "ips": ["203.0.113.10"],
                "btc_wallets": [],
                "ssns": [],
                "phone_numbers": [],
                "passwords": [],
                "physical_addresses": [],
                "names": []
            }
        },
        {
            "source": "tor",
            "url": "http://exampleonionabcdef.onion/page",
            "title": "Onion forum post with BTC and name",
            "content": "Payment to bc1qexampleexampleexampleexamplex0j2z by user John Doe.",
            "entities": {
                "emails": [],
                "domains": [],
                "ips": [],
                "btc_wallets": ["bc1qexampleexampleexampleexamplex0j2z"],
                "ssns": [],
                "phone_numbers": [],
                "passwords": [],
                "physical_addresses": [],
                "names": ["john doe"]
            },
            "names": ["john doe"]
        },
        {
            "source": "i2p",
            "url": "http://mock.i2p/page",
            "title": "I2P leak with SSN and phone",
            "content": "Employee SSN 123-45-6789 and phone (555) 123-4567 recorded.",
            "entities": {
                "emails": [],
                "domains": [],
                "ips": [],
                "btc_wallets": [],
                "ssns": ["123456789"],
                "phone_numbers": ["5551234567"],
                "passwords": [],
                "physical_addresses": [],
                "names": []
            },
            "ssn": ["123456789"],
            "phone_numbers": ["5551234567"]
        },
        {
            "source": "freenet",
            "url": "freenet://USK@mock-key/mock-site/0/",
            "title": "Freenet page with address",
            "content": "Contact at 123 Main Street for delivery.",
            "entities": {
                "emails": [],
                "domains": [],
                "ips": [],
                "btc_wallets": [],
                "ssns": [],
                "phone_numbers": [],
                "passwords": [],
                "physical_addresses": ["123 Main Street"],
                "names": []
            },
            "physical_addresses": ["123 Main Street"]
        },
    ]

    from backend.database import insert_leak_with_dedupe
    inserted = []
    dupes = 0
    for s in samples:
        try:
            text = s["content"] or ""
            ch = "sha256:" + hashlib.sha256(text.encode("utf-8", errors="ignore")).hexdigest()
            leak_id, is_dup = insert_leak_with_dedupe(
                source=s["source"],
                url=s.get("url"),
                title=s.get("title"),
                content=text,
                content_hash=ch,
                severity=None,
                entities=s.get("entities") or {},
                passwords=s.get("passwords"),
                ssn=s.get("ssn"),
                names=s.get("names"),
                phone_numbers=s.get("phone_numbers"),
                physical_addresses=s.get("physical_addresses"),
                user_id=uid,
            )
            if is_dup:
                dupes += 1
            inserted.append(leak_id)
        except Exception as e:
            return jsonify({"status": "error", "message": str(e)}), 500

    return jsonify({"status": "ok", "inserted": len(inserted), "ids": inserted, "duplicates": dupes}), 200


# Trigger Pastebin crawler from the web app
@app.route("/api/crawlers/pastebin/run", methods=["POST"])
def api_run_pastebin():
    current_user_id = get_current_user_id()
    if not current_user_id:
        return jsonify({"error": "not authenticated"}), 401

    # Create a crawl run record at start
    run_id = insert_crawl_run(source="pastebin", user_id=current_user_id, status="running")

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
            inserted = pastebin_fetch(limit=limit, user_id=current_user_id)
        except TypeError:
            inserted = pastebin_fetch() or 0
        # Update run status to completed
        update_crawl_run_status(run_id, "completed")

    except RuntimeError as e:
        update_crawl_run_status(run_id, "failed")
        return jsonify({"status": "error", "message": str(e)}), 500
    return jsonify({"status": "ok", "inserted": inserted}), 200


# Trigger Tor crawler from the web app
@app.route("/api/crawlers/tor/run", methods=["POST"])
def api_run_tor():
    current_user_id = get_current_user_id()
    if not current_user_id:
        return jsonify({"error": "not authenticated"}), 401

    # Create a crawl run record at start
    run_id = insert_crawl_run(source="tor", user_id=current_user_id, status="running")

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
        ok = tor_fetch(SAFE_ONION, retries=retries, delay=delay, user_id=current_user_id)
    except (TypeError, ValueError, RuntimeError) as e:
        update_crawl_run_status(run_id, "failed")
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
    current_user_id = get_current_user_id()
    if not current_user_id:
        return jsonify({"error": "not authenticated"}), 401

    run_id = insert_crawl_run(source="i2p", user_id=current_user_id, status="running")

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
            user_id=current_user_id
        )
        update_crawl_run_status(run_id, "completed")
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
            update_crawl_run_status(run_id, "failed")
            return jsonify({"status": "error", "message": "url is required when proxy is available"}), 400
        ok = i2p_fetch(url, retries=retries, delay=delay, user_id=current_user_id)
        update_crawl_run_status(run_id, "completed")
    except (TypeError, ValueError, RuntimeError) as e:
        update_crawl_run_status(run_id, "failed")
        return jsonify({"status": "error", "message": str(e)}), 500
    return jsonify({"status": "ok", "fetched": bool(ok), "mocked": False}), 200


# Trigger GitHub crawler from the web app
@app.route("/api/crawlers/github/run", methods=["POST"])
def api_run_github():
    current_user_id = get_current_user_id()
    if not current_user_id:
        return jsonify({"error": "not authenticated"}), 401

    # Create a crawl run record at start
    run_id = insert_crawl_run(source="github", user_id=current_user_id, status="running")

    # Optional limit parameter
    limit = 10
    if request.is_json:
        body = request.get_json(silent=True) or {}
        try:
            limit = int(body.get("limit", limit))
        except (TypeError, ValueError):
            pass

    try:
        def run_github_crawler(limit, user_id):
            import importlib
            github_crawler = importlib.import_module("backend.crawler.github_crawler")
            return github_crawler.fetch_and_store(limit=limit, user_id=user_id)

        inserted = run_github_crawler(limit, current_user_id)

        update_crawl_run_status(run_id, "completed")
    except RuntimeError as e:
        update_crawl_run_status(run_id, "failed")
        return jsonify({"status": "error", "message": str(e)}), 500

    return jsonify({"status": "ok", "inserted": inserted}), 200


# --- Freenet proxy health ---
@app.route("/api/proxy/freenet/health")
def freenet_health():
    try:
        from backend.crawler.freenet_crawler import health_check
        result = health_check()
        return jsonify(result)
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


# --- Run Freenet crawler (API-key/session scoped) ---
@app.route("/api/crawlers/freenet/run", methods=["POST"])
def api_run_freenet():
    current_user_id = get_current_user_id()
    if not current_user_id:
        return jsonify({"error": "not authenticated"}), 401

    # create crawl run
    run_id = insert_crawl_run(source="freenet", user_id=current_user_id, status="running")

    body = request.get_json(silent=True) or {}
    limit = body.get("limit", 5)
    urls = body.get("urls")  # optional override list
    mock = bool(body.get("mock", False))

    try:
        from backend.crawler.freenet_crawler import fetch_and_store
        inserted = fetch_and_store(
            limit=int(limit),
            user_id=int(current_user_id),
            urls=urls if isinstance(urls, list) else None,
            mock=mock,
        )
        update_crawl_run_status(run_id, "completed")
        return jsonify({"status": "ok", "inserted": inserted}), 200
    except Exception as e:
        update_crawl_run_status(run_id, "failed")
        return jsonify({"status": "error", "message": str(e)}), 500



@app.route("/api/crawl_runs", methods=["GET"])
def api_crawl_runs():
    current_user_id = get_current_user_id()
    if not current_user_id:
        return jsonify({"error": "not authenticated"}), 401

    # Defensive: ensure it's int
    try:
        current_user_id = int(current_user_id)
    except (TypeError, ValueError):
        return jsonify({"error": "invalid user id"}), 400

    runs = get_crawl_runs_for_user(current_user_id)
    return jsonify([
        {
            "id": r.id,
            "source": r.source,
            "started_at": r.started_at.isoformat() if r.started_at else None,
            "finished_at": r.finished_at.isoformat() if r.finished_at else None,
            "status": r.status,
            "user_id": r.user_id,
        }
        for r in runs
    ])




# ---- Assets (watchlist) API ----

# --- Consolidated Asset API using data.sqlite ---

def hash_sensitive_value(value: str) -> str:
    """Deterministically hash sensitive values for storage/deduplication."""
    if not value:
        return value
    try:
        import hashlib as _hl
        return _hl.sha256(value.strip().encode('utf-8')).hexdigest()
    except Exception:
        return value

def normalize_asset_value(asset_type: str, value: str) -> str:
    """Normalize asset values consistently with entity extraction before hashing/storage."""
    if not value:
        return value
    t = (asset_type or '').strip().lower()
    v = value.strip()
    if t in ('email', 'domain', 'ip'):
        return v.lower()
    if t == 'ssn':
        # store only digits
        import re as _re
        return _re.sub(r"\D", "", v)
    if t == 'phone':
        import re as _re
        return _re.sub(r"\D", "", v)
    if t == 'name':
        return v.lower()
    if t == 'address':
        # entities are Title Cased; align to that to match hashing comparison
        return v.title()
    if t == 'btc':
        # BTC addresses are case sensitive for bech32 prefix casing, but matching supports hash/plain; keep as-is
        return v
    if t == 'password':
        return v
    return v

@app.route("/api/assets", methods=["GET"])
def api_assets_list():
    uid = get_current_user_id()
    if not uid:
        return jsonify({"error": "not authenticated"}), 401
    session = SessionLocal()
    try:
        assets = (
            session.query(Asset)
            .filter(Asset.user_id == uid)
            .order_by(Asset.created_at.desc())
            .all()
        )
        return jsonify([
            {
                'id': a.id,
                'type': a.type,
                'value': a.value,
                'created_at': a.created_at.isoformat() if a.created_at else None,
                'user_id': a.user_id
            } for a in assets
        ])
    finally:
        session.close()

@app.route("/api/assets", methods=["POST"])
def api_assets_add():
    body = request.get_json(silent=True) or {}
    t = (body.get('type') or '').strip().lower()
    v = (body.get('value') or '').strip()
    user_id = get_current_user_id()
    if not user_id:
        return jsonify({"error": "not authenticated"}), 401
    if not t or not v:
        return jsonify({"code": "validation_error", "message": "type and value required"}), 400
    # Normalize then hash/encrypt sensitive fields
    SENSITIVE_TYPES = ['ssn', 'phone', 'btc', 'password', 'name', 'address']
    if t in SENSITIVE_TYPES:
        v = hash_sensitive_value(normalize_asset_value(t, v))
    else:
        v = normalize_asset_value(t, v)
    session_db = SessionLocal()
    try:
        # Check for existing asset
        existing = session_db.query(Asset).filter(Asset.type == t, Asset.value == v, Asset.user_id == user_id).first()
        if existing:
            # Recompute severities in case this existing asset just became relevant
            try:
                from backend.database import recompute_severity_for_user_leaks
                updated = recompute_severity_for_user_leaks(user_id)
            except Exception:
                updated = 0
            return jsonify({"status": "ok", "id": existing.id, "updated": updated}), 200
        obj = Asset(type=t, value=v, user_id=user_id)
        session_db.add(obj)
        session_db.commit()
        session_db.refresh(obj)
        # After adding an asset, recompute severities for this user's leaks
        try:
            from backend.database import recompute_severity_for_user_leaks
            updated = recompute_severity_for_user_leaks(user_id)
        except Exception:
            updated = 0
        return jsonify({"status": "ok", "id": obj.id, "updated": updated}), 201
    finally:
        session_db.close()

@app.route("/api/assets/<int:asset_id>", methods=["DELETE"])
def api_assets_delete(asset_id: int):
    session_db = SessionLocal()
    try:
        obj = session_db.query(Asset).filter(Asset.id == asset_id).first()
        if not obj:
            return jsonify({"code": "not_found", "message": "asset not found"}), 404
        uid = obj.user_id
        session_db.delete(obj)
        session_db.commit()
        # Recompute severities after deletion
        try:
            from backend.database import recompute_severity_for_user_leaks
            updated = recompute_severity_for_user_leaks(uid)
        except Exception:
            updated = 0
        return jsonify({"status": "ok", "updated": updated}), 200
    finally:
        session_db.close()


# Delete a leak (for the current user)
@app.route("/api/leaks/<int:leak_id>", methods=["DELETE"])
def api_leaks_delete(leak_id: int):
    uid = get_current_user_id()
    if not uid:
        return jsonify({"error": "not authenticated"}), 401
    session_db = SessionLocal()
    try:
        lk = session_db.query(Leak).filter(Leak.id == leak_id, Leak.user_id == uid).first()
        if not lk:
            return jsonify({"code": "not_found", "message": "leak not found"}), 404
        session_db.delete(lk)
        session_db.commit()
        return jsonify({"status": "ok"}), 200
    finally:
        session_db.close()


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
    # Allow API key auth for non-/api path
    try:
        key = request.headers.get("x-api-key") or request.headers.get("X-API-Key")
        if not key and request.is_json:
            body = request.get_json(silent=True) or {}
            key = body.get("api_key")
        if key:
            from backend.utils import get_user_by_api_key as _get_by_key
            uid = _get_by_key(key)
            if uid == "EXPIRED":
                return jsonify({"error": "Expired API key"}), 401
            if uid:
                g.current_user_id = uid
    except Exception:
        pass

    return api_leaks_ingest()


# Config route to backend
@app.route("/v1/config/org/<int:org_id>", methods=["GET"])
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
            },
            "tor": {
                "socks_port": 9050,
                "timeout_sec": 40,
                "keywords": ["dump", "breach", "login", "database", "leak"]
            },
            "i2p": {
                "proxy_host": "127.0.0.1",
                "proxy_port": 4444,
                "timeout_sec": 40,
                "keywords": ["credential", "compromised", "breach", "account"]
            },
            "github": {
                "token": os.getenv("DEFAULT_GITHUB_TOKEN", ""),
                "timeout_sec": 20,
                "limit": 10,
                "keywords": [
                    "password", "apikey", "secret", "aws_access_key_id", "private_key, api_key, token, database, credential, access_key"
                ]
            }
            ,
            "freenet": {
                "seeds": ["http://127.0.0.1:8888/USK@dCnkUL22fAmKbKg-Cftx9j2m4IwyWB0QbGoiq1RSLP8,4d1TDqwRr4tYlsubLrQK~c4h0~FtmE-OXCDmFiI8BB4,AQACAAE/Sharesite/41/"],
                "keywords": ["test", "freenet", "leak", "credential", "password", "breach", "database", "dump, sharesite"],
                "timeout_sec": 30
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
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template('login.html')
    data = request.form or request.json or {}
    # CSRF check
    if not validate_csrf(data.get('csrf_token')):
        flash('Invalid CSRF token. Refresh and try again.', 'error')
        return render_template('login.html')
    # Rate limit by IP
    ip = request.remote_addr or 'unknown'
    if rate_limited(f'login:{ip}'):
        flash('Too many login attempts. Please wait a minute.', 'error')
        return render_template('login.html')
    username_or_email = (data.get("user_login") or '').strip()
    password = data.get("user_password")
    if not (username_or_email and password):
        flash("Both fields are required.", "error")
        return render_template('login.html', login_val=username_or_email)
    user = authenticate_user(username_or_email, password)
    if not user:
        flash("Invalid credentials.", "error")
        return render_template('login.html', login_val=username_or_email)
    
    login_user(user)
    
    session['logged_in'] = True
    session['username'] = user.username
    session['user_id'] = user.id
    flash("Welcome back, {}!".format(user.username), "success")
    return redirect('/dashboard/')

# Logout route
@app.route("/logout", methods=["GET", "POST"])
def logout():
    session.clear()
    return redirect('/auth/login.html')

# Register route (GET = show form, POST = process)
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "GET":
        return render_template('register.html')
    data = request.form or request.json or {}
    # CSRF check
    if not validate_csrf(data.get('csrf_token')):
        flash('Invalid CSRF token. Refresh and try again.', 'error')
        return render_template('register.html')
    # Rate limit by IP
    ip = request.remote_addr or 'unknown'
    if rate_limited(f'register:{ip}'):
        flash('Too many registration attempts. Please wait a minute.', 'error')
        return render_template('register.html')
    username = (data.get("username") or data.get("reg_user") or "").strip()
    email = (data.get("email") or data.get("reg_email") or "").strip().lower()
    password = data.get("password") or data.get("reg_password")
    if not (username and email and password):
        flash("All fields are required.", "error")
        return render_template('register.html', username_val=username, email_val=email, error="All fields are required.")
    # Server-side password validation
    def password_errors(pw: str):
        errs = []
        if len(pw) < 10:
            errs.append('Password must be at least 10 characters.')
        if not re.search(r'[A-Z]', pw):
            errs.append('Add an uppercase letter.')
        if not re.search(r'[a-z]', pw):
            errs.append('Add a lowercase letter.')
        if not re.search(r'\d', pw):
            errs.append('Add a digit.')
        if not re.search(r'[^A-Za-z0-9]', pw):
            errs.append('Add a special character.')
        return errs
    pw_errs = password_errors(password or '')
    if pw_errs:
        msg = ' '.join(pw_errs)
        flash(msg, 'error')
        return render_template('register.html', username_val=username, email_val=email, error=msg)
    try:
        user_id = create_user(username, email, password)

        #Generate API key for new user
        session_db = SessionLocal()
        api_key_value = secrets.token_hex(32)
        api_key = APIKey(user_id=user_id, key=api_key_value)
        session_db.add(api_key)
        session_db.commit()
        session_db.close()

        print(f"[DEBUG] Created API key for user {username}: {api_key_value}")

    except ValueError as e:
        error_msg = str(e)
        lowered = error_msg.lower()
        if "email" in lowered:
            error_msg = "This email is already linked to another account."
        elif "username" in lowered:
            error_msg = "This username is already taken."
        else:
            error_msg = "Registration failed. Please try again."
        flash(error_msg, "error")
        return render_template('register.html', username_val=username, email_val=email, error=error_msg)
    session['logged_in'] = True
    session['username'] = username
    session['user_id'] = user_id
    flash("Registration successful!", "success")
    return redirect('/homepage/')

@app.route('/api/check_email')
def api_check_email():
    # lightweight availability check
    from backend.database import SessionLocal, User  # local import to avoid circular
    email = (request.args.get('email') or '').strip().lower()
    if not email:
        return jsonify({"available": False, "error": "email required"}), 400
    session_db = SessionLocal()
    try:
        exists = session_db.query(User.id).filter(User.email == email).first() is not None
    finally:
        session_db.close()
    return jsonify({"available": not exists})

# Legacy path served as static file previously; redirect to dynamic template route
@app.route('/auth/register.html', methods=['GET'])
def legacy_register_static():
    return redirect('/register')

@app.route('/auth/login.html', methods=['GET'])
def legacy_login_static():
    return redirect('/login')

# Additional legacy/SEO-friendly aliases
@app.route('/login.html', methods=['GET'])
def login_html_alias():
    return redirect('/login')

@app.route('/register.html', methods=['GET'])
def register_html_alias():
    return redirect('/register')

@app.route('/login/', methods=['GET'])
def login_trailing():
    return redirect('/login')

@app.route('/register/', methods=['GET'])
def register_trailing():
    return redirect('/register')


# Delete account endpoint
@app.route("/api/account/delete", methods=["POST"])
def api_account_delete():
    user_id = session.get("user_id")
    if not user_id:
        return jsonify({"status": "error", "message": "Not authenticated"}), 401
    from backend.database import delete_user
    ok = delete_user(user_id)
    if ok:
        session.clear()
        return jsonify({"status": "deleted"}), 200
    else:
        return jsonify({"status": "error", "message": "User not found"}), 404


# Password reset endpoint
@app.route("/api/reset_password", methods=["POST"])
def api_reset_password():

    from backend.database import SessionLocal, User, hash_password
    if not session.get('logged_in') or not session.get('user_id'):
        return jsonify({"status": "error", "message": "Not authenticated."}), 401
    data = request.get_json(silent=True) or {}
    new_password = data.get("new_password")
    if not new_password:
        return jsonify({"status": "error", "message": "New password required."}), 400
    # Basic password validation (reuse registration rules)
    def password_errors(pw: str):
        errs = []
        if len(pw) < 10:
            errs.append('Password must be at least 10 characters.')
        if not re.search(r'[A-Z]', pw):
            errs.append('Add an uppercase letter.')
        if not re.search(r'[a-z]', pw):
            errs.append('Add a lowercase letter.')
        if not re.search(r'\d', pw):
            errs.append('Add a digit.')
        if not re.search(r'[^A-Za-z0-9]', pw):
            errs.append('Add a special character.')
        return errs
    pw_errs = password_errors(new_password)
    if pw_errs:
        return jsonify({"status": "error", "message": ' '.join(pw_errs)}), 400
    session_db = SessionLocal()
    try:
        user = session_db.query(User).filter(User.id == session['user_id']).first()
        if not user:
            return jsonify({"status": "error", "message": "User not found."}), 404
        user.password_hash = hash_password(new_password)
        session_db.commit()
        return jsonify({"status": "ok", "message": "Password changed successfully."}), 200
    except Exception as e:
        session_db.rollback()
        return jsonify({"status": "error", "message": str(e)}), 500
    finally:
        session_db.close()

@app.route("/api/keys/new", methods=["POST"])
def create_api_key():
    user_id = session.get("user_id")
    if not user_id:
        return jsonify({"error": "Not authenticated"}), 401

    session_db = SessionLocal()
    try:
        new_key = secrets.token_hex(32)
        expires_at = datetime.utcnow() + timedelta(days=30)

        api_key = APIKey(
            key=new_key,
            user_id=user_id,
            expires_at=expires_at
        )
        session_db.add(api_key)
        session_db.commit()
        return jsonify({"api_key": new_key, "expires_at": expires_at.isoformat()})
    finally:
        session_db.close()




if __name__ == "__main__":
    app.run(debug=True)



