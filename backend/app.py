import os
from backend.database import Leak, CrawlRun, Asset, AlertHistory, SavedReport
from backend.database import SessionLocal
DBSession = SessionLocal
import random
import string
from dotenv import load_dotenv
from flask import Flask, jsonify, request, send_from_directory, abort, redirect, session, render_template, flash, g, make_response
from flask import current_app as app
import socket
import re
import hashlib
import time
from collections import defaultdict, deque
import json
from textwrap import wrap
from backend.utils import get_user_by_api_key
from flask_login import login_required, current_user, LoginManager, login_user
from backend.database import SessionLocal, APIKey, User, Config, AlertHistory, SavedReport
import secrets
from datetime import datetime, timedelta
import requests
import io
from reportlab.lib.utils import ImageReader
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
import base64
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from sqlalchemy import func
from flask_login import current_user
from sqlalchemy import or_


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
    from backend.analytics import get_critical_leaks, risk_summary, risk_time_series, severity_time_series, asset_risk
    from backend.pdf_builder import create_pdf_from_config
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

# Session and cookie configuration
# - PERMANENT_SESSION_LIFETIME controls how long a "permanent" session lives.
# - We default to 30 minutes but allow override via env var SESSION_TIMEOUT_MINUTES.
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=int(os.environ.get("SESSION_TIMEOUT_MINUTES", "30")))
# Cookie security flags; allow overriding secure flag via env var for local dev if needed.
app.config['SESSION_COOKIE_SECURE'] = os.environ.get("SESSION_COOKIE_SECURE", "False").lower() in ("1", "true", "yes")
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

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
def refresh_session_expiry():
    """Refresh the expiry for permanent sessions on activity.

    When session.permanent is True, setting session.modified=True will cause
    Flask to issue a Set-Cookie with an updated expiry (based on
    PERMANENT_SESSION_LIFETIME). This implements an inactivity timeout.
    """
    try:
        if current_user.is_authenticated and getattr(session, 'permanent', False):
            # mark modified so the cookie expiry will be refreshed
            session.modified = True
    except Exception:
        # be conservative — don't break requests on any session issues
        pass

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
    'reports': 'dashboardpage/reports.html',
    'leaks': 'dashboardpage/leaks.html',
    'login': 'auth/login.html',
    'register': 'auth/register.html',
}
# Secret key for session management is set from environment earlier. Do not hard-code here.

PUBLIC_ROUTES = [
    '/login', '/register', '/auth/login.html', '/auth/register.html', '/static/', '/favicon.ico', '/dashboard/base.css', '/api/check_email', '/api/check_username',
    '/v1/config/',  # allow crawlers to fetch config without session
    '/v1/events'    # allow crawler event ingestion without session; will validate API key inside handler
]

def get_current_user_id():
    # Prefer API key derived identity if middleware set it, else session
    uid = getattr(g, 'current_user_id', None)
    if uid:
        return uid
    # Prefer Flask-Login's current_user when available
    try:
        if current_user.is_authenticated:
            # current_user.get_id() is usually a str; try to return int when possible
            cid = current_user.get_id()
            try:
                return int(cid)
            except Exception:
                return cid
    except Exception:
        pass
    return session.get('user_id')


@app.before_request
def check_api_key():
    # Allow certain endpoints to use session-based auth (no API key required)
    exempt_paths = [
        "/login", "/register", "/api/keys/new", "/api/account/delete", 
        "/api/reset_password", "/api/check_email", "/api/check_username",
        "/api/reports/preview", "/api/reports/download", "/api/reports/data/",
        "/api/reports/save", "/api/reports/saved"
    ]
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
        if request.method == "GET" and current_user.is_authenticated:
            try:
                cid = current_user.get_id()
                g.current_user_id = int(cid) if cid is not None else None
            except Exception:
                g.current_user_id = current_user.get_id()
            if g.current_user_id:
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
    # For API routes, return JSON error instead of redirect
    if path.startswith("/api"):
        if not (current_user.is_authenticated or session.get('user_id')):
            return jsonify({"error": "Authentication required"}), 401
    # For non-API routes, redirect to login page
    if not (current_user.is_authenticated or session.get('user_id')):
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


# Reports page routes
@app.route('/reports')
def reports_noext():
    return redirect('/reports/')


@app.route('/reports/')
def reports():
    username = session.get('username', 'User')
    return render_template('reports.html', username=username)


@app.route("/reports/download/<report_type>")
def download_report(report_type):
    db_session = SessionLocal()
    user_id = getattr(current_user, "id", None) or session.get("user_id")
    username = getattr(current_user, "username", "User")

    if not user_id:
        return "Unauthorized - please log in first", 401

    buffer = io.BytesIO()
    pdf = canvas.Canvas(buffer, pagesize=letter)
    pdf.setTitle(f"{report_type.capitalize()} Report")

    # Call correct report generator
    if report_type == "weekly":
        generate_weekly_report(pdf, db_session, user_id)
    elif report_type == "incident":
        generate_incident_report(pdf, db_session, user_id)
    elif report_type == "risk":
        generate_risk_report(pdf, db_session, user_id)
    else:
        pdf.drawString(80, 740, "Invalid report type requested.")

    db_session.close()
    pdf.save()
    buffer.seek(0)

    response = make_response(buffer.read())
    response.headers["Content-Type"] = "application/pdf"
    response.headers["Content-Disposition"] = f"attachment; filename={username}_{report_type}_Report.pdf"
    return response


# -----------------------------------------------------------
# WEEKLY SECURITY SUMMARY
# -----------------------------------------------------------
def generate_weekly_report(pdf, db_session, user_id):
    start_date = datetime.now() - timedelta(days=7)
    end_date = datetime.now()

    # Query leaks for the last 7 days
    leaks = (
        db_session.query(Leak)
        .filter(Leak.user_id == user_id, Leak.timestamp >= start_date)
        .order_by(Leak.timestamp.desc())
        .all()
    )

    # Title + Date Range
    pdf.setFont("Helvetica-Bold", 14)
    pdf.drawString(
        80,
        740,
        f"Weekly Security Summary — {start_date.strftime('%b %d')}–{end_date.strftime('%b %d, %Y')}"
    )
    y = 710

    total = len(leaks)

    # --- Count severities ---
    severities = {"low": 0, "medium": 0, "high": 0, "critical": 0, "zero": 0}
    for leak in leaks:
        sev = (leak.severity or "").lower().strip()
        if sev in ("zero", "zero severity", "none", "unclassified"):
            sev = "zero"
        if sev not in severities:
            sev = "zero"
        severities[sev] += 1


    # --- Summary Header ---
    pdf.setFont("Helvetica-Bold", 12)
    pdf.drawString(80, y, "Summary of Detected Leaks")
    y -= 20
    pdf.setFont("Helvetica", 10)
    pdf.drawString(80, y, f"Total leaks detected this week: {total}")
    y -= 20

    # --- Organized Severity Breakdown ---
    pdf.setFont("Helvetica", 10)
    col_x1, col_x2 = 100, 300
    line_height = 15
    levels = list(severities.items())
    half = (len(levels) + 1) // 2  # split into 2 columns
    left_col = levels[:half]
    right_col = levels[half:]

    for i in range(max(len(left_col), len(right_col))):
        if i < len(left_col):
            level, count = left_col[i]
            color = (
                "#4cffd0" if level == "low"
                else "#ffd84c" if level == "medium"
                else "#ff914c" if level == "high"
                else "#ff4c4c" if level == "critical"
                else "#808080"
            )
            pdf.setFillColor(color)
            pdf.circle(col_x1 - 10, y + 3, 3, stroke=0, fill=1)
            pdf.setFillColorRGB(0, 0, 0)
            label = "Unclassified" if level == "zero" else level.capitalize()
            pdf.drawString(col_x1, y, f"{label:<12}: {count}")

        if i < len(right_col):
            level, count = right_col[i]
            color = (
                "#4cffd0" if level == "low"
                else "#ffd84c" if level == "medium"
                else "#ff914c" if level == "high"
                else "#ff4c4c" if level == "critical"
                else "#808080"
            )
            pdf.setFillColor(color)
            pdf.circle(col_x2 - 10, y + 3, 3, stroke=0, fill=1)
            pdf.setFillColorRGB(0, 0, 0)
            label = "Unclassified" if level == "zero" else level.capitalize()
            pdf.drawString(col_x2, y, f"{label:<12}: {count}")

        y -= line_height
    y -= 10

    # --- Severity Distribution Chart ---
    if total > 0:
        order = ["critical", "high", "medium", "low", "zero"]
        display_labels = ["Critical", "High", "Medium", "Low", "Unclassified"]
        values = [severities.get(k, 0) for k in order]

        fig, ax = plt.subplots(figsize=(4.5, 2.5))
        ax.bar(display_labels, values, color=["#ff4c4c", "#ff914c", "#ffd84c", "#4cffd0", "#808080"])
        ax.set_title("Severity Distribution (Past 7 Days)")
        ax.set_xlabel("Severity Level")
        ax.set_ylabel("Number of Leaks")

        # Y-axis scaling: make it dynamic
        max_y = max(values) if any(values) else 1
        ax.set_ylim(0, max_y + 1)
        plt.tight_layout()

        img_buf = io.BytesIO()
        plt.savefig(img_buf, format="png")
        plt.close(fig)
        img_buf.seek(0)
        pdf.drawImage(ImageReader(img_buf), 80, y - 230, width=400, height=200)
        y -= 250


    # --- Chart 2: Leaks per Source ---
    if leaks:
        leak_sources = {}
        for leak in leaks:
            src = leak.source or "Unknown"
            leak_sources[src] = leak_sources.get(src, 0) + 1

        fig, ax = plt.subplots(figsize=(4, 2.5))
        ax.bar(leak_sources.keys(), leak_sources.values(), color="#004c99")
        ax.set_title("Leaks by Source (Past 7 Days)")
        ax.set_xlabel("Source")
        ax.set_ylabel("Count")
        plt.tight_layout()
        src_buf = io.BytesIO()
        plt.savefig(src_buf, format="png")
        plt.close(fig)
        src_buf.seek(0)
        pdf.drawImage(ImageReader(src_buf), 80, y - 220, width=400, height=200)
        y -= 250

    # --- Table of leaks ---
    pdf.setFont("Helvetica-Bold", 11)
    pdf.drawString(80, y, "Recent Leaks (Top 10):")
    y -= 18

    if leaks:
        # Table Header
        pdf.setFont("Helvetica-Bold", 9)
        pdf.drawString(80, y, "Timestamp")
        pdf.drawString(180, y, "Source")
        pdf.drawString(240, y, "Severity")
        pdf.drawString(340, y, "Snippet")
        y -= 10
        pdf.line(80, y, 520, y)
        y -= 13

        pdf.setFont("Helvetica", 9)
        for leak in leaks[:10]:
            ts = leak.timestamp.strftime("%Y-%m-%d %H:%M")
            snippet = (leak.data or "")[:40].replace("\n", " ") + "..."
            pdf.drawString(80, y, ts)
            pdf.drawString(180, y, (leak.source or "Unknown")[:10])
            pdf.drawString(240, y, (leak.severity or "Unclassified")[:10])
            pdf.drawString(340, y, snippet)
            y -= 12
            if y < 100:
                pdf.showPage()
                y = 740
    else:
        pdf.setFont("Helvetica", 9)
        pdf.drawString(100, y, "No new leaks found this week.")
        y -= 15

    # --- High-Risk Leaks Table (Medium and Above) ---
    high_risk_leaks = [
        leak for leak in leaks
        if (leak.severity or "").lower() in ("medium", "high", "critical")
    ]

    if high_risk_leaks:
        y -= 25
        pdf.setFont("Helvetica-Bold", 11)
        pdf.drawString(80, y, "High-Risk Leaks (Medium and Above):")
        y -= 15
        pdf.setFont("Helvetica-Bold", 9)
        pdf.drawString(80, y, "Timestamp")
        pdf.drawString(180, y, "Source")
        pdf.drawString(280, y, "Severity")
        pdf.drawString(360, y, "Snippet")
        y -= 12
        pdf.setFont("Helvetica", 9)
        for leak in high_risk_leaks[:10]:
            ts = leak.timestamp.strftime('%Y-%m-%d %H:%M')
            snippet = (leak.data or "")[:35].replace("\n", " ") + "..."
            pdf.drawString(80, y, ts)
            pdf.drawString(180, y, leak.source[:15])
            sev = (leak.severity or "").lower()
            color = (
                "#ff4c4c" if sev == "critical"
                else "#ff914c" if sev == "high"
                else "#ffd84c" if sev == "medium"
                else "#4cffd0" if sev == "low"
                else "#808080"
            )
            pdf.setFillColor(color)
            pdf.drawString(280, y, (leak.severity or "unknown").capitalize())
            pdf.setFillColorRGB(0, 0, 0)

            pdf.drawString(360, y, snippet)
            y -= 12
            if y < 100:
                pdf.showPage()
                y = 740



    # --- Short summary paragraph ---
    last_week_count = (
        db_session.query(func.count(Leak.id))
        .filter(
            Leak.user_id == user_id,
            Leak.timestamp < start_date,
            Leak.timestamp >= start_date - timedelta(days=7),
        )
        .scalar()
    ) or 0

    change = ((total - last_week_count) / max(last_week_count or 1, 1)) * 100
    trend = "increase" if change > 0 else "decrease" if change < 0 else "no change"

    top_source = (
        max(leak_sources, key=leak_sources.get) if leaks and leak_sources else "N/A"
    )

    pdf.setFont("Helvetica-Oblique", 10)
    pdf.drawString(
        80,
        y - 10,
        f"This week’s activity shows a {abs(change):.1f}% {trend} compared to last week. "
        f"Most leaks originated from {top_source}.",
    )
    top_severity = max(severities, key=severities.get)
    if top_severity in ("zero", "zero severity"):
        pdf.setFont("Helvetica-Oblique", 10)
        pdf.drawString(80, y - 25, "Note: All/Most detected leaks this week are unclassified and may require manual review.")

    # --- Footer ---
    pdf.setFont("Helvetica-Oblique", 8)
    pdf.drawString(80, 50, "Generated by Dark Web Risk Monitoring — Confidential Report")
    pdf.showPage()


# -----------------------------------------------------------
# INCIDENT RESPONSE REPORT
# -----------------------------------------------------------
# -----------------------------------------------------------
# INCIDENT RESPONSE REPORT (Multi-Leak Version)
# -----------------------------------------------------------
def generate_incident_report(pdf, db_session, user_id):
    pdf.setFont("Helvetica-Bold", 14)
    pdf.drawString(80, 760, "Dark Web Risk Monitoring — Incident Response Report")
    pdf.setFont("Helvetica", 10)
    pdf.drawString(80, 740, f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    pdf.drawString(80, 725, f"User ID: {user_id}")
    y = 700

    # --- Pull all relevant incidents (critical, high, medium)
    incidents = (
        db_session.query(Leak)
        .filter(Leak.user_id == user_id, Leak.severity.in_(["critical", "high", "medium"]))
        .order_by(Leak.timestamp.desc())
        .all()
    )

    if not incidents:
        pdf.setFont("Helvetica", 10)
        pdf.drawString(80, y, "No critical, high, or medium severity incidents found.")
        pdf.showPage()
        return

    for i, leak in enumerate(incidents):
        if y < 200:  # start a new page if running out of space
            pdf.showPage()
            y = 740

        pdf.setFont("Helvetica-Bold", 12)
        pdf.drawString(80, y, f"Incident #{i + 1} — ID {leak.id}")
        pdf.setFont("Helvetica", 10)
        y -= 15
        pdf.drawString(80, y, f"Detected: {leak.timestamp.strftime('%Y-%m-%d %H:%M')}")
        pdf.drawString(80, y - 15, f"Source: {leak.source}")

        # Color-coded severity label
        color = (
            "#ff4c4c" if leak.severity == "critical"
            else "#ff914c" if leak.severity == "high"
            else "#ffd84c"
        )
        pdf.setFillColor(color)
        pdf.drawString(80, y - 30, f"Severity: {leak.severity.upper()}")
        pdf.setFillColorRGB(0, 0, 0)
        y -= 55

        # --- Incident Summary
        pdf.setFont("Helvetica-Bold", 11)
        pdf.drawString(80, y, "Incident Summary:")
        pdf.setFont("Helvetica", 10)
        y -= 15
        summary = (
            f"A {leak.severity}-severity leak was detected on {leak.source}. "
            "It may contain sensitive data or credentials. Further review is recommended."
        )
        wrapped_summary = wrap(summary, width=90)
        for line in wrapped_summary:
            pdf.drawString(100, y, line)
            y -= 12
        y -= 10

        # --- Leak Details
        pdf.setFont("Helvetica-Bold", 11)
        pdf.drawString(80, y, "Leak Details:")
        y -= 15
        pdf.setFont("Helvetica", 9)
        snippet = (leak.data or "")[:200].replace("\n", " ") + "..."
        wrapped_snippet = wrap(snippet, width=95)
        for line in wrapped_snippet:
            pdf.drawString(100, y, line)
            y -= 11
        y -= 10

        # --- Risk Level Explanation
        pdf.setFont("Helvetica-Bold", 11)
        pdf.drawString(80, y, "Risk Level Explanation:")
        pdf.setFont("Helvetica", 10)
        y -= 15
        if leak.severity == "critical":
            explanation = "Critical: Contains credentials or domain references requiring immediate response."
        elif leak.severity == "high":
            explanation = "High: Includes sensitive information or internal identifiers."
        else:
            explanation = "Medium: Contains low-priority findings."
        wrapped_exp = wrap(explanation, width=90)
        for line in wrapped_exp:
            pdf.drawString(100, y, line)
            y -= 12
        y -= 10

        # --- Recommended Actions
        pdf.setFont("Helvetica-Bold", 11)
        pdf.drawString(80, y, "Recommended Actions:")
        pdf.setFont("Helvetica", 10)
        y -= 15
        actions = [
            "• Reset affected credentials immediately.",
            "• Notify internal IT and security teams.",
            "• Conduct further investigation on source platform.",
            "• Monitor related accounts for unusual activity.",
        ]
        for action in actions:
            pdf.drawString(100, y, action)
            y -= 12

        # --- Divider line between incidents
        y -= 15
        pdf.setLineWidth(0.5)
        pdf.setStrokeColorRGB(0.6, 0.6, 0.6)
        pdf.line(75, y, 525, y)
        pdf.setStrokeColorRGB(0, 0, 0)
        y -= 25

    # --- Footer
    pdf.setFont("Helvetica-Oblique", 8)
    pdf.drawString(80, 50, "Generated by Dark Web Risk Monitoring — Confidential Report")
    pdf.showPage()


# -----------------------------------------------------------
# RISK ASSESSMENT OVERVIEW
# -----------------------------------------------------------
def generate_risk_report(pdf, db_session, user_id):
    from textwrap import wrap
    now = datetime.now()
    start_date = now - timedelta(days=30)

    # --- Header ---
    pdf.setFont("Helvetica-Bold", 14)
    pdf.drawString(80, 760, f"Dark Web Risk Monitoring — Risk Assessment Overview")
    pdf.setFont("Helvetica", 10)
    pdf.drawString(80, 740, f"Reporting Period: {start_date.strftime('%b %d')}–{now.strftime('%b %d, %Y')}")
    y = 710

    # --- Query severity counts (last 30 days) ---
    severities = ["critical", "high", "medium", "low", "zero severity"]
    counts = {}
    for s in severities:
        if s == "zero severity":
            n = db_session.query(func.count(Leak.id)).filter(
                Leak.user_id == user_id,
                or_(Leak.severity == None, Leak.severity == "zero severity"),
                Leak.timestamp >= start_date
            ).scalar() or 0
        else:
            n = db_session.query(func.count(Leak.id)).filter(
                Leak.user_id == user_id,
                Leak.severity == s,
                Leak.timestamp >= start_date
            ).scalar() or 0
        counts[s] = n

    total = sum(counts.values())

    # --- Text summary of counts ---
    pdf.setFont("Helvetica", 10)
    pdf.drawString(80, y, f"Total leaks detected (past 30 days): {total}")
    y -= 15
    pdf.drawString(
        100, y,
        f"Critical: {counts['critical']} | High: {counts['high']} | "
        f"Medium: {counts['medium']} | Low: {counts['low']} | Unclassified: {counts['zero severity']}"
    )
    y -= 30

    # --- Pie Chart: Severity Breakdown ---
    if total > 0:
        pdf.setFont("Helvetica-Bold", 11)
        pdf.drawString(80, y, "Severity Breakdown (Last 30 Days):")
        y -= 15
        fig, ax = plt.subplots(figsize=(5, 3))
        labels = ["Critical", "High", "Medium", "Low", "Unclassified"]
        sizes = [
            counts["critical"], counts["high"], counts["medium"],
            counts["low"], counts["zero severity"]
        ]
        colors = ["#ff4c4c", "#ff914c", "#ffd84c", "#4cffd0", "#bfbfbf"]
        wedges, texts = ax.pie(sizes, colors=colors, startangle=90, wedgeprops=dict(width=0.6))
        ax.legend(
            wedges,
            [f"{l}: {s} ({(s / max(total, 1)) * 100:.1f}%)" for l, s in zip(labels, sizes)],
            loc="center left",
            bbox_to_anchor=(1.15, 0.5),
            fontsize=8
        )
        ax.set_title("Leak Severity Distribution")
        plt.subplots_adjust(left=0.1, right=0.8)
        img_buf = io.BytesIO()
        plt.savefig(img_buf, format="png", bbox_inches="tight")
        plt.close(fig)
        img_buf.seek(0)
        pdf.drawImage(ImageReader(img_buf), 70, y - 210, width=460, height=210)
        y -= 230
    else:
        pdf.setFont("Helvetica-Oblique", 10)
        pdf.drawString(100, y, "No severity data available in the past 30 days.")
        y -= 30

    # --- Top Risk Sources (where critical/high leaks came from) ---
    risk_sources = (
        db_session.query(Leak.source, func.count(Leak.id))
        .filter(
            Leak.user_id == user_id,
            Leak.severity.in_(["critical", "high"]),
            Leak.timestamp >= start_date
        )
        .group_by(Leak.source)
        .order_by(func.count(Leak.id).desc())
        .limit(5)
        .all()
    )

    if risk_sources:
        pdf.setFont("Helvetica-Bold", 11)
        pdf.drawString(80, y, "Top Risk Sources:")
        y -= 15
        fig, ax = plt.subplots(figsize=(3.5, 2))
        sources = [r[0] for r in risk_sources]
        values = [r[1] for r in risk_sources]
        ax.bar(sources, values, color="#ff4c4c")
        ax.set_ylabel("Leak Count")
        ax.set_title("Top Sources of High/Critical Leaks")
        ax.set_ylim(0, max(values) + 2)
        ax.set_yticks(range(0, max(values) + 3, max(1, (max(values) // 5) or 1)))

        plt.tight_layout()
        img_buf = io.BytesIO()
        plt.savefig(img_buf, format="png")
        plt.close(fig)
        img_buf.seek(0)
        pdf.drawImage(ImageReader(img_buf), 80, y - 170, width=390, height=170)
        y -= 190

    # --- Most Common Leak Categories (keyword scan in leak.data) ---
    leaks = (
        db_session.query(Leak)
        .filter(Leak.user_id == user_id, Leak.timestamp >= start_date)
        .all()
    )
    categories = {"credentials": 0, "email": 0, "api key": 0, "password": 0}
    for leak in leaks:
        data_text = (leak.data or "").lower()
        for key in categories:
            if key in data_text:
                categories[key] += 1

    if any(categories.values()):
        pdf.setFont("Helvetica-Bold", 11)
        pdf.drawString(80, y, "Most Common Leak Categories:")
        y -= 43

        fig, ax = plt.subplots(figsize=(4, 2.5))
        cat_labels = list(categories.keys())
        cat_values = list(categories.values())
        ax.barh(cat_labels, cat_values, color="#007acc")
        ax.set_xlabel("Mentions in Leaks")
        ax.set_title("Most Common Keywords in Leaks")
        plt.subplots_adjust(left=0.2, right=0.85, bottom=0.2, top=0.85)
        img_buf = io.BytesIO()
        plt.savefig(img_buf, format="png", bbox_inches="tight")
        plt.close(fig)
        img_buf.seek(0)
        pdf.drawImage(ImageReader(img_buf), 80, y - 160, width=400, height=200)
        y -= 270


    # --- Trend Chart: High/Critical over time ---
    trend_data = (
        db_session.query(
            func.date(Leak.timestamp),
            func.count(Leak.id)
        )
        .filter(
            Leak.user_id == user_id,
            Leak.timestamp >= start_date,
            Leak.severity.in_(["high", "critical"])
        )
        .group_by(func.date(Leak.timestamp))
        .order_by(func.date(Leak.timestamp))
        .all()
    )
    if trend_data:
        if y < 300:
            pdf.showPage()
            y = 740

        pdf.setFont("Helvetica-Bold", 11)
        pdf.drawString(80, y, "Trend: High-Risk Leaks Over Time")
        y -= 15

        dates = [str(d[0]) for d in trend_data]
        counts_over_time = [d[1] for d in trend_data]
        fig, ax = plt.subplots(figsize=(4.8, 3))
        ax.plot(dates, counts_over_time, marker="o", color="#ff4c4c", linewidth=1.5)
        ax.set_xticklabels(dates, rotation=45, ha="right", fontsize=8)
        ax.set_ylabel("Leak Count")
        ax.grid(True, linestyle="--", alpha=0.5)
        ax.set_title("High/Critical Leaks (Past 30 Days)")
        plt.tight_layout()

        img_buf = io.BytesIO()
        plt.savefig(img_buf, format="png")
        plt.close(fig)
        img_buf.seek(0)
        pdf.drawImage(ImageReader(img_buf), 80, y - 240, width=420, height=240)
        y -= 260


    # --- Summary paragraph ---
    last_month_total = (
        db_session.query(func.count(Leak.id))
        .filter(
            Leak.user_id == user_id,
            Leak.timestamp < start_date,
            Leak.timestamp >= start_date - timedelta(days=30)
        )
        .scalar()
        or 0
    )
    change = ((total - last_month_total) / max(last_month_total or 1, 1)) * 100
    trend = "increase" if change > 0 else "decrease" if change < 0 else "no change"
    summary = (
        f"Overall risk shows a {abs(change):.1f}% {trend} in total leaks compared to the previous month. "
        f"Most high-severity incidents originated from {risk_sources[0][0] if risk_sources else 'varied sources'}."
    )
    wrapped = wrap(summary, width=95)
    pdf.setFont("Helvetica-Oblique", 10)
    for line in wrapped:
        pdf.drawString(80, y, line)
        y -= 12

    # --- Footer ---
    pdf.setFont("Helvetica-Oblique", 8)
    pdf.drawString(80, 50, "Generated by Dark Web Risk Monitoring — Confidential Report")

    pdf.showPage()


# Config page routes
@app.route('/config')
def config_noext():
    return redirect('/config/')


@app.route('/config/')
@login_required
def config():
    username = session.get('username', 'User')
    return render_template('config.html', username=username)

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
    date_range = request.args.get('range', default='weekly', type=str)
    start_date = request.args.get('start', default=None, type=str)
    end_date = request.args.get('end', default=None, type=str)
    
    user_id = session.get("user_id")
    if not user_id:
        return jsonify({"error": "not authenticated"}), 401

    crits = get_critical_leaks(limit=limit, user_id=user_id)
    
    # Filter by date range if specified
    if date_range == 'custom' and start_date and end_date:
        from datetime import datetime
        try:
            start = datetime.fromisoformat(start_date)
            end = datetime.fromisoformat(end_date)
            crits = [c for c in crits if start_date <= (c.get('date') or c.get('timestamp', ''))[:10] <= end_date]
        except:
            pass  # If date parsing fails, return unfiltered
    elif date_range in ['daily', 'weekly', 'monthly']:
        from datetime import datetime, timedelta
        now = datetime.now()
        if date_range == 'daily':
            cutoff = now - timedelta(days=1)
        elif date_range == 'weekly':
            cutoff = now - timedelta(weeks=1)
        else:  # monthly
            cutoff = now - timedelta(days=30)
        
        cutoff_str = cutoff.strftime('%Y-%m-%d')
        crits = [c for c in crits if (c.get('date') or c.get('timestamp', ''))[:10] >= cutoff_str]
    
    return jsonify(crits)


# Alert history endpoint
@app.route("/api/alerts/history", methods=["GET"])
def api_alert_history():
    user_id = get_current_user_id()
    if not user_id:
        return jsonify({"error": "not authenticated"}), 401
    
    db = SessionLocal()
    try:
        alerts = db.query(AlertHistory).filter_by(user_id=user_id).order_by(AlertHistory.sent_at.desc()).limit(100).all()
        return jsonify([{
            'id': alert.id,
            'leak_id': alert.leak_id,
            'alert_type': alert.alert_type,
            'destination': alert.destination,
            'status': alert.status,
            'error_message': alert.error_message,
            'sent_at': alert.sent_at.isoformat() if alert.sent_at else None
        } for alert in alerts])
    finally:
        db.close()


# Risk summary aggregation
@app.route("/api/risk/summary", methods=["GET"])
def api_risk_summary():
    user_id = session.get('user_id')
    if not user_id:
        return jsonify({"error": "not authenticated"}), 401

    return jsonify(risk_summary(user_id=user_id))


@app.route("/api/risk/time_series", methods=["GET"])
def api_risk_time_series():
    """Return a daily overall risk score time series for the requesting user.

    Query params:
      - range: 'daily', 'weekly', 'monthly', or 'custom'
      - start: start date for custom range (YYYY-MM-DD)
      - end: end date for custom range (YYYY-MM-DD)
      - days: number of days back (legacy, overridden by range)
    """
    user_id = session.get('user_id')
    if not user_id:
        return jsonify({"error": "not authenticated"}), 401

    date_range = request.args.get('range', default='weekly', type=str)
    start_date = request.args.get('start', default=None, type=str)
    end_date = request.args.get('end', default=None, type=str)
    
    # Calculate days based on range
    if date_range == 'custom' and start_date and end_date:
        from datetime import datetime
        try:
            start = datetime.fromisoformat(start_date)
            end = datetime.fromisoformat(end_date)
            days = (end - start).days + 1
        except:
            days = 7
    elif date_range == 'daily':
        days = 1
    elif date_range == 'monthly':
        days = 30
    else:  # weekly
        days = 7
    
    try:
        series = risk_time_series(days=days, user_id=user_id)
        
        # Filter by custom date range if specified
        if date_range == 'custom' and start_date and end_date:
            series = [s for s in series if start_date <= s.get('date', '') <= end_date]
        
    except Exception as e:
        return jsonify({"error": "failed to compute time series", "message": str(e)}), 500
    return jsonify(series)


@app.route("/api/risk/severity_time_series", methods=["GET"])
def api_risk_severity_time_series():
    """Return daily severity counts for the requesting user.

    Query params:
      - range: 'daily', 'weekly', 'monthly', or 'custom'
      - start: start date for custom range (YYYY-MM-DD)
      - end: end date for custom range (YYYY-MM-DD)
      - days: number of days back (legacy, overridden by range)
    """
    user_id = session.get('user_id')
    if not user_id:
        return jsonify({"error": "not authenticated"}), 401

    date_range = request.args.get('range', default='weekly', type=str)
    start_date = request.args.get('start', default=None, type=str)
    end_date = request.args.get('end', default=None, type=str)
    
    # Calculate days based on range
    if date_range == 'custom' and start_date and end_date:
        from datetime import datetime
        try:
            start = datetime.fromisoformat(start_date)
            end = datetime.fromisoformat(end_date)
            days = (end - start).days + 1
        except:
            days = 7
    elif date_range == 'daily':
        days = 1
    elif date_range == 'monthly':
        days = 30
    else:  # weekly
        days = 7
    
    try:
        series = severity_time_series(days=days, user_id=user_id)
        
        # Filter by custom date range if specified
        if date_range == 'custom' and start_date and end_date:
            series = [s for s in series if start_date <= s.get('date', '') <= end_date]
        
    except Exception as e:
        return jsonify({"error": "failed to compute severity time series", "message": str(e)}), 500
    return jsonify(series)


@app.route("/api/risk/top_assets", methods=["GET"])
def api_risk_top_assets():
    """Return top-N risky assets for the requesting user.

    Query params:
      - limit: number of assets to return (default 10)
    """
    user_id = session.get('user_id')
    if not user_id:
        return jsonify({"error": "not authenticated"}), 401

    limit = request.args.get('limit', default=10, type=int)
    try:
        session_db = SessionLocal()
        try:
            user_assets = session_db.query(Asset).filter(Asset.user_id == user_id).all()
        finally:
            session_db.close()

        # If no user watchlist assets, return empty list
        if not user_assets:
            return jsonify([])

        # Fetch all leaks for this user to compute counts
        leaks = get_leaks_for_user(user_id)

        results = []
        for a in user_assets:
            a_type = (a.type or '').lower()
            a_value = a.value
            leak_count = 0
            crit_hit = False

            for leak in leaks:
                norm = getattr(leak, 'normalized', {}) or {}
                ents = (norm or {}).get('entities') or {}

                matched = False
                # Non-sensitive direct comparisons
                if a_type in ('email', 'domain', 'ip', 'btc'):
                    key_map = {
                        'email': 'emails',
                        'domain': 'domains',
                        'ip': 'ips',
                        'btc': 'btc_wallets'
                    }
                    vals = ents.get(key_map.get(a_type, ''), []) or []
                    for v in vals:
                        if isinstance(v, str) and v.lower().strip() == a_value:
                            matched = True
                            break

                # Sensitive types: compare by hashing the normalized leak value
                if not matched and a_type in ('ssn', 'phone', 'name', 'address', 'btc'):
                    # handle ssn
                    if a_type == 'ssn' and leak.ssn:
                        candidate = normalize_asset_value('ssn', str(leak.ssn))
                        if hash_sensitive_value(candidate) == a_value:
                            matched = True
                    if a_type == 'phone' and leak.phone_numbers:
                        try:
                            import json as _json
                            parsed = _json.loads(leak.phone_numbers) if isinstance(leak.phone_numbers, str) else leak.phone_numbers
                        except Exception:
                            parsed = [leak.phone_numbers]
                        for p in (parsed or []):
                            cand = normalize_asset_value('phone', str(p))
                            if hash_sensitive_value(cand) == a_value:
                                matched = True
                                break
                    if a_type == 'name' and leak.names:
                        try:
                            import json as _json
                            parsed = _json.loads(leak.names) if isinstance(leak.names, str) else leak.names
                        except Exception:
                            parsed = [leak.names]
                        for n in (parsed or []):
                            cand = normalize_asset_value('name', str(n))
                            if hash_sensitive_value(cand) == a_value:
                                matched = True
                                break
                    if a_type == 'address' and leak.physical_addresses:
                        try:
                            import json as _json
                            parsed = _json.loads(leak.physical_addresses) if isinstance(leak.physical_addresses, str) else leak.physical_addresses
                        except Exception:
                            parsed = [leak.physical_addresses]
                        for addr in (parsed or []):
                            cand = normalize_asset_value('address', str(addr))
                            if hash_sensitive_value(cand) == a_value:
                                matched = True
                                break

                if matched:
                    leak_count += 1
                    if (leak.severity or '').lower() == 'critical':
                        crit_hit = True

            # Derive simple risk tier
            if crit_hit:
                risk = 'high'
            elif leak_count >= 5:
                risk = 'medium'
            elif leak_count >= 1:
                risk = 'low'
            else:
                risk = 'none'

            results.append({'type': a_type, 'value': a_value, 'risk': risk, 'leak_count': leak_count})

        # Sort and return top-N
        order = {'high': 0, 'medium': 1, 'low': 2, 'none': 3}
        results.sort(key=lambda r: (order.get(r['risk'], 9), -r['leak_count'], r['value']))
        return jsonify(results[:limit])
    except Exception as e:
        return jsonify({"error": "failed to fetch top assets", "message": str(e)}), 500


# Batch webhook notification (manual trigger or can be scheduled)
@app.route("/api/alerts/send_batch", methods=["POST"])
def api_send_batch_webhook():
    """Send a single batch notification summarizing non-alerted leaks above threshold"""
    user_id = get_current_user_id()
    if not user_id:
        return jsonify({"error": "not authenticated"}), 401
    
    db = SessionLocal()
    try:
        # Get user's webhook config (use user_id as org_id)
        config_obj = db.query(Config).filter_by(org_id=user_id).first()
        if not config_obj:
            # Try with default org_id 123 (fallback for testing)
            config_obj = db.query(Config).filter_by(org_id=123).first()
            if not config_obj:
                return jsonify({"error": "no config found - please save your alert settings first"}), 404
        
        config_data = config_obj.config_data
        alerts_config = config_data.get('alerts', {})
        
        if not alerts_config.get('enabled', False):
            return jsonify({"error": "alerts not enabled"}), 400
        
        webhook_url = alerts_config.get('webhook', '').strip()
        if not webhook_url:
            return jsonify({"error": "no webhook URL configured"}), 400
        
        # Get threshold setting
        threshold = alerts_config.get('threshold', 'critical')
        # Map threshold label to minimum score
        # critical=100, high=75, medium=50, low=25, zero=0
        threshold_map = {'critical': 100, 'high': 75, 'medium': 50, 'low': 25}
        min_severity_score = threshold_map.get(threshold, 100)
        
        # Find all non-alerted leaks above threshold (excluding zero severity)
        from backend.severity import severity_label_to_score
        
        # Get all user's non-alerted leaks
        all_leaks = db.query(Leak).filter(
            Leak.user_id == user_id,
            Leak.alerted == 0
        ).all()
        
        # Filter by severity threshold
        leaks_to_alert = []
        for leak in all_leaks:
            severity_score = severity_label_to_score(leak.severity or 'info')
            if severity_score >= min_severity_score and severity_score > 0:
                leaks_to_alert.append(leak)
        
        if not leaks_to_alert:
            return jsonify({"status": "no new leaks to report above threshold"})
        
        # Group by severity
        severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        for leak in leaks_to_alert:
            sev_label = (leak.severity or 'info').lower()
            if sev_label in severity_counts:
                severity_counts[sev_label] += 1
        
        # Check if it's a Discord webhook
        is_discord = 'discord.com/api/webhooks' in webhook_url.lower()
        
        if is_discord:
            # Build fields array for non-zero severities
            fields = []
            severity_emoji = {
                'critical': '🔴',
                'high': '🟠',
                'medium': '🟡',
                'low': '🟢'
            }
            for sev in ['critical', 'high', 'medium', 'low']:
                count = severity_counts.get(sev, 0)
                if count > 0:
                    fields.append({
                        'name': f'{severity_emoji[sev]} {sev.capitalize()}',
                        'value': f'{count} leak(s)',
                        'inline': True
                    })
            
            total_count = len(leaks_to_alert)
            webhook_payload = {
                'username': 'DarkWidow Alert Digest',
                'avatar_url': 'https://i.imgur.com/4M34hi2.png',
                'embeds': [{
                    'title': '📊 Leak Detection Summary',
                    'description': f'**{total_count}** leak(s) detected above {threshold} threshold.',
                    'color': 15158332 if severity_counts.get('critical', 0) > 0 else 16744192,  # Red if critical, orange otherwise
                    'fields': fields,
                    'timestamp': datetime.utcnow().isoformat() + 'Z',
                    'footer': {
                        'text': 'DarkWidow Security Platform - Batch Digest'
                    }
                }]
            }
        else:
            # Generic webhook format
            webhook_payload = {
                'alert_type': 'batch_summary',
                'threshold': threshold,
                'timestamp': datetime.utcnow().isoformat(),
                'total_leaks': len(leaks_to_alert),
                'severity_breakdown': severity_counts
            }
        
        # Send webhook
        try:
            response = requests.post(
                webhook_url,
                json=webhook_payload,
                headers={'Content-Type': 'application/json'},
                timeout=10
            )
            
            if response.status_code < 400:
                # Mark all alerted leaks as alerted and save to history
                for leak in leaks_to_alert:
                    leak.alerted = 1
                    # Add to alert history
                    history_entry = AlertHistory(
                        leak_id=leak.id,
                        user_id=user_id,
                        alert_type='webhook',
                        destination=webhook_url,
                        status='sent',
                        error_message=None,
                        sent_at=datetime.utcnow()
                    )
                    db.add(history_entry)
                db.commit()
                
                return jsonify({
                    "status": "sent",
                    "leaks_count": len(leaks_to_alert),
                    "severity_breakdown": severity_counts
                })
            else:
                return jsonify({
                    "status": "failed",
                    "leaks_count": len(leaks_to_alert),
                    "severity_breakdown": severity_counts,
                    "error": f"HTTP {response.status_code}"
                })
            
        except Exception as e:
            return jsonify({
                "status": "failed",
                "error": str(e)
            }), 500
            
    finally:
        db.close()


# Webhook alerting function
def send_webhook_alert(leak_id: int, user_id: int, severity: int, title: str, source: str):
    """Send immediate batch webhook notification for newly detected leaks"""
    import threading
    
    def _send_async():
        db = SessionLocal()
        try:
            # Get user's webhook config
            config_obj = db.query(Config).filter_by(org_id=user_id).first()
            if not config_obj:
                return
            
            config_data = config_obj.config_data
            alerts_config = config_data.get('alerts', {})
            
            if not alerts_config.get('enabled', False):
                return
            
            # Check notification mode - skip if periodic batch mode
            notification_mode = alerts_config.get('notification_mode', 'immediate')
            if notification_mode != 'immediate':
                return  # Periodic batch mode will handle this via scheduled checks
            
            # In immediate mode, trigger batch webhook for all non-alerted leaks above threshold
            webhook_url = alerts_config.get('webhook', '').strip()
            if not webhook_url:
                return
            
            # Get threshold setting
            threshold = alerts_config.get('threshold', 'critical')
            # Map threshold label to minimum score
            # critical=100, high=75, medium=50, low=25, zero=0
            threshold_map = {'critical': 100, 'high': 75, 'medium': 50, 'low': 25}
            min_severity_score = threshold_map.get(threshold, 100)
            
            # Find all non-alerted leaks above threshold
            from backend.severity import severity_label_to_score
            
            all_leaks = db.query(Leak).filter(
                Leak.user_id == user_id,
                Leak.alerted == 0
            ).all()
            
            leaks_to_alert = []
            for leak in all_leaks:
                severity_score = severity_label_to_score(leak.severity or 'info')
                if severity_score >= min_severity_score and severity_score > 0:
                    leaks_to_alert.append(leak)
            
            if not leaks_to_alert:
                return
            
            # Group by severity
            severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
            for leak in leaks_to_alert:
                sev_label = (leak.severity or 'info').lower()
                if sev_label in severity_counts:
                    severity_counts[sev_label] += 1
            
            # Check if it's a Discord webhook
            is_discord = 'discord.com/api/webhooks' in webhook_url.lower()
            
            if is_discord:
                fields = []
                severity_emoji = {'critical': '🔴', 'high': '🟠', 'medium': '🟡', 'low': '🟢'}
                for sev in ['critical', 'high', 'medium', 'low']:
                    count = severity_counts.get(sev, 0)
                    if count > 0:
                        fields.append({
                            'name': f'{severity_emoji[sev]} {sev.capitalize()}',
                            'value': f'{count} leak(s)',
                            'inline': True
                        })
                
                total_count = len(leaks_to_alert)
                webhook_payload = {
                    'username': 'DarkWidow Alert',
                    'avatar_url': 'https://i.imgur.com/4M34hi2.png',
                    'embeds': [{
                        'title': '🚨 New Leaks Detected',
                        'description': f'**{total_count}** new leak(s) detected above {threshold} threshold.',
                        'color': 15158332 if severity_counts.get('critical', 0) > 0 else 16744192,
                        'fields': fields,
                        'timestamp': datetime.utcnow().isoformat() + 'Z',
                        'footer': {
                            'text': 'DarkWidow Security Platform - Immediate Alert'
                        }
                    }]
                }
            else:
                webhook_payload = {
                    'alert_type': 'immediate_batch',
                    'threshold': threshold,
                    'timestamp': datetime.utcnow().isoformat(),
                    'total_leaks': len(leaks_to_alert),
                    'severity_breakdown': severity_counts
                }
            
            # Send webhook
            try:
                response = requests.post(
                    webhook_url,
                    json=webhook_payload,
                    headers={'Content-Type': 'application/json'},
                    timeout=10
                )
                
                if response.status_code < 400:
                    # Mark all alerted leaks as alerted and add to history
                    for leak in leaks_to_alert:
                        leak.alerted = 1
                        # Log alert history for each leak
                        alert_record = AlertHistory(
                            leak_id=leak.id,
                            user_id=user_id,
                            alert_type='webhook',
                            destination=webhook_url,
                            status='sent',
                            error_message=None,
                            sent_at=datetime.utcnow()
                        )
                        db.add(alert_record)
                    db.commit()
                else:
                    # Log failed alert for each leak
                    for leak in leaks_to_alert:
                        alert_record = AlertHistory(
                            leak_id=leak.id,
                            user_id=user_id,
                            alert_type='webhook',
                            destination=webhook_url,
                            status='failed',
                            error_message=f"HTTP {response.status_code}",
                            sent_at=datetime.utcnow()
                        )
                        db.add(alert_record)
                    db.commit()
                
            except Exception as e:
                # Log failed alert for each leak
                for leak in leaks_to_alert:
                    alert_record = AlertHistory(
                        leak_id=leak.id,
                        user_id=user_id,
                        alert_type='webhook',
                        destination=webhook_url,
                        status='failed',
                        error_message=str(e),
                        sent_at=datetime.utcnow()
                    )
                    db.add(alert_record)
                db.commit()
                
        finally:
            db.close()
    
    # Send webhook asynchronously to avoid blocking the request
    thread = threading.Thread(target=_send_async)
    thread.daemon = True
    thread.start()


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

    user_id = get_current_user_id()
    if not user_id:
        return jsonify({"error": "not authenticated"}), 401

    # Auto-compute severity using watchlist (assets) if not provided
    if not severity:
        try:
            from backend.severity import compute_severity_with_assets
            from backend.database import get_asset_sets_for_user
            
            # Get user's watchlist/assets for severity computation
            assets_sets = get_asset_sets_for_user(user_id)
            
            # Compute severity with watchlist matching (gives higher scores to matched assets)
            severity = compute_severity_with_assets(entities, assets_sets)
            
            # Convert severity label to numeric score for webhook threshold check
            severity_map = {'zero severity': 0, 'low': 25, 'medium': 50, 'high': 75, 'critical': 90}
            severity_score = severity_map.get(severity, 0)
        except (TypeError, ValueError, KeyError) as e:
            # Fallback to basic entity-based severity if watchlist computation fails
            from backend.severity import compute_severity_from_entities
            severity = compute_severity_from_entities(entities)
            severity_map = {'zero severity': 0, 'low': 25, 'medium': 50, 'high': 75, 'critical': 90}
            severity_score = severity_map.get(severity, 0)
    else:
        # Severity provided in payload
        severity_score = severity if isinstance(severity, int) else 0

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

    # Send webhook alert if this is a new critical leak (severity_score >= 70)
    if not is_dup and severity_score >= 70:  # Critical threshold
        send_webhook_alert(leak_id, user_id, severity_score, title or "Untitled", source)

    status = "duplicate" if is_dup else "accepted"
    resp = {"status": status, "id": leak_id, "severity": severity, "severity_score": severity_score}
    return jsonify(resp), 202


# Seed mock leaks: one per crawler type, built dynamically to avoid repeats
@app.route("/api/leaks/mock", methods=["POST"])
def api_leaks_insert_mock():
    uid = get_current_user_id()
    if not uid:
        return jsonify({"error": "not authenticated"}), 401

    # Helper generators to ensure dynamic, low-collision mock data
    def rand_digits(n=6):
        return ''.join(random.choice(string.digits) for _ in range(n))

    def rand_word(n=6):
        letters = 'abcdefghijklmnopqrstuvwxyz'
        return ''.join(random.choice(letters) for _ in range(n))

    def rand_domain():
        return f"{rand_word(random.randint(5,10))}.com"

    def rand_email():
        return f"{rand_word(random.randint(4,8))}@{rand_domain()}"

    def rand_ipv4():
        # Use TEST-NET-3 203.0.113.0/24 per RFC 5737
        return f"203.0.113.{random.randint(1,254)}"

    def rand_btc():
        alpha = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l'  # bech32 charset (subset)
        return 'bc1q' + ''.join(random.choice(alpha) for _ in range(38))

    def rand_name():
        first = random.choice(["alex","sam","jordan","taylor","morgan","riley","casey","jamie"]) 
        last = random.choice(["lee","smith","johnson","brown","davis","miller","wilson","clark"]) 
        return f"{first} {last}"

    def rand_ssn():
        # 9 digits, avoid all-zero groups
        a = random.randint(100,899)
        b = random.randint(10,99)
        c = random.randint(1000,9999)
        return f"{a:03d}{b:02d}{c:04d}"

    def rand_phone():
        # 10 digits, avoid obviously invalid with a simple format; return digits
        return f"{random.randint(200,999)}{random.randint(200,999)}{random.randint(1000,9999)}"

    # Build 4 dynamic samples each call
    email = rand_email()
    domain = email.split('@')[-1]
    password = secrets.token_hex(3)
    ip = rand_ipv4()
    btc = rand_btc()
    name = rand_name()
    ssn = rand_ssn()
    phone = rand_phone()

    samples = [
        # Pastebin: email + domain + password
        {
            "source": "pastebin",
            "url": f"https://pastebin.com/{secrets.token_hex(4)}",
            "title": f"Credentials dump for {domain}",
            "content": f"Login for {email} password: {password}\nAdditional lines {secrets.token_hex(4)}...",
            "entities": {
                "emails": [email],
                "domains": [domain],
                "ips": [],
                "btc_wallets": [],
                "ssns": [],
                "phone_numbers": [],
                "passwords": [password],
                "physical_addresses": [],
                "names": []
            },
            "passwords": [password]
        },
        # GitHub: domain + IP
        {
            "source": "github",
            "url": f"https://github.com/{rand_word(6)}/{rand_word(5)}/blob/main/{rand_word(5)}.yml",
            "title": f"Config leak for {domain} with admin IP",
            "content": f"production: domain: {domain}\nadmin_ip: {ip}",
            "entities": {
                "emails": [],
                "domains": [domain],
                "ips": [ip],
                "btc_wallets": [],
                "ssns": [],
                "phone_numbers": [],
                "passwords": [],
                "physical_addresses": [],
                "names": []
            }
        },
        # Tor: BTC + name
        {
            "source": "tor",
            "url": f"http://{rand_word(16)}.onion/{rand_word(5)}",
            "title": "Onion forum post with BTC and name",
            "content": f"Payment to {btc} by user {name}.",
            "entities": {
                "emails": [],
                "domains": [],
                "ips": [],
                "btc_wallets": [btc],
                "ssns": [],
                "phone_numbers": [],
                "passwords": [],
                "physical_addresses": [],
                "names": [name.lower()]
            },
            "names": [name.lower()]
        },
        # I2P: SSN + phone
        {
            "source": "i2p",
            "url": f"http://{rand_word(6)}.i2p/{rand_word(4)}",
            "title": "I2P leak with SSN and phone",
            "content": f"Employee SSN {ssn[:3]}-{ssn[3:5]}-{ssn[5:]} and phone ({phone[:3]}) {phone[3:6]}-{phone[6:]} recorded.",
            "entities": {
                "emails": [],
                "domains": [],
                "ips": [],
                "btc_wallets": [],
                "ssns": [ssn],
                "phone_numbers": [phone],
                "passwords": [],
                "physical_addresses": [],
                "names": []
            },
            "ssn": [ssn],
            "phone_numbers": [phone]
        }
    ]

    from backend.database import insert_leak_with_dedupe
    inserted = []
    dupes = 0
    for s in samples:
        try:
            text = s["content"] or ""
            # hash incorporates random content ensuring low chance of duplicates
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

    # Accept optional limit in JSON body, otherwise use user's saved config
    limit = None  # Let crawler load from user config
    if request.is_json:
        body = request.get_json(silent=True) or {}
        if 'limit' in body:
            try:
                limit = int(body.get('limit'))
            except (TypeError, ValueError):
                pass
    try:
        # Pass limit=None to use user's config, or explicit limit if provided
        inserted = pastebin_fetch(limit=limit, user_id=current_user_id)
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


# (Freenet endpoints removed)



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
        else:
            # If no API key provided, use first available user as fallback for crawler events
            # This allows crawlers to function without explicit API key configuration
            db = SessionLocal()
            try:
                first_user = db.query(User).order_by(User.id).first()
                if first_user:
                    g.current_user_id = first_user.id
            finally:
                db.close()
    except Exception:
        pass

    return api_leaks_ingest()


def sync_watchlist_to_assets(user_id: int, watchlist: dict, db_session):
    """Sync watchlist configuration to Asset table for severity computation.
    
    This allows the watchlist to be used for:
    1. Real-time severity scoring during leak insertion
    2. Retroactive severity recomputation when watchlist changes
    
    Args:
        user_id: The user ID to associate assets with
        watchlist: Dictionary containing watchlist arrays by type
        db_session: Active SQLAlchemy session
    """
    if not watchlist:
        return
    
    # Map watchlist keys to asset types
    watchlist_to_asset_type = {
        'domains': 'domain',
        'emails': 'email',
        'ips': 'ip',
        'btc_wallets': 'btc',
        'names': 'name',
        'ssns': 'ssn',
        'passwords': 'password',
        'phone_numbers': 'phone',
        'physical_addresses': 'address'
    }
    
    # Tag to identify assets synced from watchlist (for cleanup)
    watchlist_tag = 'watchlist_sync'
    
    # Remove old watchlist-synced assets to avoid duplicates
    db_session.query(Asset).filter(
        Asset.user_id == user_id,
        Asset.type.in_(watchlist_to_asset_type.values())
    ).delete(synchronize_session=False)
    
    # Add new assets from watchlist
    for watchlist_key, asset_type in watchlist_to_asset_type.items():
        values = watchlist.get(watchlist_key, [])
        if not values:
            continue
        
        for value in values:
            if not value or not str(value).strip():
                continue
            
            # Values are already hashed for sensitive types (done before this function)
            # For non-sensitive types, normalize to lowercase
            if asset_type in ['email', 'domain', 'ip']:
                normalized_value = str(value).strip().lower()
            else:
                normalized_value = str(value).strip()
            
            # Create asset entry
            asset = Asset(
                type=asset_type,
                value=normalized_value,
                user_id=user_id
            )
            db_session.add(asset)
    
    try:
        db_session.commit()
    except Exception as e:
        db_session.rollback()
        print(f"Error syncing watchlist to assets: {e}")


# Config routes with database persistence
@app.route("/v1/config/org/<int:org_id>", methods=["GET", "POST"])
def get_config(org_id):
    if request.method == "POST":
        # Save config
        user_id = get_current_user_id()
        if not user_id:
            return jsonify({"error": "not authenticated"}), 401
        
        try:
            config_data = request.json or {}
            
            # Hash sensitive watchlist data before storing
            watchlist = config_data.get('watchlist', {})
            if watchlist:
                # Sensitive fields that should be hashed
                sensitive_fields = ['ssns', 'passwords', 'phone_numbers', 'physical_addresses', 'names']
                for field in sensitive_fields:
                    if field in watchlist and watchlist[field]:
                        # Hash each value in the list (skip if already hashed - 64 char hex string)
                        hashed_values = []
                        for val in watchlist[field]:
                            if val and str(val).strip():
                                val_str = str(val).strip()
                                # Check if already a SHA-256 hash (64 hex chars)
                                if len(val_str) == 64 and all(c in '0123456789abcdef' for c in val_str.lower()):
                                    # Already hashed, keep as-is
                                    hashed_values.append(val_str)
                                else:
                                    # New plaintext value, hash it
                                    hashed_values.append(
                                        hashlib.sha256(val_str.encode('utf-8')).hexdigest()
                                    )
                        watchlist[field] = hashed_values
            
            db = SessionLocal()
            try:
                config_obj = db.query(Config).filter_by(org_id=org_id).first()
                if config_obj:
                    config_obj.config_data = config_data
                    config_obj.updated_at = datetime.utcnow()
                else:
                    config_obj = Config(org_id=org_id, config_data=config_data)
                    db.add(config_obj)
                db.commit()
                
                # Sync watchlist to Assets table for severity computation
                sync_watchlist_to_assets(user_id, watchlist, db)
                
                # Recompute severity scores for all user leaks with new watchlist
                from backend.database import recompute_severity_for_user_leaks
                updated_leaks = recompute_severity_for_user_leaks(user_id)
                
                # Trigger immediate alerts if enabled and leaks were updated
                if updated_leaks > 0:
                    alerts_cfg = config_data.get('alerts', {})
                    notification_mode = alerts_cfg.get('notification_mode', 'immediate')
                    if notification_mode == 'immediate' and alerts_cfg.get('enabled', False):
                        # Check if any updated leaks meet threshold and trigger batch alert
                        webhook_url = alerts_cfg.get('webhook', '').strip()
                        if webhook_url:
                            print(f"Severity updated for {updated_leaks} leaks, triggering immediate batch alert")
                            # Trigger async to avoid blocking config save
                            import threading
                            def trigger_alert():
                                try:
                                    # Use the send_webhook_alert logic (it already batches in immediate mode)
                                    from backend.database import get_leaks_for_user
                                    leaks = get_leaks_for_user(user_id)
                                    if leaks:
                                        # Trigger for the first leak (will batch all non-alerted leaks)
                                        send_webhook_alert(leaks[0].id, user_id, 0, '', '')
                                except Exception as e:
                                    print(f"Error triggering immediate alert after severity update: {e}")
                            threading.Thread(target=trigger_alert, daemon=True).start()
                
                return jsonify({
                    "status": "saved",
                    "config": config_data,
                    "updated_leaks": updated_leaks,
                    "message": f"Config saved and {updated_leaks} leak severity scores updated"
                })
            finally:
                db.close()
        except Exception as e:
            import traceback
            print(f"Error saving config: {str(e)}")
            print(traceback.format_exc())
            return jsonify({"error": str(e)}), 400
    
    # GET: Return stored config or defaults
    db = SessionLocal()
    try:
        config_obj = db.query(Config).filter_by(org_id=org_id).first()
        if config_obj:
            return jsonify(config_obj.config_data)
    finally:
        db.close()
    
    # Default config
    return jsonify({
        "api": {
            "events_url": "http://127.0.0.1:5000/v1/events"
        },
        "watchlist": {
            "domains": ["example.com", "test.org"],
            "emails": ["admin@example.com"],
            "ips": [],
            "btc_wallets": [],
            "names": [],
            "keywords": ["password", "login", "shadow"],
            "ssns": [],
            "passwords": [],
            "phone_numbers": [],
            "physical_addresses": []
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
                    "password", "apikey", "secret", "aws_access_key_id", "private_key", "api_key", "token", "database", "credential", "access_key"
                ]
            }
        },
        "alerts": {
            "enabled": True,
            "threshold": "critical",
            "email": "",
            "webhook": "",
            "notification_mode": "immediate",
            "check_interval_min": 15
        }
    })

@app.route("/v1/config/org/<int:org_id>/reset", methods=["POST"])
def reset_config(org_id):
    user_id = get_current_user_id()
    if not user_id:
        return jsonify({"error": "not authenticated"}), 401
    
    # Remove custom config to force defaults
    db = SessionLocal()
    try:
        config_obj = db.query(Config).filter_by(org_id=org_id).first()
        if config_obj:
            db.delete(config_obj)
            db.commit()
    finally:
        db.close()
    
    return jsonify({"status": "reset"})

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
    # Use permanent sessions so PERMANENT_SESSION_LIFETIME is applied.
    session.permanent = True
    # mark modified so cookie expiry is refreshed immediately
    session.modified = True

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
        
        # Get the user object for Flask-Login
        user = session_db.query(User).filter_by(id=user_id).first()
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
    
    # Log in the user using Flask-Login
    login_user(user)
    # Use permanent sessions so PERMANENT_SESSION_LIFETIME is applied
    session.permanent = True
    # Mark modified so cookie expiry is refreshed immediately
    session.modified = True
    
    session['logged_in'] = True
    session['username'] = username
    session['user_id'] = user_id
    flash("Registration successful! Welcome, {}!".format(username), "success")
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

@app.route('/api/check_username')
def api_check_username():
    # lightweight availability check for username
    from backend.database import SessionLocal, User  # local import to avoid circular
    username = (request.args.get('username') or '').strip()
    if not username:
        return jsonify({"available": False, "error": "username required"}), 400
    session_db = SessionLocal()
    try:
        exists = session_db.query(User.id).filter(User.username == username).first() is not None
    finally:
        session_db.close()
    return jsonify({"available": not exists})

@app.route('/api/me')
@login_required
def api_get_current_user():
    """Return current authenticated user's ID and username"""
    return jsonify({
        "user_id": current_user.id,
        "username": current_user.username
    })

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
    # Debug: log session information to help diagnose why deletion may fail
    try:
        print(f"[DEBUG] /api/account/delete called, session_keys={list(session.keys())}, user_id={session.get('user_id')}")
    except Exception:
        print("[DEBUG] /api/account/delete called, unable to read session keys")

    # CSRF protection: expect token in JSON body or X-CSRF-Token header
    data = request.get_json(silent=True) or {}
    token = data.get('csrf_token') or request.headers.get('X-CSRF-Token')
    if not validate_csrf(token):
        return jsonify({"status": "error", "message": "Invalid CSRF token"}), 400

    user_id = session.get("user_id")
    if not user_id:
        return jsonify({"status": "error", "message": "Not authenticated"}), 401
    from backend.database import delete_user
    try:
        ok = delete_user(user_id)
    except Exception as e:
        # Log the exception for debugging and return error to client
        import traceback
        traceback.print_exc()
        return jsonify({"status": "error", "message": "Server error during deletion."}), 500
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


# -----------------------------------------------------------
# CUSTOM PDF BUILDER ROUTES
# -----------------------------------------------------------
@app.route('/reports/custom')
def custom_report():
    """Page for building custom PDFs."""
    username = session.get('username', 'User')
    return render_template('custom_report.html', username=username)


@app.route('/api/reports/preview', methods=['POST'])
def preview_custom_report():
    """Generate a preview of the custom PDF."""
    user_id = getattr(current_user, "id", None) or session.get("user_id")
    if not user_id:
        return jsonify({"error": "Unauthorized"}), 401
    
    try:
        config = request.get_json()
        if not config:
            return jsonify({"error": "No configuration provided"}), 400
        
        # Generate PDF
        pdf_bytes = create_pdf_from_config(config)
        
        # Convert to base64 for preview
        pdf_base64 = base64.b64encode(pdf_bytes).decode('utf-8')
        
        return jsonify({
            "success": True,
            "pdf_data": pdf_base64
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/api/reports/download', methods=['POST'])
def download_custom_report():
    """Download the custom PDF."""
    user_id = getattr(current_user, "id", None) or session.get("user_id")
    username = getattr(current_user, "username", "User")
    
    if not user_id:
        return "Unauthorized - please log in first", 401
    
    try:
        config = request.get_json()
        if not config:
            return "No configuration provided", 400
        
        # Generate PDF
        pdf_bytes = create_pdf_from_config(config)
        
        # Create response
        response = make_response(pdf_bytes)
        response.headers["Content-Type"] = "application/pdf"
        
        # Get filename from config or use default
        filename = config.get('filename', f'{username}_custom_report')
        if not filename.endswith('.pdf'):
            filename += '.pdf'
            
        response.headers["Content-Disposition"] = f"attachment; filename={filename}"
        return response
    except Exception as e:
        return f"Error generating PDF: {str(e)}", 500


@app.route('/api/reports/save', methods=['POST'])
def save_custom_report():
    """Save a PDF configuration for later use."""
    user_id = getattr(current_user, "id", None) or session.get("user_id")
    
    if not user_id:
        return jsonify({"error": "Unauthorized"}), 401
    
    db_session = SessionLocal()
    try:
        config = request.get_json()
        if not config:
            return jsonify({"error": "No configuration provided"}), 400
        
        title = config.get('title', 'Untitled Report')
        filename = config.get('filename', 'custom_report')
        report_id = config.get('id')  # Check if we're updating an existing report
        
        if report_id:
            # Update existing report
            saved_report = (
                db_session.query(SavedReport)
                .filter(SavedReport.id == report_id, SavedReport.user_id == user_id)
                .first()
            )
            
            if not saved_report:
                return jsonify({"error": "Report not found or unauthorized"}), 404
            
            # Update the fields
            saved_report.title = title
            saved_report.filename = filename
            saved_report.config_data = config
            message = "Report updated successfully"
        else:
            # Create new saved report
            saved_report = SavedReport(
                user_id=user_id,
                title=title,
                filename=filename,
                config_data=config
            )
            db_session.add(saved_report)
            message = "Report saved successfully"
        
        db_session.commit()
        
        return jsonify({
            "success": True,
            "id": saved_report.id,
            "message": message
        })
    except Exception as e:
        db_session.rollback()
        return jsonify({"error": str(e)}), 500
    finally:
        db_session.close()


@app.route('/api/reports/saved', methods=['GET'])
def get_saved_reports():
    """Get all saved reports for the current user."""
    user_id = getattr(current_user, "id", None) or session.get("user_id")
    
    if not user_id:
        return jsonify({"error": "Unauthorized"}), 401
    
    db_session = SessionLocal()
    try:
        reports = (
            db_session.query(SavedReport)
            .filter(SavedReport.user_id == user_id)
            .order_by(SavedReport.updated_at.desc())
            .all()
        )
        
        return jsonify([{
            "id": r.id,
            "title": r.title,
            "filename": r.filename,
            "created_at": r.created_at.isoformat(),
            "updated_at": r.updated_at.isoformat(),
            "element_count": len(r.config_data.get('elements', []))
        } for r in reports])
    finally:
        db_session.close()


@app.route('/api/reports/saved/<int:report_id>', methods=['GET'])
def get_saved_report(report_id):
    """Get a specific saved report configuration."""
    user_id = getattr(current_user, "id", None) or session.get("user_id")
    
    if not user_id:
        return jsonify({"error": "Unauthorized"}), 401
    
    db_session = SessionLocal()
    try:
        report = (
            db_session.query(SavedReport)
            .filter(SavedReport.id == report_id, SavedReport.user_id == user_id)
            .first()
        )
        
        if not report:
            return jsonify({"error": "Report not found"}), 404
        
        return jsonify(report.config_data)
    finally:
        db_session.close()


@app.route('/api/reports/saved/<int:report_id>', methods=['DELETE'])
def delete_saved_report(report_id):
    """Delete a saved report."""
    user_id = getattr(current_user, "id", None) or session.get("user_id")
    
    if not user_id:
        return jsonify({"error": "Unauthorized"}), 401
    
    db_session = SessionLocal()
    try:
        report = (
            db_session.query(SavedReport)
            .filter(SavedReport.id == report_id, SavedReport.user_id == user_id)
            .first()
        )
        
        if not report:
            return jsonify({"error": "Report not found"}), 404
        
        db_session.delete(report)
        db_session.commit()
        
        return jsonify({"success": True, "message": "Report deleted successfully"})
    except Exception as e:
        db_session.rollback()
        return jsonify({"error": str(e)}), 500
    finally:
        db_session.close()


@app.route('/api/reports/saved/<int:report_id>/download', methods=['GET'])
def download_saved_report(report_id):
    """Download a saved report as PDF."""
    user_id = getattr(current_user, "id", None) or session.get("user_id")
    
    if not user_id:
        return "Unauthorized - please log in first", 401
    
    db_session = SessionLocal()
    try:
        report = (
            db_session.query(SavedReport)
            .filter(SavedReport.id == report_id, SavedReport.user_id == user_id)
            .first()
        )
        
        if not report:
            return "Report not found", 404
        
        # Generate PDF from saved config
        pdf_bytes = create_pdf_from_config(report.config_data)
        
        # Create response
        response = make_response(pdf_bytes)
        response.headers["Content-Type"] = "application/pdf"
        
        filename = report.filename
        if not filename.endswith('.pdf'):
            filename += '.pdf'
            
        response.headers["Content-Disposition"] = f"attachment; filename={filename}"
        return response
    except Exception as e:
        return f"Error generating PDF: {str(e)}", 500
    finally:
        db_session.close()


@app.route('/api/reports/data/leaks_per_crawler', methods=['GET'])
def get_leaks_per_crawler_data():
    """Get leaks per crawler data for charts."""
    user_id = getattr(current_user, "id", None) or session.get("user_id")
    if not user_id:
        return jsonify({"error": "Unauthorized"}), 401
    
    # Get date range parameters
    date_range = request.args.get('range', 'weekly')
    start_date_str = request.args.get('start', '')
    end_date_str = request.args.get('end', '')
    
    db_session = SessionLocal()
    try:
        query = db_session.query(Leak).filter(Leak.user_id == user_id)
        
        # Apply date filtering
        if date_range == 'custom' and start_date_str and end_date_str:
            from datetime import datetime
            try:
                query = query.filter(Leak.timestamp >= start_date_str, Leak.timestamp <= end_date_str + ' 23:59:59')
            except:
                pass
        elif date_range in ['daily', 'weekly', 'monthly']:
            from datetime import datetime, timedelta
            now = datetime.now()
            if date_range == 'daily':
                cutoff = now - timedelta(days=1)
            elif date_range == 'weekly':
                cutoff = now - timedelta(weeks=1)
            else:
                cutoff = now - timedelta(days=30)
            query = query.filter(Leak.timestamp >= cutoff)
        
        leaks = query.limit(1000).all()
        sources = {}
        for leak in leaks:
            source = leak.source or leak.crawler or 'Unknown'
            sources[source] = sources.get(source, 0) + 1
        
        return jsonify({
            "labels": list(sources.keys()),
            "values": list(sources.values())
        })
    finally:
        db_session.close()


@app.route('/api/reports/data/critical_alerts', methods=['GET'])
def get_critical_alerts_data():
    """Get critical alerts over time for charts."""
    user_id = getattr(current_user, "id", None) or session.get("user_id")
    if not user_id:
        return jsonify({"error": "Unauthorized"}), 401
    
    # Get date range parameters
    date_range = request.args.get('range', 'weekly')
    start_date_str = request.args.get('start', '')
    end_date_str = request.args.get('end', '')
    
    db_session = SessionLocal()
    try:
        query = db_session.query(AlertHistory).filter(AlertHistory.user_id == user_id)
        
        # Apply date filtering
        if date_range == 'custom' and start_date_str and end_date_str:
            try:
                query = query.filter(AlertHistory.sent_at >= start_date_str, AlertHistory.sent_at <= end_date_str + ' 23:59:59')
            except:
                pass
        elif date_range in ['daily', 'weekly', 'monthly']:
            from datetime import datetime, timedelta
            now = datetime.now()
            if date_range == 'daily':
                cutoff = now - timedelta(days=1)
            elif date_range == 'weekly':
                cutoff = now - timedelta(weeks=1)
            else:
                cutoff = now - timedelta(days=30)
            query = query.filter(AlertHistory.sent_at >= cutoff)
        
        alerts = query.limit(1000).all()
        date_counts = {}
        for alert in alerts:
            date_obj = alert.sent_at or alert.created_at
            date_str = date_obj.strftime('%Y-%m-%d') if hasattr(date_obj, 'strftime') else str(date_obj)[:10]
            if date_str:
                date_counts[date_str] = date_counts.get(date_str, 0) + 1
        
        dates = sorted(date_counts.keys())
        return jsonify({
            "labels": dates,
            "values": [date_counts[d] for d in dates]
        })
    finally:
        db_session.close()


@app.route('/api/reports/data/risk_severity', methods=['GET'])
def get_risk_severity_data():
    """Get risk severity breakdown for pie charts."""
    user_id = getattr(current_user, "id", None) or session.get("user_id")
    if not user_id:
        return jsonify({"error": "Unauthorized"}), 401
    
    try:
        summary = risk_summary(user_id=user_id)
        severity_counts = summary.get('severity_counts', {})
        
        order = ['critical', 'high', 'medium', 'low', 'zero severity', 'unknown']
        labels = [k for k in order if k in severity_counts]
        values = [severity_counts[k] for k in labels]
        
        return jsonify({
            "labels": labels,
            "values": values
        })
    except Exception as e:
        return jsonify({"error": str(e), "labels": [], "values": []}), 500


@app.route('/api/reports/data/risk_trend', methods=['GET'])
def get_risk_trend_data():
    """Get overall risk trend for charts."""
    user_id = getattr(current_user, "id", None) or session.get("user_id")
    if not user_id:
        return jsonify({"error": "Unauthorized"}), 401
    
    # Handle date range parameters
    date_range = request.args.get('range', 'weekly')
    if date_range == 'daily':
        days = 1
    elif date_range == 'weekly':
        days = 7
    elif date_range == 'monthly':
        days = 30
    else:  # custom - calculate days between dates
        start_date_str = request.args.get('start', '')
        end_date_str = request.args.get('end', '')
        if start_date_str and end_date_str:
            from datetime import datetime
            start = datetime.fromisoformat(start_date_str)
            end = datetime.fromisoformat(end_date_str)
            days = max(1, (end - start).days + 1)
        else:
            days = 7  # default fallback
    
    try:
        series = risk_time_series(days=days, user_id=user_id)
        if not series:
            return jsonify({"labels": [], "values": []})
        
        return jsonify({
            "labels": [s['date'] for s in series],
            "values": [s['score'] for s in series]
        })
    except Exception as e:
        return jsonify({"error": str(e), "labels": [], "values": []}), 500


@app.route('/api/reports/data/severity_trend', methods=['GET'])
def get_severity_trend_data():
    """Get severity time series for stacked charts."""
    user_id = getattr(current_user, "id", None) or session.get("user_id")
    if not user_id:
        return jsonify({"error": "Unauthorized"}), 401
    
    # Handle date range parameters
    date_range = request.args.get('range', 'weekly')
    if date_range == 'daily':
        days = 1
    elif date_range == 'weekly':
        days = 7
    elif date_range == 'monthly':
        days = 30
    else:  # custom - calculate days between dates
        start_date_str = request.args.get('start', '')
        end_date_str = request.args.get('end', '')
        if start_date_str and end_date_str:
            from datetime import datetime
            start = datetime.fromisoformat(start_date_str)
            end = datetime.fromisoformat(end_date_str)
            days = max(1, (end - start).days + 1)
        else:
            days = 7  # default fallback
    
    try:
        series = severity_time_series(days=days, user_id=user_id)
        return jsonify(series)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/api/reports/data/top_assets', methods=['GET'])
def get_top_assets_data():
    """Get top risky assets for charts."""
    user_id = getattr(current_user, "id", None) or session.get("user_id")
    if not user_id:
        return jsonify({"error": "Unauthorized"}), 401
    
    mode = request.args.get('mode', 'type')  # 'type' or 'asset'
    limit = request.args.get('limit', 10, type=int)
    
    try:
        # Scan all leaks (1000 max) to get complete asset risk data
        assets = asset_risk(limit=1000, user_id=user_id)
        
        if mode == 'type':
            type_counts = {}
            for asset in assets:
                # Only include assets with actual leaks
                leak_count = int(asset.get('leak_count', 0))
                if leak_count > 0:
                    asset_type = asset.get('type', 'unknown')
                    type_counts[asset_type] = type_counts.get(asset_type, 0) + leak_count
            
            # If no assets have leaks, return empty but valid data
            if not type_counts:
                return jsonify({"labels": [], "values": []})
            
            sorted_types = sorted(type_counts.items(), key=lambda x: x[1], reverse=True)
            return jsonify({
                "labels": [t[0] for t in sorted_types],
                "values": [t[1] for t in sorted_types]
            })
        else:
            # Filter to only assets with leaks
            assets_with_leaks = [a for a in assets if int(a.get('leak_count', 0)) > 0]
            
            if not assets_with_leaks:
                return jsonify({"labels": [], "values": []})
            
            # Limit to top N assets
            top_assets = assets_with_leaks[:limit]
            
            return jsonify({
                "labels": [f"{a.get('type')}:{a.get('value')}" for a in top_assets],
                "values": [int(a.get('leak_count', 0)) for a in top_assets]
            })
    except Exception as e:
        return jsonify({"error": str(e), "labels": [], "values": []}), 500




if __name__ == "__main__":
    app.run(debug=True)



