import os
from flask import Flask, jsonify, request, send_from_directory, abort, redirect

# Import the database helpers in a way that works when running from the repo root
# (python -m backend.app) or when running directly from backend/ (python app.py).
try:
    # Preferred: running as a package from repo root
    from backend.database import get_latest_leaks, leak_to_dict
except ImportError:
    # Fallback: running directly in the backend/ directory
    from database import get_latest_leaks, leak_to_dict

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
}


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
    return redirect('/homepage/')


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

# Handle directory-style requests with trailing slash, serving the page file inside the folder
@app.route('/<page>/')
def serve_page_dir(page: str):
    aliases = {
        'homepage': 'homepage/homepage.html',
        'dashboard': 'dashboardpage/dashboard.html',
        'resources': 'resourcespage/resources.html',
        'account': 'accountpage/account.html',
        'index': 'homepage/homepage.html'
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

if __name__ == "__main__":
    app.run(debug=True)
