# 490_Senior_Project

Lightweight README for developers — how to get the backend serving the static frontend and the basic API.

Prerequisites

- Python 3.11+ (use a virtual environment)
- Install dependencies:

```powershell
# Create and activate the recommended virtualenv (run from repo root)
.
# Option 1: run the helper script (recommended)
.
powershell -ExecutionPolicy Bypass -File .\scripts\setup_venv.ps1

# Option 2: manual
python -m venv .venv; .\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

Run the server

From the repository root (recommended):

```powershell
# After you activate the `.venv` you can start the app with:
python app.py
```

Or run the module directly:

```powershell
python -m backend.app
```

What you can open in a browser

- `http://127.0.0.1:5000/`  -> redirects to `/homepage/`
- `http://127.0.0.1:5000/homepage/`
- `http://127.0.0.1:5000/dashboard/`
- `http://127.0.0.1:5000/resources/`
- `http://127.0.0.1:5000/account/`

API (JSON)

- `GET /api` - status
- `GET /api/leaks?limit=n` - latest leaks (default 10)
- `GET /api/resources` - static resources
- `GET, POST /api/account` - mock account endpoint

Notes for developers

- Frontend files are static HTML/CSS under `homepage/`, `dashboardpage/`, `resourcespage/`, and `accountpage/`.
- The Flask app serves these with friendly URLs (no `.html`) and remaps asset requests so CSS/images load correctly. See `backend/app.py` if you need to change mappings.
- Database helpers and models are in `backend/database.py`. `init_db()` will create the SQLite DB and the `leaks` table.
- The `/api/account` endpoint is a mock; it does not persist users.

Troubleshooting

- If a page looks unstyled, make sure you opened the trailing-slash URL (e.g. `/dashboard/`).
- If imports fail, confirm you ran from the repo root and installed dependencies in the active virtualenv.

Extras (optional improvements)

- Add a `404.html` and serve it for missing routes.
- Replace server-side remapping by changing frontend asset links to absolute paths (requires editing the HTML).


Dark Web Crawler (Tor/I2P Skeleton)
    The crawler is designed with modular support for multiple anonymity networks. Currently Tor is implemented via SOCKS5 on 9150/9050. A placeholder for I2P (fetch_i2p) has been included, which would use the I2P proxy port (127.0.0.1:4444). This allows future extension without major refactoring.

    **Setup**
    1. Install dependencies:
        pip install requests beautifulsoup4 pysocks
    2. Ensure you have SQLite (Python has it built-in).
    3. (Tor mode only) Run Tor Browser in the background. By default, it provides a SOCKS5 proxy on 127.0.0.1:9150.

    **Running the Crawler**
    Demo Mode (no Tor required)
    Fetches from a clearnet site (example.com) to prove functionality.
        USE_TOR = False
    Run:
        python backend/crawler/tor_crawler.py
    Expected:
        Fetched title: Example Domain
        Saved page to DB.

    Tor Mode
    Fetches from a known .onion site (Tor Project).
        USE_TOR = True
    Run:
        python backend/crawler/tor_crawler.py
    Expected (if Tor is running and .onion resolution works):
        Fetched title: Tor Project: Anonymity Online
        Saved page to DB.

    **Checking Results**
    Use the helper script to see what’s inside your DB:
        python check_db.py
    Example output:
        Tables in DB: [('leaks',)]
        --- Leaks Table Content ---
        (1, 'Tor', 'Tor Project: Anonymity Online - http://...onion')
        (2, 'Demo', 'Example Domain - https://example.com')

    **Future Work: I2P**
        A function stub (fetch_i2p) has been added for future I2P support.
        I2P typically runs a proxy on 127.0.0.1:4444. Extending the crawler would involve reusing the same logic as fetch_and_store, but swapping out the proxy.






If you want this README shortened further or expanded with contributor instructions, tell me what to include.