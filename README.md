# 490_Senior_Project

Lightweight README for developers — how to get the backend serving the static frontend and the basic API.

Prerequisites

- Python 3.11+ (use a virtual environment)
- Install dependencies:

```powershell
# Create and activate the recommended virtualenv (run from repo root)
.


# 490 Senior Project

## Overview
This project is a modular dark web leak analytics platform. It features:
- Flask backend API
- Static HTML/CSS/JS frontend
- SQLite database (via SQLAlchemy)
- Modular crawlers for Tor, I2P, and Pastebin
- Asset watchlist and severity analytics

---


## Tech Stack & Architecture
- **Language:** Python 3.11+
- **Backend:** Flask (can swap to FastAPI if async APIs needed)
- **Database:** SQLite (SQLAlchemy ORM; easy migration to PostgreSQL)
- **Frontend:** Static HTML/CSS/JS (see `templates/` and `static/`)
- **Crawling:** requests + BeautifulSoup (scrapy available for future)
- **Dev Environment:** VS Code devcontainer, GitHub Codespaces

## Prerequisites
- Python 3.11+
- Recommended: Use a virtual environment


## Setup
Install dependencies from the repository root:

**Option 1: Recommended (PowerShell script, Windows only)**
```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\setup_venv.ps1
```

**Option 2: Manual (cross-platform)**
```bash
python -m venv .venv
# Windows:
.\.venv\Scripts\Activate.ps1
# Linux/macOS:
source .venv/bin/activate
pip install -r requirements.txt
```


## Running the Server
Activate your virtual environment, then run:
```bash
python app.py
```
Or run as a module:
```bash
python -m backend.app
```


## Frontend URLs
- `http://127.0.0.1:5000/` → redirects to `/homepage/`
- `/homepage/`, `/dashboard/`, `/resources/`, `/account/`
- Static assets: `/static/js/`, `/dashboard/base.css`


## API Endpoints
- `GET /api` — status
- `GET /api/leaks?limit=n` — latest leaks (default 10)
- `GET /api/resources` — static resources
- `GET, POST /api/account` — mock account endpoint


## User Authentication
- Registration and login use secure password hashing via `bcrypt` (see `backend/database.py`).
- Passwords are never stored in plain text; only bcrypt hashes are saved.
- The `users` table is created automatically. See `create_user`, `authenticate_user` in `backend/database.py`.


## Developer Notes
- Static HTML/CSS/JS: `templates/`, `static/`, `dashboard/`
- Flask serves friendly URLs and remaps asset requests for correct CSS/image loading. See `backend/app.py` for mappings.
- Database helpers/models: `backend/database.py`. Run `init_db()` to create the SQLite DB and tables.
- Asset watchlist: `backend/assets_db.py` (separate SQLite DB for assets of interest)
- Analytics: `backend/analytics.py` (risk, alerts, severity)
- Utility functions: `backend/utils.py` (redaction, asset matching, tagging)
- Crawler config: `backend/crawler/config.py` (API URLs, proxies, test onions)
- `/api/account` is a mock endpoint (does not persist users).


## Testing
- Unit tests: `tests/test_database.py`, `tests/test_crawler.py`
- Run tests manually:
  ```bash
  python tests/test_database.py
  python tests/test_crawler.py
  ```
- Print latest leaks for debugging:
  ```bash
  python scripts/print_leaks.py
  ```

## Troubleshooting
- If a page looks unstyled, use the trailing-slash URL (e.g. `/dashboard/`).
- If imports fail, ensure you ran from the repo root and installed dependencies in the active virtualenv.


## Optional Improvements
- Add a `404.html` and serve for missing routes.
- Change frontend asset links to absolute paths (requires editing HTML).
- Add DB migrations (see Alembic in requirements)
- Expand crawler support (scrapy, more sources)

---


## Dark Web Crawler (Tor/I2P/Pastebin)
Modular crawlers for:
- **Tor:** SOCKS5 proxy (default 127.0.0.1:9150)
- **I2P:** HTTP proxy (default 127.0.0.1:4444)
- **Pastebin:** Clearnet scraping

### Setup
1. Install dependencies:
   ```bash
   pip install requests beautifulsoup4 pysocks
   ```
2. Ensure you have SQLite (Python built-in).
3. (Tor mode) Run Tor Browser in the background (SOCKS5 proxy on 127.0.0.1:9150).

### Running the Crawler
**Demo Mode (no Tor required):**
- Set `USE_TOR = False` in `tor_crawler.py`
- Run:
  ```bash
  python backend/crawler/tor_crawler.py
  ```
- Expected: Fetched title from example.com, saved to DB.

**Tor Mode:**
- Set `USE_TOR = True` in `tor_crawler.py`
- Run:
  ```bash
  python backend/crawler/tor_crawler.py
  ```
- Expected: Fetched title from .onion site, saved to DB (Tor must be running).

**Pastebin:**
- Run:
  ```bash
  python backend/crawler/pastebin.py
  ```

**I2P:**
- Run:
  ```bash
  python backend/crawler/i2p_crawler.py
  ```

### Checking Results
View DB contents:
```bash
python check_db.py
```
Or print latest leaks:
```bash
python scripts/print_leaks.py
```
Example output:
```
Tables in DB: [('leaks',)]
--- Leaks Table Content ---
(1, 'Tor', 'Tor Project: Anonymity Online - http://...onion')
(2, 'Demo', 'Example Domain - https://example.com')
```

### Future Work: I2P
- `fetch_i2p` stub included for future support (proxy: 127.0.0.1:4444).
- Extend by reusing `fetch_and_store` logic with I2P proxy.

---


---

## Contributing
- Fork the repo, create a feature branch, and submit a PR.
- Follow PEP8 and use type hints where possible.
- Add/expand unit tests for new features.

---

For further README changes or contributor instructions, let me know!