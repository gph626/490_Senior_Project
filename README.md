# 490_Senior_Project

Lightweight README for developers — how to get the backend serving the static frontend and the basic API.

Prerequisites

- Python 3.11+ (use a virtual environment)
- Install dependencies:

```powershell
python -m venv .venv; .\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

Run the server

From the repository root (recommended):

```powershell
python -m backend.app
```

Or from the backend folder:

```powershell
cd backend
python app.py
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

If you want this README shortened further or expanded with contributor instructions, tell me what to include.