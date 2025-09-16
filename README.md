# 490_Senior_Project

This repository contains the starter code and environment configuration for the Dark Web Monitoring senior project.

Member A deliverable (Architecture & Environment)

- Finalized tech stack and rationale in `TECH_STACK.md`.
- Repo structure and minimal backend skeleton under `backend/`.
- Development environment hints and a minimal Codespaces devcontainer in `.devcontainer/`.
- Quick run instructions and smoke checks.

Quick start (local, Windows PowerShell):

1. Create and activate a virtual environment (Python 3.11+ recommended):

	```powershell
	python -m venv .venv; .\.venv\Scripts\Activate.ps1
	pip install -r requirements.txt
	```

2. Run the backend app:

	```powershell
	python -m backend.app
	```

3. Smoke import checks:

	```powershell
	python -c "import backend.app; print('backend.app import OK')"
	python -c "import backend.database; print('backend.database import OK')"
	```

Devcontainer / Codespaces

The included `.devcontainer/devcontainer.json` installs Python and runs `pip install -r requirements.txt` when the container is built. Use GitHub Codespaces or VS Code Remote - Containers to get a consistent environment.

Repository layout

- `backend/` - Flask backend and server code.
- `dashboard/` - front-end (Node) dashboard.
- `tests/` - unit and integration tests.
- `.devcontainer/` - optional Codespaces/devcontainer configuration.

Next steps for the team

- Member D should add the production DB configuration and confirm schema.
- Member B and C will add crawlers and use the DB helpers in `backend/database.py` to persist results.

See `TECH_STACK.md` for the chosen technologies and rationale.
# 490_Senior_Project