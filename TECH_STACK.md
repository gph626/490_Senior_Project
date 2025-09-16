Tech stack and architecture decisions for Member A (Architecture & Environment)

- Language: Python 3.11+ (stable, typing support, modern standard library)
- Backend framework: Flask (small, already present in repo). Can be swapped to FastAPI later if async-first APIs are required.
- HTTP client: requests
- HTML parsing: BeautifulSoup (beautifulsoup4)
- Crawling: scrapy is available but initial crawlers will use requests + BeautifulSoup for simplicity.
- Database: SQLite via SQLAlchemy for sprint 1 (lightweight, zero-config). Move to PostgreSQL for production in Sprint 2 if needed.
- Dev/workflow: GitHub Codespaces / VS Code devcontainer with Python extension and `requirements.txt` installed.

Rationale

- Flask is already present and sufficient for a small API to expose collected data.
- SQLAlchemy abstracts DB access and allows an easy migration to a server DB later.
- Keeping requirements minimal accelerates onboarding for teammates.

Contract (minimal)

- Inputs: crawlers will pass dicts with keys: `source`, `url`, `raw_content`, `parsed_text` (optional), `timestamp`.
- Outputs: DB row in `leaks` table with standardized JSON `data` column for raw/normalized content.
- Error modes: DB connection errors (raise), validation errors (return False).

Edge cases

- Empty or duplicate content → DB unique constraints or dedup checks later.
- Large paste blobs → store as TEXT; consider external object store for huge files.

Next steps

- Add DB migrations and tests (Member D).
- Add paste crawler and Tor crawler (Members B and C).