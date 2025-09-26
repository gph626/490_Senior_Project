"""Top-level runner so repo-root `python app.py` starts the Flask app.
This simply defers to the package entry in `backend.app` so imports work
when run from the repository root.
"""
from backend import app

if __name__ == '__main__':
    app.app.run(debug=True)
