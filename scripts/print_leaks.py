"""
Simple CLI to print latest leaks from the database for testing.
"""
import sys
import os
import json

repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if repo_root not in sys.path:
    sys.path.insert(0, repo_root)

from backend import database


def main(limit: int = 10):
    database.init_db()
    leaks = database.get_latest_leaks(limit)
    out = [database.leak_to_dict(l) for l in leaks]
    print(json.dumps(out, indent=2))


if __name__ == '__main__':
    main(10)
