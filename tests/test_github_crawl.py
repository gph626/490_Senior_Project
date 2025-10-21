# test_github_crawl.py
import os
import sys

# Add project root to sys.path (go up one directory from /tests)
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from backend.crawler.github_crawler import fetch_and_store
import sqlite3
from backend.database import ENGINE

from backend.database import SessionLocal, Leak

session = SessionLocal()
print("Before test run, leaks count:", session.query(Leak).count())
session.close()


print("Using DB file:", ENGINE.url)

print("=== Running GitHub crawler user-scope test ===")


# Assign the test user_id you want to verify
TEST_USER_ID = 5

# Run the crawler with a small limit (to avoid hitting GitHub rate limits)
inserted_count = fetch_and_store(limit=3, user_id=TEST_USER_ID)
print(f"Inserted {inserted_count} leaks for user_id={TEST_USER_ID}")

# Open SQLite DB and check user IDs of the most recent GitHub leaks
conn = sqlite3.connect("backend/data.sqlite")
cursor = conn.cursor()
cursor.execute("SELECT id, source, user_id FROM leaks WHERE source='github' ORDER BY id DESC LIMIT 5;")
rows = cursor.fetchall()
conn.close()

print("\n=== Recent GitHub leaks in DB ===")
for row in rows:
    print(row)

print("\n If all recent leaks show user_id =", TEST_USER_ID, ", the association works!")
