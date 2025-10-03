import sqlite3

DB_PATH = "backend/data.sqlite"

conn = sqlite3.connect(DB_PATH)
cur = conn.cursor()

print("\n=== Tables ===")
for row in cur.execute("SELECT name FROM sqlite_master WHERE type='table';"):
    print(row)

print("\n=== Schema for leaks ===")
for row in cur.execute("PRAGMA table_info(leaks);"):
    print(row)

print("\n=== Sample leaks ===")
for row in cur.execute("SELECT id, source, title, length(content), content_hash FROM leaks ORDER BY id DESC LIMIT 5;"):
    print(row)

conn.close()
