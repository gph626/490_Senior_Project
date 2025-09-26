import sqlite3
import os

def check_db():
    # Prefer using environment variable to locate the DB so it matches the app's behaviour.
    db_path = os.environ.get('DARKWEB_DB_PATH', os.path.join('backend', 'data.sqlite'))
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    # List all tables
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
    tables = cursor.fetchall()
    print("Using DB:", db_path)
    print("Tables in DB:", tables)

    # Check if leaks table exists
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='leaks';")
    if not cursor.fetchone():
        print("No 'leaks' table found.")
        conn.close()
        return

    # Fetch rows from leaks
    cursor.execute("SELECT * FROM leaks;")
    rows = cursor.fetchall()
    
    if rows:
        print("\n--- Leaks Table Content ---")
        for row in rows:
            print(row)
    else:
        print("\n'leaks' table is empty.")

    conn.close()

if __name__ == "__main__":
    check_db()
