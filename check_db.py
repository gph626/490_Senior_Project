import sqlite3

def check_db():
    conn = sqlite3.connect("darkweb.db")
    cursor = conn.cursor()

    # List all tables
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
    tables = cursor.fetchall()
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
