"""
Script to check what tables exist in the database
"""
import sqlite3
import os

db_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'data.sqlite')

print(f"Checking database: {db_path}")
print(f"Database exists: {os.path.exists(db_path)}")

if os.path.exists(db_path):
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # Get all tables
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
    tables = cursor.fetchall()
    
    print(f"\nTables found: {len(tables)}")
    for table in tables:
        print(f"  - {table[0]}")
        # Get column info for each table
        cursor.execute(f"PRAGMA table_info({table[0]})")
        columns = cursor.fetchall()
        for col in columns:
            print(f"    * {col[1]} ({col[2]})")
    
    conn.close()
else:
    print("Database file does not exist!")
