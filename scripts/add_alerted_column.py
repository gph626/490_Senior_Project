"""
Migration script to add 'alerted' column to the leaks table.
This column tracks whether a leak has been sent in an alert webhook.
"""
import sqlite3
import os

# Path to the database file (in backend/ directory)
db_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'backend', 'data.sqlite')

print(f"Connecting to database: {db_path}")

try:
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # Check if column already exists
    cursor.execute("PRAGMA table_info(leaks)")
    columns = [col[1] for col in cursor.fetchall()]
    
    if 'alerted' in columns:
        print("✓ Column 'alerted' already exists in leaks table")
    else:
        print("Adding 'alerted' column to leaks table...")
        cursor.execute("ALTER TABLE leaks ADD COLUMN alerted INTEGER DEFAULT 0")
        conn.commit()
        print("✓ Successfully added 'alerted' column (default=0)")
        
        # Verify the column was added
        cursor.execute("PRAGMA table_info(leaks)")
        columns = [col[1] for col in cursor.fetchall()]
        if 'alerted' in columns:
            print("✓ Verified: Column exists in table")
        else:
            print("✗ Error: Column not found after addition")
    
    # Show current column count
    cursor.execute("SELECT COUNT(*) FROM leaks")
    leak_count = cursor.fetchone()[0]
    print(f"\nTotal leaks in database: {leak_count}")
    
    if leak_count > 0:
        cursor.execute("SELECT COUNT(*) FROM leaks WHERE alerted = 0")
        not_alerted = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(*) FROM leaks WHERE alerted = 1")
        alerted = cursor.fetchone()[0]
        print(f"  - Not alerted: {not_alerted}")
        print(f"  - Alerted: {alerted}")
    
    conn.close()
    print("\n✓ Migration complete!")
    
except Exception as e:
    print(f"✗ Error: {e}")
    import traceback
    traceback.print_exc()
