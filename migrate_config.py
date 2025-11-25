import sqlite3
from datetime import datetime

conn = sqlite3.connect('backend/data.sqlite')
cursor = conn.cursor()

# Get config from org_id=123
cursor.execute('SELECT config_data FROM configs WHERE org_id=123')
row = cursor.fetchone()

if row:
    config_data = row[0]
    print("Found config for org_id=123")
    
    # Insert into org_id=2
    cursor.execute('''
        INSERT OR REPLACE INTO configs (org_id, config_data, updated_at) 
        VALUES (2, ?, datetime('now'))
    ''', (config_data,))
    
    conn.commit()
    print("Successfully migrated config from org_id=123 to org_id=2")
    
    # Verify
    cursor.execute('SELECT org_id FROM configs')
    orgs = [r[0] for r in cursor.fetchall()]
    print(f"Configs now exist for org_ids: {orgs}")
else:
    print("No config found for org_id=123")

conn.close()
