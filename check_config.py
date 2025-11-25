import sqlite3
import json

conn = sqlite3.connect('backend/data.sqlite')
cursor = conn.cursor()

# List all tables
cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
tables = [r[0] for r in cursor.fetchall()]
print("Tables:", tables)

# Check if config table exists (might be lowercase or different name)
config_table = next((t for t in tables if 'config' in t.lower()), None)
if config_table:
    print(f"\nQuerying {config_table} table for org_id=2...")
    cursor.execute(f"SELECT org_id, config_data FROM {config_table} WHERE org_id=2")
    row = cursor.fetchone()
    if row:
        print(f"org_id: {row[0]}")
        config_data = json.loads(row[1]) if isinstance(row[1], str) else row[1]
        print("\nConfig data:")
        print(json.dumps(config_data, indent=2))
        
        # Check specifically for GitHub token
        github_config = config_data.get('sources', {}).get('github', {})
        github_token = github_config.get('token', '')
        print(f"\nGitHub token in config: '{github_token}' (length: {len(github_token)})")
    else:
        print("No config found for org_id=2")
else:
    print("No config table found!")
    print("\nTrying to find User table...")
    # Maybe config is in users table
    user_table = next((t for t in tables if 'user' in t.lower()), None)
    if user_table:
        cursor.execute(f"PRAGMA table_info({user_table})")
        print(f"\n{user_table} columns:", [r[1] for r in cursor.fetchall()])

conn.close()
