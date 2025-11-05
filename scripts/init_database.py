"""
Initialize or migrate the database with the alerted column
"""
import sys
import os

# Add parent directory to path so we can import backend modules
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.database import init_db

print("Initializing database...")
print("This will create all tables and add any missing columns.")

try:
    init_db()
    print("\n✓ Database initialized successfully!")
    print("✓ All tables created/updated including 'alerted' column in leaks table")
except Exception as e:
    print(f"\n✗ Error: {e}")
    import traceback
    traceback.print_exc()
