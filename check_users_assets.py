#!/usr/bin/env python3
"""Check which users have assets"""

import sys
sys.path.insert(0, '/workspaces/490_Senior_Project')

from backend.database import SessionLocal, User, Asset

session = SessionLocal()

# Get all users
users = session.query(User).all()
print(f"Total users: {len(users)}")
print()

for user in users:
    asset_count = session.query(Asset).filter(Asset.user_id == user.id).count()
    if asset_count > 0:
        print(f"User: {user.username} (ID: {user.id}) - {asset_count} assets")
        # Show first few assets
        assets = session.query(Asset).filter(Asset.user_id == user.id).limit(5).all()
        for asset in assets:
            print(f"  - {asset.type}: {asset.value[:50]}")

session.close()
