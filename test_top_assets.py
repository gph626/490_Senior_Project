#!/usr/bin/env python3
"""Test script to check what top_assets endpoint returns"""

import sys
sys.path.insert(0, '/workspaces/490_Senior_Project')

from backend.analytics import asset_risk
from backend.database import SessionLocal
from backend.database import User

# Get a test user with assets
session = SessionLocal()
user = session.query(User).filter(User.username == 'Gphebert02').first()
if not user:
    user = session.query(User).first()
session.close()

if not user:
    print("No users found in database")
    sys.exit(1)

print(f"Testing with user_id: {user.id}, username: {user.username}")
print("-" * 60)

# Test asset_risk function
assets = asset_risk(limit=1000, user_id=user.id)

print(f"Total assets returned: {len(assets)}")
print()

# Show assets with leaks
assets_with_leaks = [a for a in assets if int(a.get('leak_count', 0)) > 0]
print(f"Assets with leaks: {len(assets_with_leaks)}")
print()

if assets_with_leaks:
    print("Top 10 assets with leaks:")
    for i, asset in enumerate(assets_with_leaks[:10], 1):
        print(f"{i}. {asset['type']}:{asset['value'][:50]} - {asset['leak_count']} leaks, risk: {asset['risk']}")
else:
    print("No assets with leaks found!")
    print()
    print("All assets:")
    for i, asset in enumerate(assets[:10], 1):
        print(f"{i}. {asset['type']}:{asset['value'][:50]} - {asset['leak_count']} leaks, risk: {asset['risk']}")
