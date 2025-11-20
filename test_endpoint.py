#!/usr/bin/env python3
"""Test the top_assets endpoint directly"""

import sys
sys.path.insert(0, '/workspaces/490_Senior_Project')

from backend.app import app
from flask import session

# Create test client
client = app.test_client()

# Login as Gphebert02
with client:
    # Login first
    response = client.post('/login', data={
        'username': 'Gphebert02',
        'password': 'password123'  # You'll need to adjust this
    }, follow_redirects=True)
    
    print(f"Login response: {response.status_code}")
    
    # Now test the endpoint
    response = client.get('/api/reports/data/top_assets?mode=asset&limit=10')
    print(f"\nTop assets endpoint response: {response.status_code}")
    print(f"Data: {response.get_json()}")
