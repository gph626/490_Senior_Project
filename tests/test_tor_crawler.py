# tests/test_tor_crawler.py
import pytest
import requests
from backend.crawler import tor_crawler

SAMPLE_HTML = """
<html>
  <head><title>Leak Example</title></head>
  <body>
    test@example.com<br>
    SSN: 123-45-6789<br>
    Phone: 337-555-1234<br>
    Password: hunter2<br>
    Domain: sub.domain.com<br>
    Address: 123 Main Street
  </body>
</html>
"""

class MockResponse:
    status_code = 200
    text = SAMPLE_HTML

def mock_get(self, url, timeout):
    return MockResponse()

def test_fetch_and_store_tor(monkeypatch):
    # Mock Tor GET
    monkeypatch.setattr(requests.Session, "get", mock_get)
    ok = tor_crawler.fetch_and_store("http://mock.onion/test")
    assert ok is True

    entities = tor_crawler.extract_entities(SAMPLE_HTML)
    assert "test@example.com" in entities["emails"]
    assert "123456789" in entities["ssns"]
    assert "3375551234" in entities["phone_numbers"]
    assert "hunter2" in entities["passwords"]
    assert any("123 Main Street" in a for a in entities["physical_addresses"])
