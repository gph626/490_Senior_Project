# tests/test_i2p_crawler.py
import pytest
import requests
from backend.crawler import i2p_crawler

HTML = """
<html>
  <body>
    test@example.com
    SSN: 123-45-6789
    Password: i2ppass
    Address: 321 Oak Road
  </body>
</html>
"""

class MockResponse:
    status_code = 200
    text = HTML

def mock_get(self, url, timeout):
    return MockResponse()

def test_fetch_and_store_i2p(monkeypatch):
    monkeypatch.setattr(requests.Session, "get", mock_get)
    ok = i2p_crawler.fetch_and_store("http://mock.i2p/test")
    assert ok is True

    entities = i2p_crawler.extract_entities(HTML)
    assert "test@example.com" in entities["emails"]
    assert "123456789" in entities["ssns"]
    assert "i2ppass" in entities["passwords"]
    assert any("321 Oak Road" in a for a in entities["physical_addresses"])
