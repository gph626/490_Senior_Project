# tests/test_pastebin_crawler.py
import pytest
import requests
from backend.crawler import pastebin as pastebin_crawler

ARCHIVE_HTML = """
<table class="maintable">
<tr><td><a href="/abcd1234">Paste 1</a></td></tr>
</table>
"""

PASTE_HTML = """
<textarea id="paste_code">
test@example.com
SSN: 123-45-6789
Phone: 337-555-1234
Password: hunter2
Address: 123 Main Street
</textarea>
"""

class MockResponse:
    def __init__(self, text):
        self.status_code = 200
        self.text = text

def mock_get_archive(self, url, timeout):
    return MockResponse(ARCHIVE_HTML)

def mock_get_paste(self, url, timeout):
    return MockResponse(PASTE_HTML)

def test_pastebin_fetch_and_store(monkeypatch):
    monkeypatch.setattr(requests.Session, "get", lambda s, url, timeout=10:
                        mock_get_archive(s, url, timeout) if "archive" in url else mock_get_paste(s, url, timeout))
    inserted = pastebin_crawler.fetch_and_store(limit=1)
    assert inserted >= 0  # should not crash

    entities = pastebin_crawler.extract_entities(PASTE_HTML)
    assert "test@example.com" in entities["emails"]
    assert "123456789" in entities["ssns"]
    assert "3375551234" in entities["phone_numbers"]
