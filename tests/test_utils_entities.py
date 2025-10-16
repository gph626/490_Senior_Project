# tests/test_utils_entities.py
import pytest
from backend.utils import extract_entities

def test_extract_entities_basic_fields():
    text = """
    Email: TEST.USER@Example.Com
    Domain: Sub.Domain.Example.Org
    SSN: 987-65-4321
    Phone: (337) 555-1234
    Password = hunter2
    Name: Alice Wonderland
    Address: 42 boulevard of broken dreams
    BTC: 1BoatSLRHtKNngkdXEeobR76b53LETtpyT
    """

    entities = extract_entities(text)

    assert "test.user@example.com" in entities["emails"]
    assert "sub.domain.example.org" in entities["domains"]
    assert "987654321" in entities["ssns"]
    assert "13375551234" not in entities["phone_numbers"]  # Sanity check wrong number
    assert "3375551234" in entities["phone_numbers"]
    assert "hunter2" in entities["passwords"]
    assert any("42 Boulevard Of Broken Dreams" in a for a in entities["physical_addresses"])
    assert "alice wonderland" in entities["names"]
    assert any(w for w in entities["btc_wallets"])

def test_extract_entities_multiple_values():
    text = """
    Emails: alice@example.com, bob@Example.com
    SSNs: 123-45-6789 and 987-65-4321
    Phones: (337) 555-1234, 504-111-2222
    Password: hunter2
    Pass: secret123
    Address: 100 Main Street
    Address: 42 boulevard of broken dreams
    """

    entities = extract_entities(text)

    # Emails normalized and deduplicated
    assert "alice@example.com" in entities["emails"]
    assert "bob@example.com" in entities["emails"]
    assert len(entities["emails"]) == 2

    # SSNs stored as stripped digits
    assert "123456789" in entities["ssns"]
    assert "987654321" in entities["ssns"]
    assert len(entities["ssns"]) == 2

    # Phones digits only
    assert "3375551234" in entities["phone_numbers"]
    assert "5041112222" in entities["phone_numbers"]
    assert len(entities["phone_numbers"]) == 2

    # Passwords: multiple matches
    assert "hunter2" in entities["passwords"]
    assert "secret123" in entities["passwords"]
    assert len(entities["passwords"]) == 2

    # Addresses properly title-cased
    assert any("100 Main Street" in a for a in entities["physical_addresses"])
    assert any("42 Boulevard Of Broken Dreams" in a for a in entities["physical_addresses"])