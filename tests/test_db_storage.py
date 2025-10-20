import sqlite3
import os
import hashlib
import importlib
import backend.database as db
from backend.utils import extract_entities

def test_db_storage_for_multiple_values(tmp_path):
    # Create temp DB path
    test_db = tmp_path / "test_data.db"

    # Patch DB path and reload the database module to rebuild engine
    db.DB_PATH = str(test_db)
    os.environ["DARKWEB_DB_PATH"] = str(test_db)

    importlib.reload(db)  # ← forces SQLAlchemy to reinitialize with the new DB_PATH

    # Recreate tables for the new DB
    db.init_db()

    # --- Insert fake leak with multiple values ---
    content = """
    SSN: 123-45-6789, 987-65-4321
    Phone: (337) 555-1234, 504-111-2222
    Password: hunter2
    Password: secret123
    Name: Alice Wonderland
    Address: 42 boulevard of broken dreams
    """

    entities = extract_entities(content)
    content_hash = "sha256:" + hashlib.sha256(content.encode()).hexdigest()

    db.insert_leak_with_dedupe(
        source="Test",
        url="http://example.com/leak",
        title="Test Leak",
        content=content,
        content_hash=content_hash,
        severity="medium",
        entities=entities,
        ssn=entities.get("ssns"),
        names=entities.get("names"),
        phone_numbers=entities.get("phone_numbers"),
        physical_addresses=entities.get("physical_addresses"),
        passwords=entities.get("passwords"),
    )

    # --- Query back to check stored values ---
    conn = sqlite3.connect(test_db)
    cur = conn.cursor()
    cur.execute("SELECT passwords, ssn, names, phone_numbers, physical_addresses FROM leaks")
    row = cur.fetchone()
    conn.close()

    assert row is not None
    passwords, ssn, names, phones, addresses = row

    assert "hunter2" in passwords
    assert "secret123" in passwords
    assert "123456789" in ssn and "987654321" in ssn
    assert "alice wonderland" in names
    assert "3375551234" in phones and "5041112222" in phones
    assert "42 Boulevard Of Broken Dreams" in addresses
