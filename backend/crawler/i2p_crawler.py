import requests
import os
import hashlib
import time
from bs4 import BeautifulSoup
from backend.crawler.config import load_config
from backend.database import insert_leak, init_db
from backend.utils import (extract_items, tag_and_score, detect_language, match_assets, redact_sensitive_data, send_event_to_api)


# --- INIT DB ---
init_db()

# --- CONFIG ---
USE_I2P = True
I2P_PROXY = {
    "http": "http://127.0.0.1:4444",
    "https": "http://127.0.0.1:4444"
}

CONFIG_URL = "http://127.0.0.1:5000/v1/config/org/123"



# --- FETCH & STORE ---
def fetch_and_store(url, config, retries=3, delay=10):
    session = requests.Session()
    if USE_I2P:
        session.proxies = I2P_PROXY

    for attempt in range(retries):
        try:
            response = session.get(url, timeout=120)
            if response.status_code == 200:
                content = response.text or ""
                soup = BeautifulSoup(response.text, "html.parser")
                title = soup.title.string if soup.title else url

                # Keyword filtering
                keywords = config.get("keywords", [])
                if keywords and not any(kw.lower() in content.lower() for kw in keywords):
                    print(f"[Config] Skipping I2P page (no keyword match): {title}")
                    return True # Indicate fetch succeeded but was skipped

                # Redaction
                redacted_content, token_map = redact_sensitive_data(content)

                # Hash
                content_hash = hashlib.sha256(content.encode("utf-8")).hexdigest() if content else None

                # Extraction and enrichment
                extracted = extract_items(content)
                tags, confidence = tag_and_score(content, extracted)
                language = detect_language(content)
                asset_match = match_assets(extracted, config.get("assets", {}))

                normalized = {
                    "title": title,
                    "content_hash": content_hash,
                    "extracted": extracted,
                    "tags": tags,
                    "confidence": confidence,
                    "language": language,
                    "asset_match": asset_match,
                    "redaction": token_map,
                    "source_type": "i2p",
                    "poster": None,  
                    "post_id": url.split("/")[-1],
                    "fetched_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
                }

                # Insert redacted content
                leak_id = insert_leak(
                    source="I2P",
                    url=url,
                    title=title,
                    content=redacted_content,
                    normalized=normalized,
                    severity=None
                )

                # Send to API
                event = {
                    "leak_id": leak_id,
                    "source": "I2P",
                    "url": url,
                    "normalized": normalized
                }
                send_event_to_api(event)

                print(f"[I2P] Inserted leak id {leak_id}: {title}")
                print(f"   Language: {language} | Tags: {tags} | Confidence: {confidence}")
                if token_map:
                    print(f"   Redacted {len(token_map)} sensitive items")

                return True
            else:
                print(f"[I2P] Non-200 status: {response.status_code}")
                return False
        except Exception as e:
            print(f"[I2P] Attempt {attempt+1}/{retries} failed: {e}")
            time.sleep(delay)
    return False

# --- MAIN ---
if __name__ == "__main__":
    config = load_config()
    if not config:
        print("[I2P] No config available, exiting.")
        exit(1)

    source_cfg = config["sources"].get("i2p", {})
    if not source_cfg.get("enabled", False):
        print("[I2P] I2P source disabled for this org.")
        exit(0)

    # You can make this a list in config later
    urls = source_cfg.get("urls", ["http://zzz.i2p"])

    for url in urls:
        if fetch_and_store(url, config):
            print("[I2P] Saved page to DB.")
        else:
            print("[I2P] Failed to fetch page after retries.")