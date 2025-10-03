import os
import time
import hashlib
import requests
from bs4 import BeautifulSoup
from backend.crawler.config import load_config
from backend.database import insert_leak, init_db
from backend.utils import (extract_items, tag_and_score, detect_language, load_assets, match_assets, redact_sensitive_data, send_event_to_api)

# --- INIT DB ---
init_db()

# --- CONFIG ---
USE_TOR = True
TOR_PORT = os.getenv("TOR_PORT", "9050")  # 9050 = tor.exe, 9150 = Tor Browser
TOR_PROXY = {
    "http": f"socks5h://127.0.0.1:{TOR_PORT}",
    "https": f"socks5h://127.0.0.1:{TOR_PORT}"
}

CONFIG_URL = "http://127.0.0.1:5000/v1/config/org/123"
ASSETS = load_assets()


# --- FETCH & STORE ---
def fetch_and_store(url, config, retries=3, delay=10):
    """Fetch a Tor page, process it, and store results."""
    session = requests.Session()
    if USE_TOR:
        session.proxies = TOR_PROXY

    for attempt in range(retries):
        try:
            response = session.get(url, timeout=30)
            if response.status_code != 200:
                print(f"[Tor] Non-200 status {response.status_code} for {url}")
                continue

            soup = BeautifulSoup(response.text, "html.parser")
            title = soup.title.string.strip() if soup.title else "No title"
            content = soup.get_text(separator="\n")

            # --- Keyword filtering ---
            keywords = config.get("keywords", [])
            if keywords and not any(kw.lower() in content.lower() for kw in keywords):
                print(f"[Config] Skipping (no keyword match): {title}")
                return False

            # --- Redact sensitive data ---
            redacted_content, token_map = redact_sensitive_data(content)

            # --- Content hash ---
            content_hash = hashlib.sha256(content.encode("utf-8")).hexdigest() if content else None

            # --- Enrichment ---
            extracted = extract_items(content)
            tags, confidence = tag_and_score(content, extracted)
            language = detect_language(content)
            asset_match = match_assets(extracted, ASSETS)

            # --- Save to DB ---
            normalized = {
                "title": title,
                "url": url,
                "content_hash": content_hash,
                "extracted": extracted,
                "tags": tags,
                "confidence": confidence,
                "language": language,
                "asset_match": asset_match,
                "redaction": token_map,
                "source_type": "tor",
                "poster": None,
                "post_id": url.split("/")[-1],
                "fetched_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            }

            leak_id = insert_leak(
                source="Tor",
                url=url,
                title=title,
                content=redacted_content,
                normalized=normalized,
                severity=None
            )

            # --- Send event to API ---
            event = {
                "leak_id": leak_id,
                "source": "Tor",
                "url": url,
                "normalized": normalized
            }
            send_event_to_api(event)

            print(f"[Tor] Inserted leak #{leak_id}: {title}")
            print(f"   Language: {language} | Tags: {tags} | Confidence: {confidence}")
            if token_map:
                print(f"   Redacted {len(token_map)} sensitive items")

            return True

        except Exception as e:
            print(f"[Tor] Attempt {attempt+1}/{retries} failed: {e}")
            time.sleep(delay)

    print(f"[Tor] Failed to fetch {url} after {retries} attempts.")
    return False


# --- MAIN ---
if __name__ == "__main__":
    config = load_config()
    if not config:
        exit(1)

    source_cfg = config["sources"].get("tor", {})
    if not source_cfg.get("enabled", False):
        print("[Config] Tor source disabled for this org.")
        exit(0)

    # You can put real .onion URLs here or test with example.com if Tor isn't running
    test_url = "http://duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion"

    if fetch_and_store(test_url, config):
        print("Saved page to DB.")
    else:
        print("No data saved.")
