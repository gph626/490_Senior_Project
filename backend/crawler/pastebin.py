import requests
import hashlib
import time
from bs4 import BeautifulSoup
from backend.database import insert_leak, init_db
from backend.crawler.config import load_config
from backend.utils import extract_items, tag_and_score, detect_language, load_assets, match_assets, send_event_to_api, redact_sensitive_data

# Ensure DB and tables exist (consistent with other crawlers)
init_db()

# Mock config API
CONFIG_URL = "http://127.0.0.1:5000/v1/config/org/123"

# Load asset list once at startup
ASSETS = load_assets()



def fetch_and_store():
    # Load config
    config = load_config()
    if not config:
        print("[Config] No config loaded, skipping run.")
        return

    source_cfg = config["sources"].get("pastebin", {})
    if not source_cfg.get("enabled", False):
        print("[Config] Pastebin source disabled for this org.")
        return

    limit = source_cfg.get("limit", 5)
    keywords = config.get("keywords", [])

    url = "https://pastebin.com/archive"
    response = requests.get(url)
    if response.status_code != 200:
        print("[Crawler] Failed to fetch Pastebin archive")
        return

    soup = BeautifulSoup(response.text, "html.parser")

    for row in soup.select("table.maintable tr")[1:limit+1]:
        cols = row.find_all("td")
        link = "https://pastebin.com" + cols[0].find("a")["href"]
        title = cols[0].text.strip()

        # Fetch full paste content
        raw_link = link.replace("pastebin.com/", "pastebin.com/raw/")
        content = requests.get(raw_link).text if raw_link else ""

        # Keyword filtering (per org config)
        if keywords and not any(kw.lower() in content.lower() for kw in keywords):
            print(f"[Config] Skipping paste (no keyword match): {title}")
            continue

        # Hash for duplicate detection
        content_hash = hashlib.sha256(content.encode("utf-8")).hexdigest() if content else None

        # Redact sensitive data before storing/sending
        redacted_content, token_map = redact_sensitive_data(content)

        # Run enrichment on the paste content
        extracted = extract_items(content)
        tags, confidence = tag_and_score(content, extracted)
        language = detect_language(content)
        asset_match = match_assets(extracted, ASSETS)


        # Build normalized JSON
        normalized = {
            "title": title,
            "poster": None,   # Pastebin usually hides posters unless logged in
            "content_hash": content_hash,
            "extracted": extracted,
            "tags": tags,
            "confidence": confidence,
            "language": language,
            "asset_match": asset_match,
            "redaction": token_map,
            "source_type": "pastebin",
            "post_id": url.split("/")[-1],
            "fetched_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        }

        # Insert into DB
        leak_id = insert_leak(
            source="Pastebin",
            url=link,
            title=title,
            content=redacted_content, # Mask sensitive data
            normalized=normalized,
            severity=None,  # scoring comes later
        )

        event = {
            "leak_id": leak_id,
            "source": "Pastebin",
            "url": link,
            "normalized": normalized
        }

        send_event_to_api(event)

        print(f"Inserted leak id {leak_id}: {title}")
        print(f"   Language: {language} | Tags: {tags} | Confidence: {confidence}")
        print(f"   Asset match: {asset_match}")
        if token_map:
            print(f"   Redacted {len(token_map)} sensitive items")


if __name__ == "__main__":
    fetch_and_store()