import requests
import hashlib
import time
from bs4 import BeautifulSoup
from backend.database import insert_leak, init_db
from backend.utils import (
    extract_items, tag_and_score, detect_language,
    match_assets, redact_sensitive_data, send_event_to_api
)
from backend.crawler.config import load_config
from requests.utils import requote_uri

# --- INIT ---
init_db()

#FREENET_PROXY = "http://127.0.0.1:8888/USK@5ijbfKSJ4kPZTRDzq363CHteEUiSZjrO-E36vbHvnIU,ZEZqPXeuYiyokY2r0wkhJr5cy7KBH9omkuWDqSC6PLs,AQACAAE/clean-spider/425/index-img.htm"
FREENET_PROXY = "http://127.0.0.1:8888/USK@0NbybLqOJgJKPfAlYdVwMLkAiDyMRO2wDEJ9P27bAm8,6FGYI7qpmTMiThzYIlrc75Hq6f7Gos0ueGG0rHP-i4E,AQACAAE/freenetdoc/0/"
TIMEOUT = 60  # seconds


def normalize_html_for_hashing(html: str) -> str:
    import re
    # Remove comments (common place for timestamps)
    html = re.sub(r'<!--.*?-->', '', html)
    # Remove timestamp patterns
    html = re.sub(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z', '', html)
    return html.strip()


def fetch_and_store(url, config):
    try:
        url = requote_uri(url)
        headers = {"User-Agent": "Mozilla/5.0 (compatible; FreenetCrawler/1.0)"}
        response = requests.get(url, headers=headers, timeout=TIMEOUT)
        if response.status_code != 200:
            print(f"[Freenet] Non-200 status: {response.status_code}")
            return False

        content = response.text
        soup = BeautifulSoup(content, "html.parser")
        title = soup.title.string if soup.title else url

        # Keyword filtering
        keywords = config.get("keywords", [])
        if keywords and not any(kw.lower() in content.lower() for kw in keywords):
            print(f"[Config] Skipping Freenet page (no keyword match): {title}")
            return True

        # Redaction & Enrichment
        redacted_content, token_map = redact_sensitive_data(content)
        normalized_for_hash = normalize_html_for_hashing(content)
        content_hash = hashlib.sha256(normalized_for_hash.encode("utf-8")).hexdigest()
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
            "source_type": "freenet",
            "poster": None,
            "post_id": url.split("/")[-1],
            "fetched_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        }

        leak_id = insert_leak(
            source="Freenet",
            url=url,
            title=title,
            content=redacted_content,
            normalized=normalized
        )

        event = {
            "leak_id": leak_id,
            "source": "Freenet",
            "url": url,
            "normalized": normalized
        }
        send_event_to_api(event)
        print(f"[Freenet] Inserted leak id {leak_id}: {title}")
        return True

    except Exception as e:
        print(f"[Freenet] Failed: {e}")
        return False


if __name__ == "__main__":
    config = load_config()
    if not config:
        print("[Freenet] No config available, exiting.")
        exit(1)

    source_cfg = config["sources"].get("freenet", {})
    if not source_cfg.get("enabled", False):
        print("[Freenet] Freenet source disabled for this org.")
        exit(0)

    urls = source_cfg.get("urls", [])
    for url in urls:
        if fetch_and_store(url, config):
            print("[Freenet] Saved page to DB.")
        else:
            print("[Freenet] Failed to fetch page.")
