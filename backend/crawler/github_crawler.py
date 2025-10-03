import os
import requests
import hashlib
import time

from backend.database import insert_leak, init_db
from backend.utils import (
    extract_items, tag_and_score, detect_language,
    match_assets, redact_sensitive_data, send_event_to_api
)
from backend.crawler.config import load_config

init_db()
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN")

def search_and_store(keyword, config):
    headers = {"Accept": "application/vnd.github+json"}
    if GITHUB_TOKEN:
        headers["Authorization"] = f"token {GITHUB_TOKEN}"

    url = f"https://api.github.com/search/code?q={keyword}+in:file"
    resp = requests.get(url, headers=headers, timeout=30)
    if resp.status_code != 200:
        print(f"[GitHub] Search failed ({resp.status_code}): {resp.text}")
        return

    results = resp.json().get("items", [])
    for item in results[:5]:  # limit
        raw_url = item["html_url"].replace("github.com", "raw.githubusercontent.com").replace("/blob/", "/")
        process_file(raw_url, keyword, config)


def process_file(url, title, config):
    try:
        r = requests.get(url, timeout=30)
        if r.status_code != 200:
            print(f"[GitHub] Non-200 for file: {r.status_code}")
            return
        content = r.text

        redacted_content, token_map = redact_sensitive_data(content)
        content_hash = hashlib.sha256(content.encode("utf-8")).hexdigest()
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
            "source_type": "github",
            "fetched_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        }

        leak_id = insert_leak(
            source="GitHub",
            url=url,
            title=title,
            content=redacted_content,
            normalized=normalized
        )

        send_event_to_api({
            "leak_id": leak_id,
            "source": "GitHub",
            "url": url,
            "normalized": normalized
        })
        print(f"[GitHub] Inserted leak id {leak_id}: {title}")
    except Exception as e:
        print(f"[GitHub] Failed to process file: {e}")


if __name__ == "__main__":
    config = load_config()
    if not config:
        print("[GitHub] No config available, exiting.")
        exit(1)

    source_cfg = config["sources"].get("github", {})
    if not source_cfg.get("enabled", False):
        print("[GitHub] GitHub source disabled for this org.")
        exit(0)

    keywords = config.get("keywords", [])
    for kw in keywords:
        search_and_store(kw, config)
