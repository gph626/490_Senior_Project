import time
import re
import hashlib
import requests
from bs4 import BeautifulSoup
from backend.database import insert_leak_with_dedupe, init_db
from backend.severity import compute_severity_from_entities

# Ensure DB and tables exist (consistent with other crawlers)
init_db()

EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
DOMAIN_RE = re.compile(r"\b(?:(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)\.)+[a-z]{2,}\b", re.I)
IPV4_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(?:\.|$)){4}\b")
BTC_RE = re.compile(r"\b(?:bc1|[13])[a-zA-HJ-NP-Z0-9]{25,39}\b")


def fetch_and_store(limit: int = 10, rate_limit_ms: int = 500) -> int:
    """Fetch latest pastes, extract entities, and store with dedupe.

    Returns the number of newly inserted records.
    """
    archive_url = "https://pastebin.com/archive"
    resp = requests.get(archive_url, headers={"User-Agent": "Mozilla/5.0 (PastebinCrawler/1.0)"}, timeout=20)
    if resp.status_code != 200:
        print("Failed to fetch Pastebin archive")
        return 0

    soup = BeautifulSoup(resp.text, "html.parser")
    rows = soup.select("table.maintable tr")[1:1+max(1, int(limit))]
    inserted = 0
    for row in rows:
        cols = row.find_all("td")
        a = cols[0].find("a")
        if not a or not a.get("href"):
            continue
        link = ("https://pastebin.com" + a["href"]).strip()
        title = (cols[0].get_text(" ").strip() or None)

        # Fetch full paste content
        try:
            paste_resp = requests.get(link, headers={"User-Agent": "Mozilla/5.0 (PastebinCrawler/1.0)"}, timeout=20)
            if paste_resp.status_code != 200:
                continue
        except requests.RequestException:
            continue

        paste_soup = BeautifulSoup(paste_resp.text, "html.parser")
        # Pastebin renders content in a <textarea id="paste_code"> for raw view or in a div with class content
        content_el = paste_soup.select_one("textarea#paste_code, div.paste_box .textarea") or paste_soup.select_one("div.source")
        content = content_el.get_text("\n").strip() if content_el else None

        # Hash for dedupe (on raw content); if no content, fallback to URL-based dedupe in DB helpers
        content_hash = None
        if content:
            content_hash = "sha256:" + hashlib.sha256(content.encode("utf-8", errors="ignore")).hexdigest()

        # Extract entities
        entities = {}
        if content:
            emails = sorted(set(EMAIL_RE.findall(content)))
            domains = sorted(set(DOMAIN_RE.findall(content)))
            ips = sorted(set(IPV4_RE.findall(content)))
            btcs = sorted(set(BTC_RE.findall(content)))
            entities = {
                "emails": emails,
                "domains": [d.lower() for d in domains],
                "ips": ips,
                "btc_wallets": btcs,
            }

        # Compute severity based on entities/watchlist
        sev = None
        try:
            if entities:
                sev = compute_severity_from_entities(entities)
        except (TypeError, ValueError, KeyError):
            sev = None

        _, is_dup = insert_leak_with_dedupe(
            source="pastebin",
            url=link,
            title=title,
            content=content,
            content_hash=content_hash,
            severity=sev,
            entities=entities,
        )
        if not is_dup:
            inserted += 1
        time.sleep(max(0, rate_limit_ms) / 1000.0)
    return inserted

if __name__ == "__main__":
    fetch_and_store()