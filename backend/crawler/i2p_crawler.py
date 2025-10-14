import os
import re
import time
import hashlib
import logging
import requests
from bs4 import BeautifulSoup

from backend.database import insert_leak_with_dedupe, init_db
from backend.severity import compute_severity_from_entities
from backend.crawler.config import load_config
from backend.utils import (
    match_assets,
    detect_language,
    redact_sensitive_data,
    send_event_to_api,
    guess_tags,
)

# --- INIT ---
logger = logging.getLogger("i2p_crawler")
logger.setLevel(logging.INFO)
init_db()

# --- CONFIG ---
ORG_ID = 123  # Make dynamic later if needed
CONFIG = load_config(f"http://127.0.0.1:5000/v1/config/org/{ORG_ID}")

USE_I2P = True
I2P_PROXY = {
    "http": "http://127.0.0.1:4444",
    "https": "http://127.0.0.1:4444",
}

# --- REGEXES ---
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
DOMAIN_RE = re.compile(r"\b(?:(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)\.)+[a-z]{2,}\b", re.I)
IPV4_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(?:\.|$)){4}\b")
BTC_RE = re.compile(r"\b(?:bc1|[13])[a-zA-HJ-NP-Z0-9]{25,39}\b")

# --- HEALTH CHECK ---
def health_check():
    try:
        s = requests.Session()
        s.proxies = I2P_PROXY
        r = s.get("http://zzz.i2p", timeout=10)
        if r.status_code == 200:
            logger.info("I2P health check OK")
            return True
        else:
            logger.warning(f"I2P health check failed: {r.status_code}")
            return False
    except Exception as e:
        logger.warning(f"I2P health check exception: {e}")
        return False

# --- FETCH & PROCESS ---
def fetch_and_store(url: str, retries: int = 3, delay: int = 10) -> bool:
    session = requests.Session()
    if USE_I2P:
        session.proxies = I2P_PROXY

    for attempt in range(retries):
        try:
            logger.debug(f"[I2PCrawler] Fetch attempt {attempt+1} for {url}")
            r = session.get(url, timeout=30)
            if r.status_code != 200:
                logger.warning(f"[I2PCrawler] Non-200 status {r.status_code} for {url}")
                continue

            # --- Parse content ---
            soup = BeautifulSoup(r.text, "html.parser")
            title = soup.title.string.strip() if soup.title and soup.title.string else "No title"
            content = soup.get_text("\n").strip() if soup else ""
            if not content:
                logger.warning(f"[I2PCrawler] Empty content for {url}")
                continue

            # --- Fingerprint ---
            content_hash = "sha256:" + hashlib.sha256(content.encode("utf-8", errors="ignore")).hexdigest()

            # --- Extract Entities ---
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

            # --- Tagging & Matching ---
            lang = detect_language(content)
            matched_assets = match_assets(entities, CONFIG.get("watchlist", {}))
            tags = guess_tags(entities, matched_assets)

            # --- Redact ---
            redacted_text = redact_sensitive_data(content)

            # --- Severity ---
            severity = None
            try:
                if entities:
                    severity = compute_severity_from_entities(entities)
            except (TypeError, ValueError, KeyError):
                severity = None

            # --- Insert locally ---
            leak_id, is_dup = insert_leak_with_dedupe(
                source="I2P",
                url=url,
                title=title,
                content=content,
                content_hash=content_hash,
                severity=severity,
                entities=entities,
            )

            # --- Event Payload ---
            event_uid = hashlib.sha256((url + content_hash).encode()).hexdigest()
            event = {
                "uid": event_uid,
                "source": "I2P",
                "url": url,
                "title": title,
                "content": redacted_text,
                "content_hash": content_hash,
                "entities": entities,
                "language": lang,
                "tags": tags,
                "severity": severity,
                "matched_assets": matched_assets,
                "timestamp": time.time(),
            }

            # --- Send to API ---
            send_event_to_api(event)
            logger.info(f"[I2PCrawler] Stored & sent: {title} | dup={is_dup}")
            return True

        except Exception as e:
            logger.warning(f"[I2PCrawler] Attempt {attempt+1}/{retries} failed: {e}")
            time.sleep(int(delay))

    return False

# --- MAIN ---
if __name__ == "__main__":
    CONFIG = load_config(f"http://127.0.0.1:5000/v1/config/org/{ORG_ID}")
    if not health_check():
        logger.warning("I2P not reachable. Exiting.")
    else:
        # Test URL for I2P
        test_url = "http://zzz.i2p"
        fetch_and_store(test_url)
