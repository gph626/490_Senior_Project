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
    extract_entities,
)

# --- INIT ---
logger = logging.getLogger("tor_crawler")
logger.setLevel(logging.INFO)
init_db()



# --- CONFIG & PROXY ---
ORG_ID = int(os.getenv("ORG_ID", "123"))  # Overridable via environment
USE_TOR = True

# Default to 9150 to match Tor Browser; the web app overrides this via /api/crawlers/tor/run
TOR_PORT = os.getenv("TOR_PORT", "9150")
TOR_PROXY = {
    "http": f"socks5h://127.0.0.1:{TOR_PORT}",
    "https": f"socks5h://127.0.0.1:{TOR_PORT}",
}

# Cached org configuration (lazy-loaded). Empty on failure; crawler continues.
_CONFIG_CACHE: dict = {}

def load_org_config(force: bool = False) -> dict:
    """Load org config once and cache it; non-fatal on backend errors.

    Returns a dict (possibly empty). Set force=True to refresh the cache.
    """
    global _CONFIG_CACHE
    if _CONFIG_CACHE and not force:
        return _CONFIG_CACHE
    url = f"http://127.0.0.1:5000/v1/config/org/{ORG_ID}"
    try:
        cfg = load_config(url) or {}
        if not isinstance(cfg, dict):
            logger.warning("Org config is not a dict; using empty config")
            cfg = {}
        _CONFIG_CACHE = cfg
    except Exception as e:
        logger.warning(f"Org config load failed: {e}")
        _CONFIG_CACHE = {}
    return _CONFIG_CACHE



# --- HEALTH CHECK ---
def health_check():
    try:
        s = requests.Session()
        s.proxies = TOR_PROXY
        r = s.get("http://duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion", timeout=10)
        if r.status_code == 200:
            logger.info("Tor health check OK")
            return True
        else:
            logger.warning(f"Tor health check failed: {r.status_code}")
            return False
    except Exception as e:
        logger.warning(f"Tor health check exception: {e}")
        return False



# --- FETCH & PROCESS ---
def fetch_and_store(url: str, retries: int = 3, delay: int = 10, config: dict | None = None) -> bool:
    retries = int(retries)
    delay = int(delay)
    if config is None:
        config = load_org_config()
    session = requests.Session()
    if USE_TOR:
        session.proxies = TOR_PROXY

    for attempt in range(retries):
        try:
            r = session.get(url, timeout=30)

            if r.status_code != 200:
                logger.warning(f"[TorCrawler] Non-200 status {r.status_code} for {url}")
                continue

            soup = BeautifulSoup(r.text, "html.parser")
            title = soup.title.string.strip() if soup.title and soup.title.string else "No title"
            content = soup.get_text("\n").strip() if soup else ""

            if not content:
                logger.warning(f"[TorCrawler] Empty content for {url}")
                continue

            # --- Fingerprint ---
            content_hash = "sha256:" + hashlib.sha256(content.encode("utf-8", errors="ignore")).hexdigest()

            # --- Entities ---
            entities = extract_entities(content)

            # --- Tagging & Matching ---
            lang = detect_language(content)
            matched_assets = match_assets(entities, (config or {}).get("watchlist", {}))
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
            _, is_dup = insert_leak_with_dedupe(
                source="Tor",
                url=url,
                title=title,
                content=content,
                content_hash=content_hash,
                severity=severity,
                entities=entities,
                ssn=entities.get("ssns"),
                names=entities.get("names"),
                phone_numbers=entities.get("phone_numbers"),
                physical_addresses=entities.get("physical_addresses"),
                passwords=entities.get("passwords"),
            )


            # --- Prepare Event Payload ---
            event_uid = hashlib.sha256((url + content_hash).encode()).hexdigest()
            event = {
                "uid": event_uid,
                "source": "Tor",
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
                "ssn": entities.get("ssns"),
                "names": entities.get("names"),
                "phone_numbers": entities.get("phone_numbers"),
                "physical_addresses": entities.get("physical_addresses"),
                "passwords": entities.get("passwords"),
            }


            # --- Send to API ---
            send_event_to_api(event)
            logger.info(f"[TorCrawler] Stored & sent: {title} | dup={is_dup}")
            return True

        except Exception as e:
            logger.warning(f"[TorCrawler] Attempt {attempt+1}/{retries} failed: {e}")
            time.sleep(int(delay))

    return False

# --- MAIN ---
if __name__ == "__main__":
    # Optional preload; failures are non-fatal because fetch_and_store lazy-loads.
    load_org_config()

    if not health_check():
        logger.warning("Tor not reachable. Exiting.")
    else:
        # SAFE onion URL for testing
        test_url = "http://duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion"
        fetch_and_store(test_url)
