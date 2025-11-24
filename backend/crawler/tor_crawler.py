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
USE_TOR = True

# Default to 9150 to match Tor Browser; the web app overrides this via /api/crawlers/tor/run
TOR_PORT = os.getenv("TOR_PORT", "9150")
TOR_PROXY = {
    "http": f"socks5h://127.0.0.1:{TOR_PORT}",
    "https": f"socks5h://127.0.0.1:{TOR_PORT}",
}

# Cached user configuration (lazy-loaded per user)
_CONFIG_CACHE: dict = {}

def load_user_config(user_id: int | None = None) -> dict:
    """Load user-specific config; non-fatal on backend errors.

    Returns a dict (possibly empty).
    """
    global _CONFIG_CACHE
    if not user_id:
        return {}  # No config without user context
    
    # Check cache first
    if user_id in _CONFIG_CACHE:
        return _CONFIG_CACHE[user_id]
    
    try:
        cfg = load_config(user_id) or {}
        if not isinstance(cfg, dict):
            logger.warning("User config is not a dict; using empty config")
            cfg = {}
        _CONFIG_CACHE[user_id] = cfg
        logger.info(f"Loaded config for user_id={user_id}")
    except Exception as e:
        logger.warning(f"Config load failed for user_id={user_id}: {e}")
        _CONFIG_CACHE[user_id] = {}
    return _CONFIG_CACHE[user_id]



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
def fetch_and_store(url: str, retries: int = 3, delay: int = 10, config: dict | None = None, user_id: int | None = None) -> bool:
    retries = int(retries)
    delay = int(delay)
    if config is None:
        config = load_user_config(user_id)
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
                user_id=user_id,
            )


            # Data already stored in database
            logger.info(f"[TorCrawler] Stored: {title} | dup={is_dup}")
            return True

        except Exception as e:
            logger.warning(f"[TorCrawler] Attempt {attempt+1}/{retries} failed: {e}")
            time.sleep(int(delay))

    return False

# --- MAIN ---
if __name__ == "__main__":
    if not health_check():
        logger.warning("Tor not reachable. Exiting.")
    else:
        # SAFE onion URL for testing
        test_url = "http://duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion"
        fetch_and_store(test_url)
