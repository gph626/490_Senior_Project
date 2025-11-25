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
logger = logging.getLogger("i2p_crawler")
logger.setLevel(logging.INFO)
init_db()

# --- CONFIG ---
USE_I2P = True
I2P_PROXY = {
    "http": "http://127.0.0.1:4444",
    "https": "http://127.0.0.1:4444",
}

_CONFIG_CACHE: dict = {}

def load_user_config(user_id: int | None = None) -> dict:
    """Load user-specific config."""
    global _CONFIG_CACHE
    if not user_id:
        return {}
    if user_id in _CONFIG_CACHE:
        return _CONFIG_CACHE[user_id]
    try:
        _CONFIG_CACHE[user_id] = load_config(user_id) or {}
        logger.info(f"Loaded config for user_id={user_id}")
    except Exception as e:
        logger.warning(f"Config load failed for user_id={user_id}: {e}")
        _CONFIG_CACHE[user_id] = {}
    return _CONFIG_CACHE[user_id]


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
def fetch_and_store(url: str, retries: int = 3, delay: int = 10, user_id: int | None = None) -> bool:
    config = load_user_config(user_id)
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

            entities = extract_entities(content)

            # --- Tagging & Matching ---
            lang = detect_language(content)
            matched_assets = match_assets(entities, config.get("watchlist", {}))
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
                source="I2P",
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
            logger.info(f"[I2PCrawler] Stored: {title} | dup={is_dup}")
            return True

        except Exception as e:
            logger.warning(f"[I2PCrawler] Attempt {attempt+1}/{retries} failed: {e}")
            time.sleep(int(delay))

    return False

# --- MAIN ---
if __name__ == "__main__":
    if not health_check():
        logger.warning("I2P not reachable. Exiting.")
    else:
        # Test URL for I2P
        test_url = "http://zzz.i2p"
        fetch_and_store(test_url)
