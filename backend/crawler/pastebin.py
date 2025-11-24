import os
import time
import re
import hashlib
import logging
import urllib.parse
import requests
from typing import Dict, Any, Optional
from bs4 import BeautifulSoup

from backend.database import insert_leak_with_dedupe, init_db
from backend.severity import compute_severity_from_entities
from backend.crawler.config import load_config
from backend.utils import (
    match_assets,
    detect_language,
    redact_sensitive_data,
    send_event_to_api,
    extract_entities,
)

# ---------- Setup ----------
logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"))
logger = logging.getLogger("pastebin_crawler")

# Ensure DB and tables exist (consistent with other crawlers)
init_db()



# Config is loaded per-user to respect individual crawler settings
_CONFIG_CACHE: Dict[int, Dict[str, Any]] = {}

def get_config(user_id: int | None = None) -> Dict[str, Any]:
    """Load user-specific crawler configuration."""
    global _CONFIG_CACHE
    if not user_id:
        return {}  # No config without user context
    
    # Check cache first
    if user_id in _CONFIG_CACHE:
        return _CONFIG_CACHE[user_id]
    
    try:
        # Load config for this specific user
        _CONFIG_CACHE[user_id] = load_config(user_id) or {}
        logger.info("Loaded config for user_id=%s", user_id)
    except Exception as e:
        logger.warning("Config load failed for user_id=%s: %s. Using defaults.", user_id, e)
        _CONFIG_CACHE[user_id] = {}
    return _CONFIG_CACHE[user_id]

def get_source_cfg(user_id: int | None = None) -> Dict[str, Any]:
    cfg = get_config(user_id)
    return (cfg.get("sources") or {}).get("pastebin", {})

def build_session(user_id: int | None = None) -> tuple[requests.Session, int]:
    s = requests.Session()
    sc = get_source_cfg(user_id)
    ua = sc.get("user_agent", "Mozilla/5.0 (PastebinCrawler/1.0)")
    s.headers.update({"User-Agent": ua})
    proxies = sc.get("proxies")
    if isinstance(proxies, dict):
        s.proxies.update(proxies)
    timeout_sec = int(sc.get("timeout_sec", 20))
    return s, timeout_sec

def stable_uid(paste_id: str, url: str, content_hash: Optional[str]) -> str:
    material = f"pastebin|{paste_id or ''}|{content_hash or url}"
    return "evt:" + hashlib.sha256(material.encode("utf-8")).hexdigest()




def guess_tags(text: str, asset_hit_count: int) -> Dict[str, Any]:
    t = text.lower()
    credentialish = any(
        k in t for k in ["combo list", "password", "passwd", "shadow", "hash:", "login:", "leak"]
    )
    threat_type = "credential_dump" if credentialish else "generic_paste"
    confidence = 0.9 if asset_hit_count > 0 else 0.4
    return {"threat_type": threat_type, "verified": asset_hit_count > 0, "confidence": confidence}

def health_check(user_id: int | None = None) -> bool:
    try:
        s, timeout = build_session(user_id)
        r = s.get("https://pastebin.com/archive", timeout=timeout)
        ok = r.status_code == 200
        logger.info("Health check: %s", "OK" if ok else f"HTTP {r.status_code}")
        return ok
    except Exception as e:
        logger.warning("Health check failed: %s", e)
        return False

# ---------- Main crawler ----------
def fetch_and_store(limit: int = None, rate_limit_ms: int = None, user_id: int | None = None) -> int:
    """
    Fetch latest pastes, extract entities, match assets, compute severity, redact,
    insert with dedupe. Returns number of newly-inserted DB rows.
    """
    if not user_id:
        logger.warning("Pastebin crawler requires user_id for config loading")
        return 0
    
    sc = get_source_cfg(user_id)
    
    # Load limit from user config if not explicitly provided
    if limit is None:
        limit = int(sc.get("limit", 10))  # Default to 10 if no config
    
    logger.info(f"Pastebin crawler using limit={limit} for user_id={user_id}")
    # Load rate_limit_ms from user config if not explicitly provided
    if rate_limit_ms is None:
        rate_limit_ms = int(sc.get("rate_limit_ms", 500))  # Default to 500ms if no config
    
    logger.info(f"Pastebin crawler using rate_limit_ms={rate_limit_ms}")

    s, timeout = build_session(user_id)

    archive_url = "https://pastebin.com/archive"
    try:
        resp = s.get(archive_url, timeout=timeout)
    except requests.RequestException as e:
        logger.error("Failed to fetch Pastebin archive: %s", e)
        return 0

    if resp.status_code != 200:
        logger.error("Archive fetch failed: HTTP %s", resp.status_code)
        return 0

    soup = BeautifulSoup(resp.text, "html.parser")
    rows = soup.select("table.maintable tr")[1:1 + max(1, int(limit))]
    inserted = 0

    for row in rows:
        cols = row.find_all("td")
        a = cols[0].find("a") if cols else None
        if not a or not a.get("href"):
            continue

        link = ("https://pastebin.com" + a["href"]).strip()
        title = (cols[0].get_text(" ").strip() or None) if cols else None

        # Fetch full paste
        try:
            paste_resp = s.get(link, timeout=timeout)
            if paste_resp.status_code != 200:
                logger.info("Skip paste (HTTP %s): %s", paste_resp.status_code, link)
                time.sleep(max(0, rate_limit_ms) / 1000.0)
                continue
        except requests.RequestException as e:
            logger.info("Skip paste (network): %s (%s)", link, e)
            time.sleep(max(0, rate_limit_ms) / 1000.0)
            continue

        paste_soup = BeautifulSoup(paste_resp.text, "html.parser")
        content_el = (
            paste_soup.select_one("textarea#paste_code, div.paste_box .textarea")
            or paste_soup.select_one("div.source")
        )
        content = content_el.get_text("\n").strip() if content_el else None

        # Optional metadata
        u = urllib.parse.urlparse(link)
        paste_id = u.path.strip("/")  # e.g., '/abcd1234' -> 'abcd1234'
        poster_el = paste_soup.select_one(".username, .username a, .usericon a")
        poster = poster_el.get_text(" ").strip() if poster_el else None
        posted_at = None  # Pastebin date parsing is inconsistent; populate if you later add a parser

        # Dedupe fingerprint
        content_hash = None
        if content:
            content_hash = "sha256:" + hashlib.sha256(
                content.encode("utf-8", errors="ignore")
            ).hexdigest()

        # Entities
        entities = extract_entities(content) if content else {}

        # Asset matching (util signature may vary; pass what your project expects)
        try:
            asset_matches = match_assets(content or "", get_config(user_id))
            asset_hit_count = len(asset_matches.get("hits", [])) if isinstance(asset_matches, dict) else 0
        except Exception as e:
            logger.warning("match_assets failed: %s", e)
            asset_matches = {}
            asset_hit_count = 0

        # Language
        lang = None
        try:
            if content:
                lang = detect_language(content)
        except Exception:
            lang = None

        # Severity
        sev = None
        try:
            if entities:
                sev = compute_severity_from_entities(entities)
        except Exception:
            sev = None

        # Tags / Confidence
        tags = guess_tags(content or "", asset_hit_count)

        # Insert to database with deduplication
        _, is_dup = insert_leak_with_dedupe(
            source="pastebin",
            url=link,
            title=title,
            content=content,
            content_hash=content_hash,
            severity=sev,
            entities=entities,
            ssn=entities.get("ssns"),
            names=entities.get("names"),
            phone_numbers=entities.get("phone_numbers"),
            physical_addresses=entities.get("physical_addresses"),
            passwords=entities.get("passwords"),
            user_id=user_id,
        )

        if not is_dup:
            inserted += 1

        # Rate limit between requests
        time.sleep(max(0, rate_limit_ms) / 1000.0)

    logger.info("Pastebin run complete. Inserted new=%s", inserted)
    return inserted

if __name__ == "__main__":
    # Optional quick health ping before a run
    health_check()
    fetch_and_store()
