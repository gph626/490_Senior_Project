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



ORG_ID = int(os.environ.get("DARKWEB_ORG_ID", "123"))
_CONFIG_CACHE: Dict[str, Any] = {}

def get_config() -> Dict[str, Any]:
    global _CONFIG_CACHE
    if not _CONFIG_CACHE:
        try:
            _CONFIG_CACHE = load_config(ORG_ID) or {}
            logger.info("Loaded config for org_id=%s", ORG_ID)
        except Exception as e:
            logger.warning("Config load failed (%s). Using defaults.", e)
            _CONFIG_CACHE = {}
    return _CONFIG_CACHE

def get_source_cfg() -> Dict[str, Any]:
    cfg = get_config()
    return (cfg.get("sources") or {}).get("pastebin", {})

def build_session() -> tuple[requests.Session, int]:
    s = requests.Session()
    sc = get_source_cfg()
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

def health_check() -> bool:
    try:
        s, timeout = build_session()
        r = s.get("https://pastebin.com/archive", timeout=timeout)
        ok = r.status_code == 200
        logger.info("Health check: %s", "OK" if ok else f"HTTP {r.status_code}")
        return ok
    except Exception as e:
        logger.warning("Health check failed: %s", e)
        return False

# ---------- Main crawler ----------
def fetch_and_store(limit: int = 10, rate_limit_ms: int = 500) -> int:
    """
    Fetch latest pastes, extract entities, match assets, compute severity, redact,
    insert with dedupe, and send event to API (idempotent via stable uid).
    Returns number of newly-inserted DB rows.
    """
    sc = get_source_cfg()
    limit = int(sc.get("limit", limit))
    rate_limit_ms = int(sc.get("rate_limit_ms", rate_limit_ms))

    s, timeout = build_session()

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
            asset_matches = match_assets(content or "", get_config())
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

        # Stable UID for idempotent upsert on the server
        uid = stable_uid(paste_id, link, content_hash)

        # Redact before sending outward (keep raw content locally if desired)
        redacted = None
        try:
            redacted = redact_sensitive_data(content) if content else None
        except Exception:
            redacted = content  # fail open to avoid losing evidence

        # Insert locally with dedupe
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
        )

        if not is_dup:
            inserted += 1

        # Build event payload for API
        event: Dict[str, Any] = {
            "uid": uid,
            "org_id": ORG_ID,
            "source": "pastebin",
            "source_type": "paste_site",
            "url": link,
            "title": title,
            "paste_id": paste_id,
            "poster": poster,
            "posted_at": posted_at,
            "content_hash": content_hash,
            "language": lang,
            "entities": entities,
            "asset_matches": asset_matches,
            "severity": sev,
            "tags": tags,
            # Send redacted/preview outward
            "content": redacted or content or "",
            "content_preview": (redacted or "")[:2000] if redacted else None,
        }
        event.update({
            "ssn": entities.get("ssns"),
            "names": entities.get("names"),
            "phone_numbers": entities.get("phone_numbers"),
            "physical_addresses": entities.get("physical_addresses"),
            "passwords": entities.get("passwords"),
        })


        # Send to API with small retry/backoff (idempotent via uid)
        for attempt in range(3):
            try:
                send_event_to_api(event)
                break
            except Exception as e:
                wait = (2 ** attempt)
                logger.warning("send_event_to_api failed (attempt %s): %s; retrying in %ss", attempt + 1, e, wait)
                time.sleep(wait)

        time.sleep(max(0, rate_limit_ms) / 1000.0)

    logger.info("Pastebin run complete. Inserted new=%s", inserted)
    return inserted

if __name__ == "__main__":
    # Optional quick health ping before a run
    health_check()
    fetch_and_store()
