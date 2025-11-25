import os
import time
import hashlib
import logging
import requests
from dotenv import load_dotenv
load_dotenv()

from typing import Dict, Any
from flask_login import current_user  
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


from backend.database import ENGINE
print(f"[DEBUG] Connected to database: {ENGINE.url}")


# ---------- Setup ----------
logger = logging.getLogger("github_crawler")
logger.setLevel(logging.INFO)
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
        # Load config for this specific user (using user_id as org_id for now)
        _CONFIG_CACHE[user_id] = load_config(user_id) or {}
        logger.info("Loaded config for user_id=%s", user_id)
    except Exception as e:
        logger.warning("Config load failed for user_id=%s: %s. Using defaults.", user_id, e)
        _CONFIG_CACHE[user_id] = {}
    return _CONFIG_CACHE[user_id]

def get_source_cfg(user_id: int | None = None) -> Dict[str, Any]:
    cfg = get_config(user_id)
    return (cfg.get("sources") or {}).get("github", {})

def build_session(user_id: int | None = None) -> tuple[requests.Session, int]:
    s = requests.Session()
    sc = get_source_cfg(user_id)
    ua = sc.get("user_agent", "Mozilla/5.0 (GitHubCrawler/1.0)")
    s.headers.update({"User-Agent": ua})

    # Token resolution order: user config > env var > fallback
    token = (
        sc.get("token")                                  # user's saved config token (primary)
        or os.getenv("GITHUB_TOKEN")                     # local env var (testing)
        or os.getenv("DEFAULT_GITHUB_TOKEN")             # fallback token (optional)
    )
    
    if token:
        s.headers["Authorization"] = f"token {token}"
        logger.info("Using GitHub token from user config")
    else:
        logger.warning("No GitHub token configured. Rate limit = 10 requests/hour. Add token in Crawler Settings.")

    timeout_sec = int(sc.get("timeout_sec", 20))
    return s, timeout_sec


def stable_uid(repo: str, path: str, html_url: str) -> str:
    material = f"github|{repo}|{path}|{html_url}"
    return "evt:" + hashlib.sha256(material.encode("utf-8")).hexdigest()


def health_check(user_id: int | None = None) -> bool:
    try:
        s, timeout = build_session(user_id)
        r = s.get("https://api.github.com/rate_limit", timeout=timeout)
        ok = r.status_code == 200
        logger.info("GitHub API health: %s", "OK" if ok else f"HTTP {r.status_code}")
        return ok
    except Exception as e:
        logger.warning("GitHub health check failed: %s", e)
        return False

# ---------- Main crawler ----------
def fetch_and_store(limit: int = 10, rate_limit_ms: int = 1500, user_id: int | None = None) -> int:
    """
    Search GitHub public code for common secret keywords, process results,
    and store any suspicious findings in the DB.
    """
    if not user_id:
        logger.warning("GitHub crawler requires user_id for config loading")
        return 0
    
    sc = get_source_cfg(user_id)
    keywords = sc.get("keywords") or ["password", "apikey", "secret", "aws_access_key_id", "private_key"]
    # Prefer explicit function arguments over config defaults
    if not (isinstance(limit, int) and limit > 0):
        try:
            limit = int(sc.get("limit", 10))
        except Exception:
            limit = 10
    if not (isinstance(rate_limit_ms, int) and rate_limit_ms >= 0):
        try:
            rate_limit_ms = int(sc.get("rate_limit_ms", 1500))
        except Exception:
            rate_limit_ms = 1500

    s, timeout = build_session(user_id)

    api_url = "https://api.github.com/search/code"
    inserted = 0

    remaining = max(0, int(limit))
    for kw in keywords:
        if remaining <= 0:
            break
        query = f"{kw} in:file public:true"
        logger.info("Searching GitHub for '%s'...", kw)
        try:
            per_page = min(max(1, remaining), 100)
            resp = s.get(api_url, params={"q": query, "per_page": per_page, "page": 1}, timeout=timeout)
            if resp.status_code != 200:
                logger.warning("GitHub search failed: HTTP %s (%s)", resp.status_code, resp.text[:200])
                time.sleep(max(0, rate_limit_ms) / 1000.0)
                continue
        except requests.RequestException as e:
            logger.warning("GitHub query error: %s", e)
            time.sleep(max(0, rate_limit_ms) / 1000.0)
            continue

        items = resp.json().get("items", [])
        if not items:
            continue
        for item in items[:remaining]:
            repo = item["repository"]["full_name"]
            path = item.get("path")
            html_url = item.get("html_url")
            snippet = f"{repo}/{path} - keyword: {kw}"

            # Entity & Asset extraction (optional raw fetch skipped for speed)
            entities = extract_entities(snippet)
            try:
                asset_matches = match_assets(snippet, get_config(user_id))
                asset_hit_count = len(asset_matches.get("hits", [])) if isinstance(asset_matches, dict) else 0
            except Exception as e:
                logger.warning("match_assets failed: %s", e)
                asset_matches = {}
                asset_hit_count = 0

            lang = detect_language(snippet)
            sev = compute_severity_from_entities(entities)
            tags = guess_tags(entities, asset_hit_count)
            uid = stable_uid(repo, path, html_url)
            redacted = redact_sensitive_data(snippet)

            # --- Insert into DB with dedupe ---
            _, is_dup = insert_leak_with_dedupe(
                source="github",
                url=html_url,
                title=f"{repo}/{path}",
                content=snippet,
                content_hash="sha256:" + hashlib.sha256(snippet.encode("utf-8")).hexdigest(),
                severity=sev,
                entities=entities,
                passwords=entities.get("passwords"),
                ssn=entities.get("ssns"),
                names=entities.get("names"),
                phone_numbers=entities.get("phone_numbers"),
                physical_addresses=entities.get("physical_addresses"),
                user_id=user_id,
            )


            if not is_dup:
                inserted += 1
                remaining -= 1
                if remaining <= 0:
                    break

            # Rate limit between searches
            time.sleep(max(0, rate_limit_ms) / 1000.0)
        if remaining <= 0:
            break

    logger.info("[GitHubCrawler] Run complete. Inserted new=%s | user_id=%s", inserted, user_id or getattr(current_user, 'id', None))
    return inserted

if __name__ == "__main__":
    health_check()
    fetch_and_store()
