import os
import time
import re
import os
import sys
import hashlib
import logging
import requests
from dotenv import load_dotenv
load_dotenv()

from typing import Dict, Any, Optional
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
    return (cfg.get("sources") or {}).get("github", {})

def build_session() -> tuple[requests.Session, int]:
    s = requests.Session()
    sc = get_source_cfg()
    ua = sc.get("user_agent", "Mozilla/5.0 (GitHubCrawler/1.0)")
    s.headers.update({"User-Agent": ua})

    # Token resolution order
    token = (
        os.getenv("GITHUB_TOKEN")                       # local env var
        or sc.get("token")                              # org config API
        or os.getenv("DEFAULT_GITHUB_TOKEN")             # fallback token (for deployment)
    )
    print(f"[DEBUG] Using token: {token}")
    if token:
        s.headers["Authorization"] = f"token {token}"
    else:
        logger.warning("No GitHub token found. Using unauthenticated mode (rate limit = 10/hr).")

    timeout_sec = int(sc.get("timeout_sec", 20))
    return s, timeout_sec


def stable_uid(repo: str, path: str, html_url: str) -> str:
    material = f"github|{repo}|{path}|{html_url}"
    return "evt:" + hashlib.sha256(material.encode("utf-8")).hexdigest()


def health_check() -> bool:
    try:
        s, timeout = build_session()
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
    sc = get_source_cfg()
    keywords = sc.get("keywords") or ["password", "apikey", "secret", "aws_access_key_id", "private_key"]
    limit = int(sc.get("limit", limit))
    rate_limit_ms = int(sc.get("rate_limit_ms", rate_limit_ms))

    s, timeout = build_session()

    api_url = "https://api.github.com/search/code"
    inserted = 0

    for kw in keywords:
        query = f"{kw} in:file public:true"
        logger.info("Searching GitHub for '%s'...", kw)
        try:
            for page in range(1, 3):  # get up to 2 pages (~60 results total)
                resp = s.get(api_url, params={"q": query, "per_page": limit, "page": page}, timeout=timeout)
                if resp.status_code != 200:
                    logger.warning("GitHub search failed: HTTP %s (%s)", resp.status_code, resp.text[:200])
                    break
                items = resp.json().get("items", [])
                if not items:
                    break
            if resp.status_code != 200:
                logger.warning("GitHub search failed: HTTP %s (%s)", resp.status_code, resp.text[:200])
                time.sleep(max(0, rate_limit_ms) / 1000.0)
                continue
        except requests.RequestException as e:
            logger.warning("GitHub query error: %s", e)
            time.sleep(max(0, rate_limit_ms) / 1000.0)
            continue

        items = resp.json().get("items", [])
        for item in items:
            repo = item["repository"]["full_name"]
            path = item.get("path")
            html_url = item.get("html_url")
            snippet = f"{repo}/{path} - keyword: {kw}"

            # Entity & Asset extraction (optional raw fetch skipped for speed)
            entities = extract_entities(snippet)
            try:
                asset_matches = match_assets(snippet, get_config())
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

            # Prepare event payload
            event: Dict[str, Any] = {
                "uid": uid,
                "org_id": ORG_ID,
                "source": "github",
                "source_type": "repo_code",
                "url": html_url,
                "repo": repo,
                "path": path,
                "keyword": kw,
                "language": lang,
                "entities": entities,
                "asset_matches": asset_matches,
                "severity": sev,
                "tags": tags,
                "content": redacted,
                "content_preview": redacted[:2000],
            }
            os.environ.setdefault("API_KEY", os.getenv("API_KEY", ""))

            for attempt in range(3):
                try:
                    # Pass API key automatically with request
                    event["api_key"] = os.getenv("API_KEY", "")
                    send_event_to_api(event)
                    break
                except Exception as e:
                    wait = (2 ** attempt)
                    logger.warning("send_event_to_api failed (attempt %s): %s; retrying in %ss", attempt + 1, e, wait)
                    time.sleep(wait)

            time.sleep(max(0, rate_limit_ms) / 1000.0)

    logger.info("[GitHubCrawler] Run complete. Inserted new=%s | user_id=%s", inserted, user_id or getattr(current_user, 'id', None))
    return inserted

if __name__ == "__main__":
    health_check()
    fetch_and_store()
