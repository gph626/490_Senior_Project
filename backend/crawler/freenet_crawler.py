import os
import time
import hashlib
import logging
from typing import Dict, Any, Optional, List

import requests
from bs4 import BeautifulSoup

from backend.database import init_db, insert_leak_with_dedupe
from backend.severity import compute_severity_from_entities
from backend.crawler.config import load_config
from backend.utils import (
    match_assets,
    detect_language,
    redact_sensitive_data,
    send_event_to_api,
    extract_entities,
)

logger = logging.getLogger("freenet_crawler")
logger.setLevel(logging.INFO)

# Ensure DB and tables exist (no path juggling here; your app sets DARKWEB_DB_PATH)
init_db()

# Config (support both FRENET_* and FREENET_* env names)
FPROXY_HOST = (
    os.environ.get("FRENET_FPROXY_HOST")
    or os.environ.get("FREENET_FPROXY_HOST")
    or os.environ.get("FREENET_HOST")
    or "127.0.0.1"
)
FPROXY_PORT = int(
    os.environ.get("FRENET_FPROXY_PORT")
    or os.environ.get("FREENET_FPROXY_PORT")
    or os.environ.get("FREENET_PORT")
    or "8888"
)
FPROXY_BASE = f"http://{FPROXY_HOST}:{FPROXY_PORT}"
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
    # expected shape (with sensible defaults):
    # "freenet": {
    #   "timeout_sec": 30,
    #   "proxy_host": "127.0.0.1",
    #   "proxy_port": 8888,
    #   "keywords": ["leak", "dump", "credential"],
    #   "seeds": ["http://127.0.0.1:8888/USK@.../index.html"]   # optional
    # }
    return (cfg.get("sources") or {}).get("freenet", {})


def build_session() -> tuple[requests.Session, int]:
    s = requests.Session()
    sc = get_source_cfg()

    timeout_sec = int(sc.get("timeout_sec", 30))

    # Freenet typically exposes FProxy at 127.0.0.1:8888 (HTTP only)
    proxy_host = (sc.get("proxy_host") or "127.0.0.1").strip()
    proxy_port = int(sc.get("proxy_port", 8888))
    proxy_url = f"http://{proxy_host}:{proxy_port}"

    # Route HTTP through FProxy; HTTPS is not typical for FProxy, so just set http
    s.proxies.update({"http": proxy_url})

    # UA just to be explicit
    s.headers.update({"User-Agent": "Mozilla/5.0 (FreenetCrawler/1.0)"})
    return s, timeout_sec


def stable_uid(url: str, content_hash: Optional[str]) -> str:
    material = f"freenet|{url}|{content_hash or ''}"
    return "evt:" + hashlib.sha256(material.encode("utf-8")).hexdigest()


def health_check() -> bool:
    try:
        r = requests.get(FPROXY_BASE + "/", timeout=3)
        ok = r.status_code == 200
        logger.info("Freenet FProxy health: %s", "OK" if ok else f"HTTP {r.status_code}")
        return ok
    except Exception as e:
        logger.warning("FProxy health check failed: %s", e)
        return False


def _extract_text(html: str) -> str:
    soup = BeautifulSoup(html or "", "html.parser")
    # keep visible text only
    for tag in soup(["script", "style", "noscript"]):
        tag.extract()
    txt = soup.get_text("\n")
    return "\n".join([line.strip() for line in txt.splitlines() if line.strip()])


def _guess_tags(text: str, asset_hit_count: int) -> Dict[str, Any]:
    t = (text or "").lower()
    credentialish = any(k in t for k in ["combo list", "password", "passwd", "shadow", "hash:", "login:", "credential", "dump"])
    return {
        "threat_type": "credential_dump" if credentialish else "freenet_content",
        "verified": asset_hit_count > 0,
        "confidence": 0.9 if asset_hit_count > 0 else 0.4,
    }


def _parse_env_seeds() -> List[str]:
    """Read optional FREENET_SEEDS (or FRENET_SEEDS) from env.
    Accepts comma/newline/semicolon-separated list. Supports raw USK@/SSK@/CHK@ URIs
    and full FProxy URLs. Raw URIs are prefixed with FPROXY_BASE.
    """
    raw = (
        os.environ.get("FREENET_SEEDS")
        or os.environ.get("FRENET_SEEDS")
        or ""
    )
    if not raw:
        return []
    import re
    # Split on newlines or semicolons ONLY; do NOT split on commas because Freenet URIs contain commas.
    parts = [p.strip() for p in re.split(r"[\n;]+", raw) if p.strip() and not p.strip().startswith("#")]
    urls: List[str] = []
    for p in parts:
        # Normalize any 'freenet:' prefix to plain path style used by FProxy
        # e.g., http://127.0.0.1:8888/freenet:USK@... -> http://127.0.0.1:8888/USK@...
        if p.startswith("http://") or p.startswith("https://"):
            if "/freenet:" in p:
                p = p.replace("/freenet:", "/", 1)
        else:
            if p.startswith("freenet:"):
                p = p.replace("freenet:", "", 1)
        if p.startswith("http://") or p.startswith("https://"):
            urls.append(p)
        elif p.startswith("USK@") or p.startswith("SSK@") or p.startswith("CHK@"):
            urls.append(f"{FPROXY_BASE}/{p}")
        else:
            # treat as path under FProxy (e.g., "/USK@..." or "USK@...")
            urls.append(f"{FPROXY_BASE}/{p.lstrip('/')}")
    return urls


def _urls_from_config(limit: int) -> List[str]:
    sc = get_source_cfg()
    seeds_cfg = sc.get("seeds") or []
    seeds_env = _parse_env_seeds()
    # Combine config and env seeds, preserve order, de-dup
    seen = set()
    combined: List[str] = []
    for lst in (seeds_cfg, seeds_env):
        for u in lst:
            if u not in seen:
                seen.add(u)
                combined.append(u)
    # seeds should be full FProxy URLs (http://127.0.0.1:8888/USK@... or SSK@... etc.)
    chosen = combined[: max(1, int(limit))]
    if not chosen:
        logger.info("No seeds found (config+env).")
    else:
        logger.info("Using Freenet seeds (limit=%s): %s", limit, chosen)
    return chosen


def fetch_and_store(
    *,
    limit: int = 5,
    rate_limit_ms: int = 800,
    user_id: Optional[int] = None,
    urls: Optional[List[str]] = None,
    mock: bool = False,
) -> int:
    """
    Crawl a small set of Freenet URLs via FProxy, extract entities, scope to user_id,
    insert with per-user dedupe, send events (idempotent via uid).
    """
    sc = get_source_cfg()
    keywords = sc.get("keywords") or ["leak", "dump", "credential", "password", "secret", "key", "private", "sharesite"]
    limit = int(sc.get("limit", limit))
    rate_limit_ms = int(sc.get("rate_limit_ms", rate_limit_ms))

    if mock:
        # Insert one deterministic mock leak for the user (handy when FProxy is not available)
        content = f"Mock Freenet page for user {user_id} with keywords: {', '.join(keywords)}"
        content_hash = "sha256:" + hashlib.sha256(content.encode("utf-8")).hexdigest()
        entities = extract_entities(content)
        sev = compute_severity_from_entities(entities)
        asset_matches = match_assets(content, get_config()) or {}
        tags = _guess_tags(content, len(asset_matches.get("hits", [])) if isinstance(asset_matches, dict) else 0)

        _, is_dup = insert_leak_with_dedupe(
            source="freenet",
            url="freenet://mock",
            title="Mock Freenet Content",
            content=content,
            content_hash=content_hash,
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
            uid = stable_uid("freenet://mock", content_hash)
            event = {
                "uid": uid,
                "org_id": ORG_ID,
                "source": "freenet",
                "source_type": "freesite",
                "url": "freenet://mock",
                "language": detect_language(content),
                "entities": entities,
                "asset_matches": asset_matches,
                "severity": sev,
                "tags": tags,
                "content": redact_sensitive_data(content),
                "content_preview": content[:2000],
            }
            send_event_to_api(event)
            return 1
        return 0

    # real run
    s, timeout = build_session()
    target_urls = list(urls or _urls_from_config(limit))
    if not target_urls:
        # Safe fallback: insert a mock leak so the UI shows activity without requiring seeds
        logger.info("No Freenet seeds/urls configured. Falling back to mock insert.")
        content = f"Mock Freenet page for user {user_id} (no seeds configured)."
        content_hash = "sha256:" + hashlib.sha256(content.encode("utf-8")).hexdigest()
        entities = extract_entities(content)
        try:
            sev = compute_severity_from_entities(entities)
        except Exception:
            sev = None
        _, is_dup = insert_leak_with_dedupe(
            source="freenet",
            url="freenet://mock-no-seeds",
            title="Mock Freenet Content (no seeds)",
            content=content,
            content_hash=content_hash,
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
            try:
                uid = stable_uid("freenet://mock-no-seeds", content_hash)
                event = {
                    "uid": uid,
                    "org_id": ORG_ID,
                    "source": "freenet",
                    "source_type": "freesite",
                    "url": "freenet://mock-no-seeds",
                    "language": detect_language(content),
                    "entities": entities,
                    "asset_matches": match_assets(content, get_config()) or {},
                    "severity": sev,
                    "tags": _guess_tags(content, 0),
                    "content": redact_sensitive_data(content),
                    "content_preview": content[:2000],
                }
                send_event_to_api(event)
            except Exception:
                pass
        return 1 if not is_dup else 0

    inserted = 0
    for u in target_urls[:limit]:
        try:
            r = s.get(u, timeout=timeout)
            print(f"\n[DEBUG] Got HTTP {r.status_code} from {u}")
            print(r.text[:1000])  # preview the first 1000 characters

        except requests.RequestException as e:
            logger.info("Skip Freenet URL (network): %s (%s)", u, e)
            time.sleep(max(0, rate_limit_ms) / 1000.0)
            continue

        if r.status_code != 200 or not r.text:
            logger.info("Skip Freenet URL (HTTP %s): %s", r.status_code, u)
            time.sleep(max(0, rate_limit_ms) / 1000.0)
            continue

        # Parse and prefilter by keywords quickly
        raw_text = _extract_text(r.text)
        if keywords and not any(k.lower() in raw_text.lower() for k in keywords):
            time.sleep(max(0, rate_limit_ms) / 1000.0)
            continue

        content = raw_text
        content_hash = "sha256:" + hashlib.sha256(content.encode("utf-8", errors="ignore")).hexdigest()
        entities = extract_entities(content)
        sev = compute_severity_from_entities(entities)
        try:
            asset_matches = match_assets(content, get_config()) or {}
            hit_count = len(asset_matches.get("hits", [])) if isinstance(asset_matches, dict) else 0
        except Exception:
            asset_matches, hit_count = {}, 0
        tags = _guess_tags(content, hit_count)

        title = (BeautifulSoup(r.text, "html.parser").title or {}).string or "Freenet page"
        title = (title or "").strip() or "Freenet page"

        _, is_dup = insert_leak_with_dedupe(
            source="freenet",
            url=u,
            title=title,
            content=content,
            content_hash=content_hash,
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

            uid = stable_uid(u, content_hash)
            redacted = redact_sensitive_data(content)
            lang = None
            try:
                lang = detect_language(content)
            except Exception:
                pass
            event = {
                "uid": uid,
                "org_id": ORG_ID,
                "source": "freenet",
                "source_type": "freesite",
                "url": u,
                "title": title,
                "language": lang,
                "entities": entities,
                "asset_matches": asset_matches,
                "severity": sev,
                "tags": tags,
                "content": redacted or content,
                "content_preview": (redacted or content)[:2000],
            }
            # best-effort send
            for attempt in range(3):
                try:
                    send_event_to_api(event)
                    break
                except Exception as e:
                    wait = 2 ** attempt
                    logger.warning("send_event_to_api failed (attempt %s): %s; retrying in %ss", attempt + 1, e, wait)
                    time.sleep(wait)

        time.sleep(max(0, rate_limit_ms) / 1000.0)

    logger.info("Freenet run complete. Inserted new=%s (user_id=%s)", inserted, user_id)
    return inserted


if __name__ == "__main__":
    ok = health_check()
    print(f"FProxy running: {ok}")

    if ok:
        test_url = "http://127.0.0.1:8888/USK@dCnkUL22fAmKbKg-Cftx9j2m4IwyWB0QbGoiq1RSLP8,4d1TDqwRr4tYlsubLrQK~c4h0~FtmE-OXCDmFiI8BB4,AQACAAE/Sharesite/41/"
        print(f"Fetching {test_url} ...")
        count = fetch_and_store(mock=False, user_id=None, urls=[test_url], limit=1)
        print(f"Inserted {count} leaks.")
    else:
        print("FProxy not reachable. Make sure Freenet is running and FProxy is enabled.")
