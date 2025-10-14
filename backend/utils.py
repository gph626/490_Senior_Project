import os
import re
import json
import time
import logging
import requests
from typing import Dict, Any

logger = logging.getLogger(__name__)

# Simple regexes for redaction
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
DOMAIN_RE = re.compile(r"\b(?:(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)\.)+[a-z]{2,}\b", re.I)
IPV4_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(?:\.|$)){4}\b")
BTC_RE = re.compile(r"\b(?:bc1|[13])[a-zA-HJ-NP-Z0-9]{25,39}\b")

# Default API URL (matches Nik's mock_api.py)
API_BASE_URL = os.environ.get("DARKWEB_API_URL", "http://127.0.0.1:5000")


def guess_tags(entities: dict, matched_assets: dict) -> dict:
    """
    Generate simple tags and confidence levels based on what was extracted.
    """
    tags = {
        "threat_type": "generic",
        "sensitivity": "low",
        "verified": False,
        "confidence": "low",
    }

    emails = entities.get("emails") or []
    domains = entities.get("domains") or []
    ips = entities.get("ips") or []
    btc = entities.get("btc_wallets") or []

    if emails or domains:
        tags["threat_type"] = "credential_dump"
        tags["sensitivity"] = "medium"
        tags["confidence"] = "medium"

    if matched_assets:
        tags["verified"] = True
        tags["confidence"] = "high"
        tags["sensitivity"] = "high"

    if btc:
        tags["threat_type"] = "financial"
        tags["sensitivity"] = "medium"

    return tags


def match_assets(text: str, config: Dict[str, Any]) -> Dict[str, Any]:
    """
    Match org-specific assets (emails/domains/keywords) inside the text.
    """
    matches = {"hits": []}
    if not text or not config:
        return matches

    watchlist = config.get("watchlist", {})
    for asset_type, assets in watchlist.items():
        if not isinstance(assets, list):
            continue
        for a in assets:
            if a and a.lower() in text.lower():
                matches["hits"].append({"type": asset_type, "value": a})
    return matches


def detect_language(text: str) -> str:
    """
    Extremely simple language guess based on character set.
    For production you'd use langdetect, but this avoids extra deps.
    """
    if not text:
        return "unknown"
    # Crude heuristic
    ascii_ratio = sum(1 for c in text if ord(c) < 128) / len(text)
    if ascii_ratio > 0.9:
        return "en"
    return "unknown"


def redact_sensitive_data(text: str) -> str:
    """
    Redact sensitive patterns (emails, domains, IPs, BTC) from the text.
    """
    if not text:
        return text

    text = EMAIL_RE.sub("[REDACTED_EMAIL]", text)
    text = DOMAIN_RE.sub("[REDACTED_DOMAIN]", text)
    text = IPV4_RE.sub("[REDACTED_IP]", text)
    text = BTC_RE.sub("[REDACTED_BTC]", text)
    return text


def send_event_to_api(event: Dict[str, Any], max_retries: int = 3, backoff: float = 1.5) -> None:
    """
    Send the leak event to the backend API (idempotent by UID).
    """
    url = f"{API_BASE_URL}/v1/events"
    print(f"[DEBUG] Sending event to {url} with uid={event.get('uid')}")

    headers = {"Content-Type": "application/json"}
    for attempt in range(max_retries):
        try:
            resp = requests.post(url, data=json.dumps(event), headers=headers, timeout=10)
            if resp.status_code in (200, 202):
                logger.info("Event sent successfully (status %s): %s", resp.status_code, event.get("uid"))
                print(f"[DEBUG] Got response {resp.status_code}: {resp.text}")

                return
            else:
                logger.warning("API responded with %s: %s", resp.status_code, resp.text)

        except requests.RequestException as e:
            logger.warning("Failed to send event (attempt %d): %s", attempt + 1, e)
        time.sleep(backoff ** attempt)

    logger.error("Failed to send event after %d attempts: %s", max_retries, event.get("uid"))
