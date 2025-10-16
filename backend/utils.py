import os
import re
import json
import time
import logging
import requests
from datetime import datetime
from typing import Dict, Any, Set
from backend.database import get_assets_for_user, SessionLocal, APIKey
from flask import session

logger = logging.getLogger(__name__)

# Simple regexes for redaction
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
DOMAIN_RE = re.compile(r"\b(?:(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)\.)+[a-z]{2,}\b", re.I)
IPV4_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(?:\.|$)){4}\b")
BTC_RE = re.compile(r"\b(?:bc1|[13])[a-zA-HJ-NP-Z0-9]{25,39}\b")
    # Very naive "password" pattern (e.g., 'password: hunter2' or 'pass = 12345')
PASSWORD_RE = re.compile(r"(?i)\b(?:password|pass|pwd)\b\s*[:=]\s*([^\s]+)")
    # U.S. SSN pattern (e.g., 123-45-6789)
SSN_RE = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
    # Matches 'Firstname Lastname' with capital letters.
NAME_RE = re.compile(r"\b[A-Z][a-z]+ [A-Z][a-z]+\b")
    # U.S. phone number pattern: (555) 123-4567, 555-123-4567, +1 555 123 4567
PHONE_RE = re.compile(
    r"(?:\+?1[-.\s]?)?(?:\(?\d{3}\)?[-.\s]?)\d{3}[-.\s]?\d{4}"
)
    # Basic physical address pattern (very rough heuristic)
ADDRESS_RE = re.compile(
    r"\b\d{1,5}\s+(?:[A-Za-z0-9]+\s+)*"  # street number + words before suffix
    r"(?:Street|St\.?|Avenue|Ave\.?|Road|Rd\.?|Lane|Ln\.?|Drive|Dr\.?|Boulevard|Blvd\.?)\b"  # suffix, period optional
    r"(?:\s+(?:[A-Za-z0-9]+|of|the|and))*",  # trailing words
    re.IGNORECASE
)




# Default API URL (matches Nik's mock_api.py)
API_BASE_URL = os.environ.get("DARKWEB_API_URL", "http://127.0.0.1:5000")

# backend/utils.py
def get_user_by_api_key(key_str: str):
    session = SessionLocal()
    try:
        api_key = session.query(APIKey).filter_by(key=key_str).first()
        if not api_key:
            return None

        if api_key.expires_at and api_key.expires_at < datetime.utcnow():
            return "EXPIRED"

        return api_key.user_id
    finally:
        session.close()



def get_current_user_id() -> int | None:
    """Return the currently logged-in user's ID from session, or None."""
    return session.get('user_id')

def extract_entities(text: str) -> Dict[str, Any]:
    """Extract and normalize key entities from leaked content consistently across crawlers."""
    if not text:
        return {
            "emails": [],
            "domains": [],
            "ips": [],
            "btc_wallets": [],
            "ssns": [],
            "phone_numbers": [],
            "passwords": [],
            "physical_addresses": [],
            "names": [],
        }

    # Core fields
    emails = sorted(set(e.lower() for e in EMAIL_RE.findall(text)))
    domains = sorted(set(d.lower() for d in DOMAIN_RE.findall(text)))
    ips = sorted(set(IPV4_RE.findall(text)))
    btcs = sorted(set(BTC_RE.findall(text)))

    # Normalized fields
    ssns = [s.replace("-", "") for s in SSN_RE.findall(text)]
    phones = [re.sub(r"\D", "", m.group(0)) for m in PHONE_RE.finditer(text)]
    phones = sorted(set(phones))
    passwords = [re.sub(r"<br>|\\s+", "", p.strip()) for p in PASSWORD_RE.findall(text)]
    addresses = [a.strip().title() for a in ADDRESS_RE.findall(text)]
    names = [n.strip().lower() for n in NAME_RE.findall(text)]

    return {
        "emails": emails,
        "domains": domains,
        "ips": ips,
        "btc_wallets": btcs,
        "ssns": ssns,
        "phone_numbers": phones,
        "passwords": passwords,
        "physical_addresses": addresses,
        "names": names,
    }




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
    text = PASSWORD_RE.sub("[REDACTED_PASSWORD]", text)
    text = SSN_RE.sub("[REDACTED_SSN]", text)
    text = NAME_RE.sub("[REDACTED_NAME]", text)
    text = PHONE_RE.sub("[REDACTED_PHONE]", text)
    text = ADDRESS_RE.sub("[REDACTED_ADDRESS]", text)

    return text


def extract_passwords(text: str) -> list[str]:
    """Extract possible passwords from text."""
    if not text:
        return []
    return [m.group(1) for m in PASSWORD_RE.finditer(text)]


def extract_ssn(text: str) -> str | None:
    """Extract the first SSN found, if any."""
    if not text:
        return None
    match = SSN_RE.search(text)
    return match.group(0) if match else None


def extract_names(text: str) -> list[str]:
    """Extract probable personal names from text."""
    if not text:
        return []
    return list(set(NAME_RE.findall(text)))  # use set to avoid duplicates


def extract_phone_numbers(text: str) -> list[str]:
    """Extract phone numbers from text."""
    if not text:
        return []
    return list(set(PHONE_RE.findall(text)))


def extract_addresses(text: str) -> list[str]:
    """Extract rough physical addresses from text."""
    if not text:
        return []
    return list(set(ADDRESS_RE.findall(text)))


def get_assets_sets() -> Dict[str, Set[str]]:
    """
    Returns a dictionary of the current user's assets grouped by type.
    Example:
      {
        "email": {"alice@example.com", "bob@example.com"},
        "domain": {"example.com"},
        "ip": {"192.168.1.1"},
        "btc": {"bc1qxyz..."}
      }
    """
    user_id = get_current_user_id()
    if not user_id:
        return {"email": set(), "domain": set(), "ip": set(), "btc": set()}

    assets = get_assets_for_user(user_id)  # should return list of asset rows
    result: Dict[str, Set[str]] = {"email": set(), "domain": set(), "ip": set(), "btc": set()}
    for asset in assets:
        a_type = asset.type.lower()
        val = asset.value.strip().lower()
        if a_type in result:
            result[a_type].add(val)
    return result


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
