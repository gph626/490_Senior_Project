import re
import json
import os
import requests
import time
from langdetect import detect, DetectorFactory
DetectorFactory.seed = 0  # makes language detection deterministic


def extract_items(content: str) -> dict:
    """Extract useful indicators from paste content."""

    if not content:
        return {}

    results = {
        "emails": [],
        "domains": [],
        "ips": [],
        "btc_wallets": [],
    }

    # Email addresses
    email_pattern = re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")
    results["emails"] = list(set(email_pattern.findall(content)))

    # Domains (basic regex, catches example.com)
    domain_pattern = re.compile(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b")
    results["domains"] = list(set(domain_pattern.findall(content)))

    # IPv4 addresses
    ip_pattern = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
    results["ips"] = list(set(ip_pattern.findall(content)))

    # Bitcoin wallet addresses (starting with 1 or 3, 26–35 chars long)
    btc_pattern = re.compile(r"\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b")
    results["btc_wallets"] = list(set(btc_pattern.findall(content)))

    return results


def tag_and_score(content: str, extracted: dict) -> tuple[list[str], str]:
    """
    Generate rule-based tags and confidence score for a piece of content.
    Returns (tags, confidence).
    """
    tags = []
    confidence = "low"

    lower_content = content.lower() if content else ""

    # --- TAGS ---
    if extracted.get("emails"):
        tags.append("credentials")

    if extracted.get("btc_wallets"):
        tags.append("financial")

    if any(domain.endswith(".onion") for domain in extracted.get("domains", [])):
        tags.append("darkweb")

    if "password" in lower_content or "login" in lower_content:
        tags.append("credentials")

    if "credit card" in lower_content or "ssn" in lower_content or "pii" in lower_content:
        tags.append("personal-data")

    if "exploit" in lower_content or "0day" in lower_content:
        tags.append("exploitation")

    if not tags:
        tags.append("other")

    # --- CONFIDENCE ---
    if extracted.get("emails") or extracted.get("btc_wallets"):
        confidence = "high"
    elif any(keyword in lower_content for keyword in ["password", "exploit", "credit card"]):
        confidence = "medium"

    return list(set(tags)), confidence


def detect_language(content: str) -> str:
    """
    Detect the language of the given text. Returns ISO 639-1 code like 'en', 'ru', 'zh'.
    Returns 'unknown' if detection fails or content is too short.
    """
    try:
        if not content or len(content) < 20:
            return "unknown"
        return detect(content)
    except Exception:
        return "unknown"
    


def load_assets(config_path="backend/config/assets.json") -> dict:
    """Load the organization's asset list from JSON."""
    try:
        with open(config_path, "r", encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"[WARN] Asset file not found at {config_path}, using empty assets.")
        return {"domains": [], "emails": []}

def match_assets(extracted: dict, assets: dict) -> dict:
    """
    Compare extracted indicators to the asset list.
    Returns matched domains, matched emails, and is_relevant flag.
    """
    matched_domains = []
    matched_emails = []

    # Domain match
    for d in extracted.get("domains", []):
        if d.lower() in [a.lower() for a in assets.get("domains", [])]:
            matched_domains.append(d)

    # Email match
    for e in extracted.get("emails", []):
        if e.lower() in [a.lower() for a in assets.get("emails", [])]:
            matched_emails.append(e)

    is_relevant = len(matched_domains) > 0 or len(matched_emails) > 0

    return {
        "matched_domains": matched_domains,
        "matched_emails": matched_emails,
        "is_relevant": is_relevant
    }


def send_event_to_api(event: dict, api_url="http://127.0.0.1:5000/v1/events", max_retries=3):
    """
    Send the crawler event to a backend API with simple retry logic.
    """
    for attempt in range(1, max_retries + 1):
        try:
            resp = requests.post(api_url, json=event, timeout=5)
            if resp.status_code == 200:
                print(f"[API] Event sent successfully (attempt {attempt})")
                return True
            else:
                print(f"[API] Server responded with {resp.status_code}: {resp.text}")
        except Exception as e:
            print(f"[API] Attempt {attempt} failed: {e}")
            time.sleep(2 ** attempt)  # exponential backoff
    return False



def redact_sensitive_data(content: str) -> tuple[str, dict]:
    """
    Redact sensitive elements in the content and replace with tokens.
    Returns (redacted_content, token_map).
    """
    token_map = {}
    redacted = content

    # Email addresses
    email_pattern = r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"
    emails = re.findall(email_pattern, content)
    for i, email in enumerate(emails, 1):
        token = f"EMAIL_{i}"
        redacted = redacted.replace(email, token)
        token_map[token] = email

    # Credit card numbers (basic pattern, not Luhn validated)
    card_pattern = r"\b(?:\d[ -]*?){13,16}\b"
    cards = re.findall(card_pattern, content)
    for i, card in enumerate(cards, 1):
        token = f"CARD_{i}"
        redacted = redacted.replace(card, token)
        token_map[token] = card

    # SSNs (U.S. pattern: ###-##-####)
    ssn_pattern = r"\b\d{3}-\d{2}-\d{4}\b"
    ssns = re.findall(ssn_pattern, content)
    for i, ssn in enumerate(ssns, 1):
        token = f"SSN_{i}"
        redacted = redacted.replace(ssn, token)
        token_map[token] = ssn

    return redacted, token_map
