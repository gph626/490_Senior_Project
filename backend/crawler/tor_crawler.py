import requests
from bs4 import BeautifulSoup
import time
import os
import re
import hashlib
from backend.database import insert_leak_with_dedupe, init_db
from backend.severity import compute_severity_from_entities

# --- INIT DB ---
init_db()

# --- CONFIG ---
USE_TOR = True
# Default to Tor Browser's SOCKS port 9150; allow override via TOR_PORT env
TOR_PORT = os.getenv("TOR_PORT", "9150")
TOR_PROXY = {
    "http": f"socks5h://127.0.0.1:{TOR_PORT}",
    "https": f"socks5h://127.0.0.1:{TOR_PORT}"
}

# --- FETCH & STORE ---
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
DOMAIN_RE = re.compile(r"\b(?:(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)\.)+[a-z]{2,}\b", re.I)
IPV4_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(?:\.|$)){4}\b")
BTC_RE = re.compile(r"\b(?:bc1|[13])[a-zA-HJ-NP-Z0-9]{25,39}\b")


def fetch_and_store(url, retries=3, delay=10):
    session = requests.Session()
    if USE_TOR:
        session.proxies = TOR_PROXY

    for attempt in range(retries):
        try:
            response = session.get(url, timeout=30)
            if response.status_code == 200:
                soup = BeautifulSoup(response.text, "html.parser")
                title = soup.title.string.strip() if soup.title and soup.title.string else "No title"
                # For content, prefer text to avoid HTML noise
                content = soup.get_text("\n").strip()
                content_hash = None
                if content:
                    content_hash = "sha256:" + hashlib.sha256(content.encode("utf-8", errors="ignore")).hexdigest()

                # Extract simple entities
                entities = {}
                if content:
                    emails = sorted(set(EMAIL_RE.findall(content)))
                    domains = sorted(set(DOMAIN_RE.findall(content)))
                    ips = sorted(set(IPV4_RE.findall(content)))
                    btcs = sorted(set(BTC_RE.findall(content)))
                    entities = {
                        "emails": emails,
                        "domains": [d.lower() for d in domains],
                        "ips": ips,
                        "btc_wallets": btcs,
                    }

                sev = None
                try:
                    if entities:
                        sev = compute_severity_from_entities(entities)
                except (TypeError, ValueError, KeyError):
                    sev = None

                _, is_dup = insert_leak_with_dedupe(
                    source="Tor" if USE_TOR else "Demo",
                    url=url,
                    title=title,
                    content=content,
                    content_hash=content_hash,
                    severity=sev,
                    entities=entities,
                )
                print(f"Fetched via Tor: {title} | duplicate={is_dup}")
                return True
            else:
                print(f"Non-200 status: {response.status_code}")
        except (requests.RequestException, RuntimeError) as e:
            print(f"Attempt {attempt+1}/{retries} failed: {e}")
            time.sleep(delay)
    return False

# --- MAIN ---
if __name__ == "__main__":
    if USE_TOR:
        test_url = "http://duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion"
    else:
        test_url = "https://example.com"

    if fetch_and_store(test_url):
        print("Saved page to DB.")
    else:
        print("Failed to fetch page after retries.")
