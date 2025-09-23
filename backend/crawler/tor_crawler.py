import requests
from bs4 import BeautifulSoup
import time
import os
from backend.database import insert_leak, init_db

# --- INIT DB ---
init_db()

# --- CONFIG ---
USE_TOR = True
TOR_PORT = os.getenv("TOR_PORT", "9050")  # 9050 = tor.exe, 9150 = Tor Browser
TOR_PROXY = {
    "http": f"socks5h://127.0.0.1:{TOR_PORT}",
    "https": f"socks5h://127.0.0.1:{TOR_PORT}"
}

# --- FETCH & STORE ---
def fetch_and_store(url, retries=3, delay=10):
    session = requests.Session()
    if USE_TOR:
        session.proxies = TOR_PROXY

    for attempt in range(retries):
        try:
            response = session.get(url, timeout=30)
            if response.status_code == 200:
                soup = BeautifulSoup(response.text, "html.parser")
                title = soup.title.string if soup.title else "No title"

                leak_id = insert_leak(
                    source="Tor" if USE_TOR else "Demo",
                    url=url,
                    data=title
                )
                print(f"Fetched title: {title} | Saved leak #{leak_id}")
                return True
            else:
                print(f"Non-200 status: {response.status_code}")
        except Exception as e:
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
