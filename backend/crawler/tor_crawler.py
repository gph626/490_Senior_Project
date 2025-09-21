import requests
from bs4 import BeautifulSoup
import sqlite3
import time

# --- CONFIG ---
# Switch between demo (clearnet) and tor mode here
USE_TOR = False  # set to True when testing with Tor + onion URLs

# Proxy setup for Tor Browser (must be running on port 9150)
TOR_PROXY = {
    "http": "socks5h://127.0.0.1:9150",
    "https": "socks5h://127.0.0.1:9150"
}

# --- DB SETUP ---
def save_to_db(source, url, title):
    conn = sqlite3.connect("darkweb.db")
    cursor = conn.cursor()
    cursor.execute(
        "CREATE TABLE IF NOT EXISTS leaks (id INTEGER PRIMARY KEY AUTOINCREMENT, source TEXT, content TEXT)"
    )
    cursor.execute(
        "INSERT INTO leaks (source, content) VALUES (?, ?)",
        (source, f"{title} - {url}")
    )
    conn.commit()
    conn.close()

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
                save_to_db("Tor" if USE_TOR else "Demo", url, title)
                print(f"Fetched title: {title}")
                return True
            else:
                print(f"Non-200 status: {response.status_code}")
        except Exception as e:
            print(f"Attempt {attempt+1}/{retries} failed: {e}")
            time.sleep(delay)
    return False

def fetch_i2p(url):
    """
    Placeholder for future I2P crawler support.
    Structure would be similar to fetch_and_store() but use an I2P proxy instead of Tor.
    
    Example:
      session.proxies = {
          "http": "http://127.0.0.1:4444",
          "https": "http://127.0.0.1:4444"
      }
    """
    #pass



# --- MAIN ---
if __name__ == "__main__":
    if USE_TOR:
        # Safe test onion (Tor Project)
        test_url = "http://torprojectyrj4usqjz2mfavw7qyvcfj3tqmqzb7h3dir6jdj7oqcijad.onion"
    else:
        # Fallback demo site
        test_url = "https://example.com"

    if fetch_and_store(test_url):
        print("Saved page to DB.")
    else:
        print("Failed to fetch page after retries.")
