import requests
from bs4 import BeautifulSoup
import sqlite3
from config import TOR_PROXY, TEST_ONION


def save_to_db(source, url, title):
    conn = sqlite3.connect("darkweb.db")
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS leaks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            source TEXT,
            content TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)
    cursor.execute("INSERT INTO leaks (source, content) VALUES (?, ?)", (source, f"{title} - {url}"))
    conn.commit()
    conn.close()

def fetch_and_store(url):
    session = requests.Session()
    session.proxies = TOR_PROXY
    #session.proxies = {"http": "socks5h://localhost:9050", "https": "socks5h://localhost:9050"}
    response = session.get(url, timeout=120)
    if response.status_code == 200:
        soup = BeautifulSoup(response.text, "html.parser")
        title = soup.title.string.strip() if soup.title and soup.title.string else "No title"
        save_to_db("Tor", url, title)

if __name__ == "__main__":
    #test_url = "http://3g2upl4pq6kufc4m.onion"
    test_url = "https://www.engadget.com/wearables/meta-cto-explains-the-cause-of-its-embarrassing-smart-glasses-demo-failures-123011790.html?guccounter=1&guce_referrer=aHR0cHM6Ly93d3cuZ29vZ2xlLmNvbS8&guce_referrer_sig=AQAAADxRDddUOdFeohYD-2YS_U2tmFvNkxKcOxlEB1nWuP4b96SFdrmFN-eHZ56wAXvOoyuBGDxfrCuV7hv_F6c_xsuDtqnKQc_Sjm8kahylyRHftIZi4-vddTZj_b1lGVYK3a3x0jzC5G4bJzZyu_jS0lKJIcU8ngOOAFKOb93L8Nl9"
    fetch_and_store(test_url)
    print("Saved Tor page to DB.")
