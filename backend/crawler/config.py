TOR_PROXY = {
    "http": "socks5h://127.0.0.1:9050",
    "https": "socks5h://127.0.0.1:9050"
}

# A safe .onion for testing (DuckDuckGo)
#TEST_ONION = "http://3g2upl4pq6kufc4m.onion"
TEST_ONION = "https://www.engadget.com/wearables/meta-cto-explains-the-cause-of-its-embarrassing-smart-glasses-demo-failures-123011790.html?guccounter=1&guce_referrer=aHR0cHM6Ly93d3cuZ29vZ2xlLmNvbS8&guce_referrer_sig=AQAAADxRDddUOdFeohYD-2YS_U2tmFvNkxKcOxlEB1nWuP4b96SFdrmFN-eHZ56wAXvOoyuBGDxfrCuV7hv_F6c_xsuDtqnKQc_Sjm8kahylyRHftIZi4-vddTZj_b1lGVYK3a3x0jzC5G4bJzZyu_jS0lKJIcU8ngOOAFKOb93L8Nl9"

import requests

CONFIG_URL = "http://127.0.0.1:5000/v1/config/org/123"

def load_config():
    try:
        resp = requests.get(CONFIG_URL, timeout=5)
        resp.raise_for_status()
        return resp.json()
    except Exception as e:
        print(f"[Config] Failed to load config: {e}")
        return None
