# backend/crawler/config.py
from __future__ import annotations
import requests
import os

DEFAULT_CONFIG = {
    "api": {
        "events_url": os.environ.get("DARKWEB_API_URL", "http://127.0.0.1:5000/v1/events")
    },
    "watchlist": {},
    "sources": {}
}

API_BASE_URL = os.environ.get("DARKWEB_API_URL_BASE", "http://127.0.0.1:5000")

TOR_PROXY = {
    "http": "socks5h://127.0.0.1:9050",
    "https": "socks5h://127.0.0.1:9050"
}

# A safe .onion for testing (DuckDuckGo)
#TEST_ONION = "http://3g2upl4pq6kufc4m.onion"
TEST_ONION = "https://www.engadget.com/wearables/meta-cto-explains-the-cause-of-its-embarrassing-smart-glasses-demo-failures-123011790.html?guccounter=1&guce_referrer=aHR0cHM6Ly93d3cuZ29vZ2xlLmNvbS8&guce_referrer_sig=AQAAADxRDddUOdFeohYD-2YS_U2tmFvNkxKcOxlEB1nWuP4b96SFdrmFN-eHZ56wAXvOoyuBGDxfrCuV7hv_F6c_xsuDtqnKQc_Sjm8kahylyRHftIZi4-vddTZj_b1lGVYK3a3x0jzC5G4bJzZyu_jS0lKJIcU8ngOOAFKOb93L8Nl9"


def load_config(org_id: int | str | None = None) -> dict:
    """
    Load crawler config from central API or return defaults.
    org_id can be int or str. Builds URL automatically.
    """
    if not org_id:
        return DEFAULT_CONFIG

    # If org_id looks like a number, build the URL
    if isinstance(org_id, int) or str(org_id).isdigit():
        url = f"{API_BASE_URL}/v1/config/org/{org_id}"
    else:
        # Assume the caller passed a full URL
        url = str(org_id)

    try:
        r = requests.get(url, timeout=5)
        if r.status_code == 200:
            cfg = r.json() or {}
            # Merge minimally to ensure required keys exist
            api = cfg.get("api") or {}
            if "events_url" not in api:
                api["events_url"] = DEFAULT_CONFIG["api"]["events_url"]
            cfg["api"] = api
            return cfg
        else:
            print(f"[Config] {url} -> {r.status_code}; using defaults")
            return DEFAULT_CONFIG
    except Exception as e:
        print(f"[Config] Failed to load config from {url}: {e}")
        return DEFAULT_CONFIG