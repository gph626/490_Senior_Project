import schedule
import time
import subprocess
import requests

CONFIG_URL = "http://127.0.0.1:5000/v1/config/org/123"

def get_config():
    try:
        resp = requests.get(CONFIG_URL, timeout=5)
        resp.raise_for_status()
        return resp.json()
    except Exception as e:
        print(f"[Scheduler] Failed to load config: {e}")
        return None

def run_pastebin():
    subprocess.run(["python", "-m", "backend.crawler.pastebin"])

def run_i2p():
    subprocess.run(["python", "-m", "backend.crawler.i2p_crawler"])

def run_tor():
    subprocess.run(["python", "-m", "backend.crawler.tor_crawler"])

def run_freenet():
    subprocess.run(["python", "-m", "backend.crawler.freenet_crawler"])

def run_github():
    subprocess.run(["python", "-m", "backend.crawler.github_crawler"])


# --- Dynamic scheduling setup ---
config = get_config()
if not config:
    print("[Scheduler] Could not load config; using default intervals.")
    intervals = {
        "pastebin": 1,
        "i2p": 2,
        "tor": 3,
        "freenet": 4,
        "github": 10,
    }
else:
    sources = config.get("sources", {})
    intervals = {
        "pastebin": sources.get("pastebin", {}).get("crawl_interval_minutes", 1),
        "i2p":      sources.get("i2p", {}).get("crawl_interval_minutes", 2),
        "tor":      sources.get("tor", {}).get("crawl_interval_minutes", 3),
        "freenet":  sources.get("freenet", {}).get("crawl_interval_minutes", 5),
        "github":   sources.get("github", {}).get("crawl_interval_minutes", 10),
    }

# Apply scheduling using dynamic intervals
schedule.every(intervals["pastebin"]).minutes.do(run_pastebin)
schedule.every(intervals["i2p"]).minutes.do(run_i2p)
schedule.every(intervals["tor"]).minutes.do(run_tor)
schedule.every(intervals["freenet"]).minutes.do(run_freenet)
schedule.every(intervals["github"]).minutes.do(run_github)

print("[Scheduler] Starting crawler scheduler with dynamic intervals...")
for name, interval in intervals.items():
    print(f"  - {name}: every {interval} minute(s)")

while True:
    schedule.run_pending()
    time.sleep(1)
