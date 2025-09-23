import requests

# Configure Tor SOCKS proxy
proxies = {
    "http": "socks5h://127.0.0.1:9050",
    "https": "socks5h://127.0.0.1:9050"
}

def fetch(url):
    r = requests.get(url, proxies=proxies, timeout=30)
    return r.status_code, r.text[:500]  # return status + first 500 chars

if __name__ == "__main__":
    print(fetch("http://duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion"))

