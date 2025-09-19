import requests
from config import TOR_PROXY, TEST_ONION

def test_connection():
    session = requests.Session()
    session.proxies.update(TOR_PROXY)

    try:
        response = session.get(TEST_ONION, timeout=120)
        print("Status Code:", response.status_code)

        if "<title>" in response.text:
            title = response.text.split("<title>")[1].split("</title>")[0]
            print("Page Title:", title)
        else:
            print("No <title> found in response.")
    except Exception as e:
        print("Error:", e)

if __name__ == "__main__":
    test_connection()
