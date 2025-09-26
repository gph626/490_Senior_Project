import requests
from bs4 import BeautifulSoup
from backend.database import insert_leak, init_db

# Ensure DB and tables exist (consistent with other crawlers)
init_db()

def fetch_and_store():
    url = "https://pastebin.com/archive"
    response = requests.get(url)
    if response.status_code != 200:
        print("Failed to fetch Pastebin")
        return

    soup = BeautifulSoup(response.text, "html.parser")

    for row in soup.select("table.maintable tr")[1:6]:
        cols = row.find_all("td")
        link = "https://pastebin.com" + cols[0].find("a")["href"]
        title = cols[0].text.strip()
        leak_id = insert_leak(source="Pastebin", url=link, data=title)
        print(f"Inserted leak id {leak_id}: {title} - {link}")

if __name__ == "__main__":
    fetch_and_store()