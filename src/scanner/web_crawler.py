import requests
from bs4 import BeautifulSoup
from bs4 import XMLParsedAsHTMLWarning
from pathlib import Path
from urllib.parse import urljoin, urlparse

import warnings

warnings.filterwarnings("ignore", category=XMLParsedAsHTMLWarning)

BASE_DIR = Path(__file__).resolve().parents[2]
OUTPUT = BASE_DIR / "outputs" / "endpoints.txt"
OUTPUT.parent.mkdir(parents=True, exist_ok=True)

visited = set()
endpoints = set()

COMMON_ROUTES = [
    "/",
    "/login",
    "/register",
    "/search",
    "/basket",
    "/admin",
    "/profile",
    "/contact",
    "/products",
    "/api",
]


def reset_state():
    visited.clear()
    endpoints.clear()


def _normalize_url(url: str) -> str:
    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}{parsed.path}"


def crawl(url, domain):
    try:
        r = requests.get(url, timeout=5)
        soup = BeautifulSoup(r.text, "html.parser")

        for link in soup.find_all("a", href=True):
            full_url = _normalize_url(urljoin(url, link["href"]))
            parsed = urlparse(full_url)

            if parsed.netloc == domain and full_url not in visited:
                visited.add(full_url)
                endpoints.add(full_url)
                print("Discovered:", full_url)
                crawl(full_url, domain)

        for form in soup.find_all("form"):
            action = form.get("action")
            if not action:
                continue

            full_url = _normalize_url(urljoin(url, action))
            parsed = urlparse(full_url)

            if parsed.netloc == domain and full_url not in visited:
                visited.add(full_url)
                endpoints.add(full_url)
                print("Form endpoint:", full_url)

        for script in soup.find_all("script", src=True):
            full_url = _normalize_url(urljoin(url, script["src"]))
            parsed = urlparse(full_url)

            if parsed.netloc == domain and full_url not in visited:
                visited.add(full_url)
                endpoints.add(full_url)
                print("Script endpoint:", full_url)

    except Exception:
        pass


def add_common_routes(base_url):
    parsed = urlparse(base_url)

    for route in COMMON_ROUTES:
        full = f"{parsed.scheme}://{parsed.netloc}{route}"
        if full not in endpoints:
            endpoints.add(full)
            print("Seed route:", full)


def main():
    start_url = input("Enter target URL: ").strip()

    parsed = urlparse(start_url if start_url.startswith("http") else f"http://{start_url}")
    start_url = f"{parsed.scheme}://{parsed.netloc}"

    print("\nStarting crawl...\n")
    reset_state()
    crawl(start_url, parsed.netloc)

    print("\nAdding common SPA routes...\n")
    add_common_routes(start_url)

    print("\nCrawling finished")
    print("Total endpoints discovered:", len(endpoints))

    with open(OUTPUT, "w", encoding="utf-8") as f:
        for e in sorted(endpoints):
            f.write(e + "\n")

    print("\nEndpoints saved at:")
    print(OUTPUT)


if __name__ == "__main__":
    main()