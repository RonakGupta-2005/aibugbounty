import re
from pathlib import Path
from urllib.parse import urljoin

import requests
from bs4 import BeautifulSoup

BASE_DIR = Path(__file__).resolve().parents[2]
OUTPUT = BASE_DIR / "outputs" / "api_endpoints.txt"
OUTPUT.parent.mkdir(parents=True, exist_ok=True)

HEADERS = {
    "User-Agent": "Mozilla/5.0 (APIDiscoveryEngine)",
}

API_PATTERNS = [
    r"/api/[a-zA-Z0-9_/.\-?=&%]*",
    r"/rest/[a-zA-Z0-9_/.\-?=&%]*",
    r"/graphql(?:/[a-zA-Z0-9_/.\-?=&%]*)?",
    r"/v1/[a-zA-Z0-9_/.\-?=&%]*",
    r"/v2/[a-zA-Z0-9_/.\-?=&%]*",
]

JS_CALL_PATTERNS = [
    r'fetch\(["\'](.*?)["\']',
    r'axios\.(?:get|post|put|delete|patch)\(["\'](.*?)["\']',
    r'url\s*:\s*["\'](.*?)["\']',
    r'["\'](\/(?:api|rest|graphql|v\d+)[^"\']*)["\']',
]


def fetch_url(url: str) -> str:
    try:
        res = requests.get(url, headers=HEADERS, timeout=10)
        return res.text
    except Exception:
        return ""


def extract_js_files(html: str, base_url: str):
    soup = BeautifulSoup(html, "html.parser")
    js_files = []

    for script in soup.find_all("script"):
        src = script.get("src")
        if src:
            js_files.append(urljoin(base_url, src))

    return js_files


def extract_api_from_text(text: str):
    found = set()

    for pattern in API_PATTERNS:
        for match in re.findall(pattern, text, flags=re.IGNORECASE):
            if match:
                found.add(match)

    return found


def analyze_js_file(js_url: str):
    endpoints = set()

    try:
        res = requests.get(js_url, headers=HEADERS, timeout=10)
        js_text = res.text
    except Exception:
        return endpoints

    endpoints.update(extract_api_from_text(js_text))

    for pattern in JS_CALL_PATTERNS:
        for match in re.findall(pattern, js_text, flags=re.IGNORECASE):
            if not match:
                continue
            if match in {"get", "post", "put", "delete", "patch"}:
                continue
            endpoints.add(match)

    return endpoints


def extract_api_endpoints(url: str):
    all_endpoints = set()

    print(f"[+] Fetching: {url}")
    html = fetch_url(url)

    if not html:
        return []

    all_endpoints.update(extract_api_from_text(html))

    js_files = extract_js_files(html, url)
    print(f"[+] Found {len(js_files)} JS files")

    for js in js_files:
        print(f"[+] Analyzing JS: {js}")
        all_endpoints.update(analyze_js_file(js))

    final_endpoints = set()
    for ep in all_endpoints:
        if not ep:
            continue
        if ep.startswith("http://") or ep.startswith("https://"):
            final_endpoints.add(ep)
        else:
            final_endpoints.add(urljoin(url, ep))

    return sorted(final_endpoints)


def save_endpoints(endpoints):
    with open(OUTPUT, "w", encoding="utf-8") as f:
        for ep in endpoints:
            f.write(ep + "\n")


if __name__ == "__main__":
    target = input("Enter target URL: ").strip()
    endpoints = extract_api_endpoints(target)

    print("\n==== API ENDPOINTS ====\n")
    for ep in endpoints:
        print(ep)

    print(f"\nTotal API Endpoints Found: {len(endpoints)}")
    save_endpoints(endpoints)