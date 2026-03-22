import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Iterable, List, Optional

import requests
from bs4 import BeautifulSoup
from bs4 import XMLParsedAsHTMLWarning
from urllib.parse import urljoin

import warnings

warnings.filterwarnings("ignore", category=XMLParsedAsHTMLWarning)

BASE_DIR = Path(__file__).resolve().parents[2]
INPUT = BASE_DIR / "outputs" / "prioritized_subdomains.txt"
OUTPUT = BASE_DIR / "outputs" / "discovered_endpoints.txt"
OUTPUT.parent.mkdir(parents=True, exist_ok=True)

visited = set()
endpoints = set()
_LOCK = threading.Lock()


def reset_state():
    with _LOCK:
        visited.clear()
        endpoints.clear()


def crawl(url: str):
    try:
        r = requests.get(url, timeout=5)
        soup = BeautifulSoup(r.text, "html.parser")

        discovered = set()

        for link in soup.find_all("a", href=True):
            full = urljoin(url, link["href"])
            discovered.add(full)

        for script in soup.find_all("script", src=True):
            full = urljoin(url, script["src"])
            discovered.add(full)

        for form in soup.find_all("form"):
            action = form.get("action")
            if action:
                discovered.add(urljoin(url, action))

        with _LOCK:
            for full in discovered:
                if full not in visited:
                    visited.add(full)
                    endpoints.add(full)

    except Exception:
        pass


def load_targets(subdomains: Optional[Iterable[str]] = None) -> List[str]:
    targets = []

    if subdomains is not None:
        source = list(subdomains)
    else:
        if not INPUT.exists():
            return []
        with open(INPUT, "r", encoding="utf-8") as f:
            source = [line.strip() for line in f if line.strip()]

    for line in source:
        if not line or line.startswith("#"):
            continue

        line = line.strip()
        if line.startswith("http://") or line.startswith("https://"):
            targets.append(line)
        else:
            targets.append("http://" + line)

    deduped = []
    seen = set()
    for t in targets:
        if t not in seen:
            seen.add(t)
            deduped.append(t)

    return deduped


def run_fast_crawler(subdomains: Optional[Iterable[str]] = None, save_output: bool = True) -> List[str]:
    targets = load_targets(subdomains)

    print(f"\n[+] Fast crawler targets: {len(targets)}")
    print("\nStarting high-speed crawl...\n")

    if not targets:
        return []

    with ThreadPoolExecutor(max_workers=30) as executor:
        list(executor.map(crawl, targets))

    results = sorted(endpoints)
    print(f"[+] Fast crawler endpoints: {len(results)}")

    if save_output:
        with open(OUTPUT, "w", encoding="utf-8") as f:
            for e in results:
                f.write(e + "\n")

        print("\nSaved to:")
        print(OUTPUT)

    return results


def main():
    raw = input("Enter subdomains (comma separated), or blank to use file: ").strip()

    if raw:
        subdomains = [s.strip() for s in raw.split(",") if s.strip()]
    else:
        subdomains = None

    reset_state()
    results = run_fast_crawler(subdomains=subdomains, save_output=True)
    print("\nTotal endpoints discovered:", len(results))


if __name__ == "__main__":
    main()