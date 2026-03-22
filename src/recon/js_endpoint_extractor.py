import re
from pathlib import Path
from typing import Iterable, List, Optional, Set

import requests
from urllib.parse import urljoin

BASE_DIR = Path(__file__).resolve().parents[2]
INPUT = BASE_DIR / "outputs" / "discovered_endpoints.txt"
OUTPUT = BASE_DIR / "outputs" / "js_discovered_endpoints.txt"
OUTPUT.parent.mkdir(parents=True, exist_ok=True)

JS_PATTERNS = [
    r'fetch\(["\'](.*?)["\']',
    r'axios\.(?:get|post|put|delete|patch)\(["\'](.*?)["\']',
    r'["\'](\/(?:api|rest|graphql|v\d+)[^"\']*)["\']',
    r'url\s*:\s*["\'](.*?)["\']',
]


def _load_endpoints(endpoints: Optional[Iterable[str]] = None) -> List[str]:
    if endpoints is not None:
        return [str(x).strip() for x in endpoints if str(x).strip()]

    if not INPUT.exists():
        return []

    with open(INPUT, "r", encoding="utf-8") as f:
        return [line.strip() for line in f if line.strip()]


def _looks_like_js(url: str) -> bool:
    lowered = url.lower()
    return ".js" in lowered or lowered.endswith(".mjs") or lowered.endswith(".cjs")


def _extract_from_js(js_url: str) -> Set[str]:
    endpoints = set()

    try:
        r = requests.get(js_url, timeout=10)
        text = r.text
    except Exception:
        return endpoints

    for pattern in JS_PATTERNS:
        for match in re.findall(pattern, text, flags=re.IGNORECASE):
            if not match:
                continue
            if match in {"get", "post", "put", "delete", "patch"}:
                continue
            if match.startswith("http://") or match.startswith("https://"):
                endpoints.add(match)
            else:
                endpoints.add(urljoin(js_url, match))

    return endpoints


def extract_endpoints(endpoints: Optional[Iterable[str]] = None) -> List[str]:
    source = _load_endpoints(endpoints)
    js_files = [url for url in source if _looks_like_js(url)]

    print("\nScanning JavaScript files...\n")
    print("JavaScript files discovered:", len(js_files))

    discovered = set()
    for js in js_files:
        try:
            discovered.update(_extract_from_js(js))
        except Exception:
            continue

    results = sorted(discovered)

    print("\nAPI endpoints extracted:", len(results))

    with open(OUTPUT, "w", encoding="utf-8") as f:
        for ep in results:
            f.write(ep + "\n")

    print("\nSaved to:")
    print(OUTPUT)

    return results


def main():
    extract_endpoints()


if __name__ == "__main__":
    main()