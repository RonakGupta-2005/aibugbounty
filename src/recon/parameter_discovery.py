import random
import re
import warnings
from pathlib import Path
from typing import Iterable, List, Optional, Set

import requests
from bs4 import BeautifulSoup
from bs4 import XMLParsedAsHTMLWarning

warnings.filterwarnings("ignore", category=XMLParsedAsHTMLWarning)

BASE_DIR = Path(__file__).resolve().parents[2]
INPUT = BASE_DIR / "outputs" / "discovered_endpoints.txt"
JS_INPUT = BASE_DIR / "outputs" / "js_discovered_endpoints.txt"
OUTPUT = BASE_DIR / "outputs" / "discovered_parameters.txt"
OUTPUT.parent.mkdir(parents=True, exist_ok=True)

HIDDEN_PARAMS = [
    "admin",
    "isAdmin",
    "role",
    "debug",
    "access",
    "privilege",
    "auth",
    "token",
]

TEST_VALUES = ["true", "1", "admin", "yes"]

parameters: Set[str] = set()


def _reset():
    parameters.clear()


def _load_lines(path: Path) -> List[str]:
    if not path.exists():
        return []
    with open(path, "r", encoding="utf-8") as f:
        return [line.strip() for line in f if line.strip()]


def _load_endpoints(endpoints: Optional[Iterable[str]] = None) -> List[str]:
    if endpoints is not None:
        return [str(x).strip() for x in endpoints if str(x).strip()]
    return _load_lines(INPUT)


def _load_js_endpoints(js_endpoints: Optional[Iterable[str]] = None) -> List[str]:
    if js_endpoints is not None:
        return [str(x).strip() for x in js_endpoints if str(x).strip()]
    return _load_lines(JS_INPUT)


def extract_query_parameters(url: str, sink: Optional[Set[str]] = None):
    target = sink if sink is not None else parameters

    if "?" not in url:
        return

    query = url.split("?", 1)[1]
    for param in query.split("&"):
        key = param.split("=", 1)[0].strip()
        if key:
            target.add(key)


def detect_rest_parameters(url: str, sink: Optional[Set[str]] = None):
    target = sink if sink is not None else parameters

    parts = url.split("/")
    for part in parts:
        if part.isdigit():
            target.add("id")


def extract_form_parameters(url: str, sink: Optional[Set[str]] = None):
    target = sink if sink is not None else parameters

    lowered = url.lower()
    if any(lowered.endswith(ext) for ext in [".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg"]):
        return

    try:
        r = requests.get(url, timeout=5)
        soup = BeautifulSoup(r.text, "html.parser")

        for tag in soup.find_all(["input", "textarea", "select"]):
            name = tag.get("name")
            if name:
                target.add(str(name).strip())
    except Exception:
        pass


def analyze_endpoints(endpoints: Optional[Iterable[str]] = None) -> List[str]:
    _reset()
    print("\nAnalyzing endpoints...\n")

    for url in _load_endpoints(endpoints):
        extract_query_parameters(url)
        detect_rest_parameters(url)
        extract_form_parameters(url)

    print("\nParameters discovered:", len(parameters))
    return sorted(parameters)


def analyze_js(js_endpoints: Optional[Iterable[str]] = None) -> List[str]:
    _reset()
    print("\nAnalyzing JS-discovered endpoints...\n")

    for ep in _load_js_endpoints(js_endpoints):
        matches = re.findall(r"[?&]([a-zA-Z0-9_]+)=", ep)
        for m in matches:
            parameters.add(m)

    print("\nParameters discovered from JS:", len(parameters))
    return sorted(parameters)


def discover_parameters(
    endpoints: Optional[Iterable[str]] = None,
    js_endpoints: Optional[Iterable[str]] = None,
) -> List[str]:
    _reset()
    print("\n[+] Discovering parameters...\n")

    for url in _load_endpoints(endpoints):
        extract_query_parameters(url)
        detect_rest_parameters(url)
        extract_form_parameters(url)

    for ep in _load_js_endpoints(js_endpoints):
        matches = re.findall(r"[?&]([a-zA-Z0-9_]+)=", ep)
        for m in matches:
            parameters.add(m)

    results = sorted(parameters)

    with open(OUTPUT, "w", encoding="utf-8") as f:
        for p in results:
            f.write(p + "\n")

    print("\nParameters discovered:", len(results))
    print("\nSaved to:")
    print(OUTPUT)

    return results


async def discover_hidden_params(session, url, fetch):
    findings = []
    lowered = url.lower()

    for param in HIDDEN_PARAMS:
        sample_size = min(3, len(TEST_VALUES))
        for val in random.sample(TEST_VALUES, sample_size):
            test_url = f"{url}?{param}={val}"

            try:
                body, status = await fetch(session, test_url)
            except Exception:
                continue

            if not body:
                continue

            body_lower = body.lower()
            if "admin" in body_lower or "true" in body_lower or "role" in body_lower:
                findings.append({
                    "type": "HIDDEN_PARAM",
                    "endpoint": url,
                    "param": param,
                    "payload": val,
                    "confidence_score": 70 if "admin" in body_lower else 65,
                    "severity": "HIGH",
                })

    return findings


def main():
    discover_parameters()


if __name__ == "__main__":
    main()