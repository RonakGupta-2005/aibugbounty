import asyncio
import sys
from pathlib import Path
from urllib.parse import urlparse

BASE_DIR = Path(__file__).resolve().parent
SRC_DIR = BASE_DIR / "src"

sys.path.insert(0, str(BASE_DIR))
sys.path.insert(0, str(SRC_DIR))

OUTPUTS = BASE_DIR / "outputs"
OUTPUTS.mkdir(exist_ok=True)

from config import (
    CRT_FILE,
    ENDPOINT_FILE,
    HUMAN_REPORT,
    LEGACY_ENDPOINTS_FILE,
    PARAMETER_FILE,
    PRIORITIZED_FILE,
    SUBDOMAIN_FILE,
)

from src.recon.clean_prioritize_subdomains import clean_and_prioritize
from src.recon.crtsh_finder import find_subdomains as crtsh_find
from src.recon.js_endpoint_extractor import extract_endpoints as js_extract
from src.recon.parameter_discovery import discover_parameters
from src.recon.subdomain_finder import find_subdomains

from src.scanner.advanced_scanner import run_scanner
from src.scanner.api_endpoint_extractor import extract_api_endpoints, save_endpoints as save_api_endpoints
from src.scanner.multi_target_crawler import reset_state as reset_fast_crawler
from src.scanner.multi_target_crawler import run_fast_crawler
from src.scanner.reporter import save_reports
from src.scanner.smart_scanner import run_smart_scanner
from src.scanner.web_crawler import add_common_routes, crawl as deep_crawl
from src.scanner.web_crawler import reset_state as reset_deep_crawler
from src.scanner.web_crawler import endpoints as deep_endpoints


# ================================
# HELPERS
# ================================

def _normalize_target(target: str):
    target = target.strip()
    parsed = urlparse(target if target.startswith(("http://", "https://")) else f"http://{target}")

    if not parsed.netloc:
        raise ValueError("Invalid target supplied")

    scheme = parsed.scheme or "http"
    start_url = f"{scheme}://{parsed.netloc}"
    domain = parsed.netloc

    return start_url, domain


def _write_lines(path: Path, values):
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        for item in values:
            f.write(str(item).strip() + "\n")


def _dedupe(findings):
    unique = {}

    for f in findings:
        key = (
            f.get("type"),
            f.get("endpoint"),
            f.get("param"),
            f.get("payload"),
        )
        unique[key] = f

    return list(unique.values())


# ================================
# FILTER TARGETS (🔥 VERY IMPORTANT)
# ================================

def filter_targets(endpoints, domain):

    clean = []

    for url in endpoints:

        if not isinstance(url, str):
            continue

        url = url.strip()

        # only target domain
        if domain not in url:
            continue

        # remove static files
        if any(ext in url for ext in [".js", ".css", ".png", ".jpg", ".svg"]):
            continue

        # remove broken JS garbage
        if "${" in url or "{" in url:
            continue

        # remove external redirect endpoints
        if "redirect?" in url:
            continue

        clean.append(url)

    return list(set(clean))


# ================================
# HEAVY ENDPOINT FILTER (🔥 FIX CRASH)
# ================================

def remove_heavy_endpoints(endpoints):

    heavy_keywords = [
        "products",
        "basket",
        "search",
        "track",
        "order"
    ]

    return [
        e for e in endpoints
        if not any(k in e.lower() for k in heavy_keywords)
    ]


# ================================
# BATCH SCANNING (🔥 FIX FREEZE)
# ================================

async def run_scan(endpoints):

    print("\n[+] Running AI Scanner...\n")

    batch_size = 15  # 🔥 prevents overload
    all_results = []

    for i in range(0, len(endpoints), batch_size):

        batch = endpoints[i:i + batch_size]

        print(f"[+] Scanning batch {i//batch_size + 1} ({len(batch)} targets)")

        advanced_results = await run_scanner(batch)

        smart_results = run_smart_scanner(batch)

        combined = _dedupe(advanced_results + smart_results)

        all_results.extend(combined)

    return _dedupe(all_results)


# ================================
# PIPELINE
# ================================

def run_recon(domain):
    print("\n[+] Subdomain Enumeration...\n")

    dns_subs = find_subdomains(domain)
    crt_subs = crtsh_find(domain)

    all_subs = sorted(set(dns_subs + crt_subs))

    _write_lines(CRT_FILE, crt_subs)
    _write_lines(SUBDOMAIN_FILE, all_subs)

    print(f"[+] Total subdomains: {len(all_subs)}")
    return all_subs


def run_prioritization(subdomains):
    print("\n[+] Prioritizing targets...\n")

    high, normal = clean_and_prioritize(subdomains)

    with open(PRIORITIZED_FILE, "w", encoding="utf-8") as f:
        f.write("# HIGH PRIORITY\n")
        for s in high:
            f.write(s + "\n")

        f.write("\n# NORMAL\n")
        for s in normal:
            f.write(s + "\n")

    print(f"[+] High priority: {len(high)}")
    print(f"[+] Normal: {len(normal)}")

    return high + normal


def run_crawlers(start_url, domain, seed_targets):
    print("\n[+] Hybrid Crawling...\n")

    reset_deep_crawler()
    reset_fast_crawler()

    deep_crawl(start_url, domain)
    add_common_routes(start_url)

    fast_results = run_fast_crawler(seed_targets or [start_url], save_output=True)

    api_results = extract_api_endpoints(start_url)
    save_api_endpoints(api_results)

    all_endpoints = sorted(set(deep_endpoints) | set(fast_results) | set(api_results) | {start_url})

    _write_lines(ENDPOINT_FILE, all_endpoints)
    _write_lines(LEGACY_ENDPOINTS_FILE, all_endpoints)

    print(f"[+] Total endpoints: {len(all_endpoints)}")
    return all_endpoints


def run_js_extraction(endpoints):
    print("\n[+] JS Endpoint Extraction...\n")
    return js_extract(endpoints)


def run_param_discovery(endpoints, js_endpoints):
    print("\n[+] Parameter Discovery...\n")
    return discover_parameters(endpoints, js_endpoints)


# ================================
# MAIN
# ================================

def main():
    print("\n🔥 CLEAN AI BUG BOUNTY ENGINE 🔥\n")

    target = input("Enter target (domain or URL): ").strip()

    start_url, domain = _normalize_target(target)

    print(f"\n[+] Target: {domain}")

    subdomains = run_recon(domain)
    prioritized = run_prioritization(subdomains)

    crawled_endpoints = run_crawlers(start_url, domain, prioritized or [start_url])
    js_endpoints = run_js_extraction(crawled_endpoints)

    run_param_discovery(crawled_endpoints, js_endpoints)

    # 🔥 CLEAN TARGETS
    scan_targets = filter_targets(
        list(set(crawled_endpoints) | set(js_endpoints)),
        domain
    )

    # 🔥 REMOVE HEAVY ENDPOINTS
    scan_targets = remove_heavy_endpoints(scan_targets)

    print(f"[+] Final scan targets: {len(scan_targets)}")

    results = asyncio.run(run_scan(scan_targets))

    print(f"\n🔥 FINAL FINDINGS: {len(results)}\n")

    for r in results[:10]:
        print(r)

    save_reports(results)

    print("\n📄 Reports saved in outputs folder")
    print(f"📄 Parameters saved to: {PARAMETER_FILE}")
    print("\n🔥 DONE 🔥")


# ================================
# ENTRY
# ================================

if __name__ == "__main__":
    main()