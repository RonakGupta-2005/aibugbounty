import asyncio
from pathlib import Path
from typing import Iterable, List, Optional

import aiohttp

from config import API_FILE, CONCURRENCY, ENDPOINT_FILE, HEADERS, TIMEOUT
from src.scanner.filters import filter_results
from src.scanner.graphql_engine import test_graphql
from src.scanner.ai_engine import ai_test_parameters
from src.scanner.idor_engine import intelligent_idor
from src.scanner.param_discovery import discover_hidden_params
from src.scanner.reporter import save_reports


# ================================
# CONFIG
# ================================

REQUEST_TIMEOUT = aiohttp.ClientTimeout(total=TIMEOUT)
REQUEST_DELAY = 0.05   # 🔥 prevents server overload
RETRIES = 2


# ================================
# FETCH (ROBUST)
# ================================

async def fetch(session, url, method="GET", data=None):

    for attempt in range(RETRIES):
        try:
            async with session.request(
                method,
                url,
                json=data,
                timeout=REQUEST_TIMEOUT
            ) as r:

                text = await r.text()
                return text, r.status

        except asyncio.TimeoutError:
            await asyncio.sleep(0.3)

        except aiohttp.ClientConnectionError:
            await asyncio.sleep(0.5)

        except Exception:
            await asyncio.sleep(0.2)

    return None, None


# ================================
# LOAD URLS
# ================================

def _load_urls(urls=None):

    if urls is None:
        for candidate in (API_FILE, ENDPOINT_FILE):
            if Path(candidate).exists():
                with open(candidate, "r", encoding="utf-8") as f:
                    return [line.strip() for line in f if line.strip()]
        return []

    if isinstance(urls, (str, Path)):
        path = Path(urls)
        if path.exists():
            with open(path, "r", encoding="utf-8") as f:
                return [line.strip() for line in f if line.strip()]
        return [str(urls).strip()]

    return [str(u).strip() for u in urls if str(u).strip()]


# ================================
# SCAN SINGLE ENDPOINT
# ================================

async def scan_api(session, url, semaphore):

    async with semaphore:  # 🔥 TRUE concurrency control

        print(f"[+] Scanning: {url}")

        results = []

        try:
            results.extend(await intelligent_idor(session, url, fetch))
            await asyncio.sleep(REQUEST_DELAY)

            results.extend(await ai_test_parameters(session, url, fetch))
            await asyncio.sleep(REQUEST_DELAY)

            results.extend(await discover_hidden_params(session, url, fetch))
            await asyncio.sleep(REQUEST_DELAY)

            results.extend(await test_graphql(session, url, fetch))
            await asyncio.sleep(REQUEST_DELAY)

        except Exception:
            # 🔥 prevent crash of entire pipeline
            pass

        return results


# ================================
# MAIN SCANNER
# ================================

async def run_scanner(urls=None):

    targets = _load_urls(urls)

    if not targets:
        return []

    # 🔥 LIMIT CONCURRENT TASKS (IMPORTANT)
    semaphore = asyncio.Semaphore(CONCURRENCY)

    connector = aiohttp.TCPConnector(
        limit=CONCURRENCY,
        ssl=False
    )

    async with aiohttp.ClientSession(
        connector=connector,
        headers=HEADERS,
        timeout=REQUEST_TIMEOUT
    ) as session:

        tasks = [
            scan_api(session, url, semaphore)
            for url in targets
        ]

        results = await asyncio.gather(*tasks, return_exceptions=True)

    # flatten safely
    flat = []
    for r in results:
        if isinstance(r, list):
            flat.extend(r)

    return filter_results(flat)


# ================================
# ENTRY
# ================================

if __name__ == "__main__":

    urls = _load_urls()

    if not urls:
        print("API file not found")
        raise SystemExit(1)

    print(f"\n[+] Loaded {len(urls)} APIs\n")

    start = asyncio.get_event_loop().time()

    results = asyncio.run(run_scanner(urls))

    print("\n==== FINAL RESULTS ====\n")

    for r in results[:20]:
        print(r)

    print(f"\nTotal Findings: {len(results)}")
    print(f"Time Taken: {round(asyncio.get_event_loop().time() - start, 2)} sec")

    save_reports(results)