import json
from pathlib import Path
from typing import List

import requests

BASE_DIR = Path(__file__).resolve().parents[2]
OUTPUT = BASE_DIR / "outputs" / "crtsh_subdomains.txt"
OUTPUT.parent.mkdir(parents=True, exist_ok=True)


def _normalize_domain(domain: str) -> str:
    domain = (domain or "").strip()
    domain = domain.replace("http://", "").replace("https://", "")
    domain = domain.split("/")[0].strip()
    return domain.rstrip(".")


def find_subdomains(domain: str) -> List[str]:
    domain = _normalize_domain(domain)
    url = f"https://crt.sh/?q=%25.{domain}&output=json"

    headers = {
        "User-Agent": "Mozilla/5.0",
    }

    print("\nQuerying certificate transparency logs...\n")

    try:
        r = requests.get(url, headers=headers, timeout=20)

        if r.status_code != 200:
            print("crt.sh returned status:", r.status_code)
            return []

        try:
            data = r.json()
        except Exception:
            try:
                data = json.loads(r.text)
            except Exception:
                print("crt.sh returned non-JSON response")
                return []

        subdomains = set()

        if isinstance(data, dict):
            data = [data]

        for entry in data:
            if not isinstance(entry, dict):
                continue

            name = entry.get("name_value", "")
            for sub in str(name).split("\n"):
                sub = sub.strip().lower()
                if not sub:
                    continue
                if domain in sub:
                    subdomains.add(sub)

        return sorted(subdomains)

    except Exception as e:
        print("Error querying crt.sh:", e)
        return []


def main():
    domain = input("Enter target domain: ").strip()
    results = find_subdomains(domain)

    for sub in results:
        print("Discovered:", sub)

    with open(OUTPUT, "w", encoding="utf-8") as f:
        for r in results:
            f.write(r + "\n")

    print("\nTotal discovered:", len(results))
    print("\nSaved to:", OUTPUT)


if __name__ == "__main__":
    main()