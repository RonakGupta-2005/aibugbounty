import socket
from pathlib import Path
from typing import Iterable, List, Optional

BASE_DIR = Path(__file__).resolve().parents[2]
OUTPUT = BASE_DIR / "outputs" / "subdomains.txt"
OUTPUT.parent.mkdir(parents=True, exist_ok=True)

WORDLIST = [
    "www",
    "api",
    "dev",
    "admin",
    "test",
    "staging",
    "beta",
    "mail",
    "portal",
    "dashboard",
    "cdn",
    "static",
    "assets",
    "gateway",
    "auth",
]


def _normalize_domain(domain: str) -> str:
    domain = (domain or "").strip()
    domain = domain.replace("http://", "").replace("https://", "")
    domain = domain.split("/")[0].strip()
    return domain.rstrip(".")


def find_subdomains(domain: str, wordlist: Optional[Iterable[str]] = None) -> List[str]:
    domain = _normalize_domain(domain)
    candidates = list(wordlist or WORDLIST)

    discovered = set()

    print("\nStarting DNS subdomain enumeration...\n")

    for word in candidates:
        subdomain = f"{word}.{domain}"

        try:
            socket.gethostbyname(subdomain)
            print("Discovered:", subdomain)
            discovered.add(subdomain)
        except socket.gaierror:
            continue
        except Exception:
            continue

    return sorted(discovered)


def main():
    domain = input("Enter target domain (example.com): ").strip()
    results = find_subdomains(domain)

    with open(OUTPUT, "w", encoding="utf-8") as f:
        for r in results:
            f.write(r + "\n")

    print("\nTotal subdomains found:", len(results))
    print("\nSaved to:")
    print(OUTPUT)


if __name__ == "__main__":
    main()