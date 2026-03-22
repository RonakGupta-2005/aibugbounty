from pathlib import Path
from typing import Iterable, List, Optional, Tuple

BASE_DIR = Path(__file__).resolve().parents[2]
INPUT = BASE_DIR / "outputs" / "crtsh_subdomains.txt"
OUTPUT = BASE_DIR / "outputs" / "prioritized_subdomains.txt"

HIGH_VALUE_KEYWORDS = [
    "api",
    "dev",
    "admin",
    "staging",
    "vpn",
    "internal",
    "auth",
    "gateway",
    "dashboard",
    "portal",
]


def _normalize_subdomain(value: str) -> Optional[str]:
    if value is None:
        return None

    sub = str(value).strip().lower()
    if not sub or sub.startswith("#"):
        return None

    sub = sub.replace("http://", "").replace("https://", "")
    sub = sub.split("/")[0].strip().rstrip(".")

    if not sub:
        return None
    if "*" in sub:
        return None
    if "--" in sub:
        return None

    return sub


def _score_subdomain(subdomain: str) -> int:
    score = 0
    for kw in HIGH_VALUE_KEYWORDS:
        if kw in subdomain:
            score += 2

    labels = subdomain.split(".")
    if labels:
        if labels[0] in HIGH_VALUE_KEYWORDS:
            score += 2
        if len(labels) <= 3:
            score += 1

    return score


def clean_and_prioritize(subdomains: Optional[Iterable[str]] = None) -> Tuple[List[str], List[str]]:
    if subdomains is None:
        if INPUT.exists():
            with open(INPUT, "r", encoding="utf-8") as f:
                raw = [line.strip() for line in f if line.strip()]
        else:
            raw = []
    else:
        raw = list(subdomains)

    cleaned = {}
    for sub in raw:
        norm = _normalize_subdomain(sub)
        if not norm:
            continue
        cleaned[norm] = max(cleaned.get(norm, 0), _score_subdomain(norm))

    ranked = sorted(cleaned.items(), key=lambda item: (-item[1], item[0]))

    high_priority = []
    normal_priority = []

    for sub, score in ranked:
        if score > 0:
            high_priority.append(sub)
        else:
            normal_priority.append(sub)

    return high_priority, normal_priority


def main():
    high, normal = clean_and_prioritize()

    print("\nHigh value targets:\n")
    for s in high[:20]:
        print(s)

    print("\nNormal targets:", len(normal))
    print("High value targets:", len(high))

    with open(OUTPUT, "w", encoding="utf-8") as f:
        f.write("# HIGH PRIORITY\n")
        for s in high:
            f.write(s + "\n")

        f.write("\n# NORMAL\n")
        for s in normal:
            f.write(s + "\n")

    print("\nSaved prioritized targets to:")
    print(OUTPUT)


if __name__ == "__main__":
    main()