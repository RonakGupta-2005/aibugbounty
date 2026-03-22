import random
from config import COMMON_PARAMS

HIDDEN_PARAMS = [
    "admin", "isAdmin", "role", "debug",
    "access", "privilege", "auth", "token"
]

TEST_VALUES = ["true", "1", "admin", "yes"]


async def discover_hidden_params(session, url, fetch):
    findings = []

    for param in HIDDEN_PARAMS:
        for val in random.sample(TEST_VALUES, min(3, len(TEST_VALUES))):

            test_url = f"{url}?{param}={val}"
            body, status = await fetch(session, test_url)

            if not body:
                continue

            # Heuristic: access change or admin keywords
            if "admin" in body.lower() or "true" in body.lower():
                findings.append({
                    "type": "HIDDEN_PARAM",
                    "endpoint": url,
                    "param": param,
                    "payload": val,
                    "confidence_score": 70,
                    "severity": "HIGH"
                })

    return findings