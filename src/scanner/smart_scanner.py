import re
from pathlib import Path
from typing import Iterable, List, Optional

import joblib
import pandas as pd
import requests
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from config import ENDPOINT_FILE, LEGACY_ENDPOINTS_FILE, MODEL_PATH
from src.scanner.response_analyzer import analyze_response

MODEL_CACHE = None

SQL_KEYWORDS = [
    "select",
    "union",
    "insert",
    "update",
    "delete",
    "drop",
    "where",
    "or",
    "and",
    "sleep",
]


def _load_model():
    global MODEL_CACHE

    if MODEL_CACHE is not None:
        return MODEL_CACHE

    if not MODEL_PATH.exists():
        MODEL_CACHE = None
        return None

    try:
        MODEL_CACHE = joblib.load(MODEL_PATH)
    except Exception:
        MODEL_CACHE = None

    return MODEL_CACHE


def _load_endpoints(endpoints=None):
    if endpoints is not None:
        return [str(x).strip() for x in endpoints if str(x).strip()]

    for candidate in (ENDPOINT_FILE, LEGACY_ENDPOINTS_FILE):
        if candidate.exists():
            with open(candidate, "r", encoding="utf-8") as f:
                return [line.strip() for line in f if line.strip()]

    return []


def _append_query(url, payload):
    parts = urlsplit(url)
    existing = dict(parse_qsl(parts.query, keep_blank_values=True))

    if payload.startswith("?"):
        payload = payload[1:]

    if "=" in payload and "&" not in payload and payload.count("=") == 1 and payload.split("=", 1)[0]:
        key, value = payload.split("=", 1)
        existing[key] = value
    else:
        existing["q"] = payload

    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(existing, doseq=True), parts.fragment))


def extract_features(text):
    text = "" if text is None else str(text)
    text_lower = text.lower()

    sql_count = sum(k in text_lower for k in SQL_KEYWORDS)
    special_chars = len(re.findall(r"[\'\";\-]", text))
    script_tag = int("<script>" in text_lower)
    url_length = len(text)

    return pd.DataFrame([{
        "sql_keyword_count": sql_count,
        "special_char_count": special_chars,
        "script_tag": script_tag,
        "url_length": url_length,
    }])


DEFAULT_PAYLOADS = [
    "id=1 OR 1=1",
    "q=<script>alert(1)</script>",
    "file=../../etc/passwd",
    "cmd=whoami",
    "search=' OR SLEEP(5)--",
]


def _severity_for(ml_prediction, response_prediction):
    risky = {"sqli", "command_injection", "xss_reflected", "lfi"}
    if response_prediction in risky:
        return "HIGH"
    if ml_prediction and ml_prediction != "normal":
        return "MEDIUM"
    return "LOW"


def run_smart_scanner(endpoints=None, payloads=None):
    model = _load_model()
    targets = _load_endpoints(endpoints)

    findings = []
    if not targets:
        return findings

    payloads = list(payloads or DEFAULT_PAYLOADS)

    print("\nStarting smart scanner...\n")

    for endpoint in targets:
        for payload in payloads:
            test_url = _append_query(endpoint, payload)

            try:
                r = requests.get(test_url, timeout=5)
            except Exception:
                continue

            response_prediction = analyze_response(r.text, payload=payload)

            ml_prediction = "unknown"
            if model is not None:
                try:
                    features = extract_features(f"{test_url}\n{r.text[:500]}")
                    ml_prediction = model.predict(features)[0]
                except Exception:
                    ml_prediction = "unknown"

            if ml_prediction == "normal" and response_prediction == "unknown":
                continue

            findings.append({
                "type": "SMART_SCAN",
                "endpoint": endpoint,
                "payload": payload,
                "test_url": test_url,
                "ml_prediction": ml_prediction,
                "response_prediction": response_prediction,
                "severity": _severity_for(ml_prediction, response_prediction),
                "confidence_score": 85 if response_prediction != "unknown" and ml_prediction != "normal" else 65,
            })

            print("Potential vulnerability detected!")
            print("Endpoint:", endpoint)
            print("Payload:", payload)
            print("ML Prediction:", ml_prediction)
            print("Response Analysis:", response_prediction)
            print()

    print("\nScan finished")
    return findings


def main():
    results = run_smart_scanner()
    print("\nTotal smart findings:", len(results))


if __name__ == "__main__":
    main()