# src/scanner/ai_engine.py

import random
import time
from urllib.parse import parse_qsl, quote, urlencode, urlsplit, urlunsplit

from config import COMMON_PARAMS, DELAY_THRESHOLD
from src.scanner.payload_mutator import generate_all_payloads


def _append_query_param(url, param, payload):
    parts = urlsplit(url)
    query = dict(parse_qsl(parts.query, keep_blank_values=True))
    query[param] = payload
    new_query = urlencode(query, doseq=True)
    return urlunsplit((parts.scheme, parts.netloc, parts.path, new_query, parts.fragment))


# ================================
# NEW: BASELINE COMPARISON
# ================================

def is_significant_difference(base, new):
    if not base or not new:
        return False

    base = str(base)
    new = str(new)

    # length diff
    if abs(len(base) - len(new)) > 120:
        return True

    # new errors introduced
    indicators = ["error", "exception", "warning", "unauthorized"]

    for word in indicators:
        if word in new.lower() and word not in base.lower():
            return True

    return False


def is_reflected(body, payload):
    body_lower = "" if body is None else str(body).lower()
    payload_lower = "" if payload is None else str(payload).lower()

    if payload_lower and payload_lower in body_lower:
        return True

    decoded = quote(payload_lower, safe=":/?&=%")
    if decoded and decoded.lower() in body_lower:
        return True

    keywords = ["script", "alert", "onerror", "svg", "img", "iframe"]
    if any(k in payload_lower for k in keywords) and any(k in body_lower for k in keywords):
        return True

    return False


def calculate_confidence(body, payload, baseline=None):
    score = 0

    body_lower = "" if body is None else str(body).lower()

    if "error" in body_lower:
        score += 25
    if "exception" in body_lower:
        score += 25
    if "stack trace" in body_lower:
        score += 20
    if len(body_lower) > 300:
        score += 10

    if is_reflected(body, payload):
        score += 35

    # 🔥 NEW: baseline boost
    if baseline and is_significant_difference(baseline, body):
        score += 30

    return min(score, 100)


def generate_payloads():
    bundle = generate_all_payloads()

    payloads = [
        "<script>alert(1)</script>",
        "' OR 1=1--",
        "' OR SLEEP(5)--",
        '{"$ne": null}',
        '{"$gt": ""}',
        '{"admin": true}',
        "../../etc/passwd",
        "%3Cscript%3Ealert(1)%3C/script%3E",
    ]

    payloads.extend(bundle["xss"])
    payloads.extend(bundle["sqli"])
    payloads.extend(bundle["cmd"])

    return list(set(payloads))


# ================================
# MAIN ENGINE (UPGRADED)
# ================================

async def ai_test_parameters(session, url, fetch):
    findings = []

    # 🔥 NEW: baseline request
    base_body, _ = await fetch(session, url)

    for param in COMMON_PARAMS:
        payloads = generate_payloads()
        sample_size = min(8, len(payloads))

        for payload in random.sample(payloads, sample_size):
            test_url = _append_query_param(url, param, payload)

            start = time.time()
            body, status = await fetch(session, test_url)
            delay = time.time() - start

            if not body:
                continue

            # 🔥 NEW: ignore useless responses
            if base_body and not is_significant_difference(base_body, body):
                continue

            confidence = calculate_confidence(body, payload, base_body)

            # =========================
            # XSS
            # =========================
            if any(marker in payload.lower() for marker in ["<script", "onerror", "svg"]) and is_reflected(body, payload):
                findings.append({
                    "type": "AI_XSS",
                    "endpoint": url,
                    "param": param,
                    "payload": payload,
                    "confidence_score": confidence,
                    "severity": "HIGH" if confidence >= 70 else "MEDIUM",
                })

            # =========================
            # JSON Injection
            # =========================
            if "{" in payload and confidence > 60:
                findings.append({
                    "type": "AI_JSON_INJECTION",
                    "endpoint": url,
                    "param": param,
                    "payload": payload,
                    "confidence_score": confidence,
                    "severity": "HIGH" if confidence > 75 else "MEDIUM",
                })

            # =========================
            # SQLi (TIME)
            # =========================
            if "sleep" in payload.lower() and delay > DELAY_THRESHOLD:
                findings.append({
                    "type": "AI_SQLI",
                    "endpoint": url,
                    "param": param,
                    "payload": payload,
                    "confidence_score": 95,
                    "severity": "CRITICAL",
                })

            # =========================
            # LFI (STRICT)
            # =========================
            if "../" in payload or "etc/passwd" in payload.lower():
                if "root:" in str(body).lower() or "/bin/bash" in str(body).lower():
                    findings.append({
                        "type": "AI_LFI",
                        "endpoint": url,
                        "param": param,
                        "payload": payload,
                        "confidence_score": max(confidence, 90),
                        "severity": "CRITICAL",
                    })

    return findings