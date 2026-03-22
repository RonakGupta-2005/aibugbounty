# src/scanner/filters.py

SEVERITY_RANK = {
    "CRITICAL": 4,
    "HIGH": 3,
    "MEDIUM": 2,
    "LOW": 1,
    "INFO": 0,
}


def _confidence_of(finding):
    if "confidence_score" in finding and finding["confidence_score"] is not None:
        try:
            return float(finding["confidence_score"])
        except Exception:
            return 0.0

    if "score" in finding and finding["score"] is not None:
        try:
            return float(finding["score"])
        except Exception:
            return 0.0

    return 0.0


# ================================
# 🔥 NEW: LOW VALUE ENDPOINT FILTER
# ================================

LOW_VALUE_KEYWORDS = [
    "captcha",
    "chatbot",
    "status",
    "health",
    "metrics"
]


def is_low_value(endpoint):
    endpoint = str(endpoint).lower()
    return any(k in endpoint for k in LOW_VALUE_KEYWORDS)


# ================================
# 🔥 NEW: WEAK PAYLOAD FILTER
# ================================

def is_noise_payload(payload):
    if not payload:
        return True

    payload = str(payload).lower()

    # ignore trivial payloads
    weak_patterns = ["test", "123", "abc"]

    return any(p in payload for p in weak_patterns)


# ================================
# MAIN FILTER
# ================================

def filter_results(results):
    filtered = []

    for r in results:
        if not isinstance(r, dict):
            continue

        finding_type = str(r.get("type", ""))
        endpoint = r.get("endpoint", "")
        payload = r.get("payload", "")

        confidence = _confidence_of(r)

        # =========================
        # ORIGINAL LOGIC (KEPT)
        # =========================

        if finding_type.startswith("AI_") and confidence < 60:
            continue

        if finding_type == "HIDDEN_PARAM" and confidence < 60:
            continue

        # =========================
        # 🔥 NEW: NOISE REDUCTION
        # =========================

        if is_low_value(endpoint):
            continue

        if is_noise_payload(payload):
            continue

        filtered.append(r)

    # =========================
    # BEST RESULT SELECTION (KEPT)
    # =========================

    best_by_key = {}
    for r in filtered:
        key = (
            r.get("type"),
            r.get("endpoint"),
            r.get("param"),
            r.get("payload"),
        )

        current = best_by_key.get(key)
        if current is None:
            best_by_key[key] = r
            continue

        current_rank = SEVERITY_RANK.get(str(current.get("severity", "")).upper(), 0)
        new_rank = SEVERITY_RANK.get(str(r.get("severity", "")).upper(), 0)

        if new_rank > current_rank:
            best_by_key[key] = r
        elif new_rank == current_rank and _confidence_of(r) > _confidence_of(current):
            best_by_key[key] = r

    final = list(best_by_key.values())

    # =========================
    # 🔥 NEW: HARD LIMITING (OPTIONAL BUT POWERFUL)
    # =========================

    final.sort(
        key=lambda x: (
            -SEVERITY_RANK.get(str(x.get("severity", "")).upper(), 0),
            -_confidence_of(x),
            str(x.get("endpoint", "")),
        )
    )

    return final