from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from config import COMMON_PARAMS, TEST_VALUES
from src.scanner.utils import contains_sensitive, is_error_response, is_json, is_low_value, json_diff, similarity, text_diff


def _append_query_param(url, param, value):
    parts = urlsplit(url)
    query = dict(parse_qsl(parts.query, keep_blank_values=True))
    query[param] = value
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(query, doseq=True), parts.fragment))


async def intelligent_idor(session, url, fetch):
    findings = []

    for param in COMMON_PARAMS:
        responses = []

        for val in TEST_VALUES:
            test_url = _append_query_param(url, param, val)
            body, status = await fetch(session, test_url)
            if body:
                responses.append((val, body, status, test_url))

        if len(responses) < 2:
            continue

        base_val, base_body, base_status, _ = responses[0]

        for val, body, status, test_url in responses[1:]:
            if is_error_response(body):
                continue

            score, sim = calculate_score(base_body, body, base_status, status)
            proof = generate_proof(base_body, body)

            if not proof:
                continue

            if score < 3 and sim > 0.6:
                continue

            if is_low_value(url):
                score -= 2

            if score >= 4:
                findings.append({
                    "type": "IDOR",
                    "endpoint": url,
                    "param": param,
                    "values": [base_val, val],
                    "similarity": round(sim, 2),
                    "score": score,
                    "confidence": "HIGH",
                    "severity": "HIGH",
                    "proof": proof,
                })
                break

    return findings


def calculate_score(base_body, new_body, base_status, new_status):
    score = 0
    sim = similarity(base_body, new_body)

    if sim < 0.8:
        score += 2
    if abs(len(str(base_body)) - len(str(new_body))) > 50:
        score += 2
    if base_status != new_status:
        score += 2
    if contains_sensitive(new_body):
        score += 1
    if is_json(base_body) and is_json(new_body):
        if json_diff(base_body, new_body):
            score += 2

    return score, sim


def generate_proof(body1, body2):
    if is_json(body1) and is_json(body2):
        diff = json_diff(body1, body2)
        if not diff:
            return None
        return {"type": "JSON_DIFF", "evidence": diff}

    diff = text_diff(body1, body2)
    if not diff:
        return None
    return {"type": "TEXT_DIFF", "evidence": diff}