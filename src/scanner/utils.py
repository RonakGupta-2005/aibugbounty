import json
from collections.abc import Mapping, Sequence
from difflib import SequenceMatcher, unified_diff

from config import ERROR_PATTERNS, LOW_VALUE_ENDPOINTS, SENSITIVE_KEYS


def similarity(a, b):
    a = "" if a is None else str(a)
    b = "" if b is None else str(b)

    if not a and not b:
        return 1.0

    return SequenceMatcher(None, a, b).ratio()


def contains_sensitive(text):
    text = "" if text is None else str(text).lower()
    return any(k in text for k in SENSITIVE_KEYS)


def is_json(text):
    try:
        json.loads(text)
        return True
    except Exception:
        return False


def _json_diff_recursive(left, right, path=""):
    changes = {}

    if isinstance(left, Mapping) and isinstance(right, Mapping):
        keys = set(left.keys()) | set(right.keys())
        for key in keys:
            new_path = f"{path}.{key}" if path else str(key)
            if key not in left:
                changes[new_path] = {"value_1": None, "value_2": right.get(key)}
            elif key not in right:
                changes[new_path] = {"value_1": left.get(key), "value_2": None}
            else:
                changes.update(_json_diff_recursive(left.get(key), right.get(key), new_path))
        return changes

    if isinstance(left, list) and isinstance(right, list):
        max_len = max(len(left), len(right))
        for idx in range(max_len):
            new_path = f"{path}[{idx}]"
            if idx >= len(left):
                changes[new_path] = {"value_1": None, "value_2": right[idx]}
            elif idx >= len(right):
                changes[new_path] = {"value_1": left[idx], "value_2": None}
            else:
                changes.update(_json_diff_recursive(left[idx], right[idx], new_path))
        return changes

    if left != right:
        changes[path or "$"] = {"value_1": left, "value_2": right}

    return changes


def json_diff(a, b):
    try:
        ja = json.loads(a)
        jb = json.loads(b)
        return _json_diff_recursive(ja, jb)
    except Exception:
        return {}


def text_diff(a, b):
    a = "" if a is None else str(a)
    b = "" if b is None else str(b)
    return list(unified_diff(a.splitlines(), b.splitlines(), lineterm=""))[:20]


def is_error_response(text):
    text = "" if text is None else str(text).lower()
    return any(err in text for err in ERROR_PATTERNS)


def is_low_value(url):
    url = "" if url is None else str(url).lower()
    return any(k in url for k in LOW_VALUE_ENDPOINTS)