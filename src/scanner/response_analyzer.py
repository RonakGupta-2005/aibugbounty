def analyze_response(response_text, payload=None):
    text = "" if response_text is None else str(response_text).lower()
    payload_text = "" if payload is None else str(payload).lower().strip()

    if not text:
        return "unknown"

    if payload_text and payload_text in text:
        if any(marker in payload_text for marker in ["<script", "onerror", "svg", "javascript:"]):
            return "xss_reflected"
        return "reflected"

    sql_errors = [
        "sql syntax", "mysql", "syntax error", "ora-", "sqlite",
        "odbc", "postgresql", "unknown column", "query failed",
        "warning: mysql", "unclosed quotation mark", "database error"
    ]
    if any(err in text for err in sql_errors):
        return "sqli"

    cmd_indicators = [
        "uid=", "gid=", "root:x:", "/bin/bash",
        "command not found", "sh:", "bash:"
    ]
    if any(cmd in text for cmd in cmd_indicators):
        return "command_injection"

    lfi_indicators = [
        "/etc/passwd", "root:x:", "/bin/bash"
    ]
    if any(lfi in text for lfi in lfi_indicators):
        return "lfi"

    return "clean"