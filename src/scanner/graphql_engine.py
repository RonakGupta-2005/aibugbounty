GRAPHQL_PAYLOAD = {
    "query": "{ __schema { types { name } } }"
}


async def test_graphql(session, url, fetch):
    findings = []

    if "graphql" not in url.lower():
        return findings

    body, status = await fetch(session, url, method="POST", data=GRAPHQL_PAYLOAD)

    if not body:
        return findings

    if "__schema" in body or "GraphQL" in body or "types" in body:
        findings.append({
            "type": "GRAPHQL_INTROSPECTION",
            "endpoint": url,
            "confidence_score": 90,
            "severity": "CRITICAL",
        })

    return findings