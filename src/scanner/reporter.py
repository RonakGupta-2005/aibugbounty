import json
from pathlib import Path
from typing import Iterable, List

from config import HUMAN_REPORT, REPORT_FILE


def generate_human_report(findings):
    if not findings:
        return "No findings were produced.\n"

    report = []
    for i, f in enumerate(findings, 1):
        report.append(
            f"""
==== Vulnerability #{i} ====
Type: {f.get('type', 'UNKNOWN')}
Endpoint: {f.get('endpoint', 'UNKNOWN')}
Severity: {f.get('severity', 'MEDIUM')}

Details:
{json.dumps(f, indent=2, default=str)}
"""
        )

    return "\n".join(report)


def save_reports(results, json_path=REPORT_FILE, human_path=HUMAN_REPORT):
    json_path = Path(json_path)
    human_path = Path(human_path)

    json_path.parent.mkdir(parents=True, exist_ok=True)
    human_path.parent.mkdir(parents=True, exist_ok=True)

    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=4, default=str)

    with open(human_path, "w", encoding="utf-8") as f:
        f.write(generate_human_report(results))

    print("[+] Reports saved")