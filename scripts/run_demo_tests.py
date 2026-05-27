"""Send normal and abnormal requests to a running local library app.

Start the app first:
    python app.py

Then run:
    python scripts/run_demo_tests.py
"""

from __future__ import annotations

import json
from dataclasses import dataclass

import requests


BASE_URL = "http://127.0.0.1:5000"


@dataclass(frozen=True)
class DemoCase:
    name: str
    method: str
    path: str
    expected: str
    kwargs: dict


CASES = [
    DemoCase("N001 book search", "GET", "/search?q=Web", "allowed", {}),
    DemoCase("N002 resource allowlist", "GET", "/resources?name=borrowing-guide.txt", "allowed", {}),
    DemoCase("N003 login normal", "POST", "/login", "allowed", {"data": {"username": "admin", "password": "course2026"}}),
    DemoCase(
        "N004 review normal",
        "POST",
        "/reviews",
        "allowed",
        {"data": {"name": "student", "book": "Web 应用安全实践", "content": "Useful library material."}},
    ),
    DemoCase("N005 API JSON normal", "POST", "/api/echo", "allowed", {"json": {"text": "normal json body"}}),
    DemoCase("B001 SQLi search", "GET", "/search?q=' OR 1=1 --", "R001", {}),
    DemoCase(
        "B002 XSS review",
        "POST",
        "/reviews",
        "R002",
        {"data": {"name": "x", "book": "Web 应用安全实践", "content": "<img src=x onerror=alert(1)>"}},
    ),
    DemoCase("B003 traversal resource", "GET", "/resources?name=../../windows/win.ini", "R003", {}),
    DemoCase("B004 illegal UA", "GET", "/search?q=Web", "R005", {"headers": {"User-Agent": "badbot-lab/1.0"}}),
]


def main() -> None:
    results = []
    for case in CASES:
        response = requests.request(case.method, BASE_URL + case.path, allow_redirects=False, timeout=5, **case.kwargs)
        results.append(
            {
                "case": case.name,
                "expected": case.expected,
                "status_code": response.status_code,
                "result": "blocked" if response.status_code in {403, 429} else "allowed",
            }
        )

    rate_statuses = [requests.get(BASE_URL + "/api/books", timeout=5).status_code for _ in range(7)]
    results.append(
        {
            "case": "B005 high-frequency /api/books",
            "expected": "R004",
            "status_code": rate_statuses[-1],
            "all_statuses": rate_statuses,
            "result": "blocked" if rate_statuses[-1] == 429 else "allowed",
        }
    )

    print(json.dumps(results, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
