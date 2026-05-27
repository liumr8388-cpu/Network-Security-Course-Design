"""Generate local blocked-request samples through the Flask test client."""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from app import LOG_PATH, create_app


def main() -> None:
    app = create_app()
    app.extensions["waf_engine"].reset_rate_limits()
    LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    LOG_PATH.write_text("", encoding="utf-8")

    samples = [
        ("GET", "/search?q=' OR 1=1 --", {}),
        ("POST", "/reviews", {"data": {"name": "x", "book": "Web 应用安全实践", "content": "<script>alert(1)</script>"}}),
        ("GET", "/resources?name=../../windows/win.ini", {}),
        ("GET", "/search?q=Web", {"headers": {"User-Agent": "badbot-lab/1.0"}}),
    ]

    results = []
    with app.test_client() as client:
        for method, path, kwargs in samples:
            response = client.open(path, method=method, **kwargs)
            results.append({"request": f"{method} {path}", "status_code": response.status_code})

        rate_statuses = [client.get("/api/books").status_code for _ in range(7)]
        results.append({"request": "GET /api/books x7", "status_codes": rate_statuses})

    print(json.dumps(results, ensure_ascii=False, indent=2))
    print(f"sample log written to: {LOG_PATH}")


if __name__ == "__main__":
    main()
