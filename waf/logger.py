"""JSON-lines audit logger for blocked WAF requests."""

from __future__ import annotations

import json
import threading
from datetime import datetime
from pathlib import Path
from typing import Any


class AuditLogger:
    def __init__(self, log_path: str | Path) -> None:
        self.log_path = Path(log_path)
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

    def write(self, event: dict[str, Any]) -> None:
        event = dict(event)
        event.setdefault("timestamp", datetime.now().astimezone().isoformat(timespec="seconds"))
        line = json.dumps(event, ensure_ascii=False, sort_keys=True)
        with self._lock:
            with self.log_path.open("a", encoding="utf-8") as log_file:
                log_file.write(line + "\n")

    def tail(self, limit: int = 50) -> list[dict[str, Any]]:
        if not self.log_path.exists():
            return []

        with self.log_path.open("r", encoding="utf-8") as log_file:
            lines = log_file.readlines()[-limit:]

        events: list[dict[str, Any]] = []
        for line in lines:
            line = line.strip()
            if not line:
                continue
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                events.append({"raw": line})
        return events
