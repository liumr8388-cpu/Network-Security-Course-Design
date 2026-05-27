"""Rule loading and matching logic for the local WAF."""

from __future__ import annotations

import json
import re
import time
from collections import defaultdict, deque
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, Deque
from urllib.parse import unquote_plus

from flask import Request


SENSITIVE_PARAM_KEYS = ("password", "passwd", "token", "secret", "key")


@dataclass(frozen=True)
class RulePattern:
    name: str
    pattern: str
    description: str = ""
    example: str = ""


@dataclass(frozen=True)
class WAFRule:
    id: str
    name: str
    category: str
    type: str
    target: str
    severity: str
    description: str
    enabled: bool = True
    patterns: tuple[RulePattern, ...] = ()
    threshold: int | None = None
    window_seconds: int | None = None


@dataclass(frozen=True)
class RuleMatch:
    rule: WAFRule
    matched_value: str
    reason: str
    status_code: int = 403


def load_rules(path: str | Path) -> list[WAFRule]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    rules: list[WAFRule] = []
    for item in data["rules"]:
        rules.append(
            WAFRule(
                id=item["id"],
                name=item["name"],
                category=item["category"],
                type=item["type"],
                target=item["target"],
                severity=item.get("severity", "medium"),
                description=item.get("description", ""),
                enabled=item.get("enabled", True),
                patterns=_load_patterns(item),
                threshold=item.get("threshold"),
                window_seconds=item.get("window_seconds"),
            )
        )
    return rules


class WAFEngine:
    def __init__(self, rules: list[WAFRule]) -> None:
        self.rules = rules
        self._compiled_patterns: dict[str, list[tuple[RulePattern, re.Pattern[str]]]] = {}
        for rule in rules:
            if rule.type == "regex":
                self._compiled_patterns[rule.id] = [
                    (rule_pattern, re.compile(rule_pattern.pattern)) for rule_pattern in rule.patterns
                ]
        self._request_windows: dict[tuple[str, str], Deque[float]] = defaultdict(deque)

    def reset_rate_limits(self) -> None:
        self._request_windows.clear()

    def set_rule_enabled(self, rule_id: str, enabled: bool) -> None:
        self.rules = [replace(rule, enabled=enabled) if rule.id == rule_id else rule for rule in self.rules]

    def update_rate_limit(self, rule_id: str, threshold: int, window_seconds: int) -> None:
        self.rules = [
            replace(rule, threshold=threshold, window_seconds=window_seconds) if rule.id == rule_id else rule
            for rule in self.rules
        ]
        self.reset_rate_limits()

    def check(self, request: Request) -> RuleMatch | None:
        for rule in self.rules:
            if not rule.enabled:
                continue

            if rule.type == "rate_limit":
                match = self._check_rate_limit(rule, request)
            elif rule.type == "regex":
                match = self._check_regex(rule, request)
            else:
                match = None

            if match is not None:
                return match

        return None

    def _check_regex(self, rule: WAFRule, request: Request) -> RuleMatch | None:
        values = self._values_for_target(rule.target, request)
        for source, value in values:
            decoded = unquote_plus(value)
            for rule_pattern, compiled_pattern in self._compiled_patterns.get(rule.id, []):
                if compiled_pattern.search(decoded):
                    matched_value = "***" if _is_sensitive_key(source) else _truncate(decoded)
                    return RuleMatch(
                        rule=rule,
                        matched_value=matched_value,
                        reason=f"{rule.id} 命中 {source}：{rule_pattern.name}",
                    )
        return None

    def _check_rate_limit(self, rule: WAFRule, request: Request) -> RuleMatch | None:
        threshold = rule.threshold or 1
        window_seconds = rule.window_seconds or 1
        client_ip = get_client_ip(request)
        key = (client_ip, request.path)
        now = time.monotonic()
        window = self._request_windows[key]

        while window and now - window[0] > window_seconds:
            window.popleft()

        window.append(now)
        if len(window) > threshold:
            return RuleMatch(
                rule=rule,
                matched_value=f"{window_seconds} 秒内对 {request.path} 发起 {len(window)} 次请求",
                reason=f"{rule.id} 超过阈值 {threshold}/{window_seconds}s",
                status_code=429,
            )
        return None

    def _values_for_target(self, target: str, request: Request) -> list[tuple[str, str]]:
        if target == "params":
            return list(_iter_request_params(request))
        if target == "params_path":
            values = list(_iter_request_params(request))
            values.append(("path", request.path))
            values.append(("query_string", request.query_string.decode("utf-8", errors="replace")))
            return values
        if target == "user_agent":
            return [("User-Agent", request.headers.get("User-Agent", ""))]
        if target == "path":
            return [("path", request.path)]
        return []


def get_client_ip(request: Request) -> str:
    forwarded_for = request.headers.get("X-Forwarded-For", "")
    if forwarded_for:
        return forwarded_for.split(",", 1)[0].strip()
    return request.remote_addr or "unknown"


def collect_parameters(request: Request) -> dict[str, Any]:
    params: dict[str, Any] = {}
    for key, values in request.args.lists():
        params[f"query.{key}"] = _sanitize_parameter_value(key, values if len(values) > 1 else values[0])
    for key, values in request.form.lists():
        params[f"form.{key}"] = _sanitize_parameter_value(key, values if len(values) > 1 else values[0])
    json_body = request.get_json(silent=True)
    if isinstance(json_body, dict):
        params["json"] = _sanitize_json(json_body)
    return params


def _load_patterns(item: dict[str, Any]) -> tuple[RulePattern, ...]:
    if "patterns" in item:
        return tuple(
            RulePattern(
                name=pattern_item.get("name", "未命名检测点"),
                pattern=pattern_item["pattern"],
                description=pattern_item.get("description", ""),
                example=pattern_item.get("example", ""),
            )
            for pattern_item in item["patterns"]
        )

    if "pattern" in item:
        return (
            RulePattern(
                name=item.get("name", item["id"]),
                pattern=item["pattern"],
                description=item.get("description", ""),
            ),
        )

    return ()


def _iter_request_params(request: Request) -> list[tuple[str, str]]:
    values: list[tuple[str, str]] = []
    for key, items in request.args.lists():
        for item in items:
            values.append((f"query.{key}", str(item)))
    for key, items in request.form.lists():
        for item in items:
            values.append((f"form.{key}", str(item)))

    json_body = request.get_json(silent=True)
    if isinstance(json_body, dict):
        values.extend(_flatten_json("json", json_body))
    elif json_body is not None:
        values.append(("json", str(json_body)))

    return values


def _flatten_json(prefix: str, value: Any) -> list[tuple[str, str]]:
    if isinstance(value, dict):
        result: list[tuple[str, str]] = []
        for key, nested in value.items():
            result.extend(_flatten_json(f"{prefix}.{key}", nested))
        return result
    if isinstance(value, list):
        result = []
        for index, nested in enumerate(value):
            result.extend(_flatten_json(f"{prefix}[{index}]", nested))
        return result
    return [(prefix, str(value))]


def _truncate(value: str, limit: int = 240) -> str:
    if len(value) <= limit:
        return value
    return value[: limit - 3] + "..."


def _sanitize_json(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: _sanitize_parameter_value(key, nested) for key, nested in value.items()}
    if isinstance(value, list):
        return [_sanitize_json(item) for item in value]
    return value


def _sanitize_parameter_value(key: str, value: Any) -> Any:
    if _is_sensitive_key(key):
        return "***"
    if isinstance(value, list):
        return [_sanitize_json(item) for item in value]
    if isinstance(value, dict):
        return _sanitize_json(value)
    return value


def _is_sensitive_key(key: str) -> bool:
    lowered = key.lower()
    return any(marker in lowered for marker in SENSITIVE_PARAM_KEYS)
