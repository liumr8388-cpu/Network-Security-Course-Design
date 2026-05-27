"""Flask integration for the local WAF engine."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from flask import Flask, jsonify, render_template, request

from .logger import AuditLogger
from .rules import WAFEngine, collect_parameters, get_client_ip, load_rules


def init_waf(app: Flask, rules_path: str | Path, log_path: str | Path) -> WAFEngine:
    engine = WAFEngine(load_rules(rules_path))
    audit_logger = AuditLogger(log_path)
    app.extensions["waf_engine"] = engine
    app.extensions["waf_logger"] = audit_logger

    @app.before_request
    def waf_before_request() -> Any:
        if _is_excluded_path(request.path):
            return None

        match = engine.check(request)
        if match is None:
            return None

        event = {
            "client_ip": get_client_ip(request),
            "method": request.method,
            "path": request.path,
            "query_string": request.query_string.decode("utf-8", errors="replace"),
            "parameters": collect_parameters(request),
            "user_agent": request.headers.get("User-Agent", ""),
            "rule_id": match.rule.id,
            "rule_name": match.rule.name,
            "category": match.rule.category,
            "severity": match.rule.severity,
            "matched_value": match.matched_value,
            "reason": match.reason,
            "action": "blocked",
            "status_code": match.status_code,
        }
        audit_logger.write(event)

        payload = {
            "blocked": True,
            "rule_id": match.rule.id,
            "category": match.rule.category,
            "message": "请求已被校园图书系统 WAF 策略拦截。",
        }
        if _wants_json_response(request.path):
            return jsonify(payload), match.status_code

        return render_template("blocked.html", event=event), match.status_code

    return engine


def _is_excluded_path(path: str) -> bool:
    return path.startswith("/static/")


def _wants_json_response(path: str) -> bool:
    best = request.accept_mimetypes.best
    return path.startswith("/api/") or best == "application/json"
