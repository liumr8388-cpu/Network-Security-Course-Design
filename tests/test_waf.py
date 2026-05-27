from __future__ import annotations

import json
from pathlib import Path

import pytest

from app import USERS, create_app


@pytest.fixture()
def client():
    USERS.pop("reader_test", None)
    app = create_app()
    log_path = Path(__file__).resolve().parents[1] / "logs" / "test_waf_block.log"
    log_path.parent.mkdir(parents=True, exist_ok=True)
    log_path.write_text("", encoding="utf-8")
    app.extensions["waf_logger"].log_path = log_path
    app.extensions["waf_engine"].reset_rate_limits()
    app.config.update(TESTING=True)
    return app.test_client()


def login(client, username: str = "admin", password: str = "2023117015"):
    return client.post("/login", data={"username": username, "password": password}, follow_redirects=False)


def test_root_redirects_to_login_before_authentication(client):
    response = client.get("/")

    assert response.status_code == 302
    assert "/login" in response.headers["Location"]


def test_login_then_homepage_is_available(client):
    response = login(client)

    assert response.status_code == 302
    assert response.headers["Location"].endswith("/")
    homepage = client.get("/")
    assert homepage.status_code == 200
    assert "管理员工作台".encode("utf-8") in homepage.data


def test_logout_returns_to_login(client):
    login(client)
    response = client.post("/logout", follow_redirects=False)

    assert response.status_code == 302
    assert response.headers["Location"].endswith("/login")
    assert client.get("/").status_code == 302


def test_user_homepage_is_different_from_admin(client):
    login(client, username="student", password="library2026")
    response = client.get("/")

    assert response.status_code == 200
    assert "读者服务主页".encode("utf-8") in response.data
    assert "进入安全中心".encode("utf-8") not in response.data


def test_normal_business_requests_are_allowed_after_login(client):
    login(client)
    normal_requests = [
        ("GET", "/", {}),
        ("GET", "/search?q=Web", {}),
        ("GET", "/security", {}),
        ("GET", "/resources?name=notice.txt", {}),
        ("POST", "/reviews", {"data": {"book": "Web 应用安全实践", "content": "good book"}}),
        ("POST", "/api/echo", {"json": {"text": "hello local library"}}),
    ]

    for method, path, kwargs in normal_requests:
        response = client.open(path, method=method, **kwargs)
        assert response.status_code in {200, 302}


def test_register_uses_only_username_and_password(client):
    response = client.post(
        "/register",
        data={"username": "reader_test", "password": "library2026"},
        follow_redirects=True,
    )

    assert response.status_code == 200
    assert "reader_test" in USERS
    assert USERS["reader_test"]["role"] == "user"


@pytest.mark.parametrize(
    ("path", "expected_rule"),
    [
        ("/search?q=' OR 1=1 --", "R001"),
        ("/reviews", "R002"),
        ("/resources?name=..\\..\\windows\\system.ini", "R003"),
    ],
)
def test_parameter_rules_block_business_requests(client, path, expected_rule):
    if expected_rule == "R002":
        login(client)
        response = client.post(path, data={"book": "Web 应用安全实践", "content": "<script>alert(1)</script>"})
    else:
        response = client.get(path)

    assert response.status_code == 403
    assert expected_rule.encode() in response.data


@pytest.mark.parametrize(
    "payload",
    [
        "<input onclick=alert(1) autofocus>",
        "<div onmouseover=alert(1)>hover</div>",
        "<iframe srcdoc=\"<script>alert(1)</script>\"></iframe>",
    ],
)
def test_f12_modified_xss_payloads_are_blocked(client, payload):
    login(client)
    response = client.post("/reviews", data={"book": "Web 应用安全实践", "content": payload})

    assert response.status_code == 403
    assert b"R002" in response.data


def test_register_input_is_checked_by_waf_before_creating_user(client):
    response = client.post("/register", data={"username": "<script>alert(1)</script>", "password": "library2026"})

    assert response.status_code == 403
    assert "<script>alert(1)</script>" not in USERS


def test_illegal_user_agent_is_blocked(client):
    response = client.get("/search?q=Web", headers={"User-Agent": "badbot-lab/1.0"})

    assert response.status_code == 403
    assert b"R005" in response.data


def test_rate_limit_blocks_high_frequency_requests(client):
    login(client)
    statuses = [client.get("/api/books").status_code for _ in range(7)]

    assert statuses[:6] == [200] * 6
    assert statuses[6] == 429


def test_blocked_request_is_logged(client):
    response = client.get("/search?q=union select password from users")

    assert response.status_code == 403
    log_path = client.application.extensions["waf_logger"].log_path
    log_lines = log_path.read_text(encoding="utf-8").splitlines()
    event = json.loads(log_lines[-1])

    assert event["rule_id"] == "R001"
    assert event["category"] == "SQL_INJECTION"
    assert event["action"] == "blocked"


def test_sensitive_values_are_masked_in_logs(client):
    response = client.post("/login", data={"username": "admin", "password": "' OR 1=1 --"})

    assert response.status_code == 403
    log_path = client.application.extensions["waf_logger"].log_path
    log_lines = log_path.read_text(encoding="utf-8").splitlines()
    event = json.loads(log_lines[-1])

    assert event["rule_id"] == "R001"
    assert event["parameters"]["form.password"] == "***"
    assert event["matched_value"] == "***"


def test_split_rule_patterns_are_loaded(client):
    rules = client.application.extensions["waf_engine"].rules
    sql_rule = next(rule for rule in rules if rule.id == "R001")
    xss_rule = next(rule for rule in rules if rule.id == "R002")

    assert len(sql_rule.patterns) > 1
    assert any("union select" in pattern.name for pattern in sql_rule.patterns)
    assert any("事件属性" in pattern.name for pattern in xss_rule.patterns)


def test_user_cannot_access_security_settings(client):
    login(client, username="student", password="library2026")
    response = client.get("/security")

    assert response.status_code == 403


def test_admin_can_disable_rule_and_update_rate_limit(client):
    login(client)
    response = client.post(
        "/security",
        data={
            "enabled_rules": ["R002", "R003", "R004", "R005"],
            "threshold": "3",
            "window_seconds": "8",
        },
        follow_redirects=True,
    )
    rules = client.application.extensions["waf_engine"].rules
    sql_rule = next(rule for rule in rules if rule.id == "R001")
    rate_rule = next(rule for rule in rules if rule.id == "R004")

    assert response.status_code == 200
    assert not sql_rule.enabled
    assert rate_rule.threshold == 3
    assert rate_rule.window_seconds == 8


def test_manual_page_is_admin_only(client):
    login(client, username="student", password="library2026")
    assert client.get("/manual").status_code == 403

    client.post("/logout")
    login(client)
    response = client.get("/manual")
    assert response.status_code == 200
    assert "安全自测".encode("utf-8") in response.data
