"""Campus library application protected by a simplified local WAF."""

from __future__ import annotations

from functools import wraps
from pathlib import Path
from typing import Any, Callable

from flask import Flask, jsonify, redirect, render_template, request, session, url_for

from waf import init_waf


BASE_DIR = Path(__file__).resolve().parent
RULES_PATH = BASE_DIR / "rules.json"
LOG_PATH = BASE_DIR / "logs" / "waf_block.log"

BOOKS = [
    {
        "isbn": "9787111641247",
        "title": "网络空间安全导论",
        "author": "课程参考书",
        "category": "网络安全",
        "location": "A 区 3 层",
        "available": 4,
    },
    {
        "isbn": "9787302605905",
        "title": "Web 应用安全实践",
        "author": "实验教材组",
        "category": "Web 安全",
        "location": "B 区 2 层",
        "available": 2,
    },
    {
        "isbn": "9787115521644",
        "title": "Python Flask Web 开发",
        "author": "开发参考",
        "category": "程序设计",
        "location": "C 区 1 层",
        "available": 5,
    },
    {
        "isbn": "9787115556660",
        "title": "日志审计与应急响应",
        "author": "安全运维组",
        "category": "安全运维",
        "location": "A 区 4 层",
        "available": 1,
    },
]

USERS: dict[str, dict[str, str]] = {
    "admin": {
        "password": "123456",
        "display_name": "管理员",
        "role": "admin",
    },
    "student": {
        "password": "library2026",
        "display_name": "学生读者",
        "role": "user",
    },
}

REVIEWS: list[dict[str, str]] = [
    {"name": "馆员", "book": "Web 应用安全实践", "content": "本周新增 Web 安全实验资料，可在资料中心查看。"}
]

RESOURCE_FILES = {
    "notice.txt": "图书馆通知：期末周开放时间延长至 22:00，请读者凭校园卡入馆。",
    "borrowing-guide.txt": "借阅说明：本科生最多借 8 本，借期 30 天，可续借 1 次。",
    "web-security-reading-list.txt": "推荐阅读：Web 应用安全实践、日志审计与应急响应、网络空间安全导论。",
}


def create_app() -> Flask:
    app = Flask(__name__)
    app.config["SECRET_KEY"] = "local-course-design-secret"

    init_waf(app, RULES_PATH, LOG_PATH)

    @app.get("/")
    @login_required
    def index():
        rules = app.extensions["waf_engine"].rules
        stats = {
            "books": len(BOOKS),
            "available": sum(book["available"] for book in BOOKS),
            "users": len(USERS),
            "rules": sum(1 for rule in rules if rule.enabled),
            "blocked": len(app.extensions["waf_logger"].tail(limit=200)),
        }
        return render_template("index.html", books=BOOKS[:3], reviews=REVIEWS[-3:], rules=rules, stats=stats)

    @app.get("/search")
    @login_required
    def search():
        query = request.args.get("q", "").strip()
        results = BOOKS
        if query:
            normalized = query.lower()
            results = [
                book
                for book in BOOKS
                if normalized in book["title"].lower()
                or normalized in book["author"].lower()
                or normalized in book["category"].lower()
                or normalized in book["isbn"].lower()
            ]
        return render_template("search.html", query=query, results=results)

    @app.route("/register", methods=["GET", "POST"])
    def register():
        errors: list[str] = []
        created_user = None
        if request.method == "POST":
            username = request.form.get("username", "").strip()[:40]
            password = request.form.get("password", "")

            if len(username) < 3:
                errors.append("账号至少需要 3 个字符。")
            if username in USERS:
                errors.append("该账号已经存在。")
            if len(password) < 6:
                errors.append("密码至少需要 6 位。")

            if not errors:
                USERS[username] = {
                    "password": password,
                    "display_name": username,
                    "role": "user",
                }
                created_user = username

        return render_template("register.html", errors=errors, created_user=created_user)

    @app.route("/login", methods=["GET", "POST"])
    def login():
        result = None
        next_url = request.args.get("next") or url_for("index")
        if request.method == "POST":
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "")
            profile = USERS.get(username)
            result = profile is not None and profile["password"] == password
            if result:
                session["username"] = username
                return redirect(next_url)
        return render_template("login.html", result=result, next_url=next_url)

    @app.post("/logout")
    def logout():
        session.clear()
        return redirect(url_for("login"))

    @app.route("/reviews", methods=["GET", "POST"])
    @login_required
    def reviews():
        if request.method == "POST":
            current_user = get_current_user()
            name = current_user["display_name"] if current_user else "匿名读者"
            book = request.form.get("book", "").strip()[:80] or "未选择书籍"
            content = request.form.get("content", "").strip()[:300]
            if content:
                REVIEWS.append({"name": name, "book": book, "content": content})
            return redirect(url_for("reviews"))
        return render_template("reviews.html", reviews=reversed(REVIEWS), books=BOOKS)

    @app.get("/resources")
    @login_required
    def resources():
        name = request.args.get("name", "notice.txt")
        content = RESOURCE_FILES.get(name)
        if content is None:
            content = "该资料不在图书馆公开资料列表中。"
        return render_template("resources.html", file_name=name, content=content, files=RESOURCE_FILES.keys())

    @app.route("/security", methods=["GET", "POST"])
    @admin_required
    def security():
        engine = app.extensions["waf_engine"]
        saved = request.args.get("saved") == "1"
        if request.method == "POST":
            enabled_rule_ids = set(request.form.getlist("enabled_rules"))
            for rule in engine.rules:
                engine.set_rule_enabled(rule.id, rule.id in enabled_rule_ids)

            threshold = _positive_int(request.form.get("threshold"), default=6, minimum=1, maximum=60)
            window_seconds = _positive_int(request.form.get("window_seconds"), default=10, minimum=1, maximum=300)
            engine.update_rate_limit("R004", threshold=threshold, window_seconds=window_seconds)
            return redirect(url_for("security", saved="1"))

        return render_template("security.html", rules=engine.rules, saved=saved)

    @app.get("/manual")
    @admin_required
    def manual():
        return render_template("manual.html", books=BOOKS)

    @app.get("/logs")
    @admin_required
    def logs():
        events = app.extensions["waf_logger"].tail(limit=80)
        return render_template("logs.html", events=reversed(events), log_path=LOG_PATH)

    @app.get("/api/status")
    def api_status():
        return jsonify({"status": "ok", "service": "campus-library"})

    @app.get("/api/books")
    @login_required
    def api_books():
        return jsonify({"count": len(BOOKS), "books": BOOKS})

    @app.post("/api/echo")
    @login_required
    def api_echo():
        return jsonify({"received": request.get_json(silent=True) or {}})

    @app.get("/health")
    def health():
        return "ok"

    @app.context_processor
    def inject_current_user():
        return {"current_user": get_current_user()}

    return app


def login_required(view: Callable[..., Any]) -> Callable[..., Any]:
    @wraps(view)
    def wrapped_view(*args: Any, **kwargs: Any) -> Any:
        if "username" not in session:
            if request.path.startswith("/api/"):
                return jsonify({"error": "login_required"}), 401
            return redirect(url_for("login", next=request.full_path if request.query_string else request.path))
        return view(*args, **kwargs)

    return wrapped_view


def admin_required(view: Callable[..., Any]) -> Callable[..., Any]:
    @wraps(view)
    @login_required
    def wrapped_view(*args: Any, **kwargs: Any) -> Any:
        current_user = get_current_user()
        if current_user is None or current_user.get("role") != "admin":
            if request.path.startswith("/api/"):
                return jsonify({"error": "admin_required"}), 403
            return render_template("forbidden.html"), 403
        return view(*args, **kwargs)

    return wrapped_view


def get_current_user() -> dict[str, str] | None:
    username = session.get("username")
    if not username:
        return None
    return USERS.get(username)


def _positive_int(value: str | None, *, default: int, minimum: int, maximum: int) -> int:
    try:
        parsed = int(value or default)
    except ValueError:
        return default
    return max(minimum, min(maximum, parsed))


app = create_app()


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
