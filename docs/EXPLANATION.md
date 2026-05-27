# 校园图书借阅系统 WAF 防护说明

## 项目定位

系统首先是一个校园图书借阅网站，提供图书检索、读者注册、登录、书评咨询、资料中心和馆藏 API。WAF 中间件部署在 Flask 业务路由之前，对所有业务请求进行规则检查。

## 请求处理流程

1. 用户访问图书系统页面或接口。
2. Flask 接收请求。
3. `waf/middleware.py` 中的 `before_request` 先执行。
4. WAF 读取请求路径、query 参数、form 参数、JSON body、User-Agent 和来源 IP。
5. `WAFEngine.check()` 按 `rules.json` 顺序检查 R001-R005。
6. 未命中规则：进入正常业务路由，返回图书、注册、登录、书评等页面。
7. 命中规则：生成拦截事件，写入日志，返回 403 或 429。

## 规则与业务入口

| 编号 | 规则 | 业务入口 |
|---|---|---|
| R001 | SQL 注入特征过滤 | 图书检索、登录、注册、API |
| R002 | XSS 特征过滤 | 注册显示名称、书评咨询 |
| R003 | 路径穿越特征过滤 | 资料中心文件名参数 |
| R004 | 高频请求限制 | 馆藏 API、状态 API |
| R005 | 非法 User-Agent 识别 | 所有业务请求 |

## 规则配置

`rules.json` 使用 `patterns` 数组拆分正则，每个检测点单独说明：

```json
{
  "name": "script 标签",
  "pattern": "(?ix) < \\s* script \\b",
  "example": "<script>alert(1)</script>",
  "description": "检测直接插入脚本标签的 XSS。"
}
```

`(?ix)` 让正则忽略大小写，并允许用空格排版。

## 注册防护说明

注册请求也会先经过 WAF。比如显示名称为 `<img src=x onerror=alert(1)>` 时，R002 会在注册业务逻辑执行前拦截请求，用户不会被写入本地账号表。

## 验证方式

自动测试：

```powershell
python -m pytest -q
```

手动验证入口：

```text
http://127.0.0.1:5000/security
http://127.0.0.1:5000/manual
http://127.0.0.1:5000/logs
```

详细攻击样例见 `README.md` 的“本机手动验证攻击操作”。
