# Campus Library WAF Protection System

这是一个带本地 WAF 防护的校园图书借阅系统。网站本身提供真实业务功能：登录、注册、图书检索、书评咨询、资料中心、馆藏 API、管理员安全中心和拦截日志；WAF 作为后台中间件保护这些业务入口。

## 快速运行

```powershell
python -m pip install -r requirements.txt
python app.py
```

访问后会先进入登录页：

```text
http://127.0.0.1:5000
```

运行自动测试：

```powershell
python -m pytest -q
```

## 默认账号

| 角色 | 账号 | 密码 |
|---|---|---|
| 管理员 | `admin` | `123456` |
| 普通用户 | `student` | `library2026` |

登录后点击右上角“退出登录”，会清空登录状态并回到登录界面。

## 业务功能

- 登录/注册：先登录或注册，再进入系统主页。注册只需要账号和密码。
- 首页：管理员看到安全管理工作台，普通用户看到读者服务主页。
- 图书检索：按书名、作者、ISBN、分类检索馆藏。
- 书评咨询：读者提交书评、荐购建议或咨询内容。
- 资料中心：读取公开资料文件，也可以手动输入文件名。
- 安全中心：仅管理员可访问，可手动启用/停用 WAF 规则，调整高频请求阈值。
- 日志：仅管理员可访问，查看被 WAF 拦截的请求记录。

## WAF 规则覆盖

| 编号 | 功能 | 真实业务入口 | 命中结果 |
|---|---|---|---|
| R001 | SQL 注入特征过滤 | 图书检索、登录、注册、API 参数 | 403 |
| R002 | XSS 特征过滤 | 注册账号、书评咨询、检索参数、JSON 参数 | 403 |
| R003 | 路径穿越特征过滤 | 资料中心文件名参数 | 403 |
| R004 | 高频请求限制 | `/api/books`、`/api/status` 等接口 | 429 |
| R005 | 非法 User-Agent 识别 | 所有业务请求头 | 403 |

说明：F12 控制台里“只改自己浏览器页面 DOM、不提交请求”的内容不会经过服务器，WAF 看不到。WAF 能拦截的是“修改表单值后提交到服务器”的请求，比如用 F12 把输入框 value 改成 XSS 载荷再点击提交。

## 手动设置 WAF

先使用管理员账号登录，再打开：

```text
http://127.0.0.1:5000/security
```

可以操作：

- 勾选或取消勾选 R001-R005，临时启用/停用规则。
- 修改 R004 的“高频阈值”和“窗口秒数”。
- 点击“查看检测点”查看每条规则里的具体正则。

这些设置只在本次运行期间生效。重启应用后会重新按 `rules.json` 加载。

## 怎么改规则

规则文件是 `rules.json`。每个正则规则使用 `patterns` 数组拆开写，每个检测点都有名称、正则、样例和说明：

```json
{
  "name": "通用事件属性",
  "pattern": "(?ix) \\b on [a-z]+ \\s* =",
  "example": "<input onclick=alert(1)>",
  "description": "检测 onclick、onmouseover、onfocus、onerror、onload 等事件处理器。"
}
```

`(?ix)` 的含义：

- `i`：忽略大小写。
- `x`：正则里可以加空格，让表达式更好读。

JSON 不能写 `// 注释`，所以本项目用 `name`、`description`、`example` 代替注释。修改 `rules.json` 后，重启 `python app.py` 生效。

## 本机手动验证攻击操作

以下操作只用于你自己的本地网站：`http://127.0.0.1:5000`。

### R001 SQL 注入

先登录任意账号，然后浏览器访问：

```text
http://127.0.0.1:5000/search?q=' OR 1=1 --
```

预期：返回拦截页，状态码 403，日志中 `rule_id` 为 `R001`。

也可以在登录页的密码框输入：

```text
' OR 1=1 --
```

预期：登录请求被拦截，日志中的密码字段会脱敏为 `***`。

### R002 XSS：直接输入

登录后打开书评咨询页：

```text
http://127.0.0.1:5000/reviews
```

在内容里输入：

```html
<script>alert(1)</script>
<img src=x onerror="fetch('http://127.0.0.1:5000/steal?c='+document.cookie)">
```

预期：提交后被 R002 拦截，书评不会保存。

退出登录后也可以在注册页验证。账号输入：

```html
<script>alert(1)</script>
```

预期：注册请求被 R002 拦截，账号不会创建。

### R002 XSS：F12 修改表单后提交

这个案例模拟用户绕过页面输入限制，手动改前端 DOM 后提交。步骤：

1. 登录普通用户或管理员。
2. 打开书评咨询页：`http://127.0.0.1:5000/reviews`。
3. 按 `F12` 打开开发者工具，切到 Console。
4. 在控制台执行下面任意一条，把 textarea 的值改成 XSS 载荷：

```javascript
document.querySelector('textarea[name="content"]').value = '<input onclick=alert(1) autofocus>';
```

或者：

```javascript
document.querySelector('textarea[name="content"]').value = '<iframe srcdoc="<script>alert(1)</script>"></iframe>';
```

5. 回到页面点击“提交”。

预期：请求提交到服务器后被 R002 拦截，日志中 `rule_id` 为 `R002`。  
注意：如果你只在 Console 里执行 `alert(1)` 或只改页面 DOM 但不提交请求，这不会经过服务器，WAF 无法记录，也不算本系统的请求过滤场景。

### R003 路径穿越

登录后打开资料中心：

```text
http://127.0.0.1:5000/resources
```

在“文件名”输入框手动输入：

```text
..\..\windows\system.ini
```

点击“打开资料”。

预期：返回 403，日志中 `rule_id` 为 `R003`。

也可以直接访问：

```text
http://127.0.0.1:5000/resources?name=..\..\windows\system.ini
```

### R004 高频请求限制

使用管理员登录，打开安全中心里的“安全自测”，点击“连续请求 `/api/books` 7 次”。

也可以用 PowerShell：

```powershell
1..7 | ForEach-Object { (Invoke-WebRequest -UseBasicParsing http://127.0.0.1:5000/api/books).StatusCode }

for ($i=1; $i -le 8; $i++) { 
  curl.exe -i http://127.0.0.1:5000/api/status
}
```

预期：前 6 次为 200，第 7 次为 429。

### R005 非法 User-Agent

R005 的本质是检查请求头里的 `User-Agent`。通用格式是：

```powershell
curl.exe -A "要模拟的User-Agent" "要访问的URL"
```

推荐直接访问 `/api/status`，因为它不需要登录，演示最稳定：

```powershell
curl.exe -A "badbot-lab/1.0" "http://127.0.0.1:5000/api/status"
```

预期：返回 403，日志中 `rule_id` 为 `R005`。

也可以换成规则里已有的常见扫描器特征：

```powershell
curl.exe -A "sqlmap/1.7" "http://127.0.0.1:5000/api/status"
curl.exe -A "Nikto/2.5" "http://127.0.0.1:5000/api/status"
curl.exe -A "masscan" "http://127.0.0.1:5000/api/status"
```

如果想看完整响应头，用 `-i`：

```powershell
curl.exe -i -A "sqlmap/1.7" "http://127.0.0.1:5000/api/status"
```

如果返回中能看到类似下面的状态，就说明 R005 生效：

```text
HTTP/1.1 403 FORBIDDEN
```

正常 User-Agent 不会被拦截，例如：

```powershell
curl.exe -A "Mozilla/5.0 normal-browser" "http://127.0.0.1:5000/api/status"
```

预期：返回 200。

## 查看日志

使用管理员账号登录后打开：

```text
http://127.0.0.1:5000/logs
```

日志会显示来源 IP、时间、路径、参数、命中规则、命中内容和 HTTP 状态码。

## 安全声明

本项目仅用于本机授权课程设计实验，不用于公网、校园网真实系统或第三方系统测试。
