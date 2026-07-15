# Payload Runner Burp Extension

Payload Runner is a Java Burp Suite extension MVP. It adds a context menu action,
`发送到 Payload Runner`, then runs categorized payloads against request body
parameters whose values contain `*`.

## Features

- Context menu: `发送到 Payload Runner`
- URL query parameters whose values contain `*`, including POST request lines
- Body formats:
  - `application/x-www-form-urlencoded`
  - JSON bodies
  - `multipart/form-data`
  - XML attribute values and text nodes
- Marks insertion points by finding URL/body values that contain `*`
- YAML payload categories
- Editable payload YAML with save/reset controls
- Multi-select categories before running
- Encoding strategy per run:
  - `URL encode`
  - `JSON escape`
  - `Raw`
- Request rate presets:
  - `Low`
  - `Medium`
  - `High`
- Traffic destination per run:
  - `直接发送` through `callbacks.makeHttpRequest(...)`
  - `经 Burp Proxy 发送` through a configured local Proxy Listener
- Endpoint profiles for saving and loading runner settings
- Pause/resume and stop controls
- Keyword matching against responses
- Internal Request History grouped by endpoint
- Max response KB limit for stored history response bytes
- Manual Repeater sending for current, selected, or interesting history records
- Optional Repeater tab caption prefix for manual sends
- Result filters for text, hits, interesting records, and status classes
- Result score column for quickly sorting higher-signal responses
- Result table rerun actions for selected, failed, hit, or interesting rows
- Built-in hit rule templates
- Hit rules:
  - `keyword:admin`
  - `regex:uid=\d+`
  - `status:500` or `status:5xx`
  - `length>1000`
  - `diff>200`
  - `sim<90`
- Response diff against the original Burp message response
- Results table with endpoint, Repeater send status, interesting flag, hit, diff, status code, response length, and elapsed time
- Click a result row to open its generated request and response in the History Viewer
- Export all, selected, or interesting results to CSV
- Export selected request/response message files
- Built-in payload YAML extracted from `测试payload速取.xlsx`

## Build

```sh
sh scripts/build.sh
```

The extension jar is written to:

```text
build/payload-runner-burp.jar
```

The build uses local compile-only Burp API stubs and excludes them from the jar,
so Burp's own API classes are used at runtime.

## Smoke Test

```sh
sh scripts/test.sh
```

The smoke test covers YAML parsing, marker replacement, rate presets, direct and
Proxy transport configuration, local fake-Proxy HTTP routing, CONNECT request
generation, per-request Proxy failure isolation, history navigation, response
truncation, scoring, profiles, rerun actions, manual Repeater sending, result
filtering, settings persistence, CSV export, extension load output, and queue
actions.

## Refresh Built-in Payloads

```sh
/Users/aur4r0/.cache/codex-runtimes/codex-primary-runtime/dependencies/python/bin/python3 scripts/extract_payloads.py 测试payload速取.xlsx src/main/resources/payloads.yaml
```

The workbook's first row is treated as category names. Non-empty cells under
each category become payload entries in the built-in YAML.

## Load in Burp

1. Open Burp Suite.
2. Go to `Extensions` -> `Installed`.
3. Click `Add`.
4. Select extension type `Java`.
5. Choose `build/payload-runner-burp.jar`.

After the extension is imported, Burp's extension output shows:

```text
Payload Runner loaded successfully.
Right-click a Burp request and choose Send to Payload Runner.
GitHub: https://github.com/Aur4r0/Payload-Runner
```

## Screenshots / 界面截图

### Runner

<img src="docs/images/payload-runner-runner.png" alt="Payload Runner Runner page" width="100%">

Runner 页面用于维护内置 YAML payload、编辑命中规则、套用规则模板、
选择 payload 分类、管理 queued requests，并配置编码策略、发包速率、
History 上限、响应保存大小、关键词和 endpoint Profile。

### Results and Request History

<img src="docs/images/payload-runner-results-history.png" alt="Payload Runner Results and Request History page" width="100%">

Results 页面用于查看状态码、长度、耗时、Score、Hit、Diff、Interesting 和
Sent to Repeater；上方提供过滤、手动发送到 Repeater、标记 interesting 和清空结果。
下方 Request History 可以按 endpoint 前进/后退浏览每个 payload 变体的请求和响应。

## 使用说明

1. 在 Burp 的任意请求里，把要跑 payload 的参数值位置标成 `*`。
   - URL 查询参数示例：`GET /search?q=* HTTP/1.1`
   - POST URL 查询参数示例：`POST /api?keyword=* HTTP/1.1`
   - form body 示例：`username=*&password=123`
   - JSON 示例：`{"keyword":"*"}`
   - multipart/XML 中的字段值同样支持 `*`
2. 在 Burp 请求列表、Repeater、Proxy history 等位置右键请求，选择
   `发送到 Payload Runner`。
3. 打开 `Payload Runner` 插件页，在 `任务配置` 页面确认：
   - `待执行请求`：要测试的请求队列。选中某几条时只跑选中的请求；
     不选中时跑整个队列。右键队列项可删除选中请求。
   - `Payload 分类`：选择要运行的 payload 分类。`全选` 选择全部，`全不选`
     清空选择。
   - `编码方式`：选择 payload 写入请求时的编码策略：`URL 编码`、
     `JSON 转义` 或 `原始内容`。
   - `发送速率`：选择发包速率，默认 `标准`。`低速` 每包间隔约 1000ms，
     `标准` 每包间隔约 250ms，`高速` 不增加额外等待。
   - `流量去向`：默认 `直接发送`，保持原有 `callbacks.makeHttpRequest(...)`
     行为；选择 `经 Burp Proxy 发送` 后，填写 Burp Proxy Listener 的地址和端口，
     默认 `127.0.0.1:8080`。只有 Proxy 模式下地址和端口输入框可编辑。
   - `HTTPS 证书`：如果 HTTPS 报 TLS 握手失败，可以点击 `从 Proxy 获取 CA...`，
     插件会通过当前 Listener 请求 `http://burp/cert`；也可以从 Burp 导出 DER/PEM
     格式 CA 后点击 `导入 Burp CA...`。两种方式都会显示 SHA-256 指纹并要求确认；
     该信任只作用于 Payload Runner Proxy 模式，不修改 JVM 全局信任库。
   - `单接口历史上限`：每个 endpoint 最多保留多少条完整请求/响应历史，默认 500；
     超过后释放最旧记录的请求/响应 bytes，结果表元数据仍保留。
   - `响应保存上限(KB)`：每条 History 记录最多保存多少 KB 响应 bytes，默认 1024；
     状态码、长度、diff 和命中判断仍基于完整响应，Viewer/消息导出使用截断副本。
   - `命中关键词` / `命中规则`：设置响应命中规则，也可以选择模板后点击
     `应用模板` 快速填入常见规则。
   - `接口配置`：按 endpoint 保存/加载当前分类、编码、速率、流量去向、Proxy
     地址和端口、命中规则、关键词、History 限制和 Repeater 前缀。
4. 点击 `运行选中项` 开始运行。
   - 运行前会按分类对 payload 去重，状态栏会显示 unique payload 数和跳过的重复数量。
5. 在 `运行结果` 页面查看状态码、长度、耗时、命中规则、diff、重点标记和
   Sent to Repeater。`Score` 越高代表命中、状态变化、diff 或耗时异常越明显。
   点击任意结果行会在 `Request History` 中定位到该变体。
   - `快速筛选`、`仅看命中`、`仅看重点` 和状态码下拉框可以缩小结果表范围。
   - 右键结果表可以 `Rerun Selected`、`Rerun Failed`、`Rerun Hits` 或
     `Rerun Interesting`，重跑会使用当前编码、速率、流量去向和命中规则，结果追加到表格和 History。
6. 在 `Request History` 中按 endpoint 浏览记录：
   - `上一条` / `下一条` 在当前 endpoint 内前进后退。
   - `自动跟随最新结果` 默认开启，新结果会自动跳到最新记录；关闭后不会打断当前查看位置。
   - `标记为重点` / `取消重点标记` 手动标记值得复查的记录。
7. 需要把包送到 Burp Repeater 时，使用手动按钮：
   - `Repeater 标签前缀`：可选命名前缀。填写 `查询` 时，tab 命名为
     `查询1`, `查询2`, `查询3`；留空时命名为 `1`, `2`, `3`。
   - `发送当前项到 Repeater`：发送当前 History 记录。
   - `发送选中项到 Repeater`：发送结果表中选中的记录。
   - `发送重点项到 Repeater`：发送所有已标记为重点的记录。
8. 运行中可以 `暂停` / `继续` / `停止`。需要保存结果时选择导出范围
   `全部结果` / `选中结果` / `重点结果`，再点击 `导出 CSV`；需要保存原始包时点击
   `导出报文`。

## YAML Format

```yaml
xss:
  - "<script>alert(1)</script>"
  - "\" onmouseover=\"alert(1)"

sqli:
  - "' OR '1'='1"
  - "\" OR \"1\"=\"1"
```

Inline lists are also supported:

```yaml
ids: ["1", "2", "999999"]
```

## Runtime Notes

Payload edits and UI settings are saved through Burp extension settings.
`恢复内置 Payload` restores the bundled `payloads.yaml` generated from
`测试payload速取.xlsx`. Persisted UI settings include encoding, rate, traffic
destination, Proxy host/port, max history, Repeater prefix, and Follow latest.

### 直接发送与 Burp Proxy 模式

`直接发送` 继续调用 Burp legacy API 的 `callbacks.makeHttpRequest(...)`。
`经 Burp Proxy 发送` 不会把目标服务替换成 Proxy 服务；结果表、插件 Request
History 和 endpoint 分组仍使用原始目标的 scheme、host、port 和 path。插件会在
后台 runner 线程中为每个变体连接配置的 Proxy Listener，并把 Proxy 返回的响应
交给原有状态码、命中规则、Diff、评分和响应截断逻辑。

Burp legacy API 没有向现有 Proxy Listener 或 Proxy HTTP history 注入请求的官方
接口。Montoya Proxy API 也提供 history 查询、Intercept 控制和 handler 注册，而不
提供注入接口。因此本插件使用局部、独立的标准 Java Socket/JSSE 传输，不使用反射、
Burp 内部类或内部 Swing 组件：

- HTTP 连接 Proxy Listener，并把请求行改为代理所需的 absolute-form；方法、路径、
  查询参数、Header 和 Body 保持不变。
- HTTPS 先向 Proxy Listener 发送 `CONNECT target-host:target-port`，再在隧道中用
  默认 JVM `SSLSocketFactory` 建立 TLS。TLS 使用真实目标主机进行 SNI 和主机名校验，
  隧道内请求使用 origin-form。
- 插件不会注册 Proxy request handler，也不会把经过 Proxy 的请求重新加入任务，
  因此不会由插件自身形成重复处理循环；目标服务与 Proxy 配置为完全相同的 host 和
  port 时也会拒绝发送，以阻止明显的代理回环。

这些请求确实发送到配置的 Proxy Listener，但插件无法通过官方 API 强制写入 Proxy
HTTP history。请求被 Listener 正常处理并转发时，通常会按照 Burp 自身行为出现在
Proxy HTTP history；本项目的自动测试只使用本地假 Proxy，尚未在真实 Burp 中观察
验证，因此不把“已进入 Proxy HTTP history”作为保证。

插件不会关闭或绕过 Burp Proxy Intercept。Intercept 开启时，每个 Payload 请求都
可能停在 Intercept 等待人工 Forward/Drop；大量 Payload 会产生大量拦截项，任务会
等待当前请求，长时间未处理时可能因 60 秒读取超时而把该结果标记为错误。Stop 会先
等待当前网络操作返回或超时，再停止后续请求。

HTTPS 不使用 trust-all `TrustManager`，也不关闭证书或主机名校验。由于 Burp 通常会
对 CONNECT 流量做 TLS 中间人解密，可以在任务配置中显式导入从 Burp 导出的 X.509
CA。插件会把 JVM 默认信任库与这一张导入的 CA 组合，只用于 Payload Runner 创建的
TLS 连接，并继续校验真实目标主机名。导入的证书和 SHA-256 指纹会通过 extension
settings 保存；`清除 CA` 可恢复只使用 JVM 默认信任库。没有导入且 JVM 不信任 Burp
CA 时，该条 HTTPS 结果会明确提示导入 Burp CA。自定义目标端口受支持。当前界面不
提供 Proxy 认证配置；需要认证的上游 Proxy 不在此模式的支持范围内。

HTTP Proxy 模式只为协议要求改写请求行的 request-target；HTTPS 模式会在必要时把
absolute-form 规范化为 origin-form。除此之外插件按原字节发送 Header 和 Body，
但 Burp Proxy 后续转发时是否重写连接相关 Header 或规范化报文，取决于 Burp 自身。
Proxy 连接超时为 10 秒，响应读取超时为 60 秒。单条连接、CONNECT、TLS 或响应解析
失败只标记当前 Payload 结果，不终止后续任务。

Keyword matching accepts comma, semicolon, or newline separated terms and writes
matched terms into the result table's `Hit` column. Hit rules are editable in
the `命中规则` panel and saved through Burp extension settings.

Response diff compares each payload response with the original response attached
to the Burp message that was sent to Payload Runner. If the source message has
no response, the `Diff` column is blank.

Rate limiting is applied between payload requests in the background runner
thread. It does not block the Swing UI, and Pause/Stop remain responsive during
rate waits.

Payload runs no longer auto-open Repeater tabs for every variant. Each mutated
request and response is stored in the plugin's Request History. Repeater only
receives records when you click one of the manual send buttons.

History endpoint grouping uses `METHOD + scheme + host + port + path`; query
parameters are intentionally excluded so variants of the same interface stay in
one list. Manual Repeater tab captions use the optional `Repeater 标签前缀` plus
the per-click send batch index, or only the index when the prefix is empty.
Captions are capped at 80 characters. Repeater send failures are logged through
Burp extension stderr and do not stop the payload run.

When an endpoint exceeds `单接口历史上限`, old result rows stay in the table for
status review and CSV export, but their full request/response bytes are dropped
to keep memory bounded. Those dropped rows cannot be sent to Repeater unless you
rerun or increase the history limit before they are evicted.

`响应保存上限(KB)` limits only the response bytes stored in Request History. Result
metadata such as status, response length, elapsed time, score, hit rules, and
diff are calculated before truncation.

GitHub Actions runs `sh scripts/test.sh` and `sh scripts/build.sh` on pushes and
pull requests. Tags starting with `v` also build the jar and publish or replace
the Release asset.
