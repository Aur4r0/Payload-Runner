# Payload Runner Burp Extension

Payload Runner is a Java Burp Suite extension MVP. It adds a context menu action,
`Send to Payload Runner`, then runs categorized payloads against request body
parameters whose values contain `*`.

## Features

- Context menu: `Send to Payload Runner`
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
- Pause/resume and stop controls
- Keyword matching against responses
- Optional `Auto send to Repeater` switch, off by default, with custom tab name prefix
- Hit rules:
  - `keyword:admin`
  - `regex:uid=\d+`
  - `status:500` or `status:5xx`
  - `length>1000`
  - `diff>200`
  - `sim<90`
- Response diff against the original Burp message response
- Results table with Repeater sync status, hit, diff, status code, response length, and elapsed time
- Click a result row to view the generated request and response
- Export results to CSV
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

The smoke test covers YAML category parsing plus form-urlencoded and JSON body
marker replacement.

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

## 使用说明

1. 在 Burp 的任意请求里，把要跑 payload 的参数值位置标成 `*`。
   - URL 查询参数示例：`GET /search?q=* HTTP/1.1`
   - POST URL 查询参数示例：`POST /api?keyword=* HTTP/1.1`
   - form body 示例：`username=*&password=123`
   - JSON 示例：`{"keyword":"*"}`
   - multipart/XML 中的字段值同样支持 `*`
2. 在 Burp 请求列表、Repeater、Proxy history 等位置右键请求，选择
   `Send to Payload Runner`。
3. 打开 `Payload Runner` 插件页，在 `Runner` 页面确认：
   - `Queued requests`：要测试的请求队列。选中某几条时只跑选中的请求；
     不选中时跑整个队列。右键队列项可删除选中请求。
   - `Categories`：选择要运行的 payload 分类。`All` 选择全部，`None`
     清空选择。
   - `Encoding`：选择 payload 写入请求时的编码策略：`URL encode`、
     `JSON escape` 或 `Raw`。
   - `Auto send to Repeater`：开启后，每个变体请求会同步发送到 Burp
     Repeater。
   - `Repeater name`：Auto Repeater 的 tab 前缀。留空时命名为 `1`,
     `2`, `3`；填写 `查询` 时命名为 `查询1`, `查询2`, `查询3`。
   - `Keywords` / `Hit rules`：设置响应命中规则。
4. 点击 `Run Selected` 开始运行。
5. 在 `Results` 页面查看状态码、长度、耗时、命中规则、diff 和是否发送到
   Repeater。点击任意结果行可查看该变体的完整请求和响应。
6. 运行中可以 `Pause` / `Resume` / `Stop`。需要保存结果时点击 `Export CSV`。

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

Payload edits are saved through Burp extension settings. `Reset Built-in`
restores the bundled `payloads.yaml` generated from `测试payload速取.xlsx`.

Keyword matching accepts comma, semicolon, or newline separated terms and writes
matched terms into the result table's `Hit` column. Hit rules are editable in
the `Hit rules` panel and saved through Burp extension settings.

Response diff compares each payload response with the original response attached
to the Burp message that was sent to Payload Runner. If the source message has
no response, the `Diff` column is blank.

When `Auto send to Repeater` is enabled, each mutated request is also sent to
Burp Repeater from the background runner thread. If `Repeater name` is empty,
the Repeater tab caption is the run index, for example `1`, `2`, `3`.

If `Repeater name` is filled, the caption uses that value plus the run index,
for example `查询1`, `查询2`, `查询3`. Captions are capped at 80 characters.
Repeater send failures are logged through Burp extension stderr and do not stop
the payload run.
