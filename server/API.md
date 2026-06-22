# Server API

本文档描述 `server` 目录当前对外提供的 HTTP 接口。所有接口统一使用 JSON 响应格式：

```json
{
  "code": 0,
  "message": "success",
  "data": {}
}
```

通用错误码：

- `0`：成功
- `40001`：请求参数错误
- `40401`：资源不存在
- `50001`：服务器内部错误
- `50301`：服务暂不可用

服务默认监听地址为 `:8686`，接口统一挂载在 `/api/v1` 下。

## 1. 获取模板列表

- 请求方法和路径：`GET /api/v1/templates`

- 请求参数：

| 参数         | 类型                    | 必填 | 说明                          |
|------------|-----------------------|----|-----------------------------|
| `page`     | `int`                 | 否  | 页码，最小为 `1`，默认 `1`           |
| `name`     | `string` / `string[]` | 否  | 按模板名称或模板 ID 模糊过滤，支持逗号分隔和多参数 |
| `tag`      | `string` / `string[]` | 否  | 按标签过滤，支持逗号分隔和多参数            |
| `severity` | `string` / `string[]` | 否  | 按严重级别过滤                     |
| `protocol` | `string` / `string[]` | 否  | 按协议类型过滤                     |
| `iskev`    | `bool`                | 否  | 是否仅保留包含 `kev` 标签的模板         |
| `iscve`    | `bool`                | 否  | 是否仅保留包含 `cve` 标签的模板         |

- 响应格式：

```json
{
  "code": 0,
  "message": "success",
  "data": {
    "page": 1,
    "pageSize": 20,
    "total": 2,
    "totalPages": 1,
    "items": [
      {
        "id": "CVE-2025-0001",
        "name": "Example Template",
        "description": "template description",
        "severity": "high",
        "author": "team",
        "protocols": ["http"],
        "tags": ["cve", "kev"]
      }
    ]
  }
}
```

- 错误码说明：
  - `40001`：查询参数格式不正确，例如 `page` 非整数
  - `50001`：模板目录读取或解析失败

- 使用示例：

```bash
curl "http://127.0.0.1:8686/api/v1/templates?page=1&tag=cve&severity=high"
```

## 2. 获取模板详情

- 请求方法和路径：`GET /api/v1/templates/:id`

- 请求参数：

| 参数   | 类型       | 必填 | 说明         |
|------|----------|----|------------|
| `id` | `string` | 是  | 模板 ID，路径参数 |

- 响应格式：

```json
{
  "code": 0,
  "message": "success",
  "data": {
    "id": "CVE-2025-0001",
    "protocols": ["http"],
    "name": "Example Template",
    "tags": ["cve", "kev"],
    "severity": "high",
    "description": "template description",
    "impact": "",
    "remediation": "",
    "reference": ["https://example.com"],
    "cvssScore": 9.8,
    "vendor": "vendor",
    "product": "product",
    "shodanQuery": [],
    "fofaQuery": [],
    "content": "id: CVE-2025-0001\n..."
  }
}
```

- 错误码说明：
  - `40001`：模板 ID 为空
  - `40401`：模板不存在
  - `50001`：模板文件读取或解析失败

- 使用示例：

```bash
curl "http://127.0.0.1:8686/api/v1/templates/CVE-2025-0001"
```

## 3. 获取模板标签选项

- 请求方法和路径：`GET /api/v1/templates/options/tags`

- 请求参数：无

- 响应格式：

```json
{
  "code": 0,
  "message": "success",
  "data": {
    "items": ["cve", "kev", "tech"]
  }
}
```

- 错误码说明：
  - `50001`：模板目录读取或解析失败

- 使用示例：

```bash
curl "http://127.0.0.1:8686/api/v1/templates/options/tags"
```

## 4. 获取模板协议选项

- 请求方法和路径：`GET /api/v1/templates/options/protocols`

- 请求参数：无

- 响应格式：

```json
{
  "code": 0,
  "message": "success",
  "data": {
    "items": ["dns", "http", "javascript"]
  }
}
```

- 错误码说明：
  - `50001`：模板目录读取或解析失败

- 使用示例：

```bash
curl "http://127.0.0.1:8686/api/v1/templates/options/protocols"
```

## 5. 获取模板统计

- 请求方法和路径：`GET /api/v1/templates/stats`

- 请求参数：无

- 响应格式：

```json
{
  "code": 0,
  "message": "success",
  "data": {
    "templateCount": 100,
    "kevTemplateCount": 8,
    "cveTemplateCount": 60,
    "fingerprintTemplateCount": 20
  }
}
```

- 错误码说明：
  - `50001`：模板目录读取或解析失败

- 使用示例：

```bash
curl "http://127.0.0.1:8686/api/v1/templates/stats"
```

## 6. 创建扫描任务

- 请求方法和路径：`POST /api/v1/scans`

- 请求参数：

请求体为 JSON，常用字段如下，未列出的字段会按当前实现原样透传到扫描参数构造逻辑：

| 字段                    | 类型         | 必填 | 说明                 |
|-----------------------|------------|----|--------------------|
| `name`                | `string`   | 否  | 任务名称，默认自动生成        |
| `description`         | `string`   | 否  | 任务描述               |
| `created_by`          | `string`   | 否  | 创建人，默认 `anonymous` |
| `targets`             | `string[]` | 否  | 目标列表               |
| `inline_targets_list` | `string`   | 否  | 多行目标文本             |
| `exclude_targets`     | `string[]` | 否  | 排除目标               |
| `tags`                | `string[]` | 否  | 模板标签过滤             |
| `include_ids`         | `string[]` | 否  | 模板 ID 过滤           |
| `severities`          | `string[]` | 否  | 严重级别过滤             |
| `protocols`           | `string[]` | 否  | 协议类型过滤             |
| `rate_limit`          | `int`      | 否  | 速率限制               |
| `template_threads`    | `int`      | 否  | 模板并发数              |
| `timeout`             | `int`      | 否  | 请求超时，单位秒           |
| `headless`            | `bool`     | 否  | 是否启用 headless      |
| `proxy`               | `string[]` | 否  | 代理列表               |

至少需要提供 `targets` 或 `inline_targets_list` 之一。

- 响应格式：

```json
{
  "code": 0,
  "message": "success",
  "data": {
    "task": {
      "id": 1,
      "task_no": "d4l8h4crvimc0n1abcde",
      "name": "scan-20260609-210000",
      "description": "",
      "status": "pending",
      "created_by": "anonymous"
    },
    "log_api": "/api/v1/scans/1/logs",
    "stream": "/api/v1/scans/1/stream",
    "task_api": "/api/v1/scans/1"
  }
}
```

- 错误码说明：
  - `40001`：目标为空、目标数量超限或请求体非法
  - `50001`：任务入库失败或运行时目录创建失败

- 使用示例：

```bash
curl -X POST "http://127.0.0.1:8686/api/v1/scans" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "demo-scan",
    "targets": ["https://example.com"],
    "tags": ["cve"],
    "severities": ["high"]
  }'
```

## 7. 获取扫描任务详情

- 请求方法和路径：`GET /api/v1/scans/:id`

- 请求参数：

| 参数 | 类型 | 必填 | 说明 |
| --- | --- | --- | --- |
| `id` | `int64` | 是 | 任务 ID，路径参数 |

- 响应格式：

```json
{
  "code": 0,
  "message": "success",
  "data": {
    "task": {
      "id": 1,
      "task_no": "d4l8h4crvimc0n1abcde",
      "name": "demo-scan",
      "description": "",
      "status": "running",
      "created_by": "anonymous",
      "started_at": "2026-06-09T21:00:00+08:00"
    },
    "progress": {
      "hosts": 1,
      "templates": 50,
      "total_requests": 100,
      "requests": 10,
      "matched": 1,
      "errors": 0,
      "percent": 10,
      "last_updated_at": "2026-06-09T21:01:00+08:00",
      "last_message": "扫描进度更新",
      "last_event_seq": 3,
      "finished": false,
      "finished_status": "running"
    }
  }
}
```

- 错误码说明：
  - `40001`：任务 ID 非法
  - `40401`：任务不存在
  - `50001`：查询任务失败

- 使用示例：

```bash
curl "http://127.0.0.1:8686/api/v1/scans/1"
```

## 8. 获取扫描任务日志

- 请求方法和路径：`GET /api/v1/scans/:id/logs`

- 请求参数：

| 参数 | 类型 | 必填 | 说明 |
| --- | --- | --- | --- |
| `id` | `int64` | 是 | 任务 ID，路径参数 |
| `offset` | `int64` | 否 | 起始偏移，默认 `0` |
| `limit` | `int` | 否 | 返回数量，范围 `1-1000`，默认 `200` |

- 响应格式：

```json
{
  "code": 0,
  "message": "success",
  "data": {
    "task": {
      "id": 1,
      "task_no": "d4l8h4crvimc0n1abcde",
      "name": "demo-scan",
      "description": "",
      "status": "running",
      "created_by": "anonymous"
    },
    "progress": {
      "requests": 10,
      "matched": 1,
      "errors": 0,
      "percent": 10
    },
    "events": [
      {
        "seq": 1,
        "time": "2026-06-09T21:00:00+08:00",
        "level": "info",
        "type": "task_started",
        "message": "扫描任务开始执行"
      }
    ],
    "next_offset": 2,
    "has_more": false
  }
}
```

- 错误码说明：
  - `40001`：任务 ID、`offset` 或 `limit` 非法
  - `40401`：任务不存在
  - `50001`：查询任务或读取日志失败

- 使用示例：

```bash
curl "http://127.0.0.1:8686/api/v1/scans/1/logs?offset=0&limit=100"
```

## 9. 订阅扫描任务日志流

- 请求方法和路径：`GET /api/v1/scans/:id/stream`

- 请求参数：

| 参数 | 类型 | 必填 | 说明 |
| --- | --- | --- | --- |
| `id` | `int64` | 是 | 任务 ID，路径参数 |

- 响应格式：
  - 使用 `SSE`（`text/event-stream`）返回
  - 首个事件为 `snapshot`
  - 后续事件为 `event`
  - 任务结束后发送 `complete`

- `snapshot` 示例：

```text
event: snapshot
data: {"task":{"id":1,"status":"running"},"progress":{"percent":10},"events":[],"nextOffset":1}
```

- `event` 示例：

```text
event: event
data: {"task_id":1,"seq":2,"level":"info","type":"progress","message":"扫描进度更新","progress":{"hosts":1,"templates":50,"total_requests":100,"requests":10,"matched":1,"errors":0,"percent":10,"last_updated_at":"2026-06-09T21:01:00+08:00","last_message":"扫描进度更新","last_event_seq":2,"finished":false,"finished_status":"running"},"nextOffset":3}
```

- 错误码说明：
  - `40001`：任务 ID 非法
  - `40401`：任务不存在
  - `50001`：建立流或序列化事件失败

- 使用示例：

```bash
curl -N "http://127.0.0.1:8686/api/v1/scans/1/stream"
```
