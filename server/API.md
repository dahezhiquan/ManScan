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

统计口径说明：

- 扫描任务响应中的 `tech_count` 表示命中结果中 `info.tags` 包含 `tech` 标签的数量，不再根据模板名称或结果名称是否包含“指纹识别”判断。

## 1. 获取模板列表

- 请求方法和路径：`GET /api/v1/templates`

- 请求参数：

| 参数         | 类型                    | 必填 | 说明                          |
|------------|-----------------------|----|-----------------------------|
| `page`     | `int`                 | 否  | 页码，最小为 `1`，默认 `1`           |
| `name`     | `string` / `string[]` | 否  | 按模板名称或模板 ID 模糊过滤，支持逗号分隔和多参数 |
| `tag`      | `string` / `string[]` | 否  | 按标签过滤，支持逗号分隔和多参数            |
| `severity` | `string` / `string[]` | 否  | 按严重级别过滤                     |
| `protocol` | `string` / `string[]` | 否  | 按模板 YAML 顶层执行块识别出的协议类型过滤 |
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
    "items": ["code", "dns", "file", "headless", "http", "javascript", "ssl", "tcp", "workflows"]
  }
}
```

- 说明：
  - 协议选项来自模板 YAML 顶层执行块识别，只读取顶层 key，不扫描全文字符串。
  - 当前执行块白名单包括 `http`、`tcp`、`dns`、`ssl`、`file`、`headless`、`javascript`、`code`、`workflows`、`websocket`、`whois`、`offlinehttp`，并兼容历史顶层 key：`requests` 归一为 `http`，`network` 归一为 `tcp`。

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

- 说明：
  - `fingerprintTemplateCount` 表示 `info.tags` 中包含 `tech` 标签的模板数量，其他标签不计入该字段。

- 错误码说明：
  - `50001`：模板目录读取或解析失败

- 使用示例：

```bash
curl "http://127.0.0.1:8686/api/v1/templates/stats"
```

## 6. 获取扫描任务统计

- 请求方法和路径：`GET /api/v1/scans/stats`

- 请求参数：

无

- 响应格式：

```json
{
  "code": 0,
  "message": "success",
  "data": {
    "total": 18,
    "running": 0,
    "saved_requests": 12345
  }
}
```

- 说明：
  - `total` 表示扫描任务总数。
  - `running` 表示当前状态为 `running` 的任务数。
  - `saved_requests` 仅统计最终状态为 `success` 的扫描任务，统计口径为 `SUM(total_requests - real_requests)`。
  - `failed`、`cancelled`、`paused` 以及仍在 `running` 的任务都不会计入该字段。

- 错误码说明：
  - `50001`：获取扫描任务统计失败

- 使用示例：

```bash
curl "http://127.0.0.1:8686/api/v1/scans/stats"
```

## 7. 获取扫描任务名称选项

- 请求方法和路径：`GET /api/v1/scans/options/names`

- 请求参数：

| 参数 | 类型 | 必填 | 说明 |
| --- | --- | --- | --- |
| `page` | `int` | 否 | 页码，最小为 `1`，默认 `1` |
| `page_size` | `int` | 否 | 每页数量，范围 `1-100`，默认 `20` |
| `keyword` | `string` | 否 | 按扫描任务名称模糊搜索 |

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
        "name": "demo-scan"
      }
    ]
  }
}
```

- 说明：
  - 该接口只返回去重后的任务名称，不返回任务详情。
  - 仅过滤空名称，名称以 `TRIM(name) <> ''` 为准。
  - 前端会在菜单打开时加载第一页，输入关键词后重新加载第一页，滚动到底部后继续请求下一页。

- 错误码说明：
  - `40001`：分页参数非法
  - `50001`：查询扫描任务名称失败

- 使用示例：

```bash
curl "http://127.0.0.1:8686/api/v1/scans/options/names?page=1&page_size=20&keyword=demo"
```

## 8. 获取扫描任务列表

- 请求方法和路径：`GET /api/v1/scans`

- 请求参数：

| 参数 | 类型 | 必填 | 说明 |
| --- | --- | --- | --- |
| `page` | `int` | 否 | 页码，最小为 `1`，默认 `1` |
| `page_size` | `int` | 否 | 每页数量，范围 `1-100`，默认 `10` |
| `keyword` | `string` | 否 | 按任务名称、任务编号、创建人、描述模糊搜索 |
| `status` | `string` / `string[]` | 否 | 按任务状态过滤，支持逗号分隔和多参数 |
| `scan_strategy` | `string` / `string[]` | 否 | 按扫描策略过滤，支持逗号分隔和多参数 |
| `created_by` | `string` | 否 | 按创建人精确过滤 |
| `has_high_risk` | `bool` | 否 | 传 `true` 时只返回 `critical_count > 0 OR high_count > 0` 的任务；运行中任务会结合运行时快照判断 |

- 响应格式：

```json
{
  "code": 0,
  "message": "success",
  "data": {
    "page": 1,
    "pageSize": 10,
    "total": 2,
    "totalPages": 1,
    "items": [
      {
        "id": 1,
        "task_no": "d4l8h4crvimc0n1abcde",
        "name": "demo-scan",
        "description": "",
        "status": "running",
        "created_by": "anonymous",
        "scan_strategy": "auto",
        "started_at": "2026-06-09T21:00:00+08:00",
        "finished_at": null,
        "critical_count": 0,
        "high_count": 1,
        "medium_count": 2,
        "low_count": 0,
        "info_count": 3,
        "tech_count": 4,
        "plugin_count": 50,
        "target_count": 1,
        "total_requests": 100,
        "real_requests": 10,
        "progress_percent": 10,
        "duration_seconds": 120,
        "last_message": "扫描进度更新"
      }
    ]
  }
}
```

- 说明：
  - 该接口以扫描任务表为主数据源，`manscan_task_results` 仅用于补充已完成任务的结果统计。
  - 运行中任务会叠加当前运行时快照，因此也会出现在列表中。

- 错误码说明：
  - `40001`：分页或过滤参数非法
  - `50001`：查询任务列表失败

- 使用示例：

```bash
curl "http://127.0.0.1:8686/api/v1/scans?page=1&page_size=10&keyword=demo&status=running&has_high_risk=true"
```

## 9. 创建扫描任务

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
| `protocols`           | `string[]` | 否  | 协议类型过滤，口径与模板协议选项一致 |
| `rate_limit`          | `int`      | 否  | 速率限制               |
| `template_threads`    | `int`      | 否  | 模板并发数              |
| `timeout`             | `int`      | 否  | 请求超时，单位秒           |
| `headless`            | `bool`     | 否  | 是否启用 headless      |
| `proxy`               | `string[]` | 否  | 代理列表               |

至少需要提供 `targets` 或 `inline_targets_list` 之一，当前不再限制单次任务的目标数量上限。

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
  - `40001`：目标为空或请求体非法
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

## 10. 取消扫描任务

- 请求方法和路径：`POST /api/v1/scans/:id/cancel`

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
    "task_id": 1,
    "status": "running",
    "cancel_requested": true
  }
}
```

- 说明：
  - 当任务仍在执行时，接口会立即返回受理结果，并向扫描子进程发出取消信号；响应中的 `status` 保留任务取消前的当前状态，最终状态会在子进程退出后更新为 `cancelled`。
  - 当任务已经是 `cancelled` 状态时，接口会直接返回当前状态。
  - 当任务已经是 `paused` 状态时，接口会直接将其收口为 `cancelled`，不会再恢复执行。
  - 当数据库中任务仍是 `pending` 或 `running`，但运行态已经丢失时，接口会直接将任务收口为 `cancelled`。

- 错误码说明：
  - `40001`：任务 ID 非法，或任务已结束且不支持再次取消
  - `40401`：任务不存在
  - `50001`：取消请求落库失败

- 使用示例：

```bash
curl -X POST "http://127.0.0.1:8686/api/v1/scans/1/cancel"
```

## 11. 暂停扫描任务

- 请求方法和路径：`POST /api/v1/scans/:id/pause`

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
    "task_id": 1,
    "status": "running",
    "pause_requested": true
  }
}
```

- 说明：
  - 当任务仍在执行时，接口会立即返回受理结果，并向该任务所属进程组发送中断信号，等待扫描子进程优雅退出并写出 `resume` 进度文件。
  - 响应中的 `status` 保留任务暂停前的当前状态，最终状态会在子进程退出后更新为 `paused`。
  - 暂停后的任务不会新建记录，后续恢复时会继续使用同一个任务 ID、同一个运行目录和同一个 `resume` 文件。

- 错误码说明：
  - `40001`：任务 ID 非法，或任务当前状态不支持暂停
  - `40401`：任务不存在
  - `50001`：暂停请求处理失败

- 使用示例：

```bash
curl -X POST "http://127.0.0.1:8686/api/v1/scans/1/pause"
```

## 12. 恢复扫描任务

- 请求方法和路径：`POST /api/v1/scans/:id/resume`

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
    "task_id": 1,
    "status": "running",
    "resume_requested": true
  }
}
```

- 说明：
  - 只有 `paused` 状态的任务可以恢复。
  - 恢复时不会创建新任务，而是基于原任务配置重新启动扫描子进程，并继续使用原任务运行目录中的 `resume` 文件。
  - 恢复受理后，任务状态会原子更新为 `running`，避免恢复过程中在 `pending` 与 `running` 之间反复切换。
  - 重复恢复同一个任务时，只有第一个仍处于 `paused` 状态的请求会被受理，后续请求会按“不支持恢复”返回。

- 错误码说明：
  - `40001`：任务 ID 非法，或任务当前状态不支持恢复
  - `40401`：任务不存在
  - `50001`：恢复请求处理失败

- 使用示例：

```bash
curl -X POST "http://127.0.0.1:8686/api/v1/scans/1/resume"
```

## 13. 获取扫描任务详情

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
      "started_at": "2026-06-09T21:00:00+08:00",
      "critical_count": 0,
      "high_count": 1,
      "medium_count": 2,
      "low_count": 0,
      "info_count": 3,
      "tech_count": 4,
      "plugin_count": 50,
      "target_count": 1
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

- 说明：
  - `progress.requests` 表示扫描进程实际发出的请求数，会排除项目缓存、模板聚类等没有真实出网的请求。
  - `progress.total_requests` 表示本次任务按模板和目标预估的逻辑请求总数。
  - `progress.percent` 表示逻辑扫描完成度，不直接用 `requests / total_requests` 计算，因此缓存或聚类节省大量请求时，进度仍会按扫描执行进度平滑推进。
  - `progress.matched` 表示服务端保留的去重后结果数量。

- 错误码说明：
  - `40001`：任务 ID 非法
  - `40401`：任务不存在
  - `50001`：查询任务失败

- 使用示例：

```bash
curl "http://127.0.0.1:8686/api/v1/scans/1"
```

## 14. 获取扫描任务日志

- 请求方法和路径：`GET /api/v1/scans/:id/logs`

- 请求参数：

| 参数 | 类型 | 必填 | 说明 |
| --- | --- | --- | --- |
| `id` | `int64` | 是 | 任务 ID，路径参数 |
| `offset` | `int64` | 否 | 日志偏移，默认 `0`，含义取决于 `direction` |
| `limit` | `int` | 否 | 返回数量，范围 `1-1000`，默认 `200` |
| `direction` | `string` | 否 | 读取方向，可选 `forward` 或 `before`；运行中任务默认 `forward`，已结束任务默认 `before` |

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
      "critical_count": 0,
      "high_count": 1,
      "medium_count": 2,
      "low_count": 0,
      "info_count": 3,
      "tech_count": 4,
      "plugin_count": 50,
      "target_count": 1
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
    "next_offset": 1,
    "has_more": false
  }
}
```

- 说明：
  - `direction=forward` 用于按序向后读取增量日志，返回 `seq > offset` 的事件；`next_offset` 表示本次已处理的最大 `seq`，下一次请求可直接作为 `offset` 传回。
  - `direction=before` 用于向前翻旧日志，返回 `seq < offset` 的最近一页可见事件；当 `offset=0` 时返回当前尾部最近一页；`next_offset` 表示本页最早可见事件的 `seq`，下一次请求可直接作为 `offset` 继续翻更早日志。
  - 运行中任务也支持 `direction=before`，可用于浏览器刷新后从尾部向前回补历史日志。
  - `result` 类型事件可能包含 `tags` 字段，用于记录该命中结果的模板标签。
  - 当任务开启 `matcher_status` 时，模板匹配失败会以 `level=info`、`type=match_failure` 输出为调试日志；这类事件不计入 `progress.matched`，不写入漏洞结果。

- 错误码说明：
  - `40001`：任务 ID、`offset`、`limit` 或 `direction` 非法
  - `40401`：任务不存在
  - `50001`：查询任务或读取日志失败

- 使用示例：

```bash
curl "http://127.0.0.1:8686/api/v1/scans/1/logs?offset=0&limit=100"
curl "http://127.0.0.1:8686/api/v1/scans/1/logs?direction=before&offset=0&limit=100"
```

## 15. 订阅扫描任务日志流

- 请求方法和路径：`GET /api/v1/scans/:id/stream`

- 请求参数：

| 参数 | 类型 | 必填 | 说明 |
| --- | --- | --- | --- |
| `id` | `int64` | 是 | 任务 ID，路径参数 |
| `offset` | `int64` | 否 | 日志续传偏移，默认 `0`；流会先补发 `seq > offset` 的快照事件，再推送后续实时事件 |

- 响应格式：
  - 使用 `SSE`（`text/event-stream`）返回
  - 首个事件为 `snapshot`
  - 后续事件为 `event`
  - `progress` 与 `result` 类型事件会额外携带最新的 `task` 统计快照，便于前端实时刷新漏洞数、指纹数、目标数和插件数
  - `result` 类型事件中的 `event.tags` 为该命中结果的模板标签，包含 `tech` 时计入 `tech_count`
  - 开启 `matcher_status` 后产生的 `match_failure` 事件只用于展示匹配失败调试信息，不会触发漏洞命中统计刷新
  - 任务结束后发送 `complete`

- `snapshot` 示例：

```text
event: snapshot
data: {"task":{"id":1,"status":"running","critical_count":0,"high_count":1,"medium_count":2,"low_count":0,"info_count":3,"tech_count":4,"plugin_count":50,"target_count":1},"progress":{"percent":10},"events":[{"seq":1,"level":"info","type":"task_started","message":"扫描任务开始执行"}],"nextOffset":1}
```

- `event` 示例：

```text
event: event
data: {"task_id":1,"seq":2,"level":"info","type":"progress","message":"扫描进度更新","task":{"id":1,"status":"running","critical_count":0,"high_count":1,"medium_count":2,"low_count":0,"info_count":3,"tech_count":4,"plugin_count":50,"target_count":1},"progress":{"hosts":1,"templates":50,"total_requests":100,"requests":10,"matched":1,"errors":0,"percent":10,"last_updated_at":"2026-06-09T21:01:00+08:00","last_message":"扫描进度更新","last_event_seq":2,"finished":false,"finished_status":"running"},"nextOffset":2}
```

- `result` 事件示例：

```text
event: event
data: {"task_id":1,"seq":3,"level":"match","type":"result","message":"[HTTP 安全响应头缺失][strict-transport-security] 命中 [http://example.com/]","task":{"id":1,"status":"running","critical_count":0,"high_count":1,"medium_count":2,"low_count":0,"info_count":4,"tech_count":4,"plugin_count":50,"target_count":1},"event":{"seq":3,"time":"2026-06-09T21:01:02+08:00","level":"match","type":"result","message":"[HTTP 安全响应头缺失][strict-transport-security] 命中 [http://example.com/]","tags":["cve"]},"nextOffset":3}
```

- `match_failure` 事件示例：

```text
event: event
data: {"task_id":1,"seq":4,"level":"info","type":"match_failure","message":"[HTTP 安全响应头缺失][info][strict-transport-security] 匹配失败 http://example.com/","nextOffset":4}
```

- 错误码说明：
  - `40001`：任务 ID 或 `offset` 非法
  - `40401`：任务不存在
  - `50001`：建立流或序列化事件失败

- 使用示例：

```bash
curl -N "http://127.0.0.1:8686/api/v1/scans/1/stream?offset=1"
```

## 16. 获取漏洞列表

- 请求方法和路径：`GET /api/v1/vulnerabilities`

- 请求参数：

| 参数 | 类型 | 必填 | 说明 |
| --- | --- | --- | --- |
| `page` | `int` | 否 | 页码，最小为 `1`，默认 `1` |
| `page_size` | `int` | 否 | 每页数量，范围 `1-100`，默认 `10` |
| `keyword` | `string` | 否 | 按漏洞名称或模板 ID 统一模糊搜索 |
| `asset_host` | `string` / `string[]` | 否 | 按资产 Host 模糊过滤，支持逗号分隔和多参数 |
| `status` | `string` / `string[]` | 否 | 按漏洞状态精确过滤，支持逗号分隔和多参数 |
| `tag` / `tags` | `string` / `string[]` | 否 | 按漏洞标签过滤，支持逗号分隔和多参数 |
| `severity` / `level` | `string` / `string[]` | 否 | 按严重级别精确过滤，支持逗号分隔和多参数 |
| `template_id` | `string` / `string[]` | 否 | 按模板 ID 模糊过滤，支持逗号分隔和多参数 |
| `vulnerability_name` | `string` / `string[]` | 否 | 按漏洞名称模糊过滤，支持逗号分隔和多参数 |
| `latest_scan_task_name` | `string` / `string[]` | 否 | 按最近扫描任务名称模糊过滤，支持逗号分隔和多参数，前端选项来自 `/api/v1/scans/options/names` |
| `protocol` | `string` / `string[]` | 否 | 按协议类型精确过滤，支持逗号分隔和多参数 |

- 响应格式：

```json
{
  "code": 0,
  "message": "success",
  "data": {
    "page": 1,
    "pageSize": 10,
    "total": 2,
    "totalPages": 1,
    "items": [
      {
        "id": 1,
        "name": "HTTP 安全响应头缺失",
        "severity": "high",
        "template_id": "http-missing-security-headers",
        "asset_host": "192.0.2.10",
        "status": "unreviewed",
        "tags": ["cve", "kev"],
        "latest_scan_task_name": "demo-scan",
        "protocol": "http",
        "last_found_at": "2026-08-27T12:30:00+08:00"
      }
    ]
  }
}
```

- 说明：
  - 列表默认按严重级别从高到低排序：`critical`、`high`、`medium`、`low`、`info`、`unknown`；同级别按 `last_found_at DESC, id DESC` 排序。
  - `keyword` 匹配逻辑为 `vulnerability_name OR template_id` 模糊匹配，该 OR 条件与其他筛选条件整体做 AND 组合。
  - `severity`、`status`、`protocol` 为精确匹配；协议值按模板顶层执行块白名单归一化，例如 `network` 会按 `tcp` 处理。
  - `asset_host`、`template_id`、`vulnerability_name`、`latest_scan_task_name` 为模糊匹配。
  - `tag` 和 `tags` 含义一致；`severity` 和 `level` 含义一致，前端任选一种命名即可。

- 错误码说明：
  - `40001`：分页参数非法，例如 `page` 非整数或 `page_size` 超过 `100`
  - `50001`：查询漏洞列表失败

- 使用示例：

```bash
curl "http://127.0.0.1:8686/api/v1/vulnerabilities?page=1&page_size=20&keyword=security-header&asset_host=192.0.2.10&status=unreviewed&severity=high&tag=cve&protocol=http"
```

- 前端实现需求：
  - 新增“漏洞查询”列表页，进入页面默认请求 `GET /api/v1/vulnerabilities?page=1&page_size=10`。
  - 表格列至少展示 `name`、`severity`、`template_id`、`asset_host`、`status`；建议同时展示 `latest_scan_task_name`、`protocol`、`last_found_at` 便于溯源。
  - “搜索漏洞名称或 Template ID”输入框统一传 `keyword=<输入值>`，前端不再自行判断传 `vulnerability_name` 还是 `template_id`。
  - 筛选区提供 `asset_host`、`status`、`tags`、`severity`、`latest_scan_task_name`、`protocol`。扫描任务名称选项来自 `/api/v1/scans/options/names`，多选值用重复 query 参数或逗号分隔传给后端。
  - 翻页、修改每页数量、修改筛选条件时重新请求列表；筛选条件变化后将 `page` 重置为 `1`。
  - 严重级别建议按 `critical`、`high`、`medium`、`low`、`info`、`unknown` 做固定选项；状态至少兼容当前后端写入的 `unreviewed`。

## 17. 获取漏洞详情

- 请求方法和路径：`GET /api/v1/vulnerabilities/:id`

- 请求参数：

| 参数 | 类型 | 必填 | 说明 |
| --- | --- | --- | --- |
| `id` | `int64` | 是 | 漏洞 ID，必须为大于 `0` 的整数 |

- 响应格式：

```json
{
  "code": 0,
  "message": "success",
  "data": {
    "id": 1,
    "template_id": "http-missing-security-headers",
    "vulnerability_name": "HTTP 安全响应头缺失",
    "latest_scan_task_name": "demo-scan",
    "latest_scan_task_id": "42",
    "first_found_at": "2026-08-27T12:00:00+08:00",
    "last_found_at": "2026-08-27T12:30:00+08:00",
    "fixed_at": null,
    "status": "unreviewed",
    "asset_domain": "https://app.example.com/login",
    "asset_host": "192.0.2.10",
    "asset_port": 8443,
    "tags": ["cve", "kev"],
    "severity": "high",
    "description": "漏洞描述",
    "impact": "漏洞影响",
    "cvss_score": 8.1,
    "protocol": "http",
    "vendor": "example-vendor",
    "product": "example-product",
    "remediation": "修复建议",
    "reference_links": ["https://example.com/ref"],
    "detail": {
      "matched-at": "https://app.example.com/login"
    },
    "vuln_fingerprint": "sha256-fingerprint"
  }
}
```

- 说明：
  - 详情接口按漏洞 ID 查询 `manscan_vulnerabilities` 中的单条记录，并返回漏洞表当前保存的完整业务字段。
  - `first_found_at` 表示首次发现时间，`last_found_at` 表示最近发现时间，列表页中的发现时间对应 `last_found_at`。
  - `tags`、`reference_links` 返回数组；`detail` 会在内容为合法 JSON 时返回解析后的对象或数组，否则返回原始字符串。
  - `protocol` 返回值会按模板顶层执行块白名单归一化，例如 `requests` 会返回为 `http`。

- 错误码说明：
  - `40001`：漏洞 ID 非法，例如不是整数或小于等于 `0`
  - `40401`：漏洞不存在
  - `50001`：查询漏洞详情失败

- 使用示例：

```bash
curl "http://127.0.0.1:8686/api/v1/vulnerabilities/1"
```
