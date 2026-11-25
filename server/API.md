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
- `40101`：未登录或登录状态已失效
- `40301`：已登录但无权访问当前资源
- `40401`：资源不存在
- `50001`：服务器内部错误
- `50301`：服务暂不可用

服务默认监听地址为 `:8686`，接口统一挂载在 `/api/v1` 下。

除 `GET /api/v1/auth/challenge` 和 `POST /api/v1/auth/login` 外，所有接口都需要在请求头中携带登录后获取的访问令牌：

```http
Authorization: Bearer <access_token>
```

服务端启动前必须配置 `auth.jwt_secret` 或环境变量 `MANSCAN_JWT_SECRET`，密钥长度至少 32 个字符；可通过 `auth.token_ttl_minutes` 或 `MANSCAN_TOKEN_TTL_MINUTES` 调整访问令牌有效期，默认 480 分钟。第三方 API Key 配置还必须设置独立的 `auth.api_key_encryption_key` 或环境变量 `MANSCAN_API_KEY_ENCRYPTION_KEY`，密钥长度至少 32 个字符，建议使用高熵随机值并妥善备份；密钥变更后历史密文将无法解密。此配置是服务启动必需项，不复用 JWT 密钥。

统计口径说明：

- 扫描任务响应中的 `tech_count` 表示指纹命中数量，即命中结果中 `info.tags` 包含 `tech`、`detect` 或 `favicon` 任一标签的数量，不再根据模板名称或结果名称是否包含“指纹识别”判断。

## 主页仪表盘

主页数据按四个独立区块获取，前端可并行请求并独立展示加载状态，不必等待所有统计完成。所有接口均需要 `Authorization: Bearer <access_token>`，无请求参数。

### 获取漏洞及高危端口概览

- 请求方法和路径：`GET /api/v1/dashboard/overview`
- 请求参数：无；不支持时间范围、扫描任务或资产过滤，统计整个系统的现有数据。
- 响应格式：

```json
{
  "code": 0,
  "message": "success",
  "data": {
    "vulnerability_status": {
      "total": 100,
      "unreviewed": 40,
      "confirmed": 20,
      "ticketed": 10,
      "fixed": 15,
      "false_positive": 10,
      "ignored": 5
    },
    "pending_vulnerabilities": {
      "total": 40,
      "critical": 5,
      "high": 10,
      "medium": 15,
      "low": 8
    },
    "high_risk_open_ports": 12
  }
}
```

- 字段说明：所有数量均为整数；`vulnerability_status` 从 `manscan_vulnerabilities` 统计所有漏洞记录（包括已修复、误报和忽略），六个状态分别对应未审核、已确认、已发单、已修复、误报和忽略。
- 待处理口径：仅统计 `status=unreviewed` 的漏洞，`total` 与 `vulnerability_status.unreviewed` 相等，等级字段依次表示严重、高危、中危、低危。`info`、`unknown` 等等级计入 `total`，不计入这四个等级字段，因此四项之和可能小于 `total`。
- 高危开放端口口径：`manscan_asset_host_port` 中同时满足 `is_alive=1` 和 `is_high_risk_port=1` 的记录，按 `ip_address` 与 `port_number` 去重后计数；不同主机的相同端口数字分别计数。
- 错误码：`40101` / HTTP 401 表示未登录或令牌无效；`50301` / HTTP 503 表示查询失败或超时，`data=null`，可稍后重试。
- 使用示例：

```bash
curl -H 'Authorization: Bearer <access_token>' \
  'http://127.0.0.1:8686/api/v1/dashboard/overview'
```

### 获取主机与域名资产风险数量

- 请求方法和路径：`GET /api/v1/dashboard/asset-risks`
- 请求参数：无。
- 响应格式：

```json
{
  "code": 0,
  "message": "success",
  "data": {
    "hosts": {"critical": 3, "high": 8, "medium": 12, "low": 5, "no_risk": 20, "unknown": 2},
    "domains": {"critical": 1, "high": 6, "medium": 10, "low": 4, "no_risk": 15, "unknown": 1}
  }
}
```

- 字段说明：`hosts` 表示 `manscan_asset_host` 中的资产数量，`domains` 表示 `manscan_asset_domain` 中的资产数量，均包含当前不存活的资产。每个资产只归入一个等级。
- 关联口径：主机按 `manscan_vulnerabilities.asset_host = manscan_asset_host.ip_address` 关联；域名按 `manscan_vulnerabilities.asset_endpoint = manscan_asset_domain.domain` 关联，保留资产端点中的端口，不做域名截断。未登记到对应资产表的漏洞不会增加资产数量。
- 风险口径：排除 `fixed`、`false_positive`、`ignored` 状态，以剩余漏洞的最高等级按 `critical > high > medium > low` 分类，与资产详情的有效漏洞口径一致。
- 无风险口径：`no_risk` 表示不存在有效漏洞的资产（包括仅关联已修复、误报、忽略漏洞的资产）。额外返回 `unknown`：有有效漏洞但其等级全部为 `info`、`unknown` 或其他未识别值的资产，避免错误归为无风险。六项之和等于对应资产表的记录总数。
- 错误码：`40101` / HTTP 401 表示未登录或令牌无效；`50301` / HTTP 503 表示任一聚合查询失败或超时，`data=null`，不返回部分结果。
- 使用示例：

```bash
curl -H 'Authorization: Bearer <access_token>' \
  'http://127.0.0.1:8686/api/v1/dashboard/asset-risks'
```

### 获取主机漏洞数量与开放端口数量 Top10

- 请求方法和路径：`GET /api/v1/dashboard/host-rankings`
- 请求参数：无；排行榜固定最多返回 10 项，不支持修改条数或分页。
- 响应格式：

```json
{
  "code": 0,
  "message": "success",
  "data": {
    "top_vulnerabilities": [
      {"ip_address": "10.0.0.1", "vulnerability_count": 25},
      {"ip_address": "10.0.0.2", "vulnerability_count": 18}
    ],
    "top_ports": [
      {"ip_address": "10.0.0.2", "port_count": 20},
      {"ip_address": "10.0.0.1", "port_count": 12}
    ]
  }
}
```

- 字段说明：`top_vulnerabilities` 表示主机 IP 与漏洞数量，`top_ports` 表示主机 IP 与存活端口数字数量。只返回存在对应记录且登记在 `manscan_asset_host` 中的主机，不补零，不要求主机本身 `is_alive=1`。
- 漏洞数量口径：按 `asset_host` 关联 IP，统计所有状态的漏洞记录，与主机资产列表的漏洞总数口径一致；不会将仅有域名端点、没有主机 IP 关联的漏洞猜测分配给主机。
- 端口数量口径：按 `ip_address` 关联 IP，仅统计 `is_alive=1` 的记录；同一主机的相同 `port_number` 只计 1 个，不区分协议和服务名，与主机资产列表的 `port_count` 口径一致。
- 排序：数量降序；数量相同按 IP 字符串升序。少于 10 项时返回实际条数，无数据返回 `[]`。
- 错误码：`40101` / HTTP 401 表示未登录或令牌无效；`50301` / HTTP 503 表示任一查询失败或超时，`data=null`。
- 使用示例：

```bash
curl -H 'Authorization: Bearer <access_token>' \
  'http://127.0.0.1:8686/api/v1/dashboard/host-rankings'
```

### 获取域名与主机服务指纹数量 Top10

- 请求方法和路径：`GET /api/v1/dashboard/service-fingerprints`
- 请求参数：无；两组排行榜各最多返回 10 项，不支持修改条数或分页。
- 响应格式：

```json
{
  "code": 0,
  "message": "success",
  "data": {
    "domains": [{"app_name": "nginx", "count": 30}],
    "hosts": [{"service_name": "ssh", "count": 50}]
  }
}
```

- 字段说明：`domains` 按 `manscan_asset_domain_service_assets.app_name` 分组计数；`hosts` 按 `manscan_asset_host_port.service_name` 分组计数，返回具体指纹名称和对应记录数量，不使用主机端口表的 `app_name` 替代 `service_name`。
- 统计口径：两组均仅统计 `is_alive=1` 的记录，排除名称为 NULL、空字符串或全为空格的记录，不按主机去重，也不按版本拆分。同一主机不同存活端口命中同一 `service_name` 时分别计数。沿用数据库的字符串排序规则，不额外拆分指纹字符串。
- 排序：数量降序；数量相同按指纹名称升序。少于 10 项时返回实际条数，无数据返回 `[]`。
- 错误码：`40101` / HTTP 401 表示未登录或令牌无效；`50301` / HTTP 503 表示任一查询失败或超时，`data=null`。
- 使用示例：

```bash
curl -H 'Authorization: Bearer <access_token>' \
  'http://127.0.0.1:8686/api/v1/dashboard/service-fingerprints'
```

### 性能与调用约束

- 每个区块只执行两条数据库聚合查询：概览合并状态与等级统计，资产风险分别聚合主机和域名，两组排行榜各自聚合。完整主页共八条查询，不加载漏洞明细、不按资产逐条查询，不做 N+1 查询。
- 分拆原因：资产风险需要按关联资产聚合有效漏洞，Top10 需要分组及排序，数据增长时可能比概览更慢；拆分后支持并行加载、独立失败重试，避免最慢区块阻塞整个主页。拆分本身不会减少数据库总工作量。
- 每个区块共享 5 秒数据库查询时限，并继承请求取消和更短的上游超时；超时或查询失败统一返回 HTTP 503。该时限不包含鉴权查询和网络传输，不能视为端到端延迟承诺。
- 直接查询当前数据库，不引入缓存延迟；各区块及各查询不是同一事务快照，扫描入库或修改状态期间可能出现短暂统计差异。建议前端定时刷新时避免高频轮询和重复发起同一区块的并行请求。
- 可使用 `go test ./server/internal/repository -run '^$' -bench '^BenchmarkDashboardQueries$' -benchtime=5x -count=1` 复现本地合成数据评估：1,000 个主机、1,000 个域名、100,000 条漏洞、100,000 条端口、10,000 条域名指纹。基准使用内存 SQLite 和部分现有索引，仅衡量聚合查询，不包含 MySQL 网络、鉴权和 HTTP 耗时；生产响应时间应在真实 MySQL 数据集上压测并结合 `EXPLAIN` 确认。
- 2026-10-14 在 Apple M2 / Go 1.26.3 上运行上述基准，各区块两条查询的平均累计耗时分别为：概览约 67.9 ms、资产风险约 83.0 ms、主机排行榜约 33.5 ms、服务指纹排行榜约 25.1 ms。这些不是生产接口响应时间或 P95；拆分可避免所有查询顺序串行完成后才返回第一块数据。
- 大数据部署可评估覆盖索引：漏洞表 `(status, severity)`、`(asset_host, status, severity)`、`(asset_endpoint, status, severity)`，端口表 `(is_alive, is_high_risk_port)`、`(is_alive, ip_address)`、`(is_alive, service_name)`，域名指纹表 `(is_alive, app_name)`。风险查询中的状态规范化函数可能限制状态索引条件下推；索引收益必须通过实际执行计划验证。本次不自动修改已有表结构或新增生产索引。

## 认证与鉴权

### 获取登录验证码挑战

- 请求方法和路径：`GET /api/v1/auth/challenge`

- 请求参数：无

- 响应格式：

```json
{
  "code": 0,
  "message": "success",
  "data": {
    "challenge_id": "86d4f193-6fbf-4a74-a1f1-75f0c71d6a9b",
    "challenge_type": "orbital_slider",
    "expires_at": "2026-10-12T18:05:00+08:00",
    "scene": {
      "theme": "neo_orbit",
      "seed": 1219102391,
      "canvas_size": 320,
      "center_x": 160,
      "center_y": 160,
      "radius": 112,
      "start_angle": 28.2,
      "target_angle": 246.4,
      "decoy_angles": [293.4, 5.4, 89.4, 177.4]
    },
    "requirements": {
      "angle_tolerance": 6,
      "min_drag_duration_ms": 300,
      "max_drag_duration_ms": 10000,
      "min_track_points": 3,
      "max_track_points": 240
    }
  }
}
```

- 错误码说明：
  - `50001`：生成验证码失败

- 使用示例：

```bash
curl "http://127.0.0.1:8686/api/v1/auth/challenge"
```

验证码挑战为一次性使用，默认 5 分钟过期。前端应按 `scene` 渲染轨道滑块交互，并在登录时提交最终角度、拖动耗时和轨迹点。

### 登录

- 请求方法和路径：`POST /api/v1/auth/login`

- 请求参数：

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `username` | `string` | 是 | 登录用户名，最长 64 个字符 |
| `password` | `string` | 是 | 登录密码，最长 256 个字符 |
| `challenge_id` | `string` | 是 | `GET /api/v1/auth/challenge` 返回的验证码挑战 ID |
| `challenge_answer.angle` | `number` | 是 | 前端拖动结束后的角度，单位为度 |
| `challenge_answer.drag_duration_ms` | `int` | 是 | 用户完成拖动的耗时，单位毫秒 |
| `challenge_answer.track` | `array<object>` | 是 | 拖动轨迹点数组，每个点包含 `x`、`y`、`t` |

- 响应格式：

```json
{
  "code": 0,
  "message": "success",
  "data": {
    "access_token": "eyJhbGciOiJIUzI1NiIs...",
    "token_type": "Bearer",
    "expires_at": "2026-10-10T18:00:00+08:00",
    "user": {
      "id": 1,
      "username": "admin",
      "role": "admin"
    }
  }
}
```

- 错误码说明：
  - `40001`：请求体格式错误、缺少用户名/密码/验证码参数，或验证码校验失败；验证码失败时响应 `data.refresh_required=true`
  - `40101`：用户名或密码错误；已存在的启用账户密码错误时，响应 `data.remaining_attempts` 表示剩余可尝试次数，`data.locked` 表示本次失败后是否已锁定
  - `40301`：用户已被禁用或账户已锁定
  - `50001`：登录过程发生内部错误

- 验证码失败响应示例：

```json
{
  "code": 40001,
  "message": "验证码校验失败，请刷新后重试",
  "data": {
    "refresh_required": true
  }
}
```

- 登录失败响应示例：

```json
{
  "code": 40101,
  "message": "用户名或密码错误，还可尝试 4 次",
  "data": {
    "remaining_attempts": 4,
    "locked": false
  }
}
```

- 锁定说明：
  - 同一账户连续密码错误达到 5 次后，服务端会将账户状态改为 `locked`。
  - 账户锁定后，即使输入正确密码也无法登录，响应 `40301`，并返回 `data.locked=true`、`data.remaining_attempts=0`。
  - 成功登录会清零该账户的连续登录失败次数。

- 使用示例：

```bash
curl -X POST "http://127.0.0.1:8686/api/v1/auth/login" \
  -H "Content-Type: application/json" \
  -d '{
    "username":"admin",
    "password":"YOUR_PASSWORD",
    "challenge_id":"86d4f193-6fbf-4a74-a1f1-75f0c71d6a9b",
    "challenge_answer":{
      "angle":246.4,
      "drag_duration_ms":820,
      "track":[
        {"x":160,"y":160,"t":0},
        {"x":190,"y":148,"t":320},
        {"x":220,"y":130,"t":820}
      ]
    }
  }'
```

### 获取当前用户

- 请求方法和路径：`GET /api/v1/auth/me`

- 请求参数：无

- 响应格式：

```json
{
  "code": 0,
  "message": "success",
  "data": {
    "id": 1,
    "username": "admin",
    "role": "admin"
  }
}
```

- 错误码说明：
  - `40101`：未登录、访问令牌过期、已退出登录或用户被禁用
  - `50001`：获取当前用户失败

- 使用示例：

```bash
curl "http://127.0.0.1:8686/api/v1/auth/me" \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```

### 获取用户列表

- 请求方法和路径：`GET /api/v1/users`

- 请求参数：

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `page` | `int` | 否 | 页码，最小为 `1`，默认 `1` |
| `page_size` | `int` | 否 | 每页数量，范围 `1-100`，默认 `10` |

- 响应格式：

```json
{
  "code": 0,
  "message": "success",
  "data": {
    "page": 1,
    "pageSize": 10,
    "total": 1,
    "totalPages": 1,
    "items": [
      {
        "username": "admin",
        "role": "admin",
        "status": "enabled",
        "last_login_at": "2026-10-10T18:00:00+08:00"
      }
    ]
  }
}
```

- 错误码说明：
  - `40001`：`page` 或 `page_size` 参数不合法
  - `40101`：未登录、访问令牌过期、已退出登录或用户被禁用
  - `40301`：当前用户不是管理员
  - `50001`：获取用户列表失败

- 使用示例：

```bash
curl "http://127.0.0.1:8686/api/v1/users?page=1&page_size=10" \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```

### 新增用户

- 请求方法和路径：`POST /api/v1/users`

- 请求参数：

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `username` | `string` | 是 | 登录用户名，最长 64 个字符，必须唯一 |
| `password` | `string` | 是 | 登录密码，长度必须大于 8 且最长 72 个字符，需同时包含字母、数字、标点或符号；服务端使用 bcrypt 哈希后入库 |
| `role` | `string` | 否 | 角色，可选值：`admin`、`user`，默认 `user` |
| `status` | `string` | 否 | 状态，可选值：`enabled`、`disabled`、`locked`，默认 `enabled` |

- 响应格式：

```json
{
  "code": 0,
  "message": "success",
  "data": {
    "username": "operator",
    "role": "user",
    "status": "enabled",
    "last_login_at": null
  }
}
```

- 错误码说明：
  - `40001`：请求体格式错误、缺少 `username` 或 `password`、密码不满足复杂度要求、字段长度不合法、`username` 已存在，或 `role`/`status` 取值不合法
  - `40101`：未登录、访问令牌过期、已退出登录或用户被禁用
  - `40301`：当前用户不是管理员
  - `50001`：新增用户失败

- 使用示例：

```bash
curl -X POST "http://127.0.0.1:8686/api/v1/users" \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "username":"operator",
    "password":"YOUR_PASSWORD1!",
    "role":"user",
    "status":"enabled"
  }'
```

### 修改用户

- 请求方法和路径：`PUT /api/v1/users/{username}`

- 请求参数：

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `username` | `string` | 是 | 路径参数，待修改的登录用户名 |
| `password` | `string` | 否 | 新登录密码；传入时必须长度大于 8 且最长 72 个字符，并同时包含字母、数字、标点或符号 |
| `role` | `string` | 否 | 新角色，可选值：`admin`、`user` |
| `status` | `string` | 否 | 新状态，可选值：`enabled`、`disabled`、`locked`；设置为 `enabled` 时会清零连续登录失败次数 |

- 响应格式：

```json
{
  "code": 0,
  "message": "success",
  "data": {
    "username": "operator",
    "role": "admin",
    "status": "enabled",
    "last_login_at": null
  }
}
```

- 错误码说明：
  - `40001`：请求体格式错误、未提供任何可修改字段、密码不满足复杂度要求，或 `role`/`status` 取值不合法
  - `40101`：未登录、访问令牌过期、已退出登录或用户被禁用
  - `40301`：当前用户不是管理员
  - `40401`：用户不存在
  - `50001`：修改用户失败

- 使用示例：

```bash
curl -X PUT "http://127.0.0.1:8686/api/v1/users/operator" \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "password":"NEW_PASSWORD1!",
    "role":"admin",
    "status":"enabled"
  }'
```

### 删除用户

- 请求方法和路径：`DELETE /api/v1/users/{username}`

- 请求参数：

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `username` | `string` | 是 | 路径参数，待删除的登录用户名 |

- 响应格式：

```json
{
  "code": 0,
  "message": "success",
  "data": {
    "username": "operator",
    "deleted_count": 1
  }
}
```

- 错误码说明：
  - `40001`：`username` 路径参数不合法
  - `40101`：未登录、访问令牌过期、已退出登录或用户被禁用
  - `40301`：当前用户不是管理员
  - `40401`：用户不存在
  - `50001`：删除用户失败

- 使用示例：

```bash
curl -X DELETE "http://127.0.0.1:8686/api/v1/users/operator" \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```

### 退出登录

- 请求方法和路径：`POST /api/v1/auth/logout`

- 请求参数：无

- 响应格式：

```json
{
  "code": 0,
  "message": "success",
  "data": {
    "revoked": true
  }
}
```

- 错误码说明：
  - `40101`：未登录或登录状态已失效
  - `50001`：退出登录失败

- 使用示例：

```bash
curl -X POST "http://127.0.0.1:8686/api/v1/auth/logout" \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```

### 数据库表

鉴权体系需要先执行以下建表 SQL：

- `docs/SQL/create_manscan_users.sql`：用户表，存储用户名、bcrypt 密码哈希、角色、状态、连续登录失败次数和最后登录时间。
- `docs/SQL/create_manscan_user_sessions.sql`：用户会话表，存储 JWT `jti`、访问令牌 SHA-256 哈希、过期时间和吊销时间。
- `docs/SQL/create_manscan_auth_challenges.sql`：登录验证码挑战表，存储一次性轨道滑块验证码的答案、渲染种子、过期时间和使用时间。
- `docs/SQL/alter_manscan_users_add_login_lock.sql`：存量用户表升级脚本，为已有部署补充账户锁定状态和连续登录失败次数字段。
- `docs/SQL/alter_manscan_users_drop_display_name.sql`：存量用户表升级脚本，删除不再使用的展示名称字段。

访问令牌本身不会明文入库；退出登录会写入会话 `revoked_at`，后续请求即使 JWT 尚未过期也会被拒绝。

## 用户设置

### 获取当前用户主题设置

- 请求方法和路径：`GET /api/v1/settings/theme`

- 请求参数：无

- 响应格式：

```json
{
  "code": 0,
  "message": "success",
  "data": {
    "theme": "cartoon",
    "dark_mode_enabled": false
  }
}
```

- 错误码说明：
  - `40101`：未登录或登录状态已失效
  - `50001`：获取主题设置失败

- 使用示例：

```bash
curl "http://127.0.0.1:8686/api/v1/settings/theme" \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```

用户尚未保存过设置时，接口返回默认配置：`theme=cartoon`、`dark_mode_enabled=false`。

### 保存当前用户主题设置

- 请求方法和路径：`PUT /api/v1/settings/theme`

- 请求参数：

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `theme` | `string` | 是 | 主题标识，1-32 位小写字母、数字、下划线或连字符，且以字母或数字开头；保存时会转为小写 |
| `dark_mode_enabled` | `bool` | 是 | 是否开启深色模式 |

- 响应格式：

```json
{
  "code": 0,
  "message": "success",
  "data": {
    "theme": "cartoon",
    "dark_mode_enabled": false
  }
}
```

- 错误码说明：
  - `40001`：请求体格式错误或 `theme` 不合法
  - `40101`：未登录或登录状态已失效
  - `50001`：保存主题设置失败

- 使用示例：

```bash
curl -X PUT "http://127.0.0.1:8686/api/v1/settings/theme" \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "theme": "cartoon",
    "dark_mode_enabled": false
  }'
```

### 数据库表

- `docs/SQL/create_manscan_user_settings.sql`：用户设置表，按当前登录用户保存主题标识和深色模式开关。

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
  - `fingerprintTemplateCount` 表示 `info.tags` 中包含 `tech`、`detect` 或 `favicon` 任一标签的模板数量，同一个模板只统计一次。

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
  - `saved_requests` 仅统计最终状态为 `success` 的扫描任务，统计口径为 `SUM(pre_cluster_total_requests - real_requests)`，并且不会小于 `0`；历史任务没有 `pre_cluster_total_requests` 时回退使用 `total_requests`。
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
        "pre_cluster_total_requests": 120,
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
  - `total_requests` 是模板聚类后的进度总量；`pre_cluster_total_requests` 是相同执行范围在模板聚类前的预估总量，用于解释请求节省数量。
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
| `automatic_scan`      | `bool`     | 否  | 自动模版映射，默认关闭，对应 `-as` |
| `preflight_fingerprint` | `bool`   | 否  | 是否前置指纹探测，默认 `true`；设置为 `false` 仅跳过扫描前主动指纹模板阶段，保留存活探测、Wappalyzer 被动识别和自动模版映射 |
| `screenshot_capture` | `bool` | 否 | 是否在扫描前 HTTP 存活探测后独立采集页面截图，默认 `false` |
| `dast`                | `bool`     | 否  | 启用 DAST/fuzzable 模板，对应 `-dast` |
| `enable_code_templates` | `bool`   | 否  | 启用 Code 协议模板，对应 `-code` |
| `enable_file_templates` | `bool`   | 否  | 启用 File 协议模板，对应 `-file` |
| `interactsh_server`   | `string`   | 否  | 当前任务使用的 Interactsh 服务根地址，可填写主机名或 `http://`/`https://` 根地址，对应 `-interactsh-server` |
| `interactsh_token`    | `string`   | 否  | 当前任务使用的 Interactsh 鉴权 Token，最长 255 个字符，对应 `-interactsh-token`；会随扫描配置获取接口原样返回 |
| `no_interactsh`       | `bool`     | 否  | 禁用当前任务的 Interactsh/OOB 请求，对应 `-no-interactsh`，不能与上述两个字段同时配置 |
| `rate_limit`          | `int`      | 否  | 速率限制               |
| `template_threads`    | `int`      | 否  | 模板并发数              |
| `timeout`             | `int`      | 否  | 请求超时，单位秒           |
| `project`             | `bool`     | 否  | 启用 Project 请求缓存，对应 `--project` |
| `project_path`        | `string`   | 否  | Project 缓存目录，对应 `--project-path`，为空时使用默认 `data/project` |
| `headless`            | `bool`     | 否  | 是否启用 headless，对应 `--headless` |
| `proxy`               | `string[]` | 否  | 代理列表               |

至少需要提供 `targets` 或 `inline_targets_list` 之一，当前不再限制单次任务的目标数量上限。

`preflight_fingerprint` 省略或传入 `null` 时按开启处理，显式传入 `false` 时关闭。关闭后，不再启动扫描前 HTTP/非 HTTP 主动指纹子进程；前置阶段仍进行存活探测和 Wappalyzer 被动指纹识别（仍受 `offline_http`、`disable_http_probe` 原有开关约束），并保留指纹缓存供后续复用。非自动映射任务不再为主扫描追加 `tech,detect,favicon` 指纹标签排除，用户通过模板 ID、标签、严重级别或协议条件选中的指纹模板会在主扫描中正常执行；开启前置指纹时仍排除这些模板，避免重复执行。`automatic_scan=true` 时自动映射流程及其 detection templates 保持原有行为，不受该参数影响。任务暂停恢复、重新扫描和配置获取接口均保留此参数。

`screenshot_capture=true` 时，服务端在存活探测与原有前置主动指纹阶段完成后，仅对 HTTP 存活目标启动独立的 `screenshot` Headless 子阶段；通常随后继续原有主扫描。如果同时满足 `automatic_scan=false` 且没有其他模板选择条件，任务会在截图后跳过主扫描，并将 `plugin_count` 按 `screenshot` 计为 1；是否开启 `preflight_fingerprint` 只决定截图前是否执行主动指纹探测，不影响主扫描跳过判断。截图阶段不继承主扫描的自动映射、模板 ID、标签、严重级别和协议筛选。截图失败会记录 warning 并继续原有扫描，取消或暂停任务会终止截图子进程。该字段不能与 `offline_http=true` 或 `disable_http_probe=true` 同时使用。为兼容历史调用方，`include_ids` 中的 `screenshot` 会迁移为 `screenshot_capture=true` 并从持久化模板 ID 中移除。

已有数据库部署需先执行 `docs/SQL/alter_manscan_scan_tasks_preflight_fingerprint.sql`，历史任务默认开启；新建数据库使用更新后的建表脚本。

独立截图功能部署还需执行 `docs/SQL/alter_manscan_scan_tasks_add_preflight_screenshot.sql`；历史任务默认不截图。

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
  - `40001`：目标为空、请求体非法、Interactsh 配置不合法，或截图采集与离线 HTTP/禁用 HTTP 探测冲突
  - `50001`：任务入库失败或运行时目录创建失败

模板能力开关默认均为关闭。`allow_local_file_access`（对应 `-lfa`）只控制本地文件访问权限，不等同于 `enable_file_templates`；需要执行 File 模板时必须显式开启后者。Headless DAST 模板需要同时开启 `headless` 和 `dast`。启用 `project` 后，扫描前存活探测、Wappalyzer 被动指纹、扫描前主动指纹模板和主漏洞扫描都会使用同一 Project 缓存目录；未设置 `project_path` 时默认共享 `data/project`，如需任务隔离可为不同任务传入不同目录。

- 使用示例：

```bash
curl -X POST "http://127.0.0.1:8686/api/v1/scans" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "demo-scan",
    "targets": ["https://example.com"],
    "preflight_fingerprint": false,
    "tags": ["cve"],
    "severities": ["high"],
    "interactsh_server": "https://oast.example.internal",
    "interactsh_token": "YOUR_TASK_TOKEN"
  }'
```

## 10. 重新扫描任务

- 请求方法和路径：`POST /api/v1/scans/:id/rescan`

- 请求参数：

| 参数 | 类型 | 必填 | 说明 |
| --- | --- | --- | --- |
| `id` | `int64` | 是 | 原扫描任务 ID，路径参数，对应 `manscan_scan_tasks.id` |

- 响应格式：

```json
{
  "code": 0,
  "message": "success",
  "data": {
    "task": {
      "id": 2,
      "task_no": "d4l8h4crvimc0n1newid",
      "name": "demo-scan",
      "description": "",
      "status": "pending",
      "created_by": "anonymous"
    },
    "log_api": "/api/v1/scans/2/logs",
    "stream": "/api/v1/scans/2/stream",
    "task_api": "/api/v1/scans/2"
  }
}
```

- 说明：
  - 该接口会读取原任务在 `manscan_scan_tasks` 中保存的扫描配置，并创建一条新的扫描任务记录。
  - 自定义 Interactsh 服务地址、Token 或禁用开关会随原任务配置继承；Token 不会通过接口响应返回。
  - 新任务会生成新的 `id` 和 `task_no`，初始状态为 `pending`，不会继承原任务的 `started_at`、`finished_at`、运行日志、进度快照或结果统计。
  - 新任务的名称、描述、创建人、目标、模板筛选、协议筛选、并发、限速、代理、headless 等扫描配置与原任务保持一致。
  - 该接口不同于 `/api/v1/scans/:id/resume`；`resume` 只恢复暂停任务并继续使用原任务 ID，`rescan` 始终创建新任务并重新发起完整扫描。

- 错误码说明：
  - `40001`：任务 ID 非法，或原任务中保存的目标配置为空
  - `40401`：原任务不存在
  - `50001`：新任务入库失败、运行时目录创建失败或重新扫描任务失败

- 使用示例：

```bash
curl -X POST "http://127.0.0.1:8686/api/v1/scans/1/rescan"
```

## 11. 获取扫描任务配置

- 请求方法和路径：`GET /api/v1/scans/:id/config`

- 请求参数：

| 参数 | 类型 | 必填 | 说明 |
| --- | --- | --- | --- |
| `id` | `int64` | 是 | 原扫描任务 ID，路径参数，对应 `manscan_scan_tasks.id` |

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
      "status": "success",
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
    "config": {
      "name": "demo-scan",
      "description": "",
      "created_by": "anonymous",
      "targets": ["https://example.com"],
      "inline_targets_list": "https://example.com\n",
      "exclude_targets": [],
      "tags": ["cve"],
      "include_ids": ["CVE-2026-0001"],
      "severities": ["high"],
      "protocols": ["http"],
      "automatic_scan": false,
      "preflight_fingerprint": true,
      "screenshot_capture": true,
      "dast": false,
      "enable_code_templates": false,
      "enable_file_templates": false,
      "interactsh_server": "https://oast.example.internal",
      "interactsh_token": "YOUR_TASK_TOKEN",
      "no_interactsh": false,
      "rate_limit": 150,
      "template_threads": 25,
      "timeout": 10,
      "headless": false,
      "proxy": []
    }
  }
}
```

- 说明：
  - 该接口会读取原任务在 `manscan_scan_tasks` 中保存的目标、模板筛选、协议筛选、并发、限速、代理、截图采集、headless、DAST、Code/File 模板开关等扫描配置，用于前端回填“重新创建扫描任务”表单。
  - `config` 字段使用创建扫描任务接口的请求结构，前端可在用户确认或调整后提交给 `POST /api/v1/scans`。
  - 该接口只读取配置，不创建新任务，不恢复任务，也不会继承原任务的运行日志、进度快照或结果统计。

- 错误码说明：
  - `40001`：任务 ID 非法，或原任务中保存的目标配置为空
  - `40401`：原任务不存在
  - `50001`：获取任务扫描配置失败

- 使用示例：

```bash
curl "http://127.0.0.1:8686/api/v1/scans/1/config"
```

## 12. 取消扫描任务

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
  - Unix 系统取消时会终止扫描进程组，包括 `go run` 启动器及其扫描子进程，避免启动器退出后实际扫描仍继续执行。
  - 运行态丢失后，详情、日志、列表和订阅返回的进度终态以数据库状态为准；旧 `progress.json` 中的 `running` 不会覆盖已落库的 `cancelled` 等终态，请求计数仍予以保留。

- 错误码说明：
  - `40001`：任务 ID 非法，或任务已结束且不支持再次取消
  - `40401`：任务不存在
  - `50001`：取消请求落库失败

- 使用示例：

```bash
curl -X POST "http://127.0.0.1:8686/api/v1/scans/1/cancel"
```

## 13. 暂停扫描任务

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

## 14. 恢复扫描任务

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

## 15. 获取扫描任务详情

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
      "target_count": 1,
      "alive_hosts": 1,
      "unresponsive_hosts": 0
    },
    "progress": {
      "hosts": 1,
      "alive_hosts": 1,
      "unresponsive_hosts": 0,
      "templates": 50,
      "total_requests": 100,
      "pre_cluster_total_requests": 120,
      "requests": 10,
      "matched": 1,
      "errors": 0,
      "percent": 10,
      "progress_status": "running",
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
  - `progress.templates` 和 `task.plugin_count` 表示本次扫描实际可执行的唯一漏洞模版数量；对于扫描前预探测确认 `http_alive=false` 的目标，HTTP、Headless 以及包含 HTTP/Headless 请求的模版不会计入。多目标扫描按“至少有一个目标可执行”计数，不按目标重复累加。
  - `progress.requests` 表示扫描进程实际发出的请求数，会排除项目缓存、模板聚类等没有真实出网的请求。
  - `progress.total_requests` 表示本次任务按模板和目标、过滤结果以及模板聚类后的逻辑请求总数，同时包含扫描前 Wappalyzer 直连探测以及主动指纹模板阶段产生的逻辑请求；前置探测中的每次实际请求尝试都会计入最终总量，但在 scanner 给出确定可执行总量前不会单独提前返回。
  - `progress.pre_cluster_total_requests` 表示同一执行范围在模板聚类前的预估逻辑请求总数，仅用于请求节省量统计，不参与 `progress.percent` 计算。
  - `progress.percent` 表示逻辑扫描完成度，不直接用 `requests / total_requests` 计算，因此缓存或聚类节省大量请求时，进度仍会按扫描执行进度平滑推进。
  - `task.alive_hosts` 和 `task.unresponsive_hosts` 表示扫描前资产存活探测结果；探测完成后会立即通过任务详情、日志接口和 SSE 推送，已探测到的 `0` 也会明确返回。
  - `progress.alive_hosts` 和 `progress.unresponsive_hosts` 是同一组存活探测统计的进度快照字段；探测尚未完成时字段不返回。
  - 自动模版映射的指纹识别阶段中，`progress_status` 为 `calculating`，此时 `total_requests` 和 `percent` 不返回，`last_message` 仍为“扫描进度更新”；全部目标完成指纹识别并得到映射模版后，`progress_status` 变为 `running`，再开始返回稳定的预估总请求数和完成度。单个目标完成映射后，其漏洞模版可以先行执行。
  - 非自动模版映射任务的扫描前存活探测和主动指纹识别阶段会先累计实际请求数，但不提前公开阶段性 `total_requests`；主漏洞 scanner 发布选中漏洞模版的确定总量后，再一次性返回“存活探测 + 主动指纹识别 + 选中漏洞模版”的总请求数。
  - `preflight_fingerprint=false` 时不产生前置主动指纹阶段的请求数；存活探测、Wappalyzer 被动识别和主扫描请求统计仍按实际执行阶段累计，自动模版映射统计逻辑不变。
  - `progress.matched` 表示服务端保留的去重后结果数量。

- 错误码说明：
  - `40001`：任务 ID 非法
  - `40401`：任务不存在
  - `50001`：查询任务失败

- 使用示例：

```bash
curl "http://127.0.0.1:8686/api/v1/scans/1"
```

## 16. 获取扫描任务日志

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
      "target_count": 1,
      "alive_hosts": 1,
      "unresponsive_hosts": 0
    },
    "progress": {
      "alive_hosts": 1,
      "unresponsive_hosts": 0,
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
  - `result` 类型事件可能包含 `tags`、`result_key`、`template_id`、`severity` 字段：`tags` 用于记录该命中结果的模板标签；`result_key` 为后端生成的不透明结构化去重键，前端只应作为稳定标识使用，不应解析其内部格式；`template_id` 和 `severity` 分别表示命中模板 ID 与严重级别。
  - 目标命中 `exclude_targets` 禁扫规则时，会在任何前置探测前产生 `level=info`、`type=target_excluded` 的事件，`message` 包含被跳过的目标和首次命中的规则。被排除目标不参与扫描前 HTTP/Wappalyzer 探测、截图采集或主扫描；全部目标被排除时跳过执行并将实际插件数量设为 `0`。
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

## 17. 订阅扫描任务日志流

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
  - `asset_domain_probe_finished` 类型事件会额外携带最新的 `task` 和 `progress` 快照，前端可在扫描前资产存活探测结束后立即刷新存活主机数和无响应主机数
  - `result` 类型事件中的 `event.tags` 为该命中结果的模板标签，包含 `tech`、`detect` 或 `favicon` 任一标签时计入 `tech_count`
  - `result` 类型事件中的 `event.result_key` 为后端生成的不透明结构化去重键，历史统计恢复、实时日志去重和续传补发均以该字段为准；`event.template_id` 与 `event.severity` 用于结构化统计分类。
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
data: {"task_id":1,"seq":2,"level":"info","type":"progress","message":"扫描进度更新","task":{"id":1,"status":"running","critical_count":0,"high_count":1,"medium_count":2,"low_count":0,"info_count":3,"tech_count":4,"plugin_count":50,"target_count":1,"alive_hosts":1,"unresponsive_hosts":0},"progress":{"hosts":1,"alive_hosts":1,"unresponsive_hosts":0,"templates":50,"total_requests":100,"pre_cluster_total_requests":120,"requests":10,"matched":1,"errors":0,"percent":10,"progress_status":"running","last_updated_at":"2026-06-09T21:01:00+08:00","last_message":"扫描进度更新","last_event_seq":2,"finished":false,"finished_status":"running"},"nextOffset":2}
```

`asset_domain_probe_finished` 事件示例：

```text
event: event
data: {"task_id":1,"seq":3,"level":"info","type":"asset_domain_probe_finished","message":"扫描前域名资产存活 & 指纹探测完成，本次扫描存活 1 个","task":{"id":1,"status":"running","critical_count":0,"high_count":0,"medium_count":0,"low_count":0,"info_count":0,"tech_count":0,"plugin_count":0,"target_count":1,"alive_hosts":1,"unresponsive_hosts":0},"progress":{"hosts":0,"alive_hosts":1,"unresponsive_hosts":0,"requests":1,"matched":0,"errors":0,"progress_status":"calculating","last_updated_at":"2026-06-09T21:00:02+08:00","last_message":"扫描前域名资产存活 & 指纹探测完成，本次扫描存活 1 个，不存活 0 个","last_event_seq":3,"finished":false,"finished_status":"running"},"nextOffset":3}
```

- `result` 事件示例：

```text
event: event
data: {"task_id":1,"seq":3,"level":"match","type":"result","message":"[HTTP 安全响应头缺失][strict-transport-security] 命中 [http://example.com/]","task":{"id":1,"status":"running","critical_count":0,"high_count":1,"medium_count":2,"low_count":0,"info_count":4,"tech_count":4,"plugin_count":50,"target_count":1},"event":{"seq":3,"time":"2026-06-09T21:01:02+08:00","level":"match","type":"result","message":"[HTTP 安全响应头缺失][strict-transport-security] 命中 [http://example.com/]","tags":["cve"],"result_key":"vulnerability\\u001fhttp-missing-security-headers\\u001fhttps://example.com\\u001fhttps://example.com\\u001fstrict-transport-security\\u001f","template_id":"http-missing-security-headers","severity":"high"},"nextOffset":3}
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

## 18. 获取漏洞列表

- 请求方法和路径：`GET /api/v1/vulnerabilities`

- 请求参数：

| 参数 | 类型 | 必填 | 说明 |
| --- | --- | --- | --- |
| `page` | `int` | 否 | 页码，最小为 `1`，默认 `1` |
| `page_size` | `int` | 否 | 每页数量，范围 `1-100`，默认 `10` |
| `keyword` | `string` | 否 | 按漏洞名称或模板 ID 统一模糊搜索 |
| `asset_host` | `string` / `string[]` | 否 | 按资产 Host 模糊过滤，支持逗号分隔和多参数 |
| `status` | `string` / `string[]` | 否 | 按漏洞状态精确过滤，支持逗号分隔和多参数；状态值见下方漏洞状态说明 |
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
        "asset_path": "https://app.example.com/login",
        "asset_endpoint": "app.example.com:443",
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
  - 漏洞状态包括：`unreviewed` 未审核、`confirmed` 已确认、`ticketed` 已发单、`fixed` 已修复、`false_positive` 误报、`ignored` 忽略。
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
  - 严重级别建议按 `critical`、`high`、`medium`、`low`、`info`、`unknown` 做固定选项；状态建议按 `unreviewed`、`confirmed`、`ticketed`、`fixed`、`false_positive`、`ignored` 做固定选项。

## 18.1 导出漏洞筛选结果

- 请求方法和路径：`GET /api/v1/vulnerabilities/export`
- 请求参数：与列表接口使用相同的筛选语义，均为可选。多值参数支持逗号分隔和重复传入；`page`、`page_size` 可随列表请求传入，但导出始终包含全部筛选结果，不受分页限制。

| 参数 | 类型 | 必填 | 说明 |
| --- | --- | --- | --- |
| `keyword` | `string` | 否 | 漏洞名称或模板 ID 模糊搜索 |
| `asset_host` | `string` / `string[]` | 否 | 资产 Host 模糊匹配 |
| `status` | `string` / `string[]` | 否 | 漏洞状态精确匹配 |
| `tag` / `tags` | `string` / `string[]` | 否 | 漏洞标签匹配 |
| `severity` / `level` | `string` / `string[]` | 否 | 严重级别精确匹配 |
| `template_id` | `string` / `string[]` | 否 | 模板 ID 模糊匹配 |
| `vulnerability_name` | `string` / `string[]` | 否 | 漏洞名称模糊匹配 |
| `latest_scan_task_name` | `string` / `string[]` | 否 | 最近扫描任务名称模糊匹配 |
| `protocol` | `string` / `string[]` | 否 | 协议类型精确匹配 |
| `page` / `page_size` | `int` | 否 | 接收但不影响导出范围 |

- 响应格式：成功时返回 `application/vnd.openxmlformats-officedocument.spreadsheetml.sheet` 附件，文件名为 `vulnerabilities-YYYYMMDD-HHMMSS.xlsx`，不使用 JSON 响应封装。`vulnerabilities` 工作表每条漏洞一行，列为 `name`、`severity`、`template_id`、`asset_path`、`asset_endpoint`、`asset_host`、`status`、`tags`、`latest_scan_task_name`、`protocol`、`last_found_at`、`latest_scan_task_id`、`first_found_at`、`fixed_at`、`asset_port`、`description`、`impact`、`cvss_score`、`vendor`、`product`、`remediation`、`reference_links`、`extracted-results`、`payload`、`detail`、`vuln_fingerprint`。`name` 即漏洞名称，导出不再重复提供 `vulnerability_name`；仅排除漏洞主键 `id`。数组和对象以 JSON 文本保存，时间为 RFC3339 格式，空值留空。顺序与列表相同。
- 工作表使用固定表头、交替底色和自动换行；主表行高 48 磅，长字段表行高 84 磅，列宽按内容类型设置。
- 超过单元格长度限制的内容在主表显示 `[see large_fields]`，完整内容分段写入 `large_fields` 工作表；该表的 `row` 指向主表行号，`field` 为字段名，按 `part` 升序拼接 `content` 即为原文。空结果仍返回带表头的文件。
- 文件包含原始漏洞详情，可能含请求、响应、Payload 中的敏感数据；此接口使用与漏洞列表相同的登录认证。前端应复用当前筛选参数请求该路径，并按二进制文件下载。
- 错误码说明：`50001` 表示创建文件、查询或生成 XLSX 失败；失败响应仍使用 `{ "code", "message", "data" }` JSON 格式。
- 使用示例：

```bash
curl -o vulnerabilities.xlsx "http://127.0.0.1:8686/api/v1/vulnerabilities/export?status=unreviewed&severity=high&tag=cve"
```

## 19. 更新漏洞状态

- 请求方法和路径：`PATCH /api/v1/vulnerabilities/:id/status`

- 请求参数：

| 参数 | 类型 | 必填 | 说明 |
| --- | --- | --- | --- |
| `id` | `int64` | 是 | 漏洞 ID，路径参数，必须为大于 `0` 的整数 |
| `status` | `string` | 是 | 请求体字段，漏洞状态，只允许 `unreviewed`、`confirmed`、`ticketed`、`fixed`、`false_positive`、`ignored` |

- 请求体示例：

```json
{
  "status": "fixed"
}
```

- 响应格式：

```json
{
  "code": 0,
  "message": "success",
  "data": {
    "id": 1,
    "status": "fixed",
    "fixed_at": "2026-08-28T18:30:00+08:00"
  }
}
```

- 说明：
  - 该接口只更新单个漏洞；如需批量更新，请使用 `PATCH /api/v1/vulnerabilities/status`。
  - 当 `status=fixed` 时，后端会将 `fixed_at` 更新为当前服务器时间。
  - 当 `status` 为其他任一允许状态时，后端会清空 `fixed_at`。
  - 状态值会去除首尾空格并转为小写后保存。
  - 漏洞状态含义：`unreviewed` 未审核、`confirmed` 已确认、`ticketed` 已发单、`fixed` 已修复、`false_positive` 误报、`ignored` 忽略。

- 错误码说明：
  - `40001`：漏洞 ID 非法、请求体非法，或 `status` 不在允许范围内
  - `40401`：漏洞不存在
  - `50001`：更新漏洞状态失败

- 使用示例：

```bash
curl -X PATCH "http://127.0.0.1:8686/api/v1/vulnerabilities/1/status" \
  -H "Content-Type: application/json" \
  -d '{"status":"fixed"}'
```

## 20. 批量更新漏洞状态

- 请求方法和路径：`PATCH /api/v1/vulnerabilities/status`

- 请求参数：

请求体为 JSON：

| 字段 | 类型 | 必填 | 说明 |
| --- | --- | --- | --- |
| `ids` | `int64[]` | 是 | 漏洞 ID 列表，必须是 `1-1000` 个大于 `0` 的整数；重复 ID 会自动去重 |
| `status` | `string` | 是 | 漏洞状态，只允许 `unreviewed`、`confirmed`、`ticketed`、`fixed`、`false_positive`、`ignored` |

- 请求体示例：

```json
{
  "ids": [1, 2, 3],
  "status": "confirmed"
}
```

- 响应格式：

```json
{
  "code": 0,
  "message": "success",
  "data": {
    "ids": [1, 2, 3],
    "status": "confirmed",
    "fixed_at": null,
    "updated_count": 3
  }
}
```

- 说明：
  - 批量接口会先校验 `ids` 中的漏洞是否全部存在；只要有任一 ID 不存在，整批返回 `40401`，不会更新任何漏洞。
  - 当 `status=fixed` 时，后端会将本批漏洞的 `fixed_at` 更新为同一个当前服务器时间。
  - 当 `status` 为其他任一允许状态时，后端会清空本批漏洞的 `fixed_at`。
  - `updated_count` 表示本次确认并处理的漏洞数量，不受数据库“值未变化时 affected rows 为 0”的口径影响。

- 错误码说明：
  - `40001`：`ids` 为空、超过 `1000` 个、包含非法 ID、请求体非法，或 `status` 不在允许范围内
  - `40401`：`ids` 中至少有一个漏洞不存在
  - `50001`：批量更新漏洞状态失败

- 使用示例：

```bash
curl -X PATCH "http://127.0.0.1:8686/api/v1/vulnerabilities/status" \
  -H "Content-Type: application/json" \
  -d '{"ids":[1,2,3],"status":"confirmed"}'
```

## 21. 删除漏洞

- 请求方法和路径：`DELETE /api/v1/vulnerabilities`

- 请求参数：

请求体为 JSON：

| 字段 | 类型 | 必填 | 说明 |
| --- | --- | --- | --- |
| `id` | `int64` | 否 | 单个漏洞 ID，必须为大于 `0` 的整数；传入 `id` 时可不传 `ids` |
| `ids` | `int64[]` | 否 | 多个漏洞 ID，必须为大于 `0` 的整数；支持 `1-1000` 个 ID，重复 ID 会自动去重 |

- 请求体示例：

单个删除：

```json
{
  "id": 1
}
```

批量删除：

```json
{
  "ids": [1, 2, 3]
}
```

- 响应格式：

```json
{
  "code": 0,
  "message": "success",
  "data": {
    "ids": [1, 2, 3],
    "deleted_count": 3
  }
}
```

- 说明：
  - 该接口按漏洞 ID 删除 `manscan_vulnerabilities` 中的漏洞记录。
  - `id` 与 `ids` 可二选一，也可以同时传入；后端会合并后按首次出现顺序去重。
  - 删除前会先校验合并后的漏洞 ID 是否全部存在；只要有任一 ID 不存在，整批返回 `40401`，不会删除任何漏洞。
  - `deleted_count` 表示本次确认并删除的漏洞数量。

- 错误码说明：
  - `40001`：请求体非法，或 `id` / `ids` 为空、超过 `1000` 个、包含非法 ID
  - `40401`：`id` / `ids` 中至少有一个漏洞不存在
  - `50001`：删除漏洞失败

- 使用示例：

```bash
curl -X DELETE "http://127.0.0.1:8686/api/v1/vulnerabilities" \
  -H "Content-Type: application/json" \
  -d '{"ids":[1,2,3]}'
```

## 22. 获取漏洞详情

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
    "asset_path": "https://app.example.com/login",
    "asset_endpoint": "app.example.com:443",
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
    "extracted-results": ["10.0.0.12", "192.168.1.20"],
    "payload": {
      "username": "admin",
      "password": "admin123"
    },
    "detail": {
      "request": {
        "1": "GET /login HTTP/1.1\r\nHost: app.example.com\r\n\r\n",
        "2": "POST /login HTTP/1.1\r\nHost: app.example.com\r\nContent-Length: 7\r\n\r\npayload"
      },
      "response": {
        "1": "HTTP/1.1 200 OK\r\n\r\nfirst",
        "2": "HTTP/1.1 500 Internal Server Error\r\n\r\nsecond"
      },
      "curl-command": "curl -k https://app.example.com/login"
    },
    "vuln_fingerprint": "sha256-fingerprint"
  }
}
```

- 说明：
  - 详情接口按漏洞 ID 查询 `manscan_vulnerabilities` 中的单条记录，并返回漏洞表当前保存的完整业务字段。
  - `first_found_at` 表示首次发现时间，`last_found_at` 表示最近发现时间，列表页中的发现时间对应 `last_found_at`。
  - `tags`、`reference_links`、`extracted-results` 返回数组；`extracted-results` 保存 Nuclei 从响应中提取的结果，未提取到内容时为空数组。`payload` 和 `detail` 会在内容为合法 JSON 时返回解析后的对象或数组，否则返回原始字符串。
  - `payload` 保存 Nuclei 命中结果顶层 `meta` 的原始值；没有 `meta` 时返回 `null`。该字段可能包含命中的账号、密码、Token、注入语句或其他字典值，调用方必须限制访问权限并避免写入日志。
  - 当漏洞来自多步 HTTP POC 时，`detail.request` 和 `detail.response` 返回 JSON 对象，对象内部按 `1`、`2` 这样的编号键保存每一步请求/响应，便于前端按步骤展示完整请求链；历史记录中这两个字段若仍是嵌套 JSON 字符串，详情接口会在读取时兼容还原为对象。
  - `protocol` 返回值会按模板顶层执行块白名单归一化，例如 `requests` 会返回为 `http`。

- 错误码说明：
  - `40001`：漏洞 ID 非法，例如不是整数或小于等于 `0`
  - `40401`：漏洞不存在
  - `50001`：查询漏洞详情失败

- 使用示例：

```bash
curl "http://127.0.0.1:8686/api/v1/vulnerabilities/1"
```

已有数据库部署需先执行 `docs/SQL/alter_manscan_vulnerabilities_add_payload.sql`；新建数据库使用更新后的 `docs/SQL/create_manscan_vulnerabilities.sql`。

## 23. 批量删除扫描任务

- 请求方法和路径：`DELETE /api/v1/scans`

- 请求参数：

请求体为 JSON，支持以下字段：

| 字段 | 类型 | 必填 | 说明 |
| --- | --- | --- | --- |
| `id` | `int64` | 否 | 单个扫描任务 ID |
| `ids` | `int64[]` | 否 | 批量扫描任务 ID 列表，支持一次删除多个任务 |

单个删除：

```json
{
  "id": 1
}
```

批量删除：

```json
{
  "ids": [1, 2, 3]
}
```

- 响应格式：

```json
{
  "code": 0,
  "message": "success",
  "data": {
    "ids": [1, 2, 3],
    "deleted_count": 3
  }
}
```

- 说明：
  - 该接口会同时删除 `manscan_scan_tasks` 中的任务记录和 `manscan_task_results` 中对应的结果记录。
  - `id` 与 `ids` 可二选一，也可以同时传入；后端会合并后按首次出现顺序去重。
  - 删除前会先校验合并后的任务 ID 是否全部存在；只要有任一 ID 不存在，整批返回 `40401`，不会删除任何任务。
  - 仅支持删除 `success`、`failed`、`cancelled`、`paused` 状态的扫描任务，`pending` 和 `running` 任务需要先取消后再删除。
  - 删除时会清理对应的运行期目录、原始日志压缩包、请求/响应压缩包和内存态数据，不再保留日志、进度和恢复文件。

- 错误码说明：
  - `40001`：请求体非法，或 `id` / `ids` 为空、超过 `1000` 个、包含非法 ID，或任务状态不支持删除
  - `40401`：`id` / `ids` 中至少有一个扫描任务不存在
  - `50001`：删除扫描任务失败

- 使用示例：

```bash
curl -X DELETE "http://127.0.0.1:8686/api/v1/scans" \
  -H "Content-Type: application/json" \
  -d '{"ids":[1,2,3]}'
```

## 24. 下载扫描任务请求/响应压缩包

- 请求方法和路径：`GET /api/v1/scans/:id/responses/archive`

- 请求参数：

| 参数 | 类型 | 必填 | 说明 |
| --- | --- | --- | --- |
| `id` | `int64` | 是 | 扫描任务 ID，路径参数 |

- 响应格式：
  - 成功时直接返回 zip 文件流，不使用统一 JSON 包裹。
  - 响应头包含 `Content-Type: application/zip`。
  - 响应头包含 `Content-Disposition: attachment; filename="<任务ID>.zip"`。

- 说明：
  - 该接口会先校验 `manscan_scan_tasks` 中是否存在对应任务，再下载 `data/responses/<任务ID>.zip`。
  - 只有任务已生成请求/响应压缩包时才能下载；未开启“保存请求/响应”、任务尚未完成压缩、或压缩包已被清理时会返回 `40401`。
  - 下载内容为任务结束后由服务端归档生成的 zip，zip 内部保留 `<任务ID>/http/`、`<任务ID>/dns/`、`<任务ID>/tcp/`、`<任务ID>/ssl/`、`<任务ID>/javascript/` 等协议目录结构。

- 错误码说明：
  - `40001`：任务 ID 非法
  - `40401`：任务不存在，或请求/响应压缩包不存在
  - `50001`：读取或下载请求/响应压缩包失败

- 使用示例：

```bash
curl -OJ "http://127.0.0.1:8686/api/v1/scans/1/responses/archive"
```

## 25. 下载扫描任务原始日志压缩包

- 请求方法和路径：`GET /api/v1/scans/:id/raw-logs/archive`

- 请求参数：

| 参数 | 类型 | 必填 | 说明 |
| --- | --- | --- | --- |
| `id` | `int64` | 是 | 扫描任务 ID，路径参数 |

- 响应格式：
  - 成功时直接返回 zip 文件流，不使用统一 JSON 包裹。
  - 响应头包含 `Content-Type: application/zip`。
  - 响应头包含 `Content-Disposition: attachment; filename="<任务ID>.zip"`。

- 说明：
  - 该接口会先校验 `manscan_scan_tasks` 中是否存在对应任务，再将 `data/runtime/<任务ID>` 实时压缩为 `data/runtime/<任务ID>.zip` 并返回。
  - zip 内部保留 `<任务ID>/` 根目录，包含该任务运行期间生成的 `events.jsonl`、`match.log`、`error.log`、`progress.json`、`resume.cfg` 等原始运行文件；实际内容以对应 runtime 目录当前存在的文件为准。
  - 原始 runtime 目录不会因下载而删除；当任务不存在或 `data/runtime/<任务ID>` 不存在时返回 `40401`。

- 错误码说明：
  - `40001`：任务 ID 非法
  - `40401`：任务不存在，或扫描原始日志目录不存在
  - `50001`：压缩或下载扫描原始日志失败

- 使用示例：

```bash
curl -OJ "http://127.0.0.1:8686/api/v1/scans/225/raw-logs/archive"
```

## 26. 获取资产配置中心列表

- 请求方法和路径：`GET /api/v1/asset-config-centers`

- 请求参数：

| 参数 | 类型 | 必填 | 说明 |
| --- | --- | --- | --- |
| `page` | `int` | 否 | 页码，最小为 `1`，默认 `1` |
| `page_size` | `int` | 否 | 每页条数，最小为 `1`，最大为 `100`，默认 `10` |
| `item_name` | `string` / `string[]` | 否 | 按项名称模糊过滤，支持逗号分隔和多参数 |
| `big_category` | `string` / `string[]` | 否 | 按大分类模糊过滤，支持逗号分隔和多参数 |
| `small_category` | `string` / `string[]` | 否 | 按小分类模糊过滤，支持逗号分隔和多参数 |
| `status` | `string` / `string[]` | 否 | 按状态过滤，支持 `enabled` 和 `disabled`，支持逗号分隔和多参数 |

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
        "item_name": "登录页配置",
        "big_category": "前端",
        "small_category": "页面",
        "status": "enabled",
        "description": "登录页相关配置"
      }
    ]
  }
}
```

- 错误码说明：
  - `40001`：请求参数格式不正确，例如 `page` 或 `page_size` 非整数，或 `page_size` 超出 `1-100`
  - `50001`：查询资产配置中心列表失败

- 使用示例：

```bash
curl "http://127.0.0.1:8686/api/v1/asset-config-centers?page=1&page_size=10&item_name=登录&status=enabled"
```

## 27. 获取资产配置中心小分类列表

- 请求方法和路径：`GET /api/v1/asset-config-centers/options/small-categories`

- 请求参数：

| 参数 | 类型 | 必填 | 说明 |
| --- | --- | --- | --- |
| `big_category` | `string` / `string[]` | 是 | 大分类，支持逗号分隔和多参数，返回这些大分类下去重后的小分类列表 |

- 响应格式：

```json
{
  "code": 0,
  "message": "success",
  "data": {
    "items": ["api", "web"]
  }
}
```

- 错误码说明：
  - `40001`：`big_category` 为空或请求参数格式不正确
  - `50001`：查询资产配置中心小分类列表失败

- 使用示例：

```bash
curl "http://127.0.0.1:8686/api/v1/asset-config-centers/options/small-categories?big_category=app"
```

## 28. 新增资产配置项

- 请求方法和路径：`POST /api/v1/asset-config-centers`

- 请求参数：

| 参数 | 类型 | 必填 | 说明 |
| --- | --- | --- | --- |
| `item_name` | `string` | 是 | 项名称，表内全局唯一 |
| `big_category` | `string` | 是 | 大分类 |
| `small_category` | `string` | 是 | 小分类 |
| `status` | `string` | 是 | 状态，可选值：`enabled`、`disabled` |
| `description` | `string` | 否 | 说明 |

- 响应格式：

```json
{
  "code": 0,
  "message": "success",
  "data": {
    "id": 1,
    "item_name": "登录页配置",
    "big_category": "前端",
    "small_category": "页面",
    "status": "enabled",
    "description": "登录页相关配置"
  }
}
```

- 错误码说明：
  - `40001`：请求体非法，必填字段为空，`status` 不合法，或 `item_name` 已存在
  - `40301`：当前用户不是管理员
  - `50001`：新增资产配置项失败

- 使用示例：

```bash
curl -X POST "http://127.0.0.1:8686/api/v1/asset-config-centers" \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"item_name":"登录页配置","big_category":"前端","small_category":"页面","status":"enabled","description":"登录页相关配置"}'
```

## 29. 编辑资产配置项

- 请求方法和路径：`PUT /api/v1/asset-config-centers/:id`

- 请求参数：

| 参数 | 类型 | 必填 | 说明 |
| --- | --- | --- | --- |
| `id` | `int64` | 是 | 资产配置项 ID，路径参数 |
| `item_name` | `string` | 是 | 项名称，表内全局唯一 |
| `big_category` | `string` | 是 | 大分类 |
| `small_category` | `string` | 是 | 小分类 |
| `status` | `string` | 是 | 状态，可选值：`enabled`、`disabled` |
| `description` | `string` | 否 | 说明 |

- 响应格式：

```json
{
  "code": 0,
  "message": "success",
  "data": {
    "id": 1,
    "item_name": "登录页配置",
    "big_category": "前端",
    "small_category": "页面",
    "status": "disabled",
    "description": "暂不启用"
  }
}
```

- 错误码说明：
  - `40001`：路径 ID 非法，请求体非法，必填字段为空，`status` 不合法，或 `item_name` 已存在
  - `40301`：当前用户不是管理员
  - `40401`：资产配置项不存在
  - `50001`：编辑资产配置项失败

- 使用示例：

```bash
curl -X PUT "http://127.0.0.1:8686/api/v1/asset-config-centers/1" \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"item_name":"登录页配置","big_category":"前端","small_category":"页面","status":"disabled","description":"暂不启用"}'
```

## 30. 删除资产配置项

- 请求方法和路径：`DELETE /api/v1/asset-config-centers/:id`

- 请求参数：

| 参数 | 类型 | 必填 | 说明 |
| --- | --- | --- | --- |
| `id` | `int64` | 是 | 资产配置项 ID，路径参数 |

- 响应格式：

```json
{
  "code": 0,
  "message": "success",
  "data": {
    "id": 1,
    "deleted_count": 1
  }
}
```

- 错误码说明：
  - `40001`：路径 ID 非法
  - `40301`：当前用户不是管理员
  - `40401`：资产配置项不存在
  - `50001`：删除资产配置项失败

- 使用示例：

```bash
curl -X DELETE "http://127.0.0.1:8686/api/v1/asset-config-centers/1" \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```

## 31. 获取域名资产清单

- 请求方法和路径：`GET /api/v1/domain-assets`

- 请求参数：

| 参数 | 类型 | 必填 | 说明 |
| --- | --- | --- | --- |
| `page` | `int` | 否 | 页码，最小为 `1`，默认 `1` |
| `page_size` | `int` | 否 | 每页数量，范围 `1-100`，默认 `10` |
| `keyword` | `string` | 否 | 按域名或站点标题模糊搜索 |
| `owner` | `string` | 否 | 按负责人模糊筛选 |
| `title` | `string` | 否 | 按站点标题模糊筛选 |
| `region` | `string` | 否 | 按区域模糊筛选 |
| `asset_address` | `string` | 否 | 按资产地址模糊筛选，当前对应 `domain` 字段 |
| `risk_level` | `string` / `string[]` | 否 | 按最高风险等级筛选，支持 `critical`、`high`、`medium`、`low`、`info`，支持逗号分隔和多参数 |
| `has_vulnerability` | `bool` | 否 | 按是否存在漏洞筛选，`true` 表示 `vulnerability_count > 0`，`false` 表示 `vulnerability_count = 0` |
| `has_component` | `bool` | 否 | 按是否存在存活组件筛选，`true` 表示 `component_count > 0`，`false` 表示 `component_count = 0` |
| `is_alive` | `bool` | 否 | 按存活状态筛选 |

- 响应格式：

```json
{
  "code": 0,
  "message": "success",
  "data": {
    "page": 1,
    "pageSize": 10,
    "total": 1,
    "totalPages": 1,
    "items": [
      {
        "id": 1,
        "domain": "app.example.com:443",
        "asset_address": "app.example.com:443",
        "owner": "安全团队",
        "title": "Example App",
        "first_alive_at": "2026-09-22T10:00:00+08:00",
        "last_alive_at": "2026-09-22T11:00:00+08:00",
        "region": "internal",
        "risk_level": "critical",
        "has_form": true,
        "has_upload": false,
        "has_admin": false,
        "has_uc_login": true,
        "has_baidu_login": false,
        "screenshot_path": "/screenshots/app.png",
        "manual_note": "",
        "http_status_code": 200,
        "request": "GET / HTTP/1.1\r\nHost: app.example.com\r\n\r\n",
        "response": "HTTP/1.1 200 OK\r\n\r\n<html>Example App</html>",
        "is_alive": true,
        "vulnerability_count": 2,
        "critical_count": 1,
        "high_count": 1,
        "medium_count": 0,
        "low_count": 0,
        "component_count": 3
      }
    ]
  }
}
```

- 说明：
  - 域名资产在扫描前 HTTP 探测完成后同步存活状态：成功取得响应的地址设为 `is_alive=true`，本次已检查但未取得响应的已有地址设为 `is_alive=false`；任务成功结束时不再重复同步域名存活状态。
  - `first_alive_at` 记录首次探测存活的同步时间，已有值不覆盖；`last_alive_at` 记录最近一次探测存活的扫描前同步时间。探测不存活时保留两个时间字段的原值。
  - `request`、`response` 分别表示该域名资产最近一次探测保存的请求与响应原文；没有记录时返回空字符串。
  - `has_form`、`has_upload`、`has_admin`、`has_uc_login`、`has_baidu_login` 为可空布尔值；数据库值为 `NULL` 时接口返回 `null`，`false` 表示已确认不存在。
  - `vulnerability_count` 表示漏洞表中 `asset_endpoint` 等于当前域名资产 `domain` 的记录数量。
  - `critical_count`、`high_count`、`medium_count`、`low_count` 表示上述关联漏洞中各严重等级的数量，按漏洞表 `severity` 字段统计。
  - `risk_level` 表示当前资产的最高风险等级，按 `critical > high > medium > low` 取值；存在漏洞但没有可识别等级时返回 `unknown`，没有漏洞时返回 `info`。
  - `component_count` 表示域名组件表中 `domain` 等于当前域名资产 `domain` 且 `is_alive = true` 的组件数量。
  - 组件在扫描前被动指纹识别或后续指纹结果写入时更新 `last_found_at`；`first_found_at` 仅在首次发现时设置。单个目标完成主动指纹识别或自动模板映射的指纹识别后，立即将该地址本次未识别到的旧组件设为 `is_alive=false`，不改动其发现时间；未启用这两类识别时不执行旧组件失活检查。任务成功结束时不再重复同步组件或改写 `last_found_at`。
  - `title`、`region` 为模糊筛选；`risk_level=high` 仅返回最高风险等级为高危的资产，存在严重漏洞的资产会归入 `critical`。
  - 列表默认按最近存活时间和 ID 倒序排序。
  - 当前后端表结构没有 `organization`、`scan_task`、`business_system` 字段，因此这些前端筛选项不会作为服务端查询条件。

- 错误码说明：
  - `40001`：分页参数非法，或 `is_alive`、`has_vulnerability`、`has_component` 不是布尔值
  - `50001`：获取域名资产清单失败

- 使用示例：

```bash
curl "http://127.0.0.1:8686/api/v1/domain-assets?page=1&page_size=10&keyword=example&title=Portal&region=internal&risk_level=high&has_vulnerability=true&has_component=true"
```

## 31.1 导出域名资产清单

- 请求方法和路径：`GET /api/v1/domain-assets/export`
- 请求参数：与域名资产列表使用同一筛选语义。所有参数均可选；`page`、`page_size` 可随列表请求传入，但不限制导出范围。

| 参数 | 类型 | 必填 | 说明 |
| --- | --- | --- | --- |
| `keyword` | `string` | 否 | 域名或站点标题模糊搜索 |
| `owner` | `string` | 否 | 负责人模糊筛选 |
| `title` | `string` | 否 | 站点标题模糊筛选 |
| `region` | `string` | 否 | 区域模糊筛选 |
| `asset_address` | `string` | 否 | 域名地址模糊筛选 |
| `risk_level` | `string` / `string[]` | 否 | 最高风险等级筛选，支持逗号分隔或重复参数 |
| `has_vulnerability` | `bool` | 否 | 是否存在漏洞 |
| `has_component` | `bool` | 否 | 是否存在存活组件 |
| `is_alive` | `bool` | 否 | 是否存活 |
| `page` / `page_size` | `int` | 否 | 接收但不影响导出范围 |

- 响应格式：成功返回 XLSX 附件，`Content-Type` 为 `application/vnd.openxmlformats-officedocument.spreadsheetml.sheet`，文件名为 `domain-assets-YYYYMMDD-HHMMSS.xlsx`。`domain_assets` 工作表每条匹配资产一行，按列表顺序排列，列为 `domain`、`owner`、`title`、`first_alive_at`、`last_alive_at`、`region`、`risk_level`、`has_form`、`has_upload`、`has_admin`、`has_uc_login`、`has_baidu_login`、`screenshot_path`、`manual_note`、`http_status_code`、`request`、`response`、`is_alive`、`vulnerability_count`、`critical_count`、`high_count`、`medium_count`、`low_count`、`component_count`、`service_assets`、`title_histories`。`domain` 即列表中的 `asset_address`，不重复导出；不包含主键 `id`。
- `service_assets` 和 `title_histories` 包含详情接口对应的完整数组，保存为 JSON 文本。统计列和 `risk_level` 使用列表接口口径；可空字段留空，时间为 RFC3339 文本。工作表沿用漏洞导出的列宽、行高、冻结首行、交替底色和长字段分段规则；超长内容存入 `large_fields` 工作表。无匹配结果时仍返回带表头的文件。
- 错误码说明：`40001` 表示布尔筛选值非法；`50001` 表示创建文件、查询或生成 XLSX 失败，错误响应使用 `{ "code", "message", "data" }` JSON 格式。
- 使用示例：

```bash
curl -H "Authorization: Bearer YOUR_ACCESS_TOKEN" -o domain-assets.xlsx "http://127.0.0.1:8686/api/v1/domain-assets/export?owner=team&risk_level=high&has_component=true"
```

## 32. 获取域名资产详情

- 请求方法和路径：`GET /api/v1/domain-assets/detail`

- 请求参数：

| 参数 | 类型 | 必填 | 说明 |
| --- | --- | --- | --- |
| `domain` | `string` | 是 | 域名资产地址，需与 `manscan_asset_domain.domain` 完全一致，例如 `app.example.com:443` |

- 响应格式：

```json
{
  "code": 0,
  "message": "success",
  "data": {
    "domain": "app.example.com:443",
    "owner": "安全团队",
    "title": "Example App",
    "first_alive_at": "2026-09-22T10:00:00+08:00",
    "last_alive_at": "2026-09-22T11:00:00+08:00",
    "region": "internal",
    "has_form": true,
    "has_upload": false,
    "has_admin": false,
    "has_uc_login": true,
    "has_baidu_login": false,
    "screenshot_path": "/screenshots/app.png",
    "manual_note": "",
    "http_status_code": 200,
    "request": "GET / HTTP/1.1\r\nHost: app.example.com\r\n\r\n",
    "response": "HTTP/1.1 200 OK\r\n\r\n<html>Example App</html>",
    "is_alive": true,
    "risk_level": "critical",
    "vulnerability_count": 2,
    "service_assets": [
      {
        "app_name": "nginx",
        "app_version": "1.24",
        "last_found_at": "2026-09-22T11:00:00+08:00",
        "first_found_at": "2026-09-22T10:00:00+08:00",
        "is_alive": true
      }
    ],
    "title_histories": [
      {
        "history_title": "Example App",
        "is_alive": true,
        "first_title_created_at": "2026-09-22T10:00:00+08:00",
        "latest_title_alive_at": "2026-09-22T11:00:00+08:00"
      }
    ]
  }
}
```

- 说明：
  - `is_alive`、`first_alive_at`、`last_alive_at` 与域名资产清单采用相同的扫描前探测同步口径；任务结束时不再重写 `last_alive_at`。
  - `service_assets` 来自 `manscan_asset_domain_service_assets`，按当前域名精确匹配 `domain` 字段。
  - `service_assets[].first_found_at` 仅记录首次发现时间；`last_found_at` 在扫描前被动识别或后续指纹结果写入时更新。新识别到的组件立即设为 `is_alive=true`；启用主动指纹识别或自动模板映射时，每个目标的指纹识别完成后，立即将该地址本次未识别到的旧组件设为 `is_alive=false`，但保留两个发现时间。未启用这两类识别时不执行旧组件失活检查；任务成功结束时不再重复同步或改写 `last_found_at`。
  - `service_assets[].app_version` 为可空字符串；未识别到版本时返回 `null`。
  - 指纹版本优先采用 `组件名:版本` 的显式归属；多个组件时，可使用模板 `info.metadata.product` 将合法的纯版本、通用 `version:版本`（含带引号的 JSON 字段片段）或可规范化的版本横幅归给同名组件。product 去除首尾空白并忽略大小写后必须与已有组件精确匹配，不推断别名、不新增组件，也不把版本复制给其他标签；同一结果含多个不同的待归属版本时，不通过 product 推断。单组件保持原有版本解析规则，显式组件版本优先于推断版本。
  - product 优先读取扫描结果 `info.metadata.product`；该字段缺失或为空字符串时，使用模板详情中解析自 `metadata.product` 的 Product。非字符串、多值或无法匹配的 product 不用于多组件版本归属。更新服务后需再次扫描才能补充版本，历史空版本不会自动回填。
  - SSH 指纹的 `service_assets[].app_version` 包含软件名称和版本，例如 `OpenSSH 7.4`、`WeOnlyDo 2.4.3`。
  - `title_histories` 来自 `manscan_asset_domain_title_history`，按当前域名精确匹配 `domain` 字段。
  - `vulnerability_count` 表示漏洞表中 `asset_endpoint` 等于当前域名资产 `domain` 的记录数量，但不统计 `status` 为 `fixed`、`false_positive`、`ignored` 的漏洞。
  - `risk_level` 表示过滤上述状态后的最高风险等级，按 `critical > high > medium > low` 取值；存在漏洞但没有可识别等级时返回 `unknown`，没有漏洞时返回 `info`。
  - 组件数组默认按 `is_alive`、`last_found_at` 和 ID 倒序排序；标题历史数组默认按 `is_alive`、`latest_title_alive_at` 和 ID 倒序排序。
  - 主表中的可空字符串字段没有记录时返回空字符串；可空时间和状态码没有记录时返回 `null`。

- 错误码说明：
  - `40001`：`domain` 参数为空
  - `40401`：域名资产不存在
  - `50001`：获取域名资产详情失败

- 使用示例：

```bash
curl "http://127.0.0.1:8686/api/v1/domain-assets/detail?domain=app.example.com:443"
```

## 33. 修改域名资产人工备注

- 请求方法和路径：`PATCH /api/v1/domain-assets/manual-note`

- 请求参数：

| 参数 | 类型 | 必填 | 说明 |
| --- | --- | --- | --- |
| `domain` | `string` | 是 | 域名资产地址，需与 `manscan_asset_domain.domain` 完全一致，例如 `app.example.com:443` |
| `asset_address` | `string` | 否 | `domain` 的兼容别名；当 `domain` 为空时生效 |
| `manual_note` | `string` | 否 | 人工备注，服务端会去除首尾空白，最多 5000 个字符；传空字符串或仅空白字符串表示清空备注 |

- 响应格式：

```json
{
  "code": 0,
  "message": "success",
  "data": {
    "domain": "app.example.com:443",
    "manual_note": "重点关注登录入口"
  }
}
```

- 错误码说明：
  - `40001`：请求体格式错误、`domain` 为空或 `manual_note` 超过 5000 个字符
  - `40401`：域名资产不存在
  - `50001`：更新域名资产人工备注失败

- 使用示例：

```bash
curl -X PATCH "http://127.0.0.1:8686/api/v1/domain-assets/manual-note" \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"domain":"app.example.com:443","manual_note":"重点关注登录入口"}'
```

清空备注示例：

```bash
curl -X PATCH "http://127.0.0.1:8686/api/v1/domain-assets/manual-note" \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"domain":"app.example.com:443","manual_note":""}'
```

## 34. 获取主机资产清单

- 请求方法和路径：`GET /api/v1/host-assets`

- 请求参数：

| 参数 | 类型 | 必填 | 说明 |
| --- | --- | --- | --- |
| `page` | `int` | 否 | 页码，最小为 `1`，默认 `1` |
| `page_size` | `int` | 否 | 每页数量，范围 `1-100`，默认 `10` |
| `keyword` | `string` | 否 | 按 IP 模糊搜索 |
| `owner` | `string` | 否 | 按负责人模糊筛选 |
| `os_type` | `string` | 否 | 按操作系统类型模糊筛选 |
| `region` | `string` | 否 | 按区域模糊筛选 |
| `asset_address` | `string` | 否 | 按资产地址模糊筛选，当前对应 `ip_address` 字段 |
| `risk_level` | `string` / `string[]` | 否 | 按最高风险等级筛选，支持 `critical`、`high`、`medium`、`low`、`info`，支持逗号分隔和多参数 |
| `has_vulnerability` | `bool` | 否 | 按是否存在漏洞筛选，`true` 表示 `vulnerability_count > 0`，`false` 表示 `vulnerability_count = 0` |
| `has_port` | `bool` | 否 | 按是否存在存活端口筛选，`true` 表示 `port_count > 0`，`false` 表示 `port_count = 0` |
| `is_alive` | `bool` | 否 | 按存活状态筛选 |

- 响应格式：

```json
{
  "code": 0,
  "message": "success",
  "data": {
    "page": 1,
    "pageSize": 10,
    "total": 1,
    "totalPages": 1,
    "items": [
      {
        "id": 1,
        "ip_address": "10.72.160.123",
        "asset_address": "10.72.160.123",
        "region": "生产区",
        "owner": "安全团队",
        "os_type": "linux",
        "os_version": "5.15",
        "scan_created_at": "2026-10-10T10:00:00+08:00",
        "last_alive_at": "2026-10-10T11:00:00+08:00",
        "manual_note": "",
        "is_alive": true,
        "related_domains": "app.example.com",
        "risk_level": "critical",
        "vulnerability_count": 2,
        "critical_count": 1,
        "high_count": 1,
        "medium_count": 0,
        "low_count": 0,
        "port_count": 3
      }
    ]
  }
}
```

- 说明：
  - `vulnerability_count` 表示漏洞表中 `asset_host` 等于当前主机 `ip_address` 的记录数量。
  - `critical_count`、`high_count`、`medium_count`、`low_count` 表示上述关联漏洞中各严重等级的数量，按漏洞表 `severity` 字段统计。
  - `risk_level` 表示当前资产的最高风险等级，计算方式暂时与域名资产一致：按 `critical > high > medium > low` 取值；存在漏洞但没有可识别等级时返回 `unknown`，没有漏洞时返回 `info`。
  - `port_count` 表示主机端口表中 `ip_address` 等于当前主机 `ip_address` 且 `is_alive = true` 的不同 `port_number` 数量；同一端口数字的多个协议或服务名只计 1 个。
  - `os_type`、`region` 为模糊筛选；`risk_level=high` 仅返回最高风险等级为高危的资产，存在严重漏洞的资产会归入 `critical`。
  - 列表默认按最近存活时间和 ID 倒序排序。

- 错误码说明：
  - `40001`：分页参数非法，或 `is_alive`、`has_vulnerability`、`has_port` 不是布尔值
  - `50001`：获取主机资产清单失败

- 使用示例：

```bash
curl "http://127.0.0.1:8686/api/v1/host-assets?page=1&page_size=10&keyword=10.72&os_type=linux&region=生产&risk_level=critical&has_vulnerability=true&has_port=true"
```

## 34.1 导出主机资产清单

- 请求方法和路径：`GET /api/v1/host-assets/export`
- 请求参数：与主机资产列表使用同一筛选语义。所有参数均可选；`page`、`page_size` 可随列表请求传入，但不限制导出范围。

| 参数 | 类型 | 必填 | 说明 |
| --- | --- | --- | --- |
| `keyword` | `string` | 否 | IP 地址模糊搜索 |
| `owner` | `string` | 否 | 负责人模糊筛选 |
| `os_type` | `string` | 否 | 操作系统类型模糊筛选 |
| `region` | `string` | 否 | 区域模糊筛选 |
| `asset_address` | `string` | 否 | IP 地址模糊筛选 |
| `risk_level` | `string` / `string[]` | 否 | 最高风险等级筛选，支持逗号分隔或重复参数 |
| `has_vulnerability` | `bool` | 否 | 是否存在漏洞 |
| `has_port` | `bool` | 否 | 是否存在存活端口 |
| `is_alive` | `bool` | 否 | 是否存活 |
| `page` / `page_size` | `int` | 否 | 接收但不影响导出范围 |

- 响应格式：成功返回 XLSX 附件，`Content-Type` 为 `application/vnd.openxmlformats-officedocument.spreadsheetml.sheet`，文件名为 `host-assets-YYYYMMDD-HHMMSS.xlsx`。`host_assets` 工作表每条匹配资产一行，按列表顺序排列，列为 `ip_address`、`region`、`owner`、`os_type`、`os_version`、`scan_created_at`、`last_alive_at`、`manual_note`、`is_alive`、`related_domains`、`risk_level`、`vulnerability_count`、`critical_count`、`high_count`、`medium_count`、`low_count`、`port_count`、`ports`。`ip_address` 即列表中的 `asset_address`，不重复导出；不包含主键 `id`。
- `ports` 包含详情接口对应的完整端口数组，包括非存活记录，保存为 JSON 文本；`port_count` 只统计存活记录中去重后的端口数字。统计列和 `risk_level` 使用列表接口口径；可空字段留空，时间为 RFC3339 文本。工作表沿用漏洞导出的列宽、行高、冻结首行、交替底色和长字段分段规则；超长内容存入 `large_fields` 工作表。无匹配结果时仍返回带表头的文件。
- 错误码说明：`40001` 表示布尔筛选值非法；`50001` 表示创建文件、查询或生成 XLSX 失败，错误响应使用 `{ "code", "message", "data" }` JSON 格式。
- 使用示例：

```bash
curl -H "Authorization: Bearer YOUR_ACCESS_TOKEN" -o host-assets.xlsx "http://127.0.0.1:8686/api/v1/host-assets/export?os_type=linux&has_port=true&risk_level=critical"
```

## 35. 获取主机资产详情

- 请求方法和路径：`GET /api/v1/host-assets/detail`

- 请求参数：

| 参数 | 类型 | 必填 | 说明 |
| --- | --- | --- | --- |
| `ip_address` | `string` | 是 | 主机资产 IP 地址，需与 `manscan_asset_host.ip_address` 完全一致，例如 `10.72.160.123` |
| `asset_address` | `string` | 否 | `ip_address` 的兼容别名；当 `ip_address` 为空时生效 |

- 响应格式：

```json
{
  "code": 0,
  "message": "success",
  "data": {
    "ip_address": "10.72.160.123",
    "region": "生产区",
    "owner": "安全团队",
    "os_type": "linux",
    "os_version": "5.15",
    "scan_created_at": "2026-10-10T10:00:00+08:00",
    "last_alive_at": "2026-10-10T11:00:00+08:00",
    "manual_note": "",
    "is_alive": true,
    "related_domains": "app.example.com",
    "risk_level": "high",
    "vulnerability_count": 2,
    "ports": [
      {
        "port_protocol": "tcp",
        "port_number": 8080,
        "service_name": "http",
        "app_name": "nginx",
        "app_version": "1.24",
        "is_alive": true,
        "is_high_risk_port": false,
        "last_alive_at": "2026-10-10T11:00:00+08:00",
        "port_created_at": "2026-10-10T10:00:00+08:00"
      }
    ]
  }
}
```

- 说明：
  - `ports` 来自 `manscan_asset_host_port`，按当前主机精确匹配 `ip_address` 字段；同一 IP、协议、端口可按不同 `service_name` 返回多条记录。
  - `ports[].port_protocol` 表示传输层协议（`tcp` / `udp`），不是模板执行类型。`jdwp`、`mssql`、`openssh`、`rsync` 指纹即使来自未声明传输协议的 `javascript` 模板，也会按已识别的服务补充为 `tcp`，同样适用于非标准端口；明确提供的传输协议优先，MSSQL Browser 的 `udp` 标签仍保留为 `udp`。结果及其元数据中的 `tls` / `ssl` 按传输层归一为 `tcp`。更新服务后需再次扫描确认，已有空协议记录不会仅因代码更新自动改写。
  - `sip-options-detect` 的 SIP 服务及产品指纹（包括 `gowvp`、`audiocodes-mediant`）优先采用结果元数据中的实际 `transport`，缺失时读取该模板 JSON 响应中的 `service: sip` 和 `transport`。不按 SIP 产品名称或默认端口猜测传输协议；同时带有 `tcp` / `udp` 标签且无实际传输证据时保留空值。同一服务在同一 IP 端口分别命中 TCP 和 UDP 时，两种观察结果在批量入库、缓存和目标完成后的存活同步中分别保留。
  - `ports[].port_created_at` 保留该 IP、端口和服务名首次写入的时间；当后续指纹确定此前空缺的 TCP/UDP 协议时，会将空协议记录合并到已确认协议记录，并保留较早的首次发现时间和已知版本。同一服务同时存在 TCP 与 UDP 时不推断空协议记录的归属。`ports[].last_alive_at` 在该组合实际被 HTTP 探测或指纹结果再次确认时更新。任务成功结束不再对端口表执行二次同步；关闭结果队列时尚未落库的实际指纹结果仍会按结果观察时间写入，不使用任务结束时间重写存活时间。
  - 扫描前 HTTP 探测完成后，已检查但未取得响应的 IP 端口，其已有 HTTP 服务记录立即设为 `is_alive=false`。启用前置指纹识别或自动模板映射时，单个目标的指纹识别完成后，立即把该 IP 端口本次未识别到的旧服务设为 `is_alive=false`；已取得 HTTP 响应的端口保留 HTTP 服务存活。失活操作不改写两个时间字段，未启用这两类识别时不执行旧服务指纹失活检查。
  - SSH 指纹的 `ports[].app_version` 包含软件名称和版本，例如 `OpenSSH 7.4`、`WeOnlyDo 2.4.3`。
  - 指纹版本优先采用 `组件名:版本` 的显式归属，不会被后续的纯版本覆盖。只有一个组件时，合法的纯版本或 `version:版本` 按原有规则写入该组件；多个组件时，优先读取扫描结果 `info.metadata.product`，该字段缺失或为空字符串时使用模板详情中解析自 `metadata.product` 的 Product。product 必须为单一字符串，去除首尾空白并忽略大小写后与已有组件精确匹配，才能将合法的纯版本、通用版本字段或可规范化的版本横幅定向写入该组件；不推断别名、不新增组件、不复制版本给其他标签。同一结果包含多个不同的待归属版本时不通过 product 推断。提取器名称 `version` 不代表产品归属。
  - 例如命中 `apache`、`zookeeper` 两个组件，`metadata.product: zookeeper` 且提取结果为 `3.6.0` 时，仅 `zookeeper` 的 `app_version` 为 `3.6.0`。新建记录没有可归属版本时数据库保存 `NULL`、接口返回空字符串；再次扫描未取得版本时不覆盖原有已知版本。更新服务后需再次扫描才能补充版本，历史空版本不会自动回填。
  - `ports[].is_high_risk_port` 为可空布尔值；数据库值为 `NULL` 时接口返回 `null`，`false` 表示已确认非高危端口。
  - `vulnerability_count` 表示漏洞表中 `asset_host` 等于当前主机 `ip_address` 的记录数量，但不统计 `status` 为 `fixed`、`false_positive`、`ignored` 的漏洞。
  - `risk_level` 表示过滤上述状态后的最高风险等级，按 `critical > high > medium > low` 取值；存在漏洞但没有可识别等级时返回 `unknown`，没有漏洞时返回 `info`。
  - 端口数组默认按 `is_alive` 倒序、`port_number` 升序和 ID 升序排序。
  - 主表和端口表中的可空字符串字段没有记录时返回空字符串；可空时间没有记录时返回 `null`。

- 错误码说明：
  - `40001`：`ip_address` 参数为空
  - `40401`：主机资产不存在
  - `50001`：获取主机资产详情失败

- 使用示例：

```bash
curl "http://127.0.0.1:8686/api/v1/host-assets/detail?ip_address=10.72.160.123"
```

## 36. 修改主机资产人工备注

- 请求方法和路径：`PATCH /api/v1/host-assets/manual-note`

- 请求参数：

| 参数 | 类型 | 必填 | 说明 |
| --- | --- | --- | --- |
| `ip_address` | `string` | 是 | 主机资产 IP 地址，需与 `manscan_asset_host.ip_address` 完全一致，例如 `10.72.160.123` |
| `asset_address` | `string` | 否 | `ip_address` 的兼容别名；当 `ip_address` 为空时生效 |
| `manual_note` | `string` | 否 | 人工备注，服务端会去除首尾空白，最多 5000 个字符；传空字符串或仅空白字符串表示清空备注 |

- 响应格式：

```json
{
  "code": 0,
  "message": "success",
  "data": {
    "ip_address": "10.72.160.123",
    "manual_note": "堡垒机入口"
  }
}
```

- 错误码说明：
  - `40001`：请求体格式错误、`ip_address` 为空、`ip_address` 不是合法 IP 地址或 `manual_note` 超过 5000 个字符
  - `40401`：主机资产不存在
  - `50001`：更新主机资产人工备注失败

- 使用示例：

```bash
curl -X PATCH "http://127.0.0.1:8686/api/v1/host-assets/manual-note" \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"ip_address":"10.72.160.123","manual_note":"堡垒机入口"}'
```

清空备注示例：

```bash
curl -X PATCH "http://127.0.0.1:8686/api/v1/host-assets/manual-note" \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"ip_address":"10.72.160.123","manual_note":""}'
```

## 37. 获取域名资产最新页面截图

- 请求方法和路径：`GET /api/v1/domain-assets/screenshots/latest`

- 请求参数：

| 参数 | 类型 | 必填 | 说明 |
| --- | --- | --- | --- |
| `domain` | `string` | 是 | 域名资产地址，例如 `http://10.107.71.65:8889`；最多 2048 个字符且不能包含控制字符 |

- 响应格式：

```json
{
  "code": 0,
  "message": "success",
  "data": {
    "domain": "http://10.107.71.65:8889",
    "captured_date": "2026-10-15",
    "file_name": "http:__10.107.71.65:8889_20261015-101500_42.png",
    "content_type": "image/png",
    "image_base64": "iVBORw0KGgoAAA..."
  }
}
```

- 说明：
  - 服务端在项目根目录的 `screenshots` 目录中查找截图。
  - 新文件名格式为 `<资产键>_<YYYYMMDD-HHmmss>_<任务ID>.<扩展名>`，并兼容历史 `<资产键>_<YYYYMMDD>.<扩展名>`。资产键由 `domain` 中的 `/` 替换为 `_` 得到，例如 `http://10.107.71.65:8889` 对应前缀 `http:__10.107.71.65:8889_`。
  - 接口按文件名中的合法采集时间选择最新截图，不使用文件修改时间；历史日期文件的采集时间按当天零点处理。
  - `image_base64` 是不带 Data URL 前缀的标准 Base64；前端展示时可按 `data:<content_type>;base64,<image_base64>` 组装。
  - 仅支持内容确认为 PNG、JPEG 或 WebP 的普通文件；单张截图最大为 20 MiB。目录、符号链接、日期格式错误及其他扩展名文件不会参与匹配。

- 错误码说明：
  - `40001`：`domain` 为空、超过长度限制或包含控制字符
  - `40401`：没有找到该域名资产的有效截图
  - `50001`：截图目录或截图文件读取失败、截图过大或文件内容不是受支持的图片格式

- 使用示例：

```bash
curl -G "http://127.0.0.1:8686/api/v1/domain-assets/screenshots/latest" \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
  --data-urlencode "domain=http://10.107.71.65:8889"
```

## 38. 获取域名资产历史页面截图

- 请求方法和路径：`GET /api/v1/domain-assets/screenshots`

- 请求参数：

| 参数 | 类型 | 必填 | 说明 |
| --- | --- | --- | --- |
| `domain` | `string` | 是 | 域名资产地址，匹配规则与最新截图接口一致 |
| `page` | `int` | 否 | 页码，最小为 `1`，默认 `1` |
| `page_size` | `int` | 否 | 每页截图数量，范围 `1-20`，默认 `10` |

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
        "domain": "http://10.107.71.65:8889",
        "captured_date": "2026-10-15",
        "file_name": "http:__10.107.71.65:8889_20261015-101500_42.png",
        "content_type": "image/png",
        "image_base64": "iVBORw0KGgoAAA..."
      },
      {
        "domain": "http://10.107.71.65:8889",
        "captured_date": "2026-10-15",
        "file_name": "http:__10.107.71.65:8889_20261015-091500_41.png",
        "content_type": "image/png",
        "image_base64": "iVBORw0KGgoBBB..."
      }
    ]
  }
}
```

- 说明：
  - 截图按文件名中的采集时间倒序返回；采集时间相同时按文件名倒序返回。
  - 没有历史截图或页码超过总页数时返回成功响应，`items` 为空数组。
  - 每页图片原始内容总量最大为 64 MiB；超过限制时返回 `50001`，调用方可减小 `page_size` 后重试。
  - 每个 `items` 元素的字段及截图文件匹配规则与最新截图接口一致。

- 错误码说明：
  - `40001`：`domain` 非法，`page` 不是大于等于 `1` 的整数，或 `page_size` 不在 `1-20` 之间
  - `50001`：截图目录或截图文件读取失败、单张截图/当前分页图片总量过大，或文件内容不是受支持的图片格式

- 使用示例：

```bash
curl -G "http://127.0.0.1:8686/api/v1/domain-assets/screenshots" \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
  --data-urlencode "domain=http://10.107.71.65:8889" \
  --data-urlencode "page=1" \
  --data-urlencode "page_size=10"
```

## 39. 第三方 API Key 配置

## 40. 定时任务

定时任务接口用于管理通用后台任务（例如同步数据或执行脚本）。当前已内置 `cve_file_names.sync` 处理器，用于从 GitHub `CVEProject/cvelistV5` 获取 CVE 文件名并原子替换 `data/tmp/cve_data/cves.txt`；`vulnx_vulnerability.sync` 处理器获取最新完整 CVE 列表并只查询数据库缺失编号的 ProjectDiscovery VulnX 详情，新增五张漏洞情报表；`chaitin_vulnerability.sync` 同步长亭全部漏洞（不限制 CVE），`aliyun_avd_vulnerability.sync` 同步阿里云高危列表全部漏洞（不限制 CVE）；`vulnerability_intelligence.incremental` 依次执行三个渠道并汇总进度。未配置 `api_key_id` 时按处理器使用 `GITHUB_TOKEN` 或 `PDCP_API_KEY`。创建未知类型仍可保存配置，但触发后会以“定时任务类型未注册”失败；后续注册同名 `JobHandler` 后即可执行。所有接口都需要登录，新增、编辑、删除和立即触发仅管理员可操作。

### 查询定时任务列表

- 请求方法和路径：`GET /api/v1/scheduled-jobs`
- 请求参数：`page`、`page_size`（可选，默认 1、10，`page_size` 最大 100）、`keyword`（可选，按名称、描述和类型模糊查询）。
- 响应格式：`data` 为分页对象，任务字段包括 `id`、`name`、`description`、`output_description`、`job_type`、`cron_expr`、`timezone`、`enabled`、`api_key_id`、`config_json`、`concurrency_policy`、`timeout_seconds`、`next_run_at`、`last_run_at`、`last_status` 和 `last_error`。`output_description` 是任务产出内容说明，未设置时为空字符串。
- `next_run_at` 按任务时区计算：服务启动注册任务、修改计划或启用任务时写入，每次自动触发时刷新为下一次计划时间，不等待任务执行完成；禁用任务时清空（响应省略该字段）。手动触发不改变定时计划。此规则同样适用于任务详情和编辑响应；前端需重新查询接口获取最新值。
- 错误码：`40101` 未登录；`40001` 分页参数不合法；`50001` 查询失败。
- 数据库升级：已有数据库需执行 `docs/SQL/alter_manscan_scheduled_jobs_add_output_description.sql`；新建数据库使用更新后的 `docs/SQL/create_manscan_scheduled_jobs.sql`。
- 使用示例：`curl -H 'Authorization: Bearer <access_token>' 'http://127.0.0.1:8686/api/v1/scheduled-jobs?page=1&page_size=20'`

### 新增定时任务

- 请求方法和路径：`POST /api/v1/scheduled-jobs`
- 请求参数：JSON body。必填 `name`、`job_type`、`cron_expr`、`config_json`；可选 `description`、`output_description`（任务产出内容描述，最长 512 字符，默认空字符串）、`timezone`（默认 `Asia/Shanghai`）、`enabled`（默认 true）、`api_key_id`、`concurrency_policy`（`forbid`/`allow`，默认 `forbid`）、`timeout_seconds`（整数，0-2592000 秒，最多 30 天，默认 0，0 表示不限制单次任务执行时长）。`config_json` 必须是合法 JSON，最大 1 MiB。Cron 使用 5 段格式（分钟、小时、日、月、星期）。
- 响应格式：HTTP 200，`data` 为新任务对象。
- 错误码：`40001` 参数、Cron、时区、并发策略或任务配置不合法；`40101` 未登录；`40301` 非管理员；`50001` 保存或注册失败。
- 使用示例：

```bash
curl -X POST -H 'Authorization: Bearer <access_token>' -H 'Content-Type: application/json' \
  -d '{"name":"数据同步","job_type":"example.sync","cron_expr":"*/5 * * * *","config_json":"{}","enabled":true}' \
  'http://127.0.0.1:8686/api/v1/scheduled-jobs'
```

### 获取、编辑和删除定时任务

- 请求方法和路径：`GET /api/v1/scheduled-jobs/:id`、`PUT /api/v1/scheduled-jobs/:id`、`DELETE /api/v1/scheduled-jobs/:id`。
- 路径参数：`id` 为正整数。
- 编辑请求：字段与新增相同，`enabled` 必填；`output_description` 可选，最长 512 字符；`timeout_seconds` 范围为 0-2592000 秒（最多 30 天），0 表示不限制单次任务执行时长；修改 Cron、时区或开关会立即重新注册或移除进程内调度。Cron 使用 5 段格式（分钟、小时、日、月、星期）。
- 响应格式：查询和编辑 HTTP 200，`data` 为任务对象；删除 HTTP 200，`data` 为 `{ "id": <id> }`。
- 错误码：`40001` 参数不合法；`40101` 未登录；`40301` 编辑/删除非管理员；`40401` 任务不存在；`50001` 数据库或调度注册失败。
- 使用示例：`curl -X PUT -H 'Authorization: Bearer <access_token>' -H 'Content-Type: application/json' -d '{"name":"数据同步","job_type":"example.sync","cron_expr":"*/10 * * * *","config_json":"{}","enabled":false}' 'http://127.0.0.1:8686/api/v1/scheduled-jobs/1'`

### 取消当前定时任务执行

- 请求方法和路径：`POST /api/v1/scheduled-jobs/:id/stop`。
- 请求参数：路径参数 `id`（整数，必填，必须为正整数）；请求体为空。仅管理员可调用。
- 行为：向该任务当前所有 queued/running 实例发送取消信号，退出后执行记录状态更新为 `cancelled`。保留任务配置、`enabled`、`next_run_at` 和 Cron 调度，后续仍按原计划自动触发；无需恢复操作。取消前已完成的业务操作不会回滚。
- 响应格式：HTTP 202，统一响应的 `data` 为 `{ "id": 1, "cancel_requested_runs": 1 }`。`cancel_requested_runs` 表示已发出取消请求的实例数量，没有执行实例时为 0；响应表示已接受取消请求，最终状态通过执行记录查询。处理器必须响应 `context.Context` 取消；不响应取消的外部操作无法被 Go 服务强制终止。
- 错误码：`40001` ID 不合法；`40101` 未登录；`40301` 非管理员；`40401` 任务不存在；`50001` 数据库或取消操作失败。
- 使用示例：`curl -X POST -H 'Authorization: Bearer <access_token>' 'http://127.0.0.1:8686/api/v1/scheduled-jobs/1/stop'`
- 原 `pause`、`resume` 接口已移除；任务启用/禁用仍通过编辑接口的 `enabled` 字段设置。

### 立即触发定时任务

- 请求方法和路径：`POST /api/v1/scheduled-jobs/:id/trigger`
- 请求参数：无；仅管理员可调用。接口只创建执行记录并异步执行，不等待任务完成。
- 响应格式：HTTP 202，`data.run` 为执行记录，初始状态通常为 `queued`；若 `forbid` 且已有执行，则记录为 `skipped`。
- 错误码：`40001` ID 不合法；`40101` 未登录；`40301` 非管理员；`40401` 任务不存在；`50001` 创建执行记录失败。
- 使用示例：`curl -X POST -H 'Authorization: Bearer <access_token>' 'http://127.0.0.1:8686/api/v1/scheduled-jobs/1/trigger'`

### 查询任务执行记录和进度

- 请求方法和路径：`GET /api/v1/scheduled-jobs/:id/runs`、`GET /api/v1/scheduled-job-runs/:run_id`。
- 请求参数：列表接口支持 `page`、`page_size`；详情接口使用正整数 `run_id`。
- 响应格式：执行记录包含 `status`（`queued`、`running`、`success`、`failed`、`timeout`、`skipped`、`cancelled`）、`progress_current`、`progress_total`、`progress_percent`、`progress_phase`、`progress_message`、`output_path`、时间字段、错误信息及预留的结果引用字段。`progress_total=0` 时百分比为空，表示任务尚未提供可计算总量。`output_path` 是相对于服务根目录的产出文件路径，没有产出时为空。
- 错误码：`40001` 参数不合法；`40101` 未登录；`40401` 任务或执行记录不存在；`50001` 查询失败。
- 使用示例：`curl -H 'Authorization: Bearer <access_token>' 'http://127.0.0.1:8686/api/v1/scheduled-jobs/1/runs?page=1&page_size=10'`
- 数据库升级：已有数据库需执行 `docs/SQL/alter_manscan_scheduled_job_runs_add_output_path.sql`；新建数据库使用更新后的 `docs/SQL/create_manscan_scheduled_job_runs.sql`。

### 下载定时任务产出

- 请求方法和路径：`GET /api/v1/scheduled-job-runs/:run_id/output`
- 请求参数：路径参数 `run_id` 为正整数；执行记录必须已经写入产出路径且对应文件仍存在。
- 响应格式：成功时直接返回产出文件内容，并通过 `Content-Disposition` 以原文件名下载；GitHub CVE 同步任务的文件名为 `cves.txt`，综合漏洞情报任务为 `incremental_outputs_<run_id>.zip`。
- 错误码：`40001` 执行记录 ID 不合法；`40101` 未登录；`40401` 执行记录或产出文件不存在；`50001` 下载失败。
- 使用示例：

```bash
curl -L -OJ \
  -H 'Authorization: Bearer <access_token>' \
  'http://127.0.0.1:8686/api/v1/scheduled-job-runs/12/output'
```

### 任务处理器扩展约定

服务启动时从数据库加载 `enabled=1` 的任务。业务代码通过 `JobHandlerRegistry.Register` 注册具体处理器；处理器实现 `Type`、`Validate` 和 `Execute`，在 `Execute` 中通过 `ProgressReporter.Report` 写入阶段、当前值、总量和说明。API Key 仅保存关联 ID，具体处理器按需通过现有 API Key 服务读取并解密，不在定时任务表中保存明文密钥。

需要发出外部请求的处理器必须复用服务启动时创建并注入的 `service.APIKeyRateLimiter`：配置 `api_key_id` 时，在每一次实际请求前调用 `Wait(ctx, apiKeyID)`，包括额外遍历、回退和重试请求。不得为单个任务或执行实例独立创建限流器，否则无法共享额度。限流配置读取失败时返回错误，不绕过限流发送请求。

### 内置任务：CVE 文件名同步

- `job_type`：`cve_file_names.sync`
- 默认计划：`0 0 * * *`，时区 `Asia/Shanghai`，每天零点执行。
- `config_json`：可选 `{"ref":"main"}`，用于指定 GitHub 分支、标签或提交 SHA；为空时使用 `main`。
- 输出：成功获取完整列表后，使用临时文件原子替换 `data/tmp/cve_data/cves.txt`，失败时保留上一次成功文件。
- 获取方式：先读取仓库根目录定位 `cves` 的 SHA，再以 `recursive=1` 请求完整子树。仅当 GitHub 成功响应明确标记 `truncated=true` 时，丢弃该部分结果，读取当前目录的直接列表，将未处理子目录加入队列，再逐个尝试获取完整子树。成功且未截断的子树不会再请求其内部子目录；目录按 SHA 去重，CVE 编号去重排序。直接目录列表仍被截断时任务失败，保留旧文件。
- 请求恢复：GitHub Tree 单次请求超时为 200 秒（包含响应体读取）。网络超时、临时网络错误或响应体提前结束时，同一请求最多尝试 3 次，重试前分别等待 1 秒、2 秒；每次尝试均参与 API Key 共享限流。重试耗尽后停止任务，不因网络失败拆分子目录。鉴权、HTTP 限流、其他 HTTP 错误、非截断类 JSON 格式错误和本地限流配置错误均停止任务。任务取消或总超时立即中止请求及退避等待。独立 VulnX 与综合增量任务获取 GitHub CVE 列表时复用此策略。
- 详细进度：复用执行记录的 `progress_phase`、`progress_message` 和 `progress_updated_at`。GitHub 阶段为 `github_waiting`（等待 API Key 额度）、`github_requesting`（请求及读取响应）、`github_retrying`（重试退避）、`github_listing`（已定位 CVE 目录）、`github_fallback`（GitHub 截断，改为直接目录列表）、`github_traversing`（当前目录单元已处理）和 `github_finished`（全部 CVE 列表获取完成，准备写文件）。说明明确区分“仅完成直接列表读取，子目录尚待处理”与“当前子树完整读取，无需再请求子目录”。包含当前位置、已处理目录单元数、排队目录数（不含当前目录）、已去重 CVE 数及实际请求次数；目录单元包含仓库根目录，重试及截断回退不会重复计数。
- 接收量及刷新：长请求和额度等待每 5 秒更新状态，请求说明包含尝试次数、耗时、本次已接收 KiB 及本次任务累计接收 KiB。接收量按解压后的响应体统计，累计量包括截断结果、失败请求已读部分和重试，不代表有效 CVE 数据量；本次接收量在每次请求开始时归零。重试说明包含原因和下次等待秒数。
- 进度口径：GitHub 获取期间 `progress_current` 为已处理目录单元数，`progress_total=0`，未知总量时不预估百分比；只从成功且未截断的响应收集 CVE。写文件阶段为 `writing`，当前值和总量切换为已写入/全部 CVE 数，并在说明中展示。最终任务完成阶段仍为 `finished`。独立 VulnX 任务沿用上述 GitHub 阶段；综合增量任务在阶段及说明前添加 `VulnX` 来源标识，当前值和总量保持原有三渠道加权口径，GitHub 获取时整体百分比不递增，读取状态持续刷新。进度上报失败会停止本次处理，不当作 GitHub 网络错误重试。
- 产出：成功执行后，在本次执行记录的 `output_path` 字段写入固定路径 `data/tmp/cve_data/cves.txt`，前端可使用“产出下载”按钮调用执行记录产出下载接口。
- 限流：当任务配置 `api_key_id` 且该 API Key 的 `rate_limit_per_minute=N` 大于 `0` 时，请求按至少 `60/N` 秒的间隔放行，不允许突发透支。同一服务进程内，相同 API Key ID 的所有任务及并发执行实例（包括自动和手动触发）共享额度，不同 API Key ID 相互独立；根目录、子树、截断回退及其重试均参与限流。未配置 API Key 或限流值为 `0` 时不启用服务端限流，但仍受 GitHub 自身限流策略约束。
- 配置变更与取消：每次请求以及等待唤醒后重新读取当前 API Key 限流值；已有等待在下一次检查时采用新值。等待计入任务的 `timeout_seconds`，支持取消和超时，等待期间取消不预占后续额度，获取列表失败时保留上一次成功文件。
- 共享范围：限流状态保存在当前服务进程内，重启后清空；多个服务进程或实例之间不共享额度。
- 初始化 SQL：`docs/SQL/insert_manscan_scheduled_job_cve_file_names.sql`，可重复执行，不会重复插入同一 `job_type`。

### 内置任务：VulnX 新增漏洞更新

- `job_type`：`vulnx_vulnerability.sync`
- 默认计划建议：`0 30 * * *`，时区 `Asia/Shanghai`，每天凌晨 00:30 执行；该任务会自行刷新 CVE 列表。
- 初始化 SQL：`docs/SQL/insert_manscan_scheduled_job_vulnx_vulnerability_sync.sql`，默认启用并使用环境变量 API Key；可在定时任务管理中关联 `api_key_id` 以启用按 Key 限流。脚本按 `job_type` 判断，可重复执行。
- `config_json`：使用 `{}`；每次执行都从 GitHub `CVEProject/cvelistV5` 获取完整 CVE 列表，并原子更新服务根目录下 `data/tmp/cve_data/cves.txt`。列表完成后分批检查数据库中 `source=vulnx` 的现有编号，只对数据库缺失的 CVE 调用详情 API。已有 CVE 不重复请求或覆盖。执行时需要存在 `cve_file_names.sync` 任务，以读取其 GitHub Key 配置。
- API Key：VulnX 详情 API 使用本任务配置的 `api_key_id`，从第三方 API Key 服务读取并解密，按每次请求发送 `X-Api-Key`；未配置时读取环境变量 `PDCP_API_KEY`。GitHub 全量 CVE 列表请求使用“全量 CVE 列表获取”（`cve_file_names.sync`）任务配置的 `api_key_id`，并应用对应 Key 的共享限流；未配置时读取环境变量 `GITHUB_TOKEN`。
- 并发与限流：每次最多并行处理 8 个 CVE；配置 `api_key_id` 后，每次 CVE 请求（包括重试）都复用服务启动时创建的共享限流器，按该 Key 的 `rate_limit_per_minute` 放行。同一 Key 的任务和并发执行共享额度，限流等待支持取消和超时。使用 `PDCP_API_KEY` 环境变量时没有服务端配置的限额，也不启用服务端限流，仍受 ProjectDiscovery API 自身限流约束。
- 更新范围：每个 CVE 查询 `https://api.projectdiscovery.io/v2/vulnerability/{CVE}`，在一个数据库事务中按 CVE 替换以下五张表的完整快照：
  - `manscan_vulnerability_intelligence_records`：`data` 中漏洞画像、时间、CVSS、CWE、EPSS、暴露主机数、HackerOne、POC、产品、厂商、修复、严重性、状态、漏洞类型和影响字段。
  - `manscan_vulnerability_intelligence_components`：`affected_products[]` 的 CPE、类别、部署方式、行业、产品、摘要和厂商。
  - `manscan_vulnerability_intelligence_articles`：`citations[]` 的添加时间、来源和 URL。
  - `manscan_vulnerability_intelligence_pocs`：`pocs[]` 的添加时间、来源和 URL。
  - `manscan_vulnerability_intelligence_shodan_exposures`：`exposure.values[]` 的产品 ID、暴露主机数和 Shodan 查询语句。
- 失败策略：单个 CVE 查询、解析或写库失败后最多尝试 3 次（首次请求 + 2 次重试），然后继续处理剩余 CVE；最终仍失败的 CVE 的编号写入服务根目录下 `data/tmp/cve_data/vulnXerror.txt`，具体错误写入 `data/tmp/cve_data/vulnXerrorDetail.log`，两个文件每次运行开始时清空。首轮全部处理后，再对失败清单中的 CVE 各补偿重试最多 3 次；成功写入数据库的编号会从失败清单和详情日志移除，仍失败的编号及原错误详情保持不变。最终清单打包为 `data/tmp/cve_data/vulnXerror.zip`，可通过执行记录的产出下载接口下载。任务进度按处理与补偿重试阶段推进；独立任务在补偿重试后仍有失败项时标记 `failed`，错误信息包含首个失败 CVE。取消或超时会立即停止后续请求。

### 内置任务：长亭漏洞情报全量同步

- `job_type`：`chaitin_vulnerability.sync`
- 默认计划建议：`0 30 * * *`，时区 `Asia/Shanghai`。
- 初始化 SQL：`docs/SQL/insert_manscan_scheduled_job_chaitin_vulnerability_sync.sql`，按 `job_type` 判断，可重复执行。
- 抓取流程：顺序请求 `https://stack.chaitin.com/api/v2/vuln/list/`，使用 `limit=15` 与 `offset=0,15,30...` 全量分页；同步全部记录，不按 `cve_id` 筛选；无论是否有关联 CVE，均以 `ct_id` 作为漏洞编号。独立全量任务不会因第一页编号全部已存在而提前停止。
- 数据库映射：在事务中按 `source=chaitin` 与 `ct_id` 更新或新增 `manscan_vulnerability_intelligence_records`，并幂等写入 `references` 到 `manscan_vulnerability_intelligence_articles`。
- records 根据 `cve_id` 分类：包含 CVE 编号时写入 `category=cve`（与 VulnX 一致），缺失、空白或“暂无”等无 CVE 编号的值写入 `category=non-cve`；仍以 CT 编号作为漏洞编号，写入标题、描述、影响、解决建议、严重性、披露时间和更新时间；`vulnerability_type`、`is_patch_available`、`cvss_metrics`、`cvss_score` 不写入。articles 的 `source` 固定为 `chaitin`，`added_at` 不写入。
- 不写入 `manscan_vulnerability_intelligence_pocs`、`manscan_vulnerability_intelligence_components` 和 `manscan_vulnerability_intelligence_shodan_exposures`。
- 分类规则同样适用于综合任务中实际同步到的记录。历史分类需重新执行独立全量同步更新，部署不会自动回填整库。

### 内置任务：阿里云高危漏洞情报全量同步

- `job_type`：`aliyun_avd_vulnerability.sync`
- 默认计划：`0 30 * * *`，时区 `Asia/Shanghai`；初始化 SQL 默认启用，可在任务管理页面调整。
- 初始化 SQL：`docs/SQL/insert_manscan_scheduled_job_aliyun_avd_no_cve_sync.sql`，按 `job_type` 判断，可重复执行。
- `config_json`：可选 `{"request_delay_ms":250,"max_pages":0}`；请求间隔范围 0-60000 毫秒（0 使用 250 毫秒默认值），最大列表页数范围 0-10000（0 使用 10000 页上限）。
- 抓取流程：顺序请求阿里云 `/high-risk/list?page=N`，解析 AVD 编号、标题、类型、披露时间及状态，对所有有效 AVD 编号请求详情页，不按列表状态、标题或详情中的 CVE 筛选；详情中的 CVE 作为采集信息保留，漏洞编号始终使用 AVD 编号。同次采集按 AVD 编号去重，列表结束时停止。列表与详情均限制为 HTTPS 固定主机 `avd.aliyun.com`，响应体最大 16 MiB，具备请求超时、退避重试、Cookie Jar，并执行页面 WAF 校验脚本以取得校验后的 URL。进度在抓取阶段按“已处理列表页/最大列表页数”逐页推送，抓取完成后切换为详情数据库同步、产物写入和完成阶段提示。
- 详情产物：包含 AVD/CVE 编号、标题、严重等级、利用情况、补丁情况、披露时间、描述、解决建议、参考 URL 数组、阿里云评分、评分拆分指标、CWE、受影响软件、阿里云安全产品覆盖、列表元数据、来源 URL 和抓取时间。源页面未提供的字段为空或缺省，不从描述推断填充。
- 输出：为兼容既有下载及综合任务打包，继续原子写入 `data/tmp/aliyun_avd/no_cve_vulnerabilities.json`，实际包含有 CVE 和无 CVE 的记录；JSON 历史字段 `no_cve_candidate_count` 现统计全部去重后的 AVD 候选数量。执行记录登记产物路径，可通过定时任务产出下载接口获取。存在部分详情失败时保留成功记录和错误摘要，任务状态标记失败。
- 数据库映射：在一个事务中按 `source=avd` 与 AVD 编号更新或新增 `manscan_vulnerability_intelligence_records`，并按漏洞编号和 URL 幂等写入参考链接到 `manscan_vulnerability_intelligence_articles`。records 根据详情中的 CVE 分类：包含 CVE 编号时写入 `category=cve`（与 VulnX 一致），无 CVE 编号时写入 `category=non-cve`；仍以 AVD 编号作为漏洞编号，写入标题、描述、解决建议、阿里云评分、披露时间到 `created_at`，severity 转为 `critical`/`high`/`medium`/`low`/`none`，`is_poc` 在利用情况或 EXP 成熟度为“EXP 已公开”或“POC 已公开”时为 1；`vulnerability_impact` 不写，`updated_at` 不由任务写入。articles 的 `source` 固定为 `avd`，`url` 为参考链接，`added_at` 不由任务写入。已有记录更新时保留现有 `updated_at`、`vulnerability_impact`；新增时间列由数据库默认值生成。
- 不写入 `manscan_vulnerability_intelligence_components`、`manscan_vulnerability_intelligence_pocs` 和 `manscan_vulnerability_intelligence_shodan_exposures`。
- 分类规则同样适用于综合任务中实际同步到的记录。历史分类需重新执行独立全量同步更新；综合任务可能提前停止并跳过已有详情，不能保证纠正全部历史记录。
- 数据库升级：已有数据库执行 `docs/SQL/alter_manscan_vulnerability_intelligence_avd_timestamp_defaults.sql`，以便 records.`updated_at` 和 articles.`added_at` 在任务省略这些字段时由数据库默认生成。

### 内置任务：漏洞情报增量更新（三渠道）

- `job_type`：`vulnerability_intelligence.incremental`
- 初始化 SQL：`docs/SQL/insert_manscan_scheduled_job_vulnerability_incremental.sql`，默认每天 02:00 执行，按 `job_type` 判断后可重复执行。默认超时 21600 秒；任务顺序执行三个渠道。
- 执行顺序：长亭全部漏洞列表、阿里云高危列表全部漏洞及详情、VulnX 最新完整 CVE 列表及缺失项详情。综合任务中，长亭获取第一页后，若该页全部 `ct_id` 均已存在于 `source=chaitin` 的数据库记录中，则更新完第一页后停止请求后续列表页；此判断不受 `cve_id` 影响。阿里云按第一页全部 AVD 编号判断，不限制 CVE；全部已存在时停止后续列表页并跳过该页全部详情请求。若第一页没有可用于判断的编号或仍有新编号，则继续分页。该提前停止逻辑仅用于综合任务，不影响独立的长亭、阿里云全量同步任务。各来源任务分别报告阶段、当前值、总量和说明，综合任务进度按渠道阶段推进；每个数据源完成后继续下一个，发生错误则停止并标明失败渠道。
- 长亭与阿里云：按各自来源和漏洞编号匹配现有记录；新编号插入，字段有变化时更新映射字段，参考链接按来源同步差异。其他来源和关联表不受影响。
- VulnX：先获取最新完整 CVE 列表，再按 1000 个编号一批检查 `source=vulnx`。只对不存在的编号请求详情并新增完整情报快照，已有 CVE 不进行重复 API 请求。
- API Key：综合任务和独立 VulnX 任务均从数据库读取 `cve_file_names.sync`（“全量 CVE 列表获取”）的 `api_key_id` 用于 GitHub 列表请求，从 `vulnx_vulnerability.sync`（“全量 VulnX 漏洞更新（长耗时）”）读取 `api_key_id` 用于 VulnX 详情请求。两种请求分别使用对应 Key 的共享限流；综合任务自身的 `api_key_id` 不参与这两种请求。CVE 列表任务不存在时任务失败；列表任务未绑定 Key 时 GitHub 请求回退到 `GITHUB_TOKEN`，VulnX 任务未绑定 Key 时详情请求回退到 `PDCP_API_KEY`。
- 下载产出：综合任务成功后，将阿里云 `no_cve_vulnerabilities.json` 与 VulnX 的 `vulnXerror.zip` 放入按执行记录 ID 命名的 `data/tmp/vulnerability_intelligence/incremental_outputs_<run_id>.zip`，并登记为本次执行的 `output_path`。在执行记录的“下载产出”按钮或 `GET /api/v1/scheduled-job-runs/:run_id/output` 下载。VulnX 压缩包包含 `vulnXerror.txt` 和 `vulnXerrorDetail.log`，无失败时两个文件为空。长亭和 VulnX 正常同步结果写入数据库。旧执行记录不会补生成汇总 ZIP。
- 部分失败状态：综合任务中单个 CVE 经重试后仍查询、解析或写库失败时，将编号和错误写入 VulnX 失败清单并继续处理其他 CVE；只要三个渠道整体流程及汇总产物生成成功，综合任务仍标记成功，进度消息会显示失败数量，可下载汇总 ZIP 查看详情。来源列表获取、数据库查询、任务取消/超时及产物生成等整体错误仍会使任务失败。独立 `vulnx_vulnerability.sync` 任务保持“存在单个失败 CVE 即标记失败”的行为。

综合增量任务还会自动推送新增漏洞预警（独立全量同步任务不触发推送）：

- 触发条件：以 `source + vulnerability_id` 判断是否新增。长亭（`chaitin`）和阿里云（`avd`）新增记录均推送；VulnX（`vulnx`）新增记录仅在 `severity` 为 `high` 或 `critical`，且 `is_kev`、`is_poc`、`is_vkev` 任一为 `true` 时推送。已有记录的字段更新不触发推送；与详情接口一致，`rejected` 记录不推送。长亭新增记录不受 `cve_id` 限制，均以 `ct_id` 推送；阿里云高危列表新增记录同样不限制 CVE，均以 AVD 编号推送。
- 配置：从 API key 管理表中查找描述为 `推送漏洞预警` 的唯一记录（忽略首尾空格及英文字母大小写）。使用该记录的解密 Key 发送 `Authorization: Bearer <key>`，并使用其共享请求限流；综合任务的 `api_key_id` 不用于推送。配置缺失、重复、密钥不可用或平台 URL 无效时，在采集前将任务标记失败。
- 接收地址：使用该记录的“平台 URL”作为基地址，追加 `/v1/alerts`；已包含该路径时不重复追加。允许内网 HTTP(S) 平台，不跟随重定向。示例：`http://intel.internal:8080` 对应 `http://intel.internal:8080/v1/alerts`。
- 请求：`POST /v1/alerts`，`Content-Type: application/json`。唯一顶层字段为 `data`，其内容直接复用 `GET /api/v1/vulnerability-intelligence-records/:vulnerability_id` 的详情数据，包含 `records`、`articles`、`components`、`pocs`、`shodan_exposures` 五个数组；无关联数据时数组为 `[]`，记录可空字段保持 `null`。不发送 ManScan 的 `code`、`message` 响应外壳；`vuln_status` 随详情发送，由接收端按协议丢弃。单个漏洞一条请求，不截断详情；超过接收端默认 256 KiB 上限时保留待处理并报告失败。
- 响应与失败处理：HTTP `202`（入队）或 `200`（重复提交），且响应 `resultCode` 与 HTTP 状态码一致时视为成功。HTTP `400`、`401`、`413`、`500`、`503`，以及其他状态、响应格式错误、连接失败或 15 秒请求超时均视为失败。新增记录成功入库后立即尝试推送；推送失败不回滚情报入库。待推送来源及编号保存在 `data/vulnerability_alerts/pending/`，不保存 Key 或详情正文，任务结束前补偿重试（包括之前执行留下的记录）；仍有失败则任务失败，并在执行记录错误信息中显示待重试数量。取消或服务重启后保留待推送记录，下次增量任务重新读取详情和最新 Key 配置再推送。该目录需随服务数据持久化，勿作为临时文件清理。接收端已接收但本地尚未确认成功时可能重复投递，由接收端按协议去重。

请求格式示意（`data` 实际为完整漏洞详情）：

```http
POST /v1/alerts
Authorization: Bearer <推送漏洞预警 API key>
Content-Type: application/json

{"data":{"records":[{"source":"chaitin","vulnerability_id":"CT-DEMO"}],"articles":[],"components":[],"pocs":[],"shodan_exposures":[]}}
```

以下接口均要求 JWT 登录且当前用户角色为管理员。API Key 使用 AES-256-GCM 加密后只存入 `manscan_third_party_api_keys.encrypted_key`；数据库不保留明文 Key 列，列表、单条查询及增改删响应均不返回密钥明文或密文，只返回 `key_configured`。如确有必要，可使用下方明文查询接口；该接口是唯一返回明文 Key 的接口。新部署请执行 `docs/SQL/create_manscan_third_party_api_keys.sql`；已有表请先备份并执行 `docs/SQL/alter_manscan_third_party_api_keys_encrypt_key.sql`。迁移会将当前版本的 `api_key` 密文列重命名为 `encrypted_key` 并保留密文；如果数据库中存在早期独立的明文 `key` 列，迁移会删除该列及其中数据。配置密钥丢失或更换后既有密文不可恢复。请求体最大 16 KiB。

### 列表

- 请求方法和路径：`GET /api/v1/third-party-api-keys`
- 请求参数：`page` 可选整数，范围 `1-2147483647`，默认 `1`；`page_size` 可选整数，范围 `1-100`，默认 `10`。
- 响应格式：标准分页结构，`data` 为 `{ "page": 1, "page_size": 10, "total": 1, "total_pages": 1, "items": [...] }`；每项含 `id`（整数）、`platform_url`（字符串）、`rate_limit_per_minute`（无符号整数）、`description`（字符串）、`key_configured`（布尔值）、`created_at` 和 `updated_at`（RFC3339 时间），不含 Key。
- 错误码：`40101` 未登录，`40301` 非管理员，`40001` 页码参数非法，`50001` 查询失败。
- 使用示例：

```bash
curl "http://127.0.0.1:8686/api/v1/third-party-api-keys?page=1&page_size=10" \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```

### 单条查询

- 请求方法和路径：`GET /api/v1/third-party-api-keys/{id}`
- 请求参数：`id` 为必填正整数路径参数。
- 响应格式：与列表单项相同，不返回 Key。
- 错误码：`40001` ID 非法，`40101` 未登录，`40301` 非管理员，`40401` 记录不存在，`50001` 查询失败。
- 使用示例：

```bash
curl "http://127.0.0.1:8686/api/v1/third-party-api-keys/1" \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```

### 查询明文密钥

此接口仅允许管理员在确有必要时调用，会记录访问审计日志。响应包含敏感信息，服务端设置 `Cache-Control: no-store` 和 `Pragma: no-cache`，调用方不得记录、转发或持久化返回值。

- 请求方法和路径：`GET /api/v1/third-party-api-keys/{id}/plaintext`
- 请求参数：`id` 为必填正整数路径参数。
- 响应格式：标准响应 envelope 中的 `data` 为 `{ "key": "YOUR_PROVIDER_KEY" }`；返回已解密的 API Key 明文。
- 错误码：`40001` ID 非法，`40101` 未登录，`40301` 非管理员，`40401` 记录不存在或未配置密钥，`50001` 解密或查询失败。
- 使用示例：

```bash
curl "http://127.0.0.1:8686/api/v1/third-party-api-keys/1/plaintext" \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```

### 新增

- 请求方法和路径：`POST /api/v1/third-party-api-keys`
- 请求参数：JSON 对象；`key` 必填且不可为空白或包含控制字符，最长 512 字节；`platform_url` 必填，仅允许带主机名且不含用户名、密码或片段的 HTTP/HTTPS URL，最长 2048 字节；`rate_limit_per_minute` 可选，范围 `0-4294967295`，`0` 表示不限制；`description` 可选，最长 512 字节。字段长度按 UTF-8 字节计算。
- 响应格式：标准响应 envelope 中的 `data` 返回配置对象，例如 `{"id":1,"platform_url":"https://api.example.com","rate_limit_per_minute":60,"description":"漏洞情报查询","key_configured":true,"created_at":"2026-10-23T10:00:00+08:00","updated_at":"2026-10-23T10:00:00+08:00"}`；不返回 Key。
- 错误码：`40001` 请求体或字段非法，`40101` 未登录，`40301` 非管理员，`50001` 加密或数据库操作失败。
- 使用示例：

```bash
curl -X POST "http://127.0.0.1:8686/api/v1/third-party-api-keys" \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"key":"YOUR_PROVIDER_KEY","platform_url":"https://api.example.com","rate_limit_per_minute":60,"description":"漏洞情报查询"}'
```

### 更新

- 请求方法和路径：`PUT /api/v1/third-party-api-keys/{id}`
- 请求参数：`id` 为必填正整数路径参数；JSON 中 `platform_url` 必填，限流和描述字段同新增；`key` 可省略或为 `null` 以保留原 Key，传入字符串时必须非空白、不含控制字符且最长 512 字节。更新按完整元信息替换处理；未提供的限流值重置为 `0`，未提供的描述重置为空字符串。
- 响应格式：标准响应 envelope 中的 `data` 返回更新后的配置对象，字段与新增响应相同；不返回 Key。
- 错误码：`40001` ID、请求体或字段非法，`40101` 未登录，`40301` 非管理员，`40401` 记录不存在，`50001` 加密或数据库操作失败。
- 使用示例：

```bash
curl -X PUT "http://127.0.0.1:8686/api/v1/third-party-api-keys/1" \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"platform_url":"https://api.example.com/v2","rate_limit_per_minute":30,"description":"漏洞情报查询"}'
```

### 删除

- 请求方法和路径：`DELETE /api/v1/third-party-api-keys/{id}`
- 请求参数：`id` 为必填正整数路径参数。
- 响应格式：`{ "id": 1, "deleted_count": 1 }`。
- 错误码：`40001` ID 非法，`40101` 未登录，`40301` 非管理员，`40401` 记录不存在，`50001` 删除失败。
- 使用示例：

```bash
curl -X DELETE "http://127.0.0.1:8686/api/v1/third-party-api-keys/1" \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```

## 漏洞情报分页查询

- 请求方法和路径：`GET /api/v1/vulnerability-intelligence-records`，需要登录。
- 请求参数：`page` 为可选正整数，默认 `1`；`page_size` 为可选整数，范围 `1-100`，默认 `10`。`source`、`vulnerability_id`、`vul_name` 为可选字符串模糊查询；`severity` 为可选字符串或字符串数组，支持逗号分隔（如 `severity=critical,high`）及重复参数（如 `severity=critical&severity=high`），多个等级按“或”匹配，每个值仍执行模糊查询，并与其他筛选条件按“且”组合。`is_poc`、`is_kev` 为可选布尔值（支持 `true`/`false`、`1`/`0`、`yes`/`no`、`y`/`n`）。`is_kev=true` 匹配数据库 `is_kev` 或 `is_vkev` 任一为 true 的记录；`is_kev=false` 匹配两者均不为 true 的记录。
- 响应格式：统一响应 envelope 中的 `data` 为分页对象，包含 `page`、`pageSize`、`total`、`totalPages`、`items`。状态 `rejected`（大小写不敏感）的漏洞记录不会出现在列表中，也不计入分页总数；空状态记录仍保留。每条记录仅返回 `source`、`vulnerability_id`、`created_at`、`updated_at`、`cvss_score`、`vul_name`、`is_kev`、`is_poc`、`severity`；`is_kev` 在数据库 `is_kev` 或 `is_vkev` 任一为 true 时为 true，否则为 false。其他数据库可空字段保持 `null`。按 `created_at DESC, id DESC` 排序。
- 错误码：`40001` 分页参数或布尔筛选参数非法，`40101` 未登录或令牌无效，`50001` 数据库查询失败。
- 使用示例：

```bash
curl -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
  "http://127.0.0.1:8686/api/v1/vulnerability-intelligence-records?page=1&page_size=10&source=vulnx&vulnerability_id=CVE-2026&vul_name=RCE&is_poc=true&severity=critical,high&is_kev=true"
```

```json
{
  "code": 0,
  "message": "success",
  "data": {
    "page": 1,
    "pageSize": 10,
    "total": 1,
    "totalPages": 1,
    "items": [{
      "source": "vulnx",
      "vulnerability_id": "CVE-2026-12345",
      "created_at": "2026-01-01T00:00:00Z",
      "updated_at": null,
      "cvss_score": 9.8,
      "vul_name": "示例漏洞",
      "is_kev": true,
      "is_poc": false,
      "severity": "critical"
    }]
  }
}
```

## 漏洞情报高危等级统计

- 请求方法和路径：`GET /api/v1/vulnerability-intelligence-records/stats`，需要登录。
- 请求参数：无。
- 响应格式：统一响应 envelope 中的 `data.last_7_days` 和 `data.last_30_days` 均为整数，分别表示对应时间窗口内 `critical` 与 `high` 等级合并后的记录数量；无匹配记录时返回 `0`。状态 `rejected`（大小写不敏感）的记录不计入，空状态记录仍计入。按 `manscan_vulnerability_intelligence_records` 的记录行数统计，不按漏洞编号去重；`created_at` 从请求时刻向前滚动 7×24 小时或 30×24 小时，起止时刻均包含，未来时间和空时间不计入。严重等级大小写不敏感；近 7 天计数包含在近 30 天计数中。
- 错误码：`40101` 未登录或令牌无效，`50001` 数据库查询失败。
- 使用示例：

```bash
curl -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
  "http://127.0.0.1:8686/api/v1/vulnerability-intelligence-records/stats"
```

```json
{
  "code": 0,
  "message": "success",
  "data": {
    "last_7_days": 3,
    "last_30_days": 7
  }
}
```

## 漏洞情报详情查询

- 请求方法和路径：`GET /api/v1/vulnerability-intelligence-records/:vulnerability_id`，需要登录。
- 请求参数：路径参数 `vulnerability_id`，必填字符串，按完整编号精确查询，去除首尾空白后长度为 1-128 字节，不允许 NUL、回车、换行或制表符。编号应按 URL 路径规则编码。
- 响应格式：统一响应 envelope 中的 `data` 包含 `records`、`articles`、`components`、`pocs`、`shodan_exposures` 五个数组，对应五张 `manscan_vulnerability_intelligence_*` 表的全部字段，字段名为数据库小写下划线命名。`records` 返回同一编号来自不同来源、状态不为 `rejected`（大小写不敏感）的记录，空状态记录仍保留；若该编号只有 `rejected` 记录，则返回 `40401`。其余数组按相同编号查询，无关联行时返回 `[]`。各数组按 `id ASC` 排序，可空字段返回 `null`。
- 字段与空值约定：每条记录始终返回该表的全部字段，数据库 `NULL` 显式输出为 JSON `null`，不省略字段，也不替换为 `""`、`0`、`false` 或 `[]`。JSON 数组列（`cwe`、`vulnerability_impact`、`cpe`、`search_queries`）为 `NULL` 时返回 `null`，存储空数组时返回 `[]`；无关联行时，表对应的顶层数组返回 `[]`。详情中的 `is_kev`、`is_vkev` 分别返回原始字段，不采用列表接口的合并值。
- 错误码：`40001` 编号非法，`40101` 未登录或令牌无效，`40401` 主记录不存在，`50001` 数据库查询失败。
- 使用示例：

```bash
curl -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
  "http://127.0.0.1:8686/api/v1/vulnerability-intelligence-records/CVE-2026-12345"
```

```json
{
  "code": 0,
  "message": "success",
  "data": {
    "records": [{
      "id": 1,
      "source": "vulnx",
      "vulnerability_id": "CVE-2026-12345",
      "age_in_days": null,
      "category": null,
      "created_at": null,
      "updated_at": null,
      "cvss_metrics": null,
      "cvss_score": null,
      "cwe": null,
      "description": "示例描述",
      "epss_percentile": null,
      "epss_score": null,
      "max_hosts": null,
      "min_hosts": null,
      "filename": null,
      "h1_rank": null,
      "h1_reports": null,
      "impact": null,
      "vul_name": null,
      "is_auth": null,
      "is_kev": null,
      "is_oss": null,
      "is_patch_available": null,
      "is_template": null,
      "is_poc": null,
      "is_remote": null,
      "is_vkev": null,
      "ntps": null,
      "poc_count": null,
      "poc_first_seen": null,
      "product": null,
      "vendor": null,
      "remediation": null,
      "severity": null,
      "vuln_status": null,
      "vulnerability_type": null,
      "vulnerability_impact": null
    }],
    "articles": [{
      "id": 2,
      "vulnerability_id": "CVE-2026-12345",
      "added_at": null,
      "source": null,
      "url": "https://example.test/advisory"
    }],
    "components": [{
      "id": 3,
      "vulnerability_id": "CVE-2026-12345",
      "cpe": [],
      "category": null,
      "deployment_model": null,
      "industry": null,
      "product": "example",
      "summary": null,
      "vendor": null
    }],
    "pocs": [{
      "id": 4,
      "vulnerability_id": "CVE-2026-12345",
      "url": "https://example.test/poc",
      "source": null,
      "added_at": null
    }],
    "shodan_exposures": [{
      "id": 5,
      "vulnerability_id": "CVE-2026-12345",
      "product_name": null,
      "max_hosts": null,
      "min_hosts": null,
      "search_queries": null
    }]
  }
}
```

上例完整展示五张表的全部字段及 `null` 的实际响应形式。

## 攻击路径识别与过滤

部署前执行 docs/SQL/create_manscan_attack_path_tasks.sql。默认使用 hybrid 模式，由本地规则先分类、疑难路径再批量调用模型，无需安装 Claude CLI；可配置 ai.attack_path_mode: cli 回退到原单会话模式，此时需要支持 HTTP MCP、--bare 与 --strict-mcp-config 的 Claude CLI。服务端读取私有 config.yaml 中 ai.model、ai.uuap_id 及可选 ai.claude_binary。每次模型请求从 manscan_third_party_api_keys 中查找描述为 `原力平台` 的唯一记录，使用该记录的 `platform_url` 和 API Key；API Key 通过现有 auth.api_key_encryption_key 解密。无需在 config.yaml 中配置记录 ID、URL 或 API Key；密钥不会写入文件或 API 响应。

已有包含 `input_text`、`output_text` 的任务表时，停止任务服务并备份数据库后，一次性执行 `docs/SQL/alter_manscan_attack_path_tasks_file_storage.sql`，再部署当前服务；新建表只执行建表脚本。升级脚本保留已落盘结果的文件名并删除两个正文列，不迁移旧版正文；仅有数据库正文的任务需要重新上传 TXT。

配置示例：

    ai:
      model: global.anthropic.claude-sonnet-5
      uuap_id: <服务账户的UUAP-ID>
      attack_path_mode: hybrid
      attack_path_concurrency: 5
      attack_path_batch_size: 500
      claude_binary: /usr/local/bin/claude # 仅 cli 模式需要

`attack_path_mode` 默认 `hybrid`，可选 `hybrid` / `batch` / `cli`；并发数默认 5、范围 1–32；每批条数默认 500、范围 1–1000。未填写或数值为 0 时使用默认值，越界配置会阻止服务启动。这些配置修改后需要重启服务，不支持按上传请求覆盖。原力平台的 URL 和 API Key 必须在第三方 API Key 管理中配置，描述填写 `原力平台`；同名配置必须唯一，URL 使用 `https://ai-force.duxiaoman-int.com/` 或其 `/agent-api/openai` 地址。

### 提示词配置

将仓库根目录的 `prompt.yaml` 与实际使用的 `config.yaml` 放在同一目录。若通过 `MANSCAN_CONFIG_FILE` 指定配置文件，提示词文件也从该配置文件所在目录读取，不受 Claude 临时工作目录影响。文件内 `prompts` 是标识到提示词正文的映射，当前攻击路径处理使用以下五个标识：

| 标识 | 用途 |
| --- | --- |
| `attack_path_filter.system` | 恶意路径识别标准、输入可信边界和任务执行规则，作为模型分类标准，CLI 模式同时用作系统提示词 |
| `attack_path_filter.task` | 当前任务的处理要求，作为 CLI 任务提示词 |
| `attack_path_filter.tools.read_paths` | 读取路径工具的说明 |
| `attack_path_filter.tools.write_filtered_paths` | 提交恶意路径编号并写入正常路径工具的说明 |
| `attack_path_filter.tools.finish` | 完成确认工具的说明 |

编辑对应标识下的正文即可调整提示词，支持中文及 YAML 多行文本；请保留标识名称。正文支持 `{{total}}`（去重后路径总数）、`{{read_default}}`（默认读取条数）、`{{read_max}}`（最大读取条数）、`{{read_max_bytes}}`（单次路径文本字节上限）四个占位符，由后端按实际参数替换，不执行模板表达式或命令。修改提示词不会改变文件工具的硬性限制、参数结构或权限。

启用 AI 功能时，服务启动会校验提示词文件；每次任务开始执行时重新读取五段提示词，整个任务使用同一份快照。部署此版本后，修改 `prompt.yaml` 无需重新编译或重启，新开始执行的任务使用最新内容，已经运行的任务不受影响。建议先编辑临时文件，再整体替换 `prompt.yaml`，避免读取到保存过程中的不完整文件。

缺失文件、缺少标识、空正文、重复标识、无效 YAML 或未知占位符会报错，不回退到代码内默认提示词。单段正文最多 32 KiB，文件最多 1 MiB。启动校验失败会阻止 AI 处理器初始化；运行期间文件被改坏时，下一次任务在调用模型前失败，详情写入服务端日志，前端通过原任务接口获得 `failed` 状态和现有失败提示。

### hybrid 模式：Coraza + 固定版本 CRS、结构化复核与模型（默认）

1. 引擎固定为 Coraza v3.8.1，规则固定为 coraza-coreruleset/v4 v4.25.0（上游 CRS 4.25.0）。版本与校验和由根目录 go.mod / go.sum 锁定，规则从依赖的嵌入文件系统编译进程序；运行时不下载、不自动更新。旧手写攻击正则、敏感路由名单、三层手工解码和 /api/ 前缀放行逻辑已删除。
2. 每条输入建立独立的离线 Coraza 事务，执行请求 phase 1 / 2，URI 和查询参数由 Coraza 解析、转换和匹配。只做内存判断，不请求输入 URL，不解析 DNS，不执行载荷。无真实请求方法、请求头、Body 和响应时，适配层使用固定 GET / HTTP/1.1 以及固定 Host、User-Agent、Accept；这些字段不是对目标站点的观测。未加载方法限制、扫描器 UA、multipart、响应检测规则，不能作为完整 HTTP WAF 或业务越权检测器。
3. 加载 CRS 的 901 初始化、905 通用排除、920 协议规范、921 协议攻击、930–934 LFI/RFI/RCE/PHP/通用攻击、941–944 XSS/SQLi/会话固定/Java 和 949 评分规则组（该编号范围内不存在的组不加载）。运行 DetectionOnly，blocking paranoia level 为 1、detection paranoia level 为 2，不提前阻断，以便获得完整评分；审计和调试输出关闭，避免把原始路径及参数写入日志。
4. 本地排除要求 CRS 的 PL1 累计分至少 10，且至少命中两个不同的 930–944 攻击检测规则。规则的流程控制命中不作为攻击证据。低分、单规则、仅高敏感等级命中先进入下述结构化复核；无法确认时才送模型。该阈值是离线清洗策略，不是 CRS 默认阻断阈值，也不保证所有高分结果均无误报。
5. 本地保留要求输入可以可靠解析，且 CRS 完整执行成功、检测分为 0、无攻击检测规则命中。不再要求参数名属于预定义清单、参数值符合数字/布尔/日期/枚举类型；自由文本、未知参数、字符串游标、文件路径值、重复参数和可解析的编码路径，在 CRS 检查干净时直接判为正常 API，不进入模型。/api/ 前缀不参与放行，所有可可靠解析的路径都必须先执行 CRS。无法解析的 URL、非法查询编码、不支持的 URL 表示等仍视为异常可疑输入（内部原因 invalid_input），保留复核，不能把未完成检查当成零分。规则执行、事务处理或评分读取异常仍使任务失败。
6. CRS 编译实例在处理器中复用，每条路径使用独立事务；本地扫描最多使用 5 个且不超过 GOMAXPROCS 的 worker，每批有界并行并按原位置收集结果。模型与本地结果通过位置掩码合并，保留原文本和顺序；疑难路径集中落盘后批量送模型，临时目录 0700、临时文件 0600，处理结束或取消时清理。
7. processed / kept 仍表示已按顺序写出或排除的输入前缀；本地扫描期间和前方疑难批次等待模型时，进度可能暂不增长。接口方法、上传参数、响应字段与下载格式均未改变。规则加载、事务处理或评分读取失败会使任务失败，不将错误当零分放行。
8. 模型并发默认 5，所有使用该分类器的任务共享配置的请求并发闸门，而不是每个任务各占 5 个上游请求。已在配置中显式设置 1 的部署需要手动改为 5 并重启；未配置时使用新默认值。上游并发额度和 API Key 本地每分钟限额是独立限制，不能互相替代。遇到 110602 或 HTTP 429 仍共享降为单并发并退避重试，进程重启后恢复配置上限。
9. prompt.yaml 只影响疑难路径的模型判定。CRS 版本、加载范围、评分阈值和复核分流策略固定在后端，需要改代码并重新构建才能变更。规则和模型均可能误报或漏报，准确率须用独立人工标注数据验证。


#### 当前分流策略：没有可疑证据就本地保留

按用户明确要求，hybrid 取消“未知参数类型必须复核”的限制：

| 本地检查结果 | 当前去向 |
| --- | --- |
| CRS 完整执行成功、零检测分且无攻击规则命中 | 本地保留，不消耗模型 token |
| CRS 有可疑命中，但分数/规则数量不足，结构确认也未成立 | 优先复用模型缓存，未命中才进入模型复核 |
| CRS 高分多规则命中，或同参数结构确认成立 | 本地排除 |
| URL/查询编码不合法或无法可靠解析 | 作为异常可疑输入使用模型判定，优先查缓存，不默认当成正常 API |
| 引擎、事务或评分读取失败 | 任务失败，不默认保留 |

例如 `/api/search?q=手机`、`/api/items?category=books`、`/api/orders?cursor=abc123`、`/api/files?path=reports/a.csv` 和 `/api/items?id=1&id=2` 在当前定向测试中均本地保留；不因自由文本、未知类型或重复参数单独请求模型。

此策略明确接受规则漏检的取舍：“正常”表示当前本地规则没有发现可疑证据，不是业务安全证明。现有回归样本 `/api?host=127.0.0.1%3Bid`（参数解码后为 `127.0.0.1;id`）在当前固定 CRS 中零分无命中，新策略会保留，旧策略曾因未知参数类型送模；该变化已写入回归测试。结构解析仍只确认同一参数已有 CRS 命中的内容，不独立兜底所有零命中载荷。

本次使用原始 1000 条样本仅运行本地诊断：本地保留 682 条、本地排除 170 条（CRS 强证据 160、Shell 结构确认 10）、模型复核 148 条，全部为尚未确认的 CRS 可疑命中。相比旧策略 420 / 170 / 410，新增本地保留 262 条，送模比例从 41.0% 降为 14.8%，送模条数减少约 63.9%。这些是分流统计，不是准确率、token 费用或处理耗时测量；本轮未调用真实模型。

本次修改不改变上传、查询、取消、下载的请求和响应字段，也不改动 batch / cli 模式。需要重新构建并重启后端后生效；已完成任务不会自动重新处理。下方旧样本和真实模型耗时均保留为历史记录，不作为此策略的新性能或准确率结论。

#### 第二层：同一参数的结构化证据确认

对原本需要复核的 CRS 命中，增加以下纯本地解析。它们是语法/结构解析库，不是三个独立 WAF，也不是按命中数量投票。

| 层 | 固定依赖 | 确认范围 |
| --- | --- | --- |
| Shell | 新增 mvdan.cc/sh/v3 v3.14.0 的 syntax 包 | 在 host/hostname/ip/target/cmd/command/exec 参数中，确认命令替换，或字面 IP 后出现完整 Shell 命令链；须同时有同一参数的 CRS 932 命中 |
| HTML / JavaScript | 复用 golang.org/x/net v0.58.0 的 html 包、github.com/projectdiscovery/goja v0.0.0-20260618133720-acb73e419534 的 parser/ast 包 | 解析完整单根 HTML 片段，确认 script、指定事件属性或 javascript URL 中存在完整的调用/赋值/new 表达式；须同时有同一参数的 CRS 941 命中 |
| 元数据 URL | Go 标准库 net/url、net/netip | 仅在 url/uri/endpoint/target 参数中确认字面地址 169.254.169.254 的 /latest/meta-data 或 /metadata/instance 资源及子路径；须同时有同一参数的 CRS 931/934 命中 |

判定约束：

- CRS 只提供真实带 attack- 标签的 ARGS/ARGS_GET 命中，必须与结构解析的参数、攻击类别一致。其他参数、请求头、参数名命中和不同攻击类别不能交叉拼凑证据。
- 查询参数只按 URL 规则解码一次；重复参数、非法查询串、解析失败和多重编码不通过二次确认，继续保留模型复核。每条路径仍受 2048 字节限制，同一参数/类别的失败解析结果在本次事务内复用。
- Shell 只导入语法解析器，不导入 interp 或执行命令；JavaScript 只生成 AST，不创建运行时；URL 只做文本与字面地址解析，不访问目标、不查询 DNS。
- HTML 普通文本、带前后解释的代码示例、嵌在 pre 等节点中的脚本示例、不执行的 script type、仅注释和无调用/赋值的内容，不通过本层确认。普通内网/回环 URL 不因地址范围而直接判恶意。
- 有对应证据时本地排除；解析器未识别、类别不一致或无法确认时继续交给模型，绝不把多库“均未命中”当成安全证明。零分且无命中的输入按上面的新策略直接保留，不再检查业务参数类型。
- Coraza 已经通过 libinjection 实现 detectSQLi/detectXSS，不重复调用它作为独立第二票。CRS 与结构解析仍可能共同误报，完整代码片段也可能是合法业务数据；这些条件识别疑似攻击结构，不证明漏洞可利用或保证零误报。

2026-11-17 历史多层判定样本验证（尚未取消类型限制）：同一份 1000 条原始输入，本地保留仍为 420 条，本地排除由 160 增至 170 条，模型复核由 420 降至 410 条（42.0% → 41.0%，复核条数减少约 2.4%）。新增 10 条均为 CRS 与 Shell 结构的共同证据；本样本 HTML/JavaScript 与元数据 URL 层没有新增排除。仍有 262 条类型/表示歧义和 148 条未被二次确认的 CRS 命中需要复核。此结果是分流数量，不是人工标注准确率，也不表示总耗时下降相同比例。

历史真实上游复测（尚未取消类型限制）：将同样的 1000 条样本扩展为 10000 条，完整处理及结果校验耗时 24.582 秒；本地保留 4200、本地排除 1700、模型复核 4100，14 个逻辑批次、19 次实际请求、上游并发峰值 5，最终保留 6890、排除 3110。上轮对应耗时为 22.982 秒、15 次请求；虽然本轮少复核 100 条，但批次数未减少且实际调用次数增加，因此尚未证明总耗时改善。本轮未重复 10 万条真实上游测试；定向竞态测试覆盖分类、顺序、取消、有界调度与 10 万条模拟处理。后端需重新构建并重启后生效，上传及轮询脚本保持原用法。

此前的参数类型/枚举清单已从当前分流逻辑删除，不再按参数名或值是否落在该清单决定送模。输入文本仍按原样处理，不删除 request_id、业务 ID 或其他参数，也不按路径模板合并不同请求的判定。

### 模型判定持久化缓存（hybrid / batch）

服务启动后自动启用，无需新增请求参数。默认缓存文件为 `<RootDir>/data/attack-path-cache/model-decisions.sqlite`，其中 `RootDir` 是服务配置中的项目根目录。使用带索引的 SQLite 文件，按当前批次查询；不会每次扫描整个历史文件，也不会将全部历史缓存读入内存。服务重启后继续复用，首次部署从空缓存开始，不自动导入旧测试报告。使用现有 SQLite 驱动，构建和运行需支持 CGO。

处理顺序：

1. **hybrid**：仍先执行当前本地规则；本地已明确保留或剔除的路径不调用模型。不确定的路径进入模型缓存查询，命中后直接复用；未命中才发送模型。
2. **batch**：所有路径先查询模型缓存；命中直接复用，未命中调用模型。
3. 只有模型完整返回且通过处理数量、索引、协议等校验的批次，才将每条路径的“保留 / 剔除”结论事务性写入缓存。明确保留也会缓存，不会因 `false` 被误当成未命中。
4. 同一批中的重复路径只发送一次，结论映射回各原始位置；同一服务实例的并发批次共享正在分析的相同路径。不同路径仍保留配置的模型并发能力。最终输出顺序、原文和进度含义保持一致。

**匹配边界**：使用完整路径原文计算 SHA-256 摘要，包括查询参数、编码形式、大小写；不会把 `/api/a?id=1` 和 `/api/a?id=2` 混为同一条，也不自动 URL 解码或按模板合并。缓存命中不发起模型请求，因此该路径不产生新的模型 Token 费用。数据库只保存摘要、判定和创建时间，不保存路径原文、参数明文、提示词或 API Key；摘要不是加密，不应当公开缓存文件。

**失效边界**：缓存键包含模型服务地址、模型名称、实际系统提示词快照、批量协议正文、CRS 指令及显式策略版本。上述内容变化会进入新的缓存命名空间，原记录不再命中。当前策略版本绑定 Coraza 3.8.1、CRS 4.25.0 和本地证据策略；维护者升级检测依赖或修改判定语义时须同步提升 `attackPathModelCachePolicy`。如果在系统提示词中使用 `{{total}}` 等动态占位符，渲染结果变化同样会使缓存失效。服务商在相同模型名称下静默更新模型无法自动检测，需手动清缓存。缓存没有自动 TTL 或数量淘汰，同一命名空间保留第一次成功存储的结论；模型误判也会被复用，不能将命中视为独立复验。

**失败处理**：模型超时、取消、失败、空缺/非法结果不写入缓存；已成功提交的其他批次可继续复用。等待同路径的请求取消不会取消其正在共享的模型调用；若原调用自身失败或取消，本次等待者也得到失败，后续任务可重试。缓存读取或写入失败会使当前任务失败，绝不按“正常路径”放行；文件损坏或不可写会导致缓存初始化失败、阻止服务启动。任务接口仍返回现有失败状态和错误提示，未增加响应字段或错误码。

**维护**：目录权限 `0700`、数据库文件 `0600`；SQLite 运行时可能存在 `-wal`、`-shm` 辅助文件，均位于该私有目录。需要清理旧记录、强制重新判断或处理损坏时，先停止服务，将整个 `data/attack-path-cache` 目录移走备份，再启动服务自动创建空缓存。不要运行中只删除数据库主文件。不同服务进程之间不协调正在进行的模型请求，因此不要把共享数据库当作分布式去重锁；多实例可能对同时出现的首次路径重复调用模型。

此缓存不改变 `cli` 模式；只在服务启动组装的 hybrid / batch 处理器中启用，直接构造原始分类器的底层集成测试不会自动启用缓存。部署需重新构建并重启服务，上传及轮询命令继续使用原接口。

### batch 模式：全部路径使用模型判定

1. 上传、去重、任务归属、落盘、下载和取消接口保持一致。每条路径使用模型判定结果：优先复用同一判定版本的历史模型缓存，仅未命中的路径实际调用模型；不采用规则放行或仅抽样判断。
2. 服务端流式读取输入，每批最多 `attack_path_batch_size` 条，且带有明确 index 编号的路径数组 JSON 编码后最多 48 KiB；长路径或转义较多时会自动减小实际批量。每个请求只包含固定分类提示词和当前批数据，不携带其他批次历史，也不让模型调用文件读写工具。
3. 每次最多并发 `attack_path_concurrency` 个批次；收到一个完成结果后即在窗口允许时补入新批次，不再等待整组请求全部完成。未按序提交的批次数（运行中与已完成等待的合计）最多为并发数的两倍，慢批次占满窗口时施加背压，不无限预读输入。模型必须返回完整处理数量和本批恶意索引；缺少字段、越界/重复索引、截断或非预期工具响应不会提交结果，同一请求批次最多容许三次格式失败（包含在五次调用上限内）。格式失败或单次请求超时且批量超过 64 条时自动二分重新判定，最多拆分三层；子批仍失败则任务失败。每个子批重新编号并映射回原位置，绝不丢弃非法索引后继续，也不按全部正常放行；鉴权、其他 HTTP 错误和父任务取消不会触发拆批。
4. 完成分类的批次按输入顺序写入正常路径，再更新 `processed` 与 `kept`。若前面的批次尚未返回，后面的已完成批次等待按序提交，因此进度可能短暂停留后一次增长多个批次；不代表串行调用模型。
5. hybrid / batch 模式使用第三方 API Key 的 `rate_limit_per_minute`，复用进程内共享限流器；0 表示不施加该本地请求频率限制，上游自身额度仍生效。HTTP 429、业务码 110602、5xx 和可重试网络错误最多调用五次，等待使用指数退避并参考 `Retry-After`（最长等待 5 分钟），取消能中断等待。每次调用最长 45 秒，整个任务最长 24 小时。
6. 所有结果仍按原顺序、原文本写出，失败或取消不会提供半成品下载。模型判断标准读取 `attack_path_filter.system`；其他四个提示词仍校验以兼容 cli 模式，但 batch 模式的文件调度与响应结构由后端执行，不由提示词覆盖。

吞吐由实际批量、并发额度、模型延迟、路径复杂度和 API Key 限流共同决定。hybrid 的提速还取决于疑难路径比例；大量复杂数据可能仍然很慢。分钟级是优化目标，不能用本地模拟测试耗时当作真实模型的 10 万条耗时。应先用真实样本验证分类质量和请求延迟，再按并发轮次数估算大任务时间。

真实模型定向验证（读取私有配置，调用当前已配置的上游）：

    MANSCAN_TEST_AI_FORCE=1 MANSCAN_TEST_ATTACK_PATH_INPUT=/absolute/path/sample.txt go test ./server/internal/service -run '^TestHybridAttackPathProcessorAIForce$' -v -count=1 -timeout=10m

可额外设置 MANSCAN_TEST_ATTACK_PATH_REPEAT=100 将同一小样本扩展为不同 benchmark_id 参数的最多 10 万条，用于同分布吞吐检查；这种扩展不代表真实生产数据的多样性或准确率。未启用 MANSCAN_TEST_AI_FORCE 时测试自动跳过，不会调用模型。

2026-11-17 上一轮类型检查优化（尚未增加第二层）：同一份原始 1000 条样本，优化前本地保留 252、排除 160、复核 588；优化后本地保留 420、排除 160、复核 420。复核比例从 58.8% 降至 42.0%，模型输入条数减少 28.6%。减少的 168 条均来自 CRS 零分且无检测命中的未知类型输入；158 条 CRS 弱命中复核数量保持不变，剩余 262 条类型/表示歧义仍复核。这是样本的分流数量变化，不能代替独立人工标注的准确率验证，也不能单凭条数比例推断总耗时。

上一轮类型检查优化的真实上游验证结果（均包含本地扫描、模型处理和结果校验，不含上传、排队、数据库进度写入及启动编译）：

| 样本 | 结果 | 模型复核 | 实际上游请求 | 耗时 |
| --- | --- | --- | --- | --- |
| 原始 1000 条 | 完成，保留 708、排除 292 | 420 条 | 3 次 | 11.822 秒 |
| 同样本扩展 10000 条 | 完成，保留 6905、排除 3095 | 4200 条，14 个逻辑批次 | 15 次，并发峰值 5 | 22.982 秒 |
| 同样本扩展 100000 条 | 未完成；达到集成测试 8 分钟 context 上限 | 未获得完整结束统计 | 未获得完整结束统计 | 480 秒后取消 |

10000 条诊断中各已完成批次记录的共享并发闸门上限均为 5。100000 条复测出现多个 50–79 秒的逻辑批次，可能包含请求等待、重试及拆分；该轮尚未记录闸门值，不能据此确认具体延迟来源。集成测试的 8 分钟超时不改变后端任务的 24 小时上限。该轮证据确认复核输入减少 28.6%，但未证明 10 万条完整耗时优于上一版；不可按 1 万条结果线性推算或承诺分钟数。保留/排除数量是模型运行结果，未做独立人工标注的准确率验证。

可只运行本地诊断，不调用模型、不输出原始路径或参数值：

    MANSCAN_TEST_ATTACK_PATH_INPUT=/absolute/path/sample.txt go test ./server/internal/service -run '^TestAttackPathRulesProfile$' -v -count=1 -timeout=90s

2026-11-17 上一版 CRS 保守策略基线（尚未扩展类型及启用补位调度）：将 1000 条原始上传样本增加不同 benchmark_id 参数扩展为 100000 条，使用 Coraza 3.8.1 / CRS 4.25.0、上述保守分流策略及模型 5 并发，完整处理和结果校验耗时 385.896 秒（6 分 25.9 秒）。本地保留 25200 条、本地排除 16000 条、模型复核 58800 条；194 个逻辑批次实际发出 216 次上游请求（包含重试及拆分），实测上游并发峰值 5；一次请求超时后通过拆分恢复。最终保留 69779 条、排除 30221 条，完成数量、输出原文、顺序及最终进度校验通过。计时包含本地规则扫描和模型处理，不包含上传、排队、数据库进度写入或服务启动时规则编译。相同源样本扩展不能替代真实生产数据的多样性与人工标注准确率评估。

该基线策略比旧手写规则更保守，复核比例由旧样本的 6.1% 增加到当时扩展样本的 58.8%，所以即使并发提高，总耗时仍高于旧基线；不能把旧的 90.525 秒作为当前版本承诺。分类数量仅为本次模型运行结果，模型仍可能误判，重复执行可能有差异。

历史基线（旧手写规则，已替换，不适用于当前 CRS）：2026-11-16 实测：将一份 1000 条上传样本按上述方式扩展为 100000 条，使用真实 AI Force、hybrid、单并发和默认批量配置，处理与结果校验耗时 90.525 秒。64400 条由规则保留、29500 条由规则排除，6100 条疑难路径分成 24 批交给模型；最终保留 70000 条、排除 30000 条，原顺序、原文本和最终进度校验通过。此计时不包含上传、任务排队和数据库进度提交，不能代表任意 10 万条生产数据的端到端耗时。

上述旧规则基线中，同一原始样本的新旧结果有 33 条分类差异：规则新增保留 16 条简单 API 路径，新增排除 17 条命中攻击特征或敏感文件规则的路径。旧模型输出并非人工标注答案，保留数量接近也不表示分类完全一致；该吞吐测试不构成准确率评估。

### cli 模式：文件处理与工具编排

1. 上传 UTF-8 TXT，每行一条路径，允许空行和 UTF-8 BOM；上限 1 GiB，去重后最多 500000 条，每条最多 2048 字节。上传流直接去重并写入 `data/attack-path-tasks/<任务ID>/input.txt`，保留首次出现顺序，不生成 multipart 临时副本。
2. 后台每次任务执行只启动一个 Claude CLI 进程。CLI 通过专用 MCP 文件工具自行编排整份文件的读取、恶意路径判断、结果写入和完成确认；不再由服务端按固定 500 条反复启动 CLI。
3. 工具 `read_paths` 从当前任务文件读取待处理路径；Claude 可选择每次读取数量（默认 1000，最大 2000），但实际返回量还受 16000 字节预算限制，预算包含路径的 JSON 引号、转义与分隔符，并为进度元数据预留空间。这可避免大段工具结果被 CLI 转存到当前会话无法读取的临时文件，导致反复读取而不提交。未提交时重读返回相同片段，供重试或上下文压缩后继续处理。
4. 工具 `write_filtered_paths` 接收片段 ID 与恶意路径编号，直接将原始正常路径按顺序写入本地结果 TXT，并更新数据库中的 `processed`、`kept`。重复提交相同片段与判断不会重复写入。前端继续轮询现有状态接口。
5. 工具 `finish` 校验所有路径均已提交、无未处理片段，完成文件同步。CLI 成功退出且文件工具确认完成后，任务才标记 `completed`；仅返回“处理完成”等自然语言不能让任务成功。
6. 下载接口直接流式读取 `data/attack-path-tasks/<任务ID>/output.<执行租约>.txt`。数据库不保存 TXT 正文，只在 `output_file_name` 列保存受校验的结果文件名。输入和结果均必须存在对应的本地文件，不再回退读取数据库正文。

模型请求链路：`Claude CLI → 服务端本地 Messages 适配器 → https://ai-force.duxiaoman-int.com/agent-api/openai/v1/chat/completions`。适配器读取并解密数据库密钥，附加 Authorization、UUAP-ID 和随机 REQUEST-ID，并转换工具定义、tool_use/tool_result、tool_calls 及结束原因。上游完整返回后会转为 CLI 所需的 Messages JSON/SSE；此处不是上游逐 token 实时转发。

文件工具链路：`Claude CLI → 仅回环监听、随机凭据鉴权的任务 MCP 服务 → 当前任务已打开的输入/结果文件`。CLI 只允许上述三个 MCP 工具，使用独立临时配置、严格 MCP 配置和非交互权限模式；内置通用 Shell/任意文件工具不开放。文件工具不接收任意路径、命令或替换文本，无法通过路径参数访问其他任务或服务器配置。上传路径仅作为模型判断数据，不会对这些路径发起 HTTP 请求。

cli 模式单次任务执行最长 24 小时；每次 AI Force 请求最长 5 分钟，取消和租约失效会终止执行。失败或取消的任务不提供半成品下载。结果目录应挂载持久化磁盘；多实例必须共享文件系统。反向代理需允许 1 GiB 文件及 multipart 开销，并设置合适的上传超时。模型分类仍可能误判，工具编排和大文件读取不会保证模型速度或准确率。

所有接口要求 JWT 登录，提交者只能查询、取消、下载自己的任务。接口调用方式如下。

### POST /api/v1/attack-path-filter-tasks

- 请求参数：`multipart/form-data`，必填文件字段 `file`，文件名后缀 `.txt`。不支持 JSON、单路径或普通文本提交。
- 响应格式：HTTP 202，统一 JSON 响应。`data` 包含 `id`（随机任务 ID）、`status`（初始为 `queued`）、`total`（去重后路径数）、`processed`、`kept`、`created_at`；完成后还可包含 `finished_at` 和失败时的 `error_message`。
- 错误码：40001（文件缺失、超过 1 GiB 或内容不合法）、40101（未登录）、50301（AI Force 配置未设置）、50001（输入落盘或任务持久化失败）。
- 示例：`curl -H 'Authorization: Bearer <token>' -F 'file=@paths.txt;type=text/plain' https://<server>/api/v1/attack-path-filter-tasks`

### GET /api/v1/attack-path-filter-tasks/:id

- 请求参数：路径参数 `id`，提交接口返回的任务 ID。
- 响应格式：统一 JSON 响应，`data` 为任务状态和进度；`status` 取值 `queued`、`running`、`completed`、`failed`、`cancelled`。前端可定期轮询，直到状态不再是 `queued` 或 `running`。
- 错误码：40101（未登录）、40401（任务不存在或不属于当前用户）、50001（查询失败）。
- 示例：`curl -H 'Authorization: Bearer <token>' https://<server>/api/v1/attack-path-filter-tasks/<id>`

### GET /api/v1/attack-path-filter-tasks/:id/download

- 请求参数：路径参数 `id`。
- 响应格式：任务 `completed` 时流式返回 `text/plain; charset=utf-8` 附件 `normal-api-paths.txt`，仅包含去重且删除恶意路径后的正常 API 路径，每行一条；没有正常路径时返回空文件。文件下载不使用 JSON 封装。
- 错误码：40101（未登录）、40401（任务不存在或不属于当前用户）、50301（任务未完成或失败）、50001（结果文件名为空或不合法、结果文件缺失或读取失败）。错误响应使用统一 JSON 封装。
- 示例：`curl -H 'Authorization: Bearer <token>' -OJ https://<server>/api/v1/attack-path-filter-tasks/<id>/download`

### POST /api/v1/attack-path-filter-tasks/:id/cancel

- 请求参数：路径参数 `id`。
- 响应格式：统一 JSON 响应，`data` 为取消后的任务状态；已结束的任务保持原状态。
- 错误码：40101（未登录）、40401（任务不存在或不属于当前用户）、50001（取消失败）。
- 示例：`curl -X POST -H 'Authorization: Bearer <token>' https://<server>/api/v1/attack-path-filter-tasks/<id>/cancel`
