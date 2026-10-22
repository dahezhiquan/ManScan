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

服务端启动前必须配置 `auth.jwt_secret` 或环境变量 `MANSCAN_JWT_SECRET`，密钥长度至少 32 个字符；可通过 `auth.token_ttl_minutes` 或 `MANSCAN_TOKEN_TTL_MINUTES` 调整访问令牌有效期，默认 480 分钟。

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
- 高危开放端口口径：`manscan_asset_host_port` 中同时满足 `is_alive=1` 和 `is_high_risk_port=1` 的记录数，不按主机去重。
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

- 字段说明：`top_vulnerabilities` 表示主机 IP 与漏洞数量，`top_ports` 表示主机 IP 与开放端口数量。只返回存在对应记录且登记在 `manscan_asset_host` 中的主机，不补零，不要求主机本身 `is_alive=1`。
- 漏洞数量口径：按 `asset_host` 关联 IP，统计所有状态的漏洞记录，与主机资产列表的漏洞总数口径一致；不会将仅有域名端点、没有主机 IP 关联的漏洞猜测分配给主机。
- 端口数量口径：按 `ip_address` 关联 IP，仅统计端口 `is_alive=1` 的记录，同一 IP 的 TCP/UDP 不同协议端口分别计数，与主机资产列表的开放端口数量口径一致。
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
  - 当漏洞来自多步 HTTP POC 时，`detail.request` 和 `detail.response` 会保存为 JSON 对象，对象内部按 `1`、`2` 这样的编号键保存每一步请求/响应，便于前端按步骤展示完整请求链。
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
  - 删除时会清理对应的运行期目录和内存态数据，不再保留日志、进度和恢复文件。

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
  - `request`、`response` 分别表示该域名资产最近一次探测保存的请求与响应原文；没有记录时返回空字符串。
  - `vulnerability_count` 表示漏洞表中 `asset_endpoint` 等于当前域名资产 `domain` 的记录数量。
  - `critical_count`、`high_count`、`medium_count`、`low_count` 表示上述关联漏洞中各严重等级的数量，按漏洞表 `severity` 字段统计。
  - `risk_level` 表示当前资产的最高风险等级，按 `critical > high > medium > low` 取值；存在漏洞但没有可识别等级时返回 `unknown`，没有漏洞时返回 `info`。
  - `component_count` 表示域名组件表中 `domain` 等于当前域名资产 `domain` 且 `is_alive = true` 的组件数量。
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
  - `service_assets` 来自 `manscan_asset_domain_service_assets`，按当前域名精确匹配 `domain` 字段。
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
  - `port_count` 表示主机端口表中 `ip_address` 等于当前主机 `ip_address` 且 `is_alive = true` 的端口数量。
  - `os_type`、`region` 为模糊筛选；`risk_level=high` 仅返回最高风险等级为高危的资产，存在严重漏洞的资产会归入 `critical`。
  - 列表默认按最近存活时间和 ID 倒序排序。

- 错误码说明：
  - `40001`：分页参数非法，或 `is_alive`、`has_vulnerability`、`has_port` 不是布尔值
  - `50001`：获取主机资产清单失败

- 使用示例：

```bash
curl "http://127.0.0.1:8686/api/v1/host-assets?page=1&page_size=10&keyword=10.72&os_type=linux&region=生产&risk_level=critical&has_vulnerability=true&has_port=true"
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
  - `ports` 来自 `manscan_asset_host_port`，按当前主机精确匹配 `ip_address` 字段。
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
