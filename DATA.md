# DATA 目录说明

本文档说明 `ManScan` 运行时默认生成到项目根目录 `data/` 下的配置、缓存、模板、报告和临时文件。

## 目录总览

默认数据根目录：

```text
data/
├── cache/
├── config/
├── project/
├── reports/
├── responses/
├── stats/
├── templates/
└── tmp/
```

说明：

- 只有在对应功能被触发时，相关子目录和文件才会真正创建。
- 如果用户显式通过命令行参数或环境变量指定了其他路径，则以用户指定路径为准。

## 默认一定会涉及的目录和文件

### `data/config/.templates-config.json`

- 触发条件：首次正常启动并进入 `runner.New` 时。
- 作用：
  - 保存模板目录路径。
  - 保存模板版本号。
  - 保存忽略文件哈希、模板版本缓存等元数据。
- 典型用途：
  - 后续启动时恢复模板相关配置。
  - 判断模板是否需要更新、索引是否需要重建。

### `data/config/.nuclei-ignore`

- 触发条件：首次初始化配置目录时。
- 作用：
  - 保存模板忽略规则。
  - 用于屏蔽弱规则或不希望执行的模板标签/文件。
- 兼容行为：
  - 如果 `data/config/.templates-config.json` 中配置的模板目录下存在 `.nuclei-ignore`，会优先复制到这里。
  - 如果模板目录中不存在该文件，则在这里创建一个空的默认文件。

### `data/config/reporting-config.yaml`

- 触发条件：首次创建报告模块默认配置时。
- 作用：
  - 作为 reporting 模块的默认 YAML 配置文件占位。
  - 用于后续填写 GitHub/GitLab/Jira/Markdown/PDF/JSON 等导出或跟踪配置。

## 缓存目录

### `data/cache/resume/resume-<xid>.cfg`

- 触发条件：
  - 扫描过程中收到 `Ctrl+C` 中断。
  - 使用 `-resume` / 断点恢复流程。
- 作用：
  - 保存扫描断点状态。
  - 便于后续恢复未完成扫描。

### `data/cache/crash/crash-resume-file-<dump-id>.dump`

- 触发条件：启用 hang monitor 并触发异常转储时。
- 作用：
  - 保存异常场景下的恢复断点文件。
  - 便于排障或恢复扫描。

### `data/cache/reporting/leveldb/`

- 触发条件：启用报告导出或 issue tracker 去重能力，且未显式指定 `-report-db` 时。
- 作用：
  - 作为 reporting 去重数据库默认目录。
  - 避免同一结果被重复上报或重复导出。

### `data/cache/reporting/leveldb/session-*`

- 触发条件：某些内部调用没有显式提供去重数据库路径时。
- 作用：
  - 创建临时 reporting 去重会话目录。
  - 会在会话关闭后清理。

## 运行时临时目录

### `data/tmp/runtime/nuclei-tmp-*`

- 触发条件：CLI 或 SDK 初始化运行时临时目录时。
- 作用：
  - 存放协议执行过程中产生的临时文件。
  - 也是代码执行、模板执行器等功能的临时工作目录父路径。

### `data/tmp/secrets/inline-secrets-*.yaml`

- 触发条件：模板 profile 中包含内联 `secrets` 配置时。
- 作用：
  - 将 profile 中的内联 secrets 落盘为临时 YAML 文件。
  - 供现有认证/密钥加载逻辑复用。
- 生命周期：
  - 进程退出时会尝试删除。

### `data/tmp/headless/nuclei-*`

- 触发条件：启用 headless 模式且未连接外部 CDP 时。
- 作用：
  - 作为本地浏览器用户数据目录。
  - 保存 Chrome/rod 的运行态缓存与 profile 数据。

## 项目缓存目录

### `data/project/`

- 触发条件：启用 `-project` 时。
- 作用：
  - 保存请求去重项目缓存。
  - 避免对同一请求重复发送。

说明：

- 该目录下具体文件名由底层 `hybrid.HybridMap` 存储实现决定。
- 本项目只保证其默认父目录迁移到 `data/project/`。

## 响应落盘目录

### `data/responses/`

- 触发条件：
  - 启用 `-store-resp`。
  - 或手动指定 `-store-resp-dir` 但未显式开启时，程序会自动开启 `store-resp`。
- 作用：
  - 保存请求和响应调试数据。
  - 便于复盘扫描命中细节。

说明：

- 其中的子目录和文件名会随 host、template、协议类型等运行上下文变化。

## 报告目录

以下文件不会在普通扫描时自动生成；只有当对应导出器启用后才会写入。

### `data/reports/markdown/index.md`

- 触发条件：启用 Markdown 导出器且未显式指定导出目录时。
- 作用：
  - 保存 Markdown 总索引页。
  - 汇总所有发现项入口。

### `data/reports/markdown/*.md`

- 触发条件：启用 Markdown 导出器且产生发现项时。
- 作用：
  - 为每个发现项生成独立 Markdown 报告。

### `data/reports/json/nuclei-report.json`

- 触发条件：启用 JSON 导出器且未显式指定文件路径时。
- 作用：
  - 保存结构化 JSON 报告。

### `data/reports/jsonl/nuclei-report.jsonl`

- 触发条件：启用 JSONL 导出器且未显式指定文件路径时。
- 作用：
  - 保存逐行 JSONL 报告。

### `data/reports/sarif/nuclei-report.sarif`

- 触发条件：启用 SARIF 导出器且未显式指定文件路径时。
- 作用：
  - 保存 SARIF 格式报告。
  - 适合对接代码扫描平台或安全平台。

### `data/reports/pdf/nuclei-report.pdf`

- 触发条件：启用 PDF 导出器且未显式指定文件路径时。
- 作用：
  - 保存最终 PDF 扫描报告。

## 统计目录

### `data/stats/nuclei-stats-<timestamp>/config.json`

- 触发条件：以 `stats` build tag 构建并启用统计事件记录时。
- 作用：
  - 保存本次扫描统计配置。
  - 包括目标数、模板数、并发数、重试数等。

### `data/stats/nuclei-stats-<timestamp>/events.jsonl`

- 触发条件：同上。
- 作用：
  - 按 JSONL 记录扫描开始、结束等统计事件。

## 其他可能出现的文件

### `data/config/config.yaml`

- 默认情况下不会主动创建。
- 仅在特定配置迁移或自定义配置目录读取流程中，才可能作为 CLI 配置文件出现。

### `data/config/keys/`

- 默认情况下不会主动创建。
- 仅在模板签名、签名验证、签名器生成密钥等场景中使用。

## 一句话总结

当前默认策略是：

- 配置放到 `data/config/`
- 模板放到 `data/templates/`
- 缓存放到 `data/cache/`
- 临时文件放到 `data/tmp/`
- 项目去重缓存放到 `data/project/`
- 响应落盘放到 `data/responses/`
- 报告放到 `data/reports/`
- 统计文件放到 `data/stats/`

这样可以把运行期产物全部收敛到仓库内，便于排查、备份、清理和按目录分类管理。
