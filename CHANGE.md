## 2026-09-02 10:43 记录漏洞详情中的完整 POC 请求链

- 变动目录：`pkg/protocols/http/`
- 变动文件：`pkg/protocols/http/operators.go`、`pkg/protocols/http/operators_test.go`
- 具体修改内容：
  - 在 `pkg/protocols/http/operators.go` 中新增 POC 历史请求/响应的汇总逻辑，优先收集 `request_1`、`request_2`、`response_1`、`response_2` 这类带序号的历史字段，再按顺序拼接成完整文本输出到 `ResultEvent.Request` 和 `ResultEvent.Response`。
  - 为多请求结果增加清晰的分段标识，保留原始请求/响应内容的顺序，避免后续漏洞详情页只看到最后一次 POC 请求。
  - 在 `pkg/protocols/http/operators_test.go` 中新增回归测试，覆盖多请求 POC 场景下结果事件会同时包含第一段和最后一段请求/响应内容，确保历史链路不会再次被覆盖。
- 修改目的或影响：
  - 修复漏洞详情页中的 `detail.request` 和 `detail.response` 只保存最后一个请求/响应的问题，让多步骤 POC 的完整交互链都能落到后端存储和前端展示中。
  - 这次调整只影响 HTTP 结果事件的历史拼接方式，不改变普通单请求模板的输出内容和现有接口结构。

## 2026-08-27 13:16 修复暂停恢复后断点与状态切换失真

- 变动目录：`cmd/nuclei/`、`internal/runner/`
- 变动文件：`cmd/nuclei/main.go`、`internal/runner/runner.go`
- 具体修改内容：
  - 在 `cmd/nuclei/main.go` 中调整 Ctrl+C 的收尾顺序，先调用 `SaveResumeConfig()` 写出断点文件，再执行 `Runner.Close()` 关闭运行器资源，避免暂停时因先关闭 dialer、项目文件或输出写入器而把未完成模板误判成已完成。
  - 在 `internal/runner/runner.go` 中，当命中已有 `resume` 文件并进入恢复模式时，强制关闭模板聚类，避免恢复后的模板 ID 和聚类映射重新洗牌，导致断点窗口失真、后半段模板被跳过。
- 修改目的或影响：
  - 修复扫描任务暂停后继续执行时，因关闭顺序不当和恢复时仍启用聚类导致的漏扫问题。
  - 让恢复扫描保持和断点文件一致的模板顺序与执行边界，减少恢复后“总请求数偏少、漏洞数量明显少于完整扫描”的情况。
  - 这次调整只影响 CLI/runner 恢复链路，不改变正常新扫描的聚类与缓存策略，因此不会拖慢未恢复任务的扫描速度。

## 2026-08-27 12:52 修复暂停恢复断点漏扫

- 变动目录：`pkg/core/`、`pkg/types/`
- 变动文件：`pkg/core/executors.go`、`pkg/core/executors_test.go`、`pkg/types/resume.go`、`pkg/types/resume_test.go`
- 具体修改内容：
  - 在 `pkg/core/executors.go` 中调整模板执行断点维护逻辑：当扫描上下文因暂停或取消结束时，不再清理正在执行的 target 的 `inFlight` 记录，避免保存 `resume.cfg` 时丢失未完成目标。
  - 在 `pkg/core/executors.go` 中增加上下文取消判断，只有模板完整执行结束时才将模板标记为 `Completed=true`，防止暂停时把未完成模板误判为已完成。
  - 在 `pkg/core/executors.go` 中跳过 host-error 目标时继续推进 target 索引，保证后续断点位置不被跳过分支打乱。
  - 在 `pkg/types/resume.go` 中修复 resume 配置编译逻辑：当模板未完成但 `inFlight` 为空时，按保守重扫处理，不再把 `SkipUnder` 保持为 `math.MaxUint32` 导致恢复后跳过所有 target。
  - 在 `pkg/core/executors_test.go` 中新增取消时保留 `inFlight` 且不标记完成的回归测试。
  - 新增 `pkg/types/resume_test.go`，覆盖未完成空断点窗口应重扫而不是全跳过的场景。
- 修改目的或影响：
  - 修复扫描任务暂停后继续扫描可能漏扫的问题，避免任务恢复后显示成功但漏洞数量少于完整扫描结果。
  - 对断点不完整的情况采用“宁可重扫，不可漏扫”的策略，可能在极端暂停时多执行少量请求，但不会改变正常扫描的并发、限速和模板调度逻辑。
  - 提升暂停恢复后进度、实际请求数和漏洞统计的可信度，减少任务 51 这类恢复后命中数量明显偏少的问题。

## 2026-06-09 16:24 本地模块名切换为 ManScan

- 变动目录：全目录
- 具体修改内容：
  - 将 `go.mod` 的模块声明从 `github.com/projectdiscovery/nuclei/v3` 改为本地模块名 `ManScan`。
  - 将所有 Go 源码、测试代码、示例代码、JS 绑定生成代码以及相关模板中的内部导入路径，从 `github.com/projectdiscovery/nuclei/v3/...` 统一替换为 `ManScan/...`。
  - 同步调整 `lib/README.md` 中展示的库导入示例路径，避免文档中的示例仍然指向旧模块名。
- 修改目的或影响：
  - 让仓库作为本地模块 `ManScan` 编译时，内部包引用能够直接解析到当前工作区，避免继续引用旧的 `github.com/projectdiscovery/nuclei/v3` 路径导致构建或测试报错。
  - 这次变更主要是模块路径层面的统一替换，不涉及业务逻辑调整，但会影响所有依赖仓库内部包路径的源码、测试、示例与文档引用方式。

## 2026-06-09 16:42 默认关闭更新检查并移除更新提示

- 变动目录：`pkg/catalog/config/`、`internal/runner/`
- 变动文件：`pkg/catalog/config/nucleiconfig.go`、`internal/runner/runner.go`
- 具体修改内容：
  - 在 `pkg/catalog/config/nucleiconfig.go` 中调整 `DefaultConfig` 初始化逻辑，将 `disableUpdates` 默认设为 `true`，使 `ManScan` 启动时默认不执行引擎更新检查和模板更新检查。
  - 在 `internal/runner/runner.go` 中移除启动阶段输出的 `nuclei` 与 `nuclei-templates` 版本更新提示，避免默认关闭更新检查后仍向终端输出更新相关提醒文案。
- 修改目的或影响：
  - 让 `ManScan` 在默认配置下不再自动检查程序更新与模板更新，减少启动时的外部更新行为。
  - 避免默认禁用更新检查后仍出现更新相关提示，保持终端输出更干净，同时不影响用户显式执行更新相关参数时的原有能力。

## 2026-06-09 18:09 取消模版签名验证

- 变动目录：`pkg/templates/`
- 变动文件：`pkg/templates/compile.go`
- 具体修改内容：
  - 在模板编译阶段的 `applyTemplateVerification` 中直接将模板标记为已验证，不再执行默认签名校验器和缓存签名校验结果的分支。
  - 保留原有模板加载、编译与执行链路，仅通过复用现有 `Verified` 判定结果，让普通协议模板、带请求签名的模板以及 `code` 协议模板不再因为未签名或签名不匹配被拦截。
  - 同时继续保留原始模板内容到 `RawTemplate`，避免影响后续依赖原模板内容的输出能力。
- 修改目的或影响：
  - 用最小代码改动关闭模板签名验证逻辑，覆盖普通协议和 `code` 协议模板的加载限制。
  - `DisableUnsignedTemplates`、请求签名模板校验限制以及 `code` 模板未签名拦截会因模板恒为“已验证”而失效，后续执行时不再出现对应跳过行为。

## 2026-06-09 19:31 默认运行数据统一迁移到 data 目录

- 变动目录：`cmd/nuclei/`、`internal/runner/`、`lib/`、`pkg/catalog/config/`、`pkg/output/`、`pkg/protocols/headless/engine/`、`pkg/reporting/`、`pkg/scan/events/`、`pkg/types/`
- 变动文件：`cmd/nuclei/main.go`、`internal/runner/options.go`、`internal/runner/runner.go`、`lib/sdk_private.go`、`pkg/catalog/config/datadir.go`、`pkg/catalog/config/nucleiconfig.go`、`pkg/output/file_output_writer.go`、`pkg/protocols/headless/engine/engine.go`、`pkg/reporting/dedupe/dedupe.go`、`pkg/reporting/exporters/jsonexporter/jsonexporter.go`、`pkg/reporting/exporters/jsonl/jsonl.go`、`pkg/reporting/exporters/markdown/markdown.go`、`pkg/reporting/exporters/pdf/pdf.go`、`pkg/reporting/exporters/sarif/sarif.go`、`pkg/scan/events/stats_build.go`、`pkg/types/resume.go`
- 具体修改内容：
  - 在 `pkg/catalog/config/datadir.go` 中新增统一的数据目录定位工具，将项目运行期默认数据根目录固定为仓库根目录下的 `data/`，并为 `config`、`cache`、`templates`、`tmp`、`project`、`responses`、`reports`、`stats` 等子目录提供统一路径函数。
  - 在 `pkg/catalog/config/nucleiconfig.go` 中将默认配置目录、缓存目录和模板目录迁移到 `data/config/`、`data/cache/`、`data/templates/`，并调整 `.nuclei-ignore` 的初始化逻辑为优先迁移旧系统配置中的 ignore 文件，否则在新目录下创建默认空文件。
  - 在 `internal/runner/options.go`、`cmd/nuclei/main.go`、`pkg/types/resume.go` 中将默认响应落盘目录、项目缓存目录、resume 文件目录、crash resume 文件目录、inline secrets 临时目录统一迁移到 `data/responses/`、`data/project/`、`data/cache/resume/`、`data/cache/crash/`、`data/tmp/secrets/`。
  - 在 `internal/runner/runner.go` 和 `lib/sdk_private.go` 中将 CLI 和 SDK 运行时临时目录迁移到 `data/tmp/runtime/`，并在 `pkg/protocols/headless/engine/engine.go` 中将 headless 浏览器的用户数据目录迁移到 `data/tmp/headless/`。
  - 在 `pkg/reporting/dedupe/dedupe.go`、`pkg/reporting/exporters/jsonexporter/jsonexporter.go`、`pkg/reporting/exporters/jsonl/jsonl.go`、`pkg/reporting/exporters/markdown/markdown.go`、`pkg/reporting/exporters/pdf/pdf.go`、`pkg/reporting/exporters/sarif/sarif.go` 中统一导出和去重模块的默认落盘位置，将去重库和默认报告路径迁移到 `data/cache/reporting/` 与 `data/reports/`，并补充父目录自动创建逻辑。
  - 在 `pkg/scan/events/stats_build.go` 中将带 `stats` build tag 的扫描统计目录从当前工作目录迁移到 `data/stats/`。
- 修改目的或影响：
  - 将 `ManScan` 默认运行期产物统一收口到项目根目录 `data/` 下，避免继续分散写入用户家目录、系统临时目录或当前工作目录。
  - 让配置、模板、缓存、临时文件、响应落盘、统计文件和默认报告产物按目录分类管理，便于排查、清理、打包和文档化维护。

## 2026-06-09 19:57 调整 .nuclei-ignore 默认初始化来源

- 变动目录：`pkg/catalog/config/`
- 变动文件：`pkg/catalog/config/nucleiconfig.go`
- 具体修改内容：
  - 在 `pkg/catalog/config/nucleiconfig.go` 中移除从旧系统级配置目录迁移 `.nuclei-ignore` 的兼容逻辑。
  - 将 `.nuclei-ignore` 的默认初始化来源改为 `data/config/.templates-config.json` 当前记录的模板目录；如果该模板目录下存在 `.nuclei-ignore`，则复制到 `data/config/.nuclei-ignore`。
  - 当模板目录中不存在 `.nuclei-ignore` 时，继续在 `data/config/` 下创建一个空的默认 ignore 文件，保证运行期依赖的必需文件始终存在。
- 修改目的或影响：
  - 让 ignore 文件来源与当前项目内 `data/` 目录体系保持一致，不再依赖用户机器上历史遗留的系统级配置目录。
  - 保证模板忽略规则优先跟随当前模板目录配置，同时保留空默认文件兜底，避免首次启动因缺少 ignore 文件而报错。

## 2026-06-09 20:24 修复默认启动未创建 .nuclei-ignore 的初始化漏洞

- 变动目录：`pkg/catalog/config/`
- 变动文件：`pkg/catalog/config/nucleiconfig.go`、`pkg/catalog/config/ignorefile.go`、`pkg/catalog/config/ignorefile_test.go`
- 具体修改内容：
  - 在 `pkg/catalog/config/nucleiconfig.go` 的默认配置初始化流程中，完成模板目录设置后立即执行 `.nuclei-ignore` 补齐逻辑，确保默认启动路径下也会把模板目录中的 ignore 文件复制到 `data/config/`。
  - 在 `pkg/catalog/config/ignorefile.go` 中为 `ReadIgnoreFile()` 增加读取前自愈逻辑；如果 `data/config/.nuclei-ignore` 缺失，会先尝试从当前模板目录补齐，再继续读取。
  - 新增 `pkg/catalog/config/ignorefile_test.go`，覆盖“配置目录缺少 `.nuclei-ignore` 时，读取逻辑会自动从模板目录复制并成功解析”的回归场景。
- 修改目的或影响：
  - 修复默认启动时未经过 `SetConfigDir()` 导致 `.nuclei-ignore` 不会自动创建的问题。
  - 即使后续有人手动删除 `data/config/.nuclei-ignore`，运行时读取也会先自愈再继续，避免再次出现文件不存在错误。

## 2026-06-22 17:01 提前输出扫描预估总请求数

- 变动目录：`pkg/progress/`
- 变动文件：`pkg/progress/progress.go`
- 具体修改内容：
  - 在 `pkg/progress/progress.go` 的 `StatsTicker.Init` 中，扫描统计初始化完成后立即输出一次当前进度快照，不再等待首个定时统计周期才打印 `stats-json`。
  - 抽取统一的当前进度输出方法，复用到初始化阶段和停止阶段，保持 JSON 与普通进度输出路径一致。
  - 为 RPS 和进度百分比计算增加零时长、零总请求数保护，避免初始化瞬间或总数为 `0` 时出现不稳定的计算结果。
- 修改目的或影响：
  - 让扫描详情页依赖的 `progress.total_requests` 能在扫描刚开始时就通过后端进度流被感知，而不是等到扫描结束或首个统计周期后才出现。
  - 对于执行很快的短任务，也能更稳定地保留初始化阶段的预估总请求数，减少详情页“预估总请求数为空/结束后才显示”的情况。

## 2026-06-22 20:20 改用内存计数统计实际请求数并移除 trace 日志依赖

- 变动目录：`internal/runner/`、`internal/tests/testutils/`、`pkg/progress/`、`pkg/protocols/http/`
- 变动文件：`internal/runner/runner.go`、`internal/tests/testutils/testutils.go`、`pkg/progress/progress.go`、`pkg/protocols/http/request.go`
- 具体修改内容：
  - 在 `pkg/progress/progress.go` 中为扫描进度新增内部 `actual_requests` 计数器，并扩展 `Progress` 接口与 `stats-json` 输出，使扫描进程可以直接维护真实发出的请求数。
  - 在 `pkg/protocols/http/request.go` 中将 HTTP 实际请求计数前移到真正调用 `Do`、`Dor`、`DoRaw`、`SendRawRequest` 的发送位置，只对真实出网的 HTTP 请求累加，自动排除项目缓存命中的情况。
  - 在 `internal/runner/runner.go` 中复用统一请求日志 hook，为非 HTTP 协议补充内部真实请求计数，同时继续保留 DAST 错误事件采集逻辑。
  - 在 `internal/tests/testutils/testutils.go` 中同步补齐新的进度接口桩实现，避免测试代码因接口扩展而失配。
- 修改目的或影响：
  - 扫描详情页和后端运行时不再依赖 `data/runtime/<task-id>/trace.log` 回扫统计真实请求数，显著减少大任务下的磁盘占用。
  - 对外接口继续只暴露 `requests` 作为真实请求数，HTTP 场景下统计口径与原先“`from_cache=false` 才计数”的需求保持一致。
