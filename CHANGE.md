## 2026-09-10 修复自动模版映射分阶段进度统计

- 变动目录：`pkg/progress/`、`pkg/protocols/common/automaticscan/`、`internal/tests/testutils/`、`server/internal/pkg/scanruntime/`、`server/internal/service/`、`server/`
- 变动文件：`pkg/progress/progress.go`、`pkg/progress/progress_test.go`、`pkg/protocols/common/automaticscan/automaticscan.go`、`internal/tests/testutils/testutils.go`、`server/internal/pkg/scanruntime/runtime.go`、`server/internal/pkg/scanruntime/runtime_test.go`、`server/internal/service/scan_task_service.go`、`server/API.md`
- 具体修改内容：
  - 在 `pkg/protocols/common/automaticscan/automaticscan.go` 中将自动扫描改为按目标流水线执行：单个目标完成指纹识别与模版映射后立即启动漏洞模版，其他目标继续并行指纹识别；全部目标完成映射后再汇总指纹请求和映射模版请求得到预估总量。
  - 在 `pkg/protocols/common/automaticscan/automaticscan.go` 中让漏洞识别阶段复用外层真实进度对象，并屏蔽 inner engine 的重复初始化，避免请求统计被覆盖或重复初始化。
  - 在 `pkg/progress/progress.go` 中增加“总请求数已确定”状态，去除 `total=0` 时将当前 requests 伪装成 total 的兜底；总量未知时 stats-json 不再输出 total 和 percent。
  - 在 `pkg/progress/progress.go` 中补充自动指纹 Wappalyzer 请求的逻辑请求和实际请求计数，使预估总量与已完成请求使用同一统计口径。
  - 在 `pkg/protocols/common/automaticscan/automaticscan.go` 中为漏洞阶段的动态 `AddToTotal` 增加汇总闸门，先缓存目标级动态增量，待全部目标映射完成后随全局预估值一次性发布，避免单个目标提前把状态切换为已计算。
  - 在 `server/internal/pkg/scanruntime/runtime.go` 中自定义进度快照序列化：总量未知时省略总量和完成度，已确定总量后即使完成度为 `0` 也保留字段。
  - 在 `server/internal/pkg/scanruntime/runtime.go` 中让 `calculating` 到 `running` 的状态切换绕过进度节流，确保总量刚确定时 SSE 能立即通知前端。
  - 在 `internal/tests/testutils/testutils.go` 中同步补齐进度桩的总量设置方法；总量设置采用可选能力探测，未实现该方法的外部进度实现仍兼容并回退到增量统计。
  - 在 `pkg/progress/progress_test.go`、`server/internal/pkg/scanruntime/runtime_test.go` 中新增总量未知、总量切换和已知零完成度的回归测试。
  - 修改目的或影响：
  - 指纹识别阶段前端不再被错误地推进到 100%，而是保持 `calculating` 状态并继续输出“扫描进度更新”；全部指纹映射完成后才展示稳定的预估总请求数和漏洞识别完成度。
  - 保留指纹识别与漏洞识别的流水线并行能力，不额外执行探测请求；漏洞模版请求仍按原有并发和限速配置执行。

## 2026-09-09 18:46 过滤自动识别阶段的 detect 标签

- 变动目录：`pkg/protocols/common/automaticscan/`
- 变动文件：`pkg/protocols/common/automaticscan/automaticscan.go`、`pkg/protocols/common/automaticscan/automaticscan_test.go`
- 具体修改内容：
  - 在自动指纹识别结果输出和最终漏洞模版加载前统一移除 `detect` 标签，避免前端展示内部识别标签，也避免将其作为模版选择条件。
  - 当过滤后没有可执行的漏洞标签时直接跳过后续漏洞模版加载，并新增大小写不敏感的过滤回归测试。
- 修改目的或影响：
  - 防止 `detect` 标签出现在前端自动识别日志中或扩大最终漏洞模版选择范围。

## 2026-09-09 18:46 当前目标写入自动指纹识别 tags 日志

- 变动目录：`pkg/protocols/common/automaticscan/`、`server/internal/pkg/scanruntime/`
- 变动文件：`pkg/protocols/common/automaticscan/automaticscan.go`、`server/internal/pkg/scanruntime/runtime.go`、`server/internal/pkg/scanruntime/runtime_test.go`
- 具体修改内容：
  - 将自动指纹识别完成日志中的固定文案“目标”替换为当前扫描目标，输出格式调整为 `<target> 已完成自动指纹识别：<tags>`。
  - 更新服务端日志解析逻辑，识别带实际目标前缀的自动指纹识别消息，并拒绝缺少目标的无效消息。
  - 更新回归测试，验证前端事件保留实际目标和 tags 内容。
- 修改目的或影响：
  - 修复前端自动模版映射 tags 结果无法区分具体扫描目标的问题，让多目标扫描时每条 tags 结果都能准确对应到本次扫描目标。

## 2026-09-09 14:28 自动扫描完成指纹识别后向前端输出 tags

- 变动目录：`pkg/protocols/common/automaticscan/`、`server/internal/pkg/scanruntime/`
- 变动文件：`pkg/protocols/common/automaticscan/automaticscan.go`、`server/internal/pkg/scanruntime/runtime.go`、`server/internal/pkg/scanruntime/runtime_test.go`
- 具体修改内容：
  - 在自动扫描完成 Wappalyzer 和指纹探测模版执行、合并并去重最终 tags 后，新增一条 info 日志，输出格式为 `目标已完成自动指纹识别：<tags>`。
  - 使用执行器配置中的 `Info()` logger 输出，并将日志放在最终模版加载前且不受 `VerboseVerbose` 开关限制，确保服务端扫描运行时能够解析并推送到前端。
  - 当目标未识别到任何 tags 时也输出空 tags 日志，然后继续执行原有的跳过自动扫描逻辑。
  - 在 `server/internal/pkg/scanruntime/runtime.go` 中仅将该指定 info 日志转成前端 `info` 事件，并去除 `[INF]`/`[INFO]` 前缀；其它普通 info 日志继续保持原有过滤行为。
  - 在 `server/internal/pkg/scanruntime/runtime_test.go` 中新增回归测试，验证自动指纹识别 info 日志能够被捕获并保留完整 tags 内容。
- 修改目的或影响：
  - 让前端能够在自动指纹识别结束后及时看到当前目标最终用于模版匹配的 tags。
  - 不改变 tags 的识别、过滤、去重和最终模版加载行为，也不增加其它引擎 info 日志的前端噪音。

## 2026-09-03 15:48 将 HTTP 状态码统计改为可被前端日志捕获

- 变动目录：`pkg/output/stats/`
- 变动文件：`pkg/output/stats/stats.go`、`pkg/output/stats/stats_test.go`
- 具体修改内容：
  - 在 `pkg/output/stats/stats.go` 的 `DisplayTopStats` 中，将 `Top Status Codes`、`Top Errors`、`WAF Detections` 三段统计输出统一改为以 `[INF]` 前缀打印，保留原有统计内容和颜色展示方式。
  - 这样扫描任务在结束时输出的统计摘要会被 `server/internal/pkg/scanruntime` 的日志解析器识别为普通 info 日志，从而进入前端的扫描日志事件流。
  - 在 `pkg/output/stats/stats_test.go` 中新增回归测试，验证状态码统计输出确实包含 `[INF]` 前缀和状态码计数，避免后续再次改回普通 `fmt.Printf` 后前端日志看不到这段摘要。
- 修改目的或影响：
  - 让开启 `HTTPStats` 后的统计摘要不再只停留在终端，而是能够进入扫描任务前端日志。
  - 这次修改只改变统计摘要的输出格式，不影响状态码统计、WAF 统计和错误统计本身的计数逻辑。

## 2026-09-02 10:43 记录漏洞详情中的完整 POC 请求链

- 变动目录：`pkg/protocols/http/`
- 变动文件：`pkg/protocols/http/operators.go`、`pkg/protocols/http/operators_test.go`
- 具体修改内容：
  - 在 `pkg/protocols/http/operators.go` 中新增 POC 历史请求/响应的汇总逻辑，优先收集 `request_1`、`request_2`、`response_1`、`response_2` 这类带序号的历史字段，并将其序列化成 JSON 对象写入 `ResultEvent.Request` 和 `ResultEvent.Response`，对象内部只保留 `1`、`2` 这类编号键。
  - 保留单请求场景的兼容行为：即使只有一次请求，也会以 `request` / `response` 容器中的 `1` 号键落入结果 JSON，便于后端保存时继续保持结构化。
  - 在 `pkg/protocols/http/operators_test.go` 中新增回归测试，覆盖多请求 POC 场景下结果事件会输出完整的编号历史字段，确保历史链路不会再次被覆盖。
- 修改目的或影响：
  - 修复漏洞详情页中的 `detail.request` 和 `detail.response` 只保存最后一个请求/响应的问题，让多步骤 POC 的完整交互链都能落到后端存储和前端展示中。
  - 这次调整只影响 HTTP 结果事件的历史表达方式，不改变普通单请求模板的扫描逻辑和匹配行为。

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
