# 2026-09-21 upstream 合并 nuclei/dev 记录

## 合并来源与目标

- 合并来源：远程 `nuclei/dev`
- 合并来源提交：`d47ace7701e223de5532e70bc50abdc7e7c0e91d`（`chore(deps): bump the modules group with 8 updates (#7758)`）
- 合并目标：本地 `upstream` 分支
- 合并方式：`git fetch nuclei dev` 后执行 `git merge --no-ff --no-commit nuclei/dev`，在未提交状态下完成冲突处理与本地适配

## 远程主要更新内容

- 引入安全上下文相关文件与工作流，包括 `SECURITY_CONTEXT.md`、`.sops.yaml` 和 `.github/workflows/security-context.yml`。
- 更新依赖与 `go.mod`、`go.sum`，合入远程 dev 分支中的依赖升级。
- 合入 CLI、runner、configuration、internal server、SDK、catalog、loader、installer、JavaScript 运行时、HTTP client pool、fuzz、template parser/signature/capability、reporting、protocol 等模块的大量新增能力、测试和回归用例。
- 新增或更新多类协议支持与测试数据，包括 JavaScript gRPC/HTTP、SMB/session、HTTP cache、TLS metadata、duration、raw/fuzz corpus、template capability gates 等。
- 合入远程新增的模板归属、安装锁、目录初始化、profile、scope/proxy、preflight port scan、render、marker、context args、variables scope 等逻辑。

## 冲突与本地适配

- 保留本地模块名 `ManScan`，将远程新增或恢复的内部 import 本地化为 `ManScan/...`。
- 保留默认运行数据目录集中在仓库 `data/` 下的二开行为：
  - `pkg/catalog/config/paths.go` 继续使用 `DefaultConfigDir()`、`DefaultCacheDir()`、`DefaultTemplatesDir()` 等本地路径。
  - `internal/runner/options.go`、`cmd/nuclei/main.go`、`pkg/types/resume.go`、`internal/configuration/profile.go`、`pkg/reporting/exporters/sarif/sarif.go` 等默认路径继续落到 `data/` 子目录。
- 保留默认关闭更新检查与不输出更新提示：
  - `pkg/catalog/config/nucleiconfig.go` 中 `DefaultConfig` 继续默认 `disableUpdates: true`。
  - `internal/runner/runner.go` 保留本地简化版本输出，不恢复远程更新提示。
- 保留模板签名验证绕过策略：
  - `pkg/templates/compile.go` 继续在模板验证阶段直接标记 `template.Verified`、`options.Verified`，并保留 `RawTemplate`。
  - 调整远程新增的未签名 code/javascript 相关测试，使其匹配 ManScan 当前允许加载未签名模板的二开约定。
- 保留 `.nuclei-ignore` 本地初始化与自愈策略：
  - active ignore 文件继续位于 `data/config/.nuclei-ignore`，优先由当前模板目录补齐，缺失时自愈为空文件。
  - 调整 loader、lib、installer、catalog config 相关测试，避免恢复远程“模板根目录 ignore 文件必须报错”的默认预期。
- 保留自动扫描进度、tags、实际模板数量和日志解析增强：
  - `pkg/progress/progress.go` 与 `pkg/protocols/common/automaticscan/automaticscan.go` 继续保留总请求数确定状态、实际请求数、模板数量更新、自动指纹识别 tags 和加载数量日志。
  - 适配远程 HTTP client pool 新签名时保留本地自动扫描流水线行为。
- 保留暂停恢复顺序：
  - `cmd/nuclei/main.go` 继续在 crash/Ctrl+C 处理时先保存 resume，再关闭 runner。
  - resume/crash 目录继续使用 `data/cache/resume` 与 `data/cache/crash`。

## Import 本地化检查

- 已搜索 Go import 形态：`"github.com/projectdiscovery/nuclei/` 和 `"github.com/projectdiscovery/nuclei/v3/`。
- 结果：Go 源码中没有残留指向原仓库内部模块的 import。
- 搜索到的 `github.com/projectdiscovery/nuclei` 文本均为文档链接、注释、User-Agent 测试字符串、release URL 或 `nuclei-templates` 外部链接，不属于内部 import。

## 已删除文件处理

- 合并过程中未无条件恢复本地历史已删除且对当前构建/运行非必要的远程文件。
- 对远程新增但不破坏当前二开约定的安全上下文、测试、协议实现、模板能力和依赖更新予以保留。
- 对会破坏本地二开行为的默认目录、更新检查、签名限制、ignore 文件位置和暂停恢复顺序，均采用本地兼容实现。

## 验证结果

- 已执行 `gofmt`，覆盖本次手工解决冲突与测试适配涉及的 Go 文件。
- 已执行 `go mod tidy`，并移除本地模块下不适用的 `retract v3.2.0`。
- 已执行 `git diff --check`：通过。
- 已执行重点回归：

```bash
go test ./pkg/catalog/config ./cmd/nuclei ./internal/runner ./pkg/progress ./pkg/protocols/common/automaticscan ./pkg/types ./server/internal/pkg/scanruntime ./pkg/protocols/common/interactsh ./pkg/catalog/index ./pkg/catalog/loader ./pkg/installer ./pkg/templates
```

结果：通过。

- 已执行全量测试：

```bash
go test ./...
```

结果：失败，剩余两项环境/外部依赖类失败：

- `ManScan/lib` 的 `ExampleThreadSafeNucleiEngine` 只返回 `[nameserver-fingerprint] scanme.sh`，未返回期望的 `[caa-fingerprint] honey.scanme.sh`，依赖外部 DNS/扫描目标实时结果。
- `ManScan/pkg/protocols/headless/engine` 的 `TestActionGetResource` 获取页面资源时 `context deadline exceeded`，属于 headless/browser 时序超时类失败。

## 保留风险与后续建议

- ManScan 按既有二开要求继续保留模板签名验证绕过能力，这会保留未签名模板执行风险。该风险不是本次远程合并新增，但本次为保护本地行为明确保留。
- 全量测试仍存在外部 DNS 与 headless 时序依赖，建议后续将对应示例/测试改为本地可控 fixture，降低 CI 和本地验收波动。
- 当前合并尚未提交；如需应用到其他分支，应先完成本地 `upstream` 分支验收和提交，再由用户确认后单独处理。
