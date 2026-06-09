## 2026-06-09 15:17 汉化 lib/README.md

- 变动目录：`lib/`
- 变动文件：`lib/README.md`
- 具体修改内容：
  - 将文档标题、章节标题、安装说明、基础示例说明、高级示例说明、更多文档说明以及注意事项全部翻译为中文。
  - 保留了原有代码块结构、导入示例、命令示例和链接地址，仅将代码注释中的英文说明同步汉化，便于中文读者理解示例逻辑。
- 修改目的或影响：
  - 让中文使用者能够更容易理解如何将 ManScan 作为 Go 库接入项目。
  - 不影响代码实现与示例可用性，仅改进文档可读性。

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
