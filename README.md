# ManScan

`ManScan` 当前是一个基于 `projectdiscovery/nuclei` 持续维护的 Go 项目分支，核心是一套以 YAML 模板为中心的漏洞扫描引擎。它既保留了 `nuclei` 的 CLI 与模板体系，也保留了 SDK、模板工具链、测试与发布配置，适合做扫描能力研发、模板扩展和工程化集成。

如果你是第一次接手这个仓库，可以先记住两点：主入口仍然是 `cmd/nuclei`，主构建产物仍然是 `./bin/nuclei`。下面的内容按“先跑起来，再开始改”的顺序整理。

## 📚 阅读导航

- 想先运行项目：看 [🚀 快速开始](#-快速开始)
- 想了解仓库结构：看 [🧱 目录结构](#-目录结构)
- 想参与开发：看 [🛠️ 开发规范](#-开发规范)
- 想查看调试开关：看 [🧭 调试与排障](#-调试与排障)
- 想排查常见问题：看 [❓ 常见问题](#-常见问题)

## 📦 项目简介

- 基于模板驱动的漏洞扫描引擎，模板格式为 YAML。
- 主入口是命令行工具，代码位于 `cmd/nuclei`，构建产物为 `./bin/nuclei`。
- 仓库同时提供 `lib/` SDK，可在 Go 项目中嵌入扫描能力。
- 除主扫描器外，还包含模板文档生成、模板标准化、JS 绑定生成等开发工具。

## 🚀 快速开始

### 前置条件

- Go 版本需满足 `go.mod` 中声明的 `1.25.7`
- 本地建议安装 `make`
- 如果要运行容器镜像构建，需安装 Docker
- 如果要使用部分 headless 能力，本地需要可用的 Chrome/Chromium 环境

### 1. 拉取依赖并校验模块

```bash
make download
make verify
```

`make download` 会拉取 Go 依赖，`make verify` 会校验 `go.sum` 与模块完整性。

### 2. 构建主程序

```bash
make build
```

构建完成后，产物位于：

```bash
./bin/nuclei
```

### 3. 查看帮助与版本

```bash
./bin/nuclei -h
./bin/nuclei -version
```

### 4. 进行一次最小扫描

```bash
./bin/nuclei -target https://example.com
```

首次使用模板相关能力时，通常还需要先更新模板：

```bash
./bin/nuclei -ut
```

### 5. 运行 SDK 示例

```bash
go run ./examples/simple
```

这个示例会通过 `lib/` 中的 Go SDK 创建扫描引擎并执行一次基础扫描。

### 6. 使用 Docker 构建

```bash
docker build -t manscan-local .
docker run --rm manscan-local -h
```

根目录 [Dockerfile](/Users/dahe/Documents/DAST/ManScan/Dockerfile:1) 会先执行 `make verify` 和 `make build`，再把 `./bin/nuclei` 放入运行时镜像。

## 🧰 常用命令

```bash
make build
make test
make integration
make vet
make tidy
make template-validate
make syntax-docs
make devtools-all
make jsupdate-all
```

- `make build`：构建主二进制到 `./bin/nuclei`
- `make test`：运行单元测试，默认带 `-race`
- `make integration`：运行集成测试套件
- `make vet`：执行 `go vet`
- `make tidy`：整理模块依赖
- `make template-validate`：更新模板并执行模板校验
- `make syntax-docs`：重新生成语法参考文档和 schema 相关产物
- `make devtools-all` / `make jsupdate-all`：构建或刷新 JS 开发工具与生成代码

## 🧪 技术栈

- `Go`：核心实现语言，负责扫描引擎、CLI、SDK 与工具链。
- `Makefile`：统一封装构建、测试、文档生成、模板校验等研发命令。
- `GitHub Actions`：在 `.github/workflows/` 中定义测试、发布、文档生成、fuzz、CodeQL 等 CI 流程。
- `Docker`：通过根目录 `Dockerfile` 和 `Dockerfile.goreleaser` 生成运行镜像与发布镜像。
- `Helm`：`helm/` 目录提供 Kubernetes 部署模板。
- `YAML 模板体系`：扫描规则与模板能力围绕 YAML 模板展开。
- `JavaScript 绑定工具链`：`pkg/js/` 与对应 devtools 用于维护 code 协议相关的 JS 能力和生成代码。

## 🧱 目录结构

```text
cmd/            命令行入口与内部工具
examples/       SDK 与使用示例
internal/       运行器、服务端、测试等内部实现
lib/            供外部 Go 项目调用的 SDK
pkg/            核心业务模块与协议实现
helm/           Kubernetes / Helm 部署模板
static/         README 与文档使用的静态资源
```

重点目录说明：

- `cmd/nuclei/`：主 CLI 入口，负责参数解析、配置读取、运行扫描。
- `cmd/tmc/`：模板处理工具入口，用于模板标准化、校验、格式化等操作。
- `internal/runner/`：扫描执行编排核心。
- `internal/tests/`：集成测试、功能测试与测试数据。
- `pkg/protocols/`：HTTP、DNS、SSL、Code 等协议实现。
- `pkg/templates/`：模板解析、编译、签名和管理逻辑。
- `pkg/input/`：多种输入格式解析能力，例如列表、Burp、OpenAPI、Swagger。
- `pkg/reporting/`：结果导出与第三方平台集成。
- `lib/`：对外提供简化后的 SDK 接口。

## 🛠️ 开发规范

### 基本流程

- 根据 [CONTRIBUTING.md](/Users/dahe/Documents/DAST/ManScan/CONTRIBUTING.md:1)，提交改动时应从 `dev` 分支开展工作。
- 提交 PR 前，建议先关联对应 issue，并在说明中写清楚问题背景、测试方式与必要示例。
- 如果是新功能，仓库现有贡献说明要求补充相应测试。

### 提交前最少检查

```bash
make vet
make build
make test
```

如果你改动了模板体系、文档生成逻辑或 schema，建议额外执行：

```bash
make template-validate
make syntax-docs
```

### 代码风格

- Go 代码遵循仓库现有风格，必要时执行 `go fmt ./...`
- 当前仓库未发现独立的提交信息规范配置；如需补充约定，可优先参考 Conventional Commits
- CI 会运行 lint、单元测试、集成测试、功能测试、模板校验、CodeQL 和发布验证，因此本地尽量先完成基础自测

## ✅ 测试与验证

仓库当前可验证的测试入口包括：

- `make test`：标准单元测试
- `make integration`：带 `integration` tag 的测试
- `make functional`：功能测试入口，依赖系统已安装的 `nuclei` 发布版二进制
- `make template-validate`：模板更新与模板校验

其中 `make functional` 的实现会同时使用：

- `PATH` 中的发布版 `nuclei`
- 当前仓库构建出的 `./bin/nuclei`

因此如果本地没有已安装的 `nuclei`，该命令会直接失败。

## 🧭 调试与排障

在新增功能、修复缺陷，或编写新模板时，先打开合适的调试开关，通常能更快看清请求、响应、变量变化和错误堆栈。下面这部分内容整理自根目录的 `DEBUG.md`，并已转换为中文说明，方便直接在 README 中查阅。

### 模板与请求调试参数

- `-debug`：打印 nuclei 发送到目标的全部请求，以及收到的全部响应，适合完整观察一次模板执行过程。
- `-debug-req`：只打印发送出去的请求，适合重点排查请求构造是否正确。
- `-debug-resp`：只打印收到的响应，适合重点分析目标返回内容。
- `-ldf`：打印当前版本中可用的全部 helper functions，然后直接退出，适合查模板函数能力。
- `-svd`：打印模板请求执行前后的 `variables`，可用于观察变量是否按预期生成、覆盖和传递。
- `-elog=errors.txt`：把运行过程中的错误写入指定文件，适合大规模扫描时单独收集错误信息。

常见用法示例：

```bash
./bin/nuclei -target https://example.com -debug
./bin/nuclei -target https://example.com -debug-req
./bin/nuclei -target https://example.com -debug-resp
./bin/nuclei -target https://example.com -svd
./bin/nuclei -target https://example.com -elog=errors.txt
./bin/nuclei -ldf
```

### 环境变量调试开关

除命令行参数外，项目还支持通过环境变量打开特定调试能力：

| 环境变量 | 说明 |
| --- | --- |
| `DEBUG=true` | 为错误打印堆栈信息，适合排查 panic、调用链或深层报错来源。 |
| `SHOW_DSL_ERRORS=true` | 显示默认被隐藏的 DSL 错误，适合排查模板表达式问题。 |
| `HIDE_TEMPLATE_SIG_WARNING=true` | 隐藏模板签名校验警告，适合在确认风险可接受时减少噪音。 |
| `NUCLEI_LOG_ALL=true` | 记录 verbose 模式下原本会被跳过的所有事件。 |
| `NUCLEI_CONFIG_DIR` | 指定自定义配置目录。 |
| `NUCLEI_TEMPLATES_DIR` | 指定自定义模板目录。 |

示例：

```bash
DEBUG=true SHOW_DSL_ERRORS=true ./bin/nuclei -target https://example.com -debug
NUCLEI_TEMPLATES_DIR=/path/to/nuclei-templates ./bin/nuclei -target https://example.com
```

### 调试建议

- 当你不确定是“请求发错了”还是“目标返回异常”时，优先使用 `-debug`。
- 当你怀疑模板变量、提取器、DSL 表达式行为异常时，优先组合使用 `-svd` 和 `SHOW_DSL_ERRORS=true`。
- 当你在批量扫描中只想保留错误信息时，优先使用 `-elog=errors.txt`，避免终端输出过多内容。
- 当你在自定义目录中维护模板时，可配合 `NUCLEI_TEMPLATES_DIR` 明确模板来源，减少“模板没加载到”的排查时间。

## 📖 相关文档

- [DESIGN.md](/Users/dahe/Documents/DAST/ManScan/DESIGN.md:1)：核心架构与执行流程说明
- [FUZZING.md](/Users/dahe/Documents/DAST/ManScan/FUZZING.md:1)：fuzz 相关说明
- [SYNTAX-REFERENCE.md](/Users/dahe/Documents/DAST/ManScan/SYNTAX-REFERENCE.md:1)：模板语法参考
- [lib/README.md](/Users/dahe/Documents/DAST/ManScan/lib/README.md:1)：Go SDK 使用方式

## ❓ 常见问题

### 1. `make build` 失败，提示 Go 版本不匹配

现象：本地构建时报 `go.mod` 版本相关错误。  
原因：仓库要求的 Go 版本高于本地版本。  
解决：

- 运行 `go version` 确认当前版本
- 升级到 `go.mod` 中声明的版本或更高兼容版本
- 升级后重新执行 `make verify && make build`

### 2. 扫描时报模板缺失或模板版本不正确

现象：执行扫描或模板校验时提示模板不存在、版本未知或需要更新。  
原因：本地尚未安装或更新 `nuclei-templates`。  
解决：

```bash
./bin/nuclei -ut
```

如果你使用了自定义模板目录，还需要检查对应路径和配置文件是否正确。

### 3. `make functional` 本地无法运行

现象：提示 `release nuclei binary not found on PATH`。  
原因：该命令需要系统中已安装一个发布版 `nuclei`，再与当前分支构建产物做对比。  
解决：

- 先确保 `nuclei` 或 `nuclei.exe` 能通过 `PATH` 找到
- 再执行 `make build`
- 最后重新运行 `make functional`

### 4. Headless 或浏览器相关能力异常

现象：涉及浏览器、截图、JS 交互的模板执行失败。  
原因：本地缺少可用的 Chrome/Chromium，或运行环境权限不足。  
解决：

- 优先确认本地是否已安装浏览器
- 如需复用系统浏览器，可查看 `-system-chrome` 相关参数
- 参考 [DEBUG.md](/Users/dahe/Documents/DAST/ManScan/DEBUG.md:1) 打开调试日志进一步定位

### 5. `make template-validate` 很慢或失败

现象：模板校验耗时长，或在更新阶段失败。  
原因：该命令会先执行 `./bin/nuclei -ut`，依赖网络拉取模板。  
解决：

- 先单独运行 `./bin/nuclei -ut` 检查网络与模板源是否正常
- 再重新执行 `make template-validate`
- 如仅验证本地代码改动，可先跑 `make build`、`make test`、`make vet`

## 📄 许可证

本仓库当前沿用 [LICENSE.md](/Users/dahe/Documents/DAST/ManScan/LICENSE.md:1) 中声明的 MIT 许可证。
