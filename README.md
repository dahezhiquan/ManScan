# ManScan

`ManScan` 是一个基于 `projectdiscovery/nuclei` 持续演进的 Go 漏洞扫描引擎分支，核心能力仍然围绕 YAML 模板驱动的目标探测、匹配、提取与结果导出展开。它既保留了 CLI 形态，也保留了 Go SDK、模板处理工具、集成测试和多协议执行能力，适合做漏洞扫描能力研发、模板扩展、自动化集成与二次开发。

如果你是第一次接手这个仓库，建议先抓住三件事：

- 主程序入口在 `cmd/nuclei`
- 常用构建命令是 `go build ./cmd/nuclei`
- 默认运行数据会写入项目根目录下的 `data/`

## 📚 阅读导航

- 想先把程序跑起来：看 [🚀 快速开始](#-快速开始)
- 想了解仓库主要模块：看 [🧱 目录结构](#-目录结构)
- 想参与开发或补测试：看 [🛠️ 开发规范](#-开发规范)
- 想了解运行数据写到哪里：看 [🗂️ 数据目录](#-数据目录)
- 想排查本地启动或测试问题：看 [❓ 常见问题](#-常见问题)

## 📦 项目简介

`ManScan` 当前本质上是一套模板驱动的漏洞扫描引擎。扫描逻辑通过 YAML 模板描述，请求执行由 Go 实现的多协议运行器完成，结果再交给输出、报告和去重模块处理。除了 CLI 以外，仓库还提供 `lib/` 下的 SDK，以及 `cmd/tmc` 等模板工具，方便把扫描能力嵌入其他系统。

基于当前仓库实现，`ManScan` 与上游常见使用体验相比，还有几个需要提前知道的分支特性：

- 本地模块名已经切换为 `ManScan`，仓库内 Go 包导入路径统一使用 `ManScan/...`
- 默认运行数据统一落到项目根目录 `data/` 下，而不是用户家目录
- 默认关闭自动更新检查；如需更新模板，需要显式执行 `-ut`
- 当前分支已取消模板签名验证，未签名模板不会因验签失败被默认拦截

## 🚀 快速开始

### 前置条件

- Go 版本需满足 [go.mod](/Users/dahe/Documents/DAST/ManScan/go.mod:1) 中声明的 `1.25.7`
- 建议本地具备稳定网络，以便首次下载依赖和模板
- 如果要运行 headless 模板，需要本机可用的 Chrome/Chromium 环境

### 1. 拉取依赖

```bash
go mod download
```

这一步会下载当前仓库依赖的 Go 模块。

### 2. 构建主程序

```bash
mkdir -p ./bin
go build -o ./bin/nuclei ./cmd/nuclei
```

构建完成后，主程序位于 `./bin/nuclei`。

### 3. 查看帮助和版本

```bash
./bin/nuclei -h
./bin/nuclei -version
```

### 4. 手动更新模板

```bash
./bin/nuclei -ut
```

当前仓库默认关闭自动更新检查，因此首次扫描前如果需要官方模板，通常要手动执行一次更新。

### 5. 进行一次最小扫描

```bash
./bin/nuclei -target https://example.com
```

如果要指定模板目录或配置目录，可以结合环境变量一起使用：

```bash
NUCLEI_TEMPLATES_DIR=/path/to/templates ./bin/nuclei -target https://example.com
NUCLEI_CONFIG_DIR=/path/to/config ./bin/nuclei -target https://example.com
```

### 6. 运行 SDK 示例

```bash
go run ./examples/simple
go run ./examples/advanced
go run ./examples/with_speed_control
```

- `examples/simple`：演示最基础的 SDK 扫描流程
- `examples/advanced`：演示线程安全引擎和并发扫描
- `examples/with_speed_control`：演示运行时速率与并发控制

## 🧰 常用命令

```bash
go build -o ./bin/nuclei ./cmd/nuclei
go test ./...
go test -tags=integration ./internal/tests/integration
go test -tags=functional ./internal/tests/functional
go test ./lib/...
go run ./cmd/tmc -h
```

- `go build -o ./bin/nuclei ./cmd/nuclei`：构建 CLI 主程序
- `go test ./...`：运行默认测试集合
- `go test -tags=integration ./internal/tests/integration`：运行集成测试
- `go test -tags=functional ./internal/tests/functional`：运行功能测试
- `go test ./lib/...`：只验证 SDK 相关包
- `go run ./cmd/tmc -h`：查看模板工具 `tmc` 的用法

## 🧪 技术栈

- `Go`：核心实现语言，负责 CLI、执行引擎、SDK 和测试框架
- `goflags`：CLI 参数解析库，`cmd/nuclei/main.go` 中的大部分参数都基于它注册
- `YAML 模板体系`：扫描规则、工作流、匹配器和提取器的核心载体
- `Go SDK`：`lib/` 提供嵌入式调用能力，适合在其他 Go 程序中集成扫描
- `JavaScript / Code 协议工具链`：`pkg/js/` 及其 devtools 用于维护脚本执行和绑定生成能力
- `LevelDB / 报告导出模块`：用于结果去重、持久化和多种报告输出

## 🧱 目录结构

```text
cmd/        命令行入口与工具程序
examples/   SDK 使用示例
internal/   运行器、测试与内部实现
lib/        对外暴露的 Go SDK
pkg/        核心扫描、模板、协议与输出模块
server/     服务端接口文档占位
data/       默认运行期数据目录
```

重点目录说明：

- `cmd/nuclei/`：主 CLI 入口，负责参数解析、配置加载和运行器初始化
- `cmd/tmc/`：模板处理工具入口，可用于模板 lint、校验、格式化等操作
- `examples/`：可直接运行的 SDK 示例
- `internal/runner/`：扫描执行编排核心
- `internal/tests/integration/`：原生集成测试与测试夹具
- `internal/tests/functional/`：功能对比测试，主要用于 CI 或本地进阶验证
- `pkg/templates/`：模板解析、编译与管理逻辑
- `pkg/protocols/`：HTTP、DNS、Network、Headless、File、Code 等协议实现
- `pkg/reporting/`：结果导出、去重和 issue tracker 集成
- `lib/`：对外提供更稳定的 SDK 封装
- `server/API.md`：当前 `server` 目录下可见内容主要是接口文档，占位能力多于可执行服务代码

## 🗂️ 数据目录

当前仓库已经把默认运行数据统一迁移到项目根目录 `data/` 下，详细说明见 [DATA.md](/Users/dahe/Documents/DAST/ManScan/DATA.md:1)。

常见子目录如下：

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

你通常会最先碰到这些位置：

- `data/config/`：配置文件、`.nuclei-ignore`、reporting 配置
- `data/templates/`：模板安装和更新后的默认目录
- `data/cache/`：resume、crash、reporting 去重缓存
- `data/responses/`：启用 `-store-resp` 后的请求响应落盘目录
- `data/reports/`：JSON、JSONL、Markdown、SARIF、PDF 等默认报告目录

如果需要把默认数据目录切到其他位置，可以设置：

```bash
MANSCAN_DATA_ROOT=/path/to/custom-data ./bin/nuclei -target https://example.com
```

## 🛠️ 开发规范

### 开发前必读

根据仓库约定，开始修改代码前至少应先阅读以下文档：

- [CHANGE.md](/Users/dahe/Documents/DAST/ManScan/CHANGE.md:1)：了解近期改动和分支特性
- [CODE_STYLE.md](/Users/dahe/Documents/DAST/ManScan/CODE_STYLE.md:1)：开发、自测、测试和文档更新要求
- [DESIGN.md](/Users/dahe/Documents/DAST/ManScan/DESIGN.md:1)：核心架构与执行链路说明

### 推荐开发流程

1. 阅读相关模块代码与文档，先确认现有实现
2. 修改代码后至少执行一次构建
3. 按改动范围补充对应测试
4. 如果 README、接口或运行路径受影响，同步更新文档

### 提交前最少检查

```bash
go build -o ./bin/nuclei ./cmd/nuclei
go test ./...
```

如果你改动了运行器、模板加载或协议实现，建议额外执行：

```bash
go test -tags=integration ./internal/tests/integration
```

如果你改动了 SDK，建议额外执行：

```bash
go test ./lib/...
```

### 关于功能测试

`internal/tests/functional` 的功能测试不是“开箱即跑”型测试。根据当前实现，它至少有这些前置条件：

- 需要带 `functional` build tag 运行
- 默认要求 `CI=true`
- 需要系统中能找到一个发布版 `nuclei` 二进制，或通过环境变量指定
- 测试过程中会构建当前仓库版本并做结果对比

因此本地日常开发时，更推荐优先跑默认测试和集成测试。

## 🧭 调试与排障

CLI 已内置多组调试参数，下面列出最常用的一批：

- `-debug`：打印请求和响应
- `-debug-req`：只打印请求
- `-debug-resp`：只打印响应
- `-svd`：打印变量 dump
- `-ldf`：列出 DSL 函数签名
- `-elog <file>`：把错误日志写入文件
- `-trace-log <file>`：输出请求跟踪日志
- `-vv`：显示本次扫描加载了哪些模板

示例：

```bash
./bin/nuclei -target https://example.com -debug
./bin/nuclei -target https://example.com -svd
./bin/nuclei -target https://example.com -vv
./bin/nuclei -ldf
```

常见环境变量：

- `DEBUG=true`：开启更详细的错误栈输出
- `SHOW_DSL_ERRORS=true`：显示 DSL 相关错误
- `NUCLEI_CONFIG_DIR`：指定配置目录
- `NUCLEI_TEMPLATES_DIR`：指定模板目录
- `MANSCAN_DATA_ROOT`：覆盖默认 `data/` 根目录

## 📖 相关文档

- [DESIGN.md](/Users/dahe/Documents/DAST/ManScan/DESIGN.md:1)：架构说明
- [DATA.md](/Users/dahe/Documents/DAST/ManScan/DATA.md:1)：运行期数据目录说明
- [lib/README.md](/Users/dahe/Documents/DAST/ManScan/lib/README.md:1)：SDK 使用说明
- [server/API.md](/Users/dahe/Documents/DAST/ManScan/server/API.md:1)：服务端接口文档

## ❓ 常见问题

### 1. `go build` 失败，提示 Go 版本不匹配

现象：构建时报 `go.mod` 版本相关错误。  
原因：本地 Go 版本低于仓库要求。  
解决：

- 运行 `go version` 检查本地版本
- 升级到 [go.mod](/Users/dahe/Documents/DAST/ManScan/go.mod:1) 声明的 `1.25.7`
- 然后重新执行 `go mod download` 和 `go build -o ./bin/nuclei ./cmd/nuclei`

### 2. 扫描时提示模板不存在或版本不正确

现象：扫描时报模板缺失、模板版本未知或模板目录为空。  
原因：当前分支默认不会自动更新模板。  
解决：

```bash
./bin/nuclei -ut
```

如果你使用了自定义模板目录，还要确认 `NUCLEI_TEMPLATES_DIR` 或相关参数配置正确。

### 3. 为什么运行后多了一个 `data/` 目录

现象：首次运行后仓库根目录出现 `data/`。  
原因：当前分支已经把配置、模板、缓存、报告和临时文件统一收口到这里。  
解决：

- 这属于正常行为
- 详细用途可查看 [DATA.md](/Users/dahe/Documents/DAST/ManScan/DATA.md:1)
- 如需改位置，可设置 `MANSCAN_DATA_ROOT`

### 4. `go test -tags=integration ./internal/tests/integration` 失败

现象：集成测试构建失败、夹具读取失败，或部分协议测试在本机不稳定。  
原因：集成测试会临时构建二进制并复制测试夹具，部分用例还依赖具体系统环境。  
解决：

- 先确认 `go build -o ./bin/nuclei ./cmd/nuclei` 能正常通过
- 再单独运行目标测试包
- 如果只想定位单个问题，可结合 `-run` 只执行某个测试

示例：

```bash
go test -tags=integration ./internal/tests/integration -run TestIntegrationSuites
```

### 5. `go test -tags=functional ./internal/tests/functional` 本地直接跳过

现象：测试被跳过或提示需要 `CI=true`。  
原因：当前功能测试实现默认面向 CI 或发布版与开发版对比场景。  
解决：

- 日常开发优先跑 `go test ./...`
- 需要深度验证时，再按测试代码要求补齐 `CI`、发布版二进制和模板环境

### 6. Headless 模板执行异常

现象：涉及浏览器、截图或 JS 交互的模板执行失败。  
原因：本机缺少 Chrome/Chromium，或运行环境权限不足。  
解决：

- 先确认本机存在可用浏览器
- 必要时尝试 `-system-chrome`
- 配合 `-debug`、`-debug-resp`、`-vv` 进一步定位

## 📄 许可证

本仓库当前沿用 [LICENSE.md](/Users/dahe/Documents/DAST/ManScan/LICENSE.md:1) 中声明的 MIT 许可证。
