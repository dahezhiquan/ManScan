# ManScan

`ManScan` 是一个基于 `projectdiscovery/nuclei` 持续演进的 Go 漏洞扫描引擎分支，核心能力围绕 YAML 模板驱动的目标探测、匹配、提取、结果导出和服务化封装展开。仓库同时保留了 CLI、Go SDK、模板处理工具和 `server` HTTP 接口，适合做漏洞扫描能力研发、模板扩展、自动化集成与二次开发。

如果你第一次接手这个仓库，建议先记住三件事：

- CLI 主入口在 `cmd/nuclei`
- 默认运行数据会写入项目根目录下的 `data/`
- 服务端入口在 `server/cmd/server`，默认监听 `:8686`

## 📚 阅读导航

- 想先跑起 CLI：看 [🚀 快速开始](#-快速开始)
- 想启动 HTTP 服务：看 [🌐 服务端启动](#-服务端启动)
- 想了解仓库主要模块：看 [🧱 目录结构](#-目录结构)
- 想参与开发或补测试：看后文“开发规范”章节
- 想看接口列表：看 [📖 相关文档](#-相关文档)
- 想排查本地问题：看 [❓ 常见问题](#-常见问题)

## 📦 项目简介

`ManScan` 当前本质上是一套模板驱动的漏洞扫描引擎。扫描规则由 YAML 模板描述，请求执行由 Go 编写的多协议运行器完成，结果再交给输出、报告、去重和服务层处理。除了 CLI 以外，仓库还提供 `lib/` 下的 Go SDK，以及 `cmd/tmc` 等模板工具，方便把扫描能力嵌入其他系统。

基于当前仓库实现，这个分支有几处需要提前知道的特性：

- 仓库模块名已经切换为 `ManScan`，内部 Go 导入路径统一使用 `ManScan/...`
- 默认运行数据统一落到项目根目录 `data/` 下，而不是用户家目录
- 默认关闭自动更新检查；如需更新模板，需要显式执行 `-ut`
- 当前分支已取消模板签名验证，未签名模板不会因验签失败被默认拦截
- `server/` 目录已经提供可运行的 HTTP 服务，而不只是接口文档占位

## 🚀 快速开始

### 前置条件

- Go 版本需满足 `go.mod` 中声明的 `1.25.7`
- 建议本地具备稳定网络，以便首次下载依赖和模板
- 如果要运行 headless 模板，需要本机可用的 Chrome 或 Chromium 环境

### 1. 下载依赖

```bash
go mod download
```

这一步会下载当前仓库依赖的 Go 模块。

### 2. 构建 CLI

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

### 5. 运行一次最小扫描

```bash
./bin/nuclei -target https://example.com
```

如果要显式指定模板目录或配置目录，可以结合环境变量：

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

- `examples/simple`：演示基础 SDK 扫描流程
- `examples/advanced`：演示线程安全引擎和并发扫描
- `examples/with_speed_control`：演示运行时速率与并发控制

## 🌐 服务端启动

`server/` 提供了基于 Gin 和 GORM 的 HTTP 服务，当前已经支持模板列表、模板详情、扫描任务创建、扫描任务分页、扫描进度和日志流等接口。

### 前置条件

- 可连接的 MySQL 实例
- 已创建服务端所需表结构
- 根目录存在可用的 `config.yaml`，或通过 `MANSCAN_CONFIG_FILE` 指定配置文件

### 1. 初始化数据库

仓库提供了 SQL 脚本作为初始化参考：

- `docs/SQL/create_manscan_scan_tasks.sql`
- `docs/SQL/create_manscan_task_results.sql`

建议在执行前先核对脚本与当前服务端实现是否一致，尤其是在数据库字段有新增调整时。

### 2. 准备配置文件

服务端默认读取仓库根目录下的 `config.yaml`。配置结构至少需要包含一个 `mysql` 段，例如：

```yaml
mysql:
  username: root
  password: your-password
  host: 127.0.0.1
  port: 3306
  database: manscan_scan
```

可用环境变量：

- `MANSCAN_CONFIG_FILE`：指定服务端配置文件路径
- `MANSCAN_SERVER_ADDR`：覆盖默认监听地址，默认值为 `:8686`
- `MANSCAN_TEMPLATES_DIR`：覆盖服务端模板目录
- `NUCLEI_TEMPLATES_DIR`：作为模板目录回退来源之一

### 3. 启动服务

```bash
go run ./server/cmd/server
```

启动后默认监听：

```text
http://127.0.0.1:8686
```

接口文档见 [`server/API.md`](./server/API.md)。

## 🧰 常用命令

```bash
go build -o ./bin/nuclei ./cmd/nuclei
go run ./server/cmd/server
go test ./...
go test ./server/...
go test -tags=integration ./internal/tests/integration
go test -tags=functional ./internal/tests/functional
go test ./lib/...
go run ./cmd/tmc -h
```

- `go build -o ./bin/nuclei ./cmd/nuclei`：构建 CLI 主程序
- `go run ./server/cmd/server`：启动 HTTP 服务
- `go test ./...`：运行默认测试集合
- `go test ./server/...`：只验证 `server` 相关实现
- `go test -tags=integration ./internal/tests/integration`：运行集成测试
- `go test -tags=functional ./internal/tests/functional`：运行功能测试
- `go test ./lib/...`：只验证 SDK 相关包
- `go run ./cmd/tmc -h`：查看模板工具 `tmc` 的用法

## 🧪 技术栈

- `Go`：核心实现语言，负责 CLI、协议执行引擎、SDK、服务端和测试框架
- `Gin`：`server/` 目录下的 HTTP 接口框架，用于扫描任务与模板能力服务化
- `GORM`：服务端数据访问层 ORM，用于管理扫描任务和结果统计
- `YAML 模板体系`：扫描规则、工作流、匹配器和提取器的核心载体
- `Go SDK`：`lib/` 提供嵌入式调用能力，适合在其他 Go 程序中集成扫描
- `多协议执行模块`：`pkg/protocols/` 提供 HTTP、DNS、Network、Headless、File、Code 等协议实现
- `报告与去重模块`：`pkg/reporting/` 和 `LevelDB` 用于结果导出、去重和 issue tracker 集成

## 🧱 目录结构

```text
cmd/        命令行入口与工具程序
docs/       附加文档和 SQL 初始化脚本
examples/   SDK 使用示例
internal/   运行器、测试与内部实现
lib/        对外暴露的 Go SDK
pkg/        核心扫描、模板、协议与输出模块
server/     HTTP 服务、接口实现与 API 文档
data/       默认运行期数据目录
```

重点目录说明：

- `cmd/nuclei/`：主 CLI 入口，负责参数解析、配置加载和运行器初始化
- `cmd/tmc/`：模板处理工具入口，可用于模板校验、格式化和补齐统计信息
- `examples/`：可直接运行的 SDK 示例
- `internal/runner/`：扫描执行编排核心
- `internal/tests/integration/`：集成测试与夹具
- `internal/tests/functional/`：功能测试，主要用于更重的对比验证场景
- `pkg/templates/`：模板解析、编译与管理逻辑
- `pkg/protocols/`：多协议请求实现
- `pkg/reporting/`：结果导出、去重和外部平台集成
- `lib/`：对外提供更稳定的 SDK 封装
- `server/internal/`：服务端的路由、处理器、服务层和仓储层实现

## 🗂️ 数据目录

当前仓库已经把默认运行数据统一迁移到项目根目录 `data/` 下，详细说明见 [`DATA.md`](./DATA.md)。

常见子目录如下：

```text
data/
├── cache/
├── config/
├── project/
├── reports/
├── responses/
├── runtime/
├── stats/
├── templates/
└── tmp/
```

你通常会最先碰到这些位置：

- `data/config/`：配置文件、`.nuclei-ignore`、reporting 配置
- `data/templates/`：模板安装和更新后的默认目录
- `data/cache/`：resume、crash、reporting 去重缓存
- `data/runtime/`：服务端扫描任务的事件日志、进度快照和目标文件
- `data/responses/`：启用 `-store-resp` 后的请求响应落盘目录
- `data/reports/`：JSON、JSONL、Markdown、SARIF、PDF 等默认报告目录

如果需要切换默认数据根目录，可以设置：

```bash
MANSCAN_DATA_ROOT=/path/to/custom-data ./bin/nuclei -target https://example.com
```

## 🛠 开发规范

### 开发前必读

根据仓库约定，开始修改代码前至少应先阅读以下文档：

- [`CHANGE.md`](./CHANGE.md)：了解近期改动和分支特性
- [`CODE_STYLE.md`](./CODE_STYLE.md)：开发、自测、测试和文档更新要求
- [`DESIGN.md`](./DESIGN.md)：核心架构与执行链路说明

### 推荐开发流程

1. 先阅读相关模块代码与文档，确认现有实现和边界。
2. 修改代码后至少执行一次构建或对应测试。
3. 按改动范围补充测试和文档。
4. 如果接口、数据目录或运行方式有变化，同步更新 `README.md`、`server/API.md` 或其他文档。

### 提交前最少检查

```bash
go build -o ./bin/nuclei ./cmd/nuclei
go test ./...
```

如果你改动了服务端，建议额外执行：

```bash
go test ./server/...
```

如果你改动了运行器、模板加载或协议实现，建议额外执行：

```bash
go test -tags=integration ./internal/tests/integration
```

如果你改动了 SDK，建议额外执行：

```bash
go test ./lib/...
```

### 提交规范说明

当前仓库未发现独立的 `commitlint`、`husky` 或显式分支策略配置。若团队内部没有额外约定，建议补充采用 `Conventional Commits` 作为提交信息规范，至少让变更类型更容易检索和回顾。

### 关于功能测试

`internal/tests/functional` 的功能测试不是“开箱即跑”型测试。根据当前实现，它至少有这些前置条件：

- 需要带 `functional` build tag 运行
- 默认要求 `CI=true`
- 需要系统中能找到一个发布版 `nuclei` 二进制，或通过环境变量指定
- 测试过程中会构建当前仓库版本并做结果对比

因此本地日常开发时，更推荐优先运行默认测试、`server` 测试和集成测试。

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
- `NUCLEI_CONFIG_DIR`：指定 CLI 配置目录
- `NUCLEI_TEMPLATES_DIR`：指定 CLI 或服务端可用的模板目录
- `MANSCAN_TEMPLATES_DIR`：显式覆盖服务端模板目录
- `MANSCAN_CONFIG_FILE`：指定服务端配置文件
- `MANSCAN_SERVER_ADDR`：覆盖服务端监听地址
- `MANSCAN_DATA_ROOT`：覆盖默认 `data/` 根目录

## ❓ 常见问题

### 1. `go build` 失败，提示 Go 版本不匹配

现象：构建时报 `go.mod` 版本相关错误。  
原因：本地 Go 版本低于仓库要求。  
解决：

- 运行 `go version` 检查本地版本
- 升级到 `go.mod` 声明的 `1.25.7`
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
- 详细用途可查看 [`DATA.md`](./DATA.md)
- 如需改位置，可设置 `MANSCAN_DATA_ROOT`

### 4. `go run ./server/cmd/server` 启动失败

现象：启动时报配置文件读取失败、MySQL 连接失败或 `mysql.username 不能为空`。  
原因：服务端默认依赖根目录 `config.yaml`，并且需要可用的 MySQL 配置。  
解决：

- 确认根目录存在可用的 `config.yaml`
- 如配置文件不在根目录，设置 `MANSCAN_CONFIG_FILE=/path/to/config.yaml`
- 确认 MySQL 服务可连通，且目标数据库和表结构已初始化
- 如需修改监听地址，可设置 `MANSCAN_SERVER_ADDR=:8686`

### 5. `go test -tags=integration ./internal/tests/integration` 失败

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

### 6. `go test -tags=functional ./internal/tests/functional` 本地直接跳过

现象：测试被跳过或提示需要 `CI=true`。  
原因：当前功能测试实现默认面向 CI 或发布版与开发版对比场景。  
解决：

- 日常开发优先跑 `go test ./...`
- 需要深度验证时，再按测试代码要求补齐 `CI`、发布版二进制和模板环境

### 7. Headless 模板执行异常

现象：涉及浏览器、截图或 JS 交互的模板执行失败。  
原因：本机缺少 Chrome/Chromium，或运行环境权限不足。  
解决：

- 先确认本机存在可用浏览器
- 必要时尝试 `-system-chrome`
- 配合 `-debug`、`-debug-resp`、`-vv` 进一步定位

## 📖 相关文档

- [`DESIGN.md`](./DESIGN.md)：架构说明
- [`DATA.md`](./DATA.md)：运行期数据目录说明
- [`CHANGE.md`](./CHANGE.md)：近期变更记录
- [`CODE_STYLE.md`](./CODE_STYLE.md)：开发规范与检查清单
- [`lib/README.md`](./lib/README.md)：SDK 使用说明
- [`server/API.md`](./server/API.md)：服务端接口文档

## 📄 许可证

本仓库当前沿用 [`LICENSE.md`](./LICENSE.md) 中声明的 MIT 许可证。
