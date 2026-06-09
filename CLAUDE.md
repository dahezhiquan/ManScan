# CLAUDE.md

本文件为 Claude Code（claude.ai/code）在本仓库中工作时提供说明。

## 项目概览

ManScan 是一个现代化、高性能的漏洞扫描器，使用基于 YAML 的模板来实现可定制的漏洞检测。它支持多种协议（HTTP、DNS、TCP、SSL、WebSocket、WHOIS、JavaScript、Code），并通过模拟真实场景条件来尽量实现零误报。


### 测试指定组件
- 运行单个测试：`go test -v ./pkg/path/to/package -run TestName`
- 集成测试位于 `internal/tests/integration/`，通过 `go test -tags=integration ./internal/tests/integration` 运行

## 架构概览

### 核心组件
- **cmd/nuclei** - 主 CLI 入口，负责参数解析和配置
- **internal/runner** - 核心运行器，编排整个扫描流程
- **pkg/core** - 执行引擎，包含工作池与模板聚类
- **pkg/templates** - 模板解析、编译与管理
- **pkg/protocols** - 各协议实现（HTTP、DNS、Network 等）
- **pkg/operators** - 匹配与提取逻辑（matchers / extractors）
- **pkg/catalog** - 从磁盘或远程源发现并加载模板

### 协议架构
每种协议（HTTP、DNS、Network 等）都实现了：
- 请求接口，包含 `Compile()`、`ExecuteWithResults()`、`Match()`、`Extract()` 等方法
- 用于匹配 / 提取能力的 operators 嵌入
- 协议特定的请求构建与执行逻辑

### 模板系统
- 模板是定义漏洞检测逻辑的 YAML 文件
- 会被编译成带 operators（matchers / extractors）的可执行请求
- 支持工作流（多步骤模板执行）
- 模板聚类会在多个模板间优化相同请求的执行

### 关键执行流程
1. 通过 `pkg/catalog/loader` 加载并编译模板
2. 为目标初始化输入提供器
3. 创建带并发工作池的执行引擎
4. 执行模板，并通过 operators 收集结果
5. 写出输出并接入报告系统

### JavaScript 集成
- 为 code 协议模板提供自定义 JavaScript 运行时
- 自动生成的绑定位于 `pkg/js/generated/`
- 库实现位于 `pkg/js/libs/`
- 绑定生成开发工具位于 `pkg/js/devtools/`

## 模板开发
- 模板位于独立的 `manscan-templates` 仓库中
- 使用包含 `info`、`requests`、`operators` 等部分的 YAML 格式
- 单个模板可支持多种协议类型
- 内置 DSL 函数可用于动态内容生成

## 关键目录
- **lib/** - 将 ManScan 作为库嵌入使用的 SDK
- **examples/** - 各类场景的使用示例
- **internal/tests/integration/** - 原生集成测试套件及其自有测试数据
- **internal/tests/functional/** - 仅供 CI 使用的原生功能对比测试与用例资源
- **pkg/fuzz/** - Fuzzing 引擎与 DAST 能力
- **pkg/input/** - 多种输入格式的处理（Burp、OpenAPI 等）
- **pkg/reporting/** - 结果导出与缺陷跟踪集成
