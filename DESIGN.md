# ManScan 架构文档

本文简要概述 ManScan 引擎的架构。随着引擎持续演进，本文档也会保持更新。

## pkg/templates

### Template

Template 是引擎的基础输入单元，用于描述需要发起的请求、需要执行的匹配、要提取的数据等内容。

这里定义了模板的数据结构，包括模板级属性，以及用于校验、解析和编译模板并创建执行器的便捷方法。

模板、引擎或请求运行所需的各种属性，也都在这里进行设置。

工作流也会在这里被编译，其引用的模板会被加载并编译；传入路径的各类校验同样在这里完成。

`Parse` 函数是主要入口，它接收 `filePath` 和 `executorOptions` 并返回一个模板对象。它会编译模板中的全部请求、所有工作流以及自包含请求等内容，并将模板缓存到内存中。

### 预处理器

这里还会应用预处理器，它们可以在模板级别执行一些操作。预处理器会拿到模板数据，并可在运行时按需修改。这一机制在引擎中被用于随机字符串生成。

自定义处理器只要满足以下接口即可使用：

```go
type Preprocessor interface {
	Process(data []byte) []byte
}
```

## pkg/model

`model` 包实现了 ManScan 模板的信息结构。`Info` 包含模板的主要元数据信息，`Classification` 结构则可为漏洞数据提供额外上下文。

它还定义了一个 `WorkflowLoader` 接口，用于模板编译阶段加载工作流。

```go
type WorkflowLoader interface {
	GetTemplatePathsByTags(tags []string) []string
	GetTemplatePaths(templatesList []string, noValidate bool) []string
}
```

## pkg/protocols

`protocols` 包实现了 ManScan 支持的所有请求协议。目前包括 `http`、`dns`、`network`、`headless` 和 `file` 等请求类型。

### Request

它暴露了一个 `Request` 接口，所有受支持的协议请求都需要实现该接口。

```go
// Request is an interface implemented any protocol based request generator.
type Request interface {
	Compile(options *ExecuterOptions) error
	Requests() int
	GetID() string
	Match(data map[string]interface{}, matcher *matchers.Matcher) (bool, []string)
	Extract(data map[string]interface{}, matcher *extractors.Extractor) map[string]struct{}
	ExecuteWithResults(input string, dynamicValues, previous output.InternalEvent, callback OutputEventCallback) error
	MakeResultEventItem(wrapped *output.InternalWrappedEvent) *output.ResultEvent
	MakeResultEvent(wrapped *output.InternalWrappedEvent) []*output.ResultEvent
	GetCompiledOperators() []*operators.Operators
}
```

这些方法中有不少在各协议之间是相似的，但也有一部分明显依赖协议自身特性。

下面对这些方法做一个简要说明：

- **Compile** - 使用给定选项编译请求
- **Requests** - 返回将要执行的请求总数
- **GetID** - 返回请求的 ID（如果有）
- **Match** - 使用 matchers 对模式执行匹配
- **Extract** - 使用 extractors 对模式执行提取
- **ExecuteWithResults** - 针对输入执行请求并返回结果
- **MakeResultEventItem** - 为中间态输出结构 `InternalWrappedEvent` 创建单个结果事件
- **MakeResultEvent** - 基于内部输出事件 `InternalWrappedEvent` 返回结果切片
- **GetCompiledOperators** - 返回已编译的 operators

如果结果生成不需要协议特定功能，可以直接使用 `MakeDefaultResultEvent` 作为 `MakeResultEvent` 的默认实现。

如果你想参考具体协议请求的实现，可以查看以下包：

1. [pkg/protocols/http](./pkg/protocols/http)
2. [pkg/protocols/dns](./pkg/protocols/dns)
3. [pkg/protocols/network](./pkg/protocols/network)

### Executer

这些不同的请求接口最终都会被转换为 `Executer`。它也是在 `pkg/protocols` 中定义的一个接口，用于模板的最终执行阶段。

```go
// Executer is an interface implemented any protocol based request executer.
type Executer interface {
	Compile() error
	Requests() int
	Execute(input string) (bool, error)
	ExecuteWithResults(input string, callback OutputEventCallback) error
}
```

`ExecuteWithResults` 接收一个回调函数，在执行过程中会将 `*output.InternalWrappedEvent` 形式的结果传给它。

默认执行器位于 `pkg/protocols/common/executer`。它接收一组 `Request` 和对应的 `ExecuterOptions`，并实现模板执行所需的 `Executer` 接口。模板编译阶段创建的执行器默认就来自这里，并直接投入使用。

另一种执行器是 Clustered Requests 执行器，它在 `pkg/templates` 中实现了 ManScan 的请求聚类能力。在多个模板可以聚类的场景下，我们只保留一个 HTTP 请求，并挂载多组 operator 列表用于匹配和提取。HTTP 请求只执行一次，而各模板对应的 matcher / extractor 会分别计算。

对于工作流执行，则会使用一个独立的 `RunWorkflow` 函数，它与普通模板执行相互独立。

在有了这些基础后，我们就可以继续看当前的 runner 实现，它也能帮助我们串起 ManScan 的整体架构。

## internal/runner

### 模板加载

在所有 CLI 层初始化完成后，第一步就是加载用户希望运行的模板 / 工作流路径。这个过程由下面这些包负责。

#### pkg/catalog

这个包用于基于混合语法解析路径。它接收一个模板目录，并同时从给定模板路径和当前用户目录中解析模板路径。

它支持非常灵活的语法，包括文件名、glob 模式、目录、绝对路径以及相对路径。

接下来会初始化报告模块，这部分由 `pkg/reporting` 处理。

#### pkg/reporting

报告模块包含 exporters、trackers，以及去重模块和结果格式化模块。

Exporters 与 Trackers 都是在 `pkg/reporting` 中定义的接口。

```go
// Tracker is an interface implemented by an issue tracker
type Tracker interface {
	CreateIssue(event *output.ResultEvent) error
}

// Exporter is an interface implemented by an issue exporter
type Exporter interface {
	Close() error
	Export(event *output.ResultEvent) error
}
```

Exporters 包括 `Elasticsearch`、`markdown`、`sarif`；Trackers 包括 `GitHub`、`GitLab` 和 `Jira`。

每个 exporter 和 tracker 都实现了自己的 YAML 配置格式，并且模块化程度很高，因此扩展新的实现相对容易。

从各种来源读取完输入并初始化完其他杂项选项后，下一步就是输出写入，这由 `pkg/output` 模块完成。

#### pkg/output

`output` 包实现了 ManScan 的输出写入功能。

Output Writer 实现了 `Writer` 接口。每当 ManScan 找到一个结果时，都会调用该接口。

```go
// Writer is an interface which writes output to somewhere for ManScan events.
type Writer interface {
	Close()
	Colorizer() aurora.Aurora
	Write(*ResultEvent) error
	Request(templateID, url, requestType string, err error)
}
```

ManScan Output Writer 接收到的 `ResultEvent` 结构中包含完整的命中结果详情。像 `InternalWrappedEvent`、`InternalEvent` 这样的中间类型，会在各协议和 matcher 的多个执行阶段中用于描述结果。

如果没有被显式禁用，`Interactsh` 也会在此时初始化。

#### pkg/protocols/common/interactsh

`interactsh` 模块用于为 ManScan 提供自动化的 OOB（带外）漏洞识别能力。

它内部使用两个 LRU 缓存：一个用于存储请求 URL 对应的交互记录，另一个用于存储交互 URL 对应的请求。这两个缓存共同用于把 Interactsh OOB 服务器收到的交互，与当前 ManScan 实例发起的请求关联起来。绝大多数底层工作由 [Interactsh Client](https://github.com/projectdiscovery/interactsh/pkg/client) 包完成。

只有当某个模板实际使用了 interactsh 模块并被 ManScan 执行时，才会开始轮询交互和向服务器注册；一旦启动，在整个运行周期内无需重复注册。

### RunEnumeration

接下来进入 runner 的 `RunEnumeration` 函数。

这里会先初始化 `HostErrorsCache`。它贯穿整个 ManScan 枚举过程，用于按主机记录错误次数；当某个主机的错误数超过设定阈值后，会跳过后续请求。该错误跟踪缓存的实现位于 [hosterrorscache.go](https://github.com/projectdiscovery/nuclei/blob/main/pkg/protocols/common/hosterrorscache/hosterrorscache.go)，整体逻辑比较直接。

然后会初始化 `WorkflowLoader`，用于加载工作流，它的实现位于 `pkg/parsers/workflow_loader.go`。

再往后会初始化 loader，它负责综合 Catalog、传入的 Tags、Filters、Paths 等条件，返回已编译的 `Templates` 和 `Workflows`。

#### pkg/catalog/loader

首先，用户以路径形式传入的输入会通过 `pkg/catalog` 模块被标准化为绝对路径。随后，路径过滤模块会移除被排除的模板 / 工作流路径。

`pkg/parsers` 模块中的 `LoadTemplate`、`LoadWorkflow` 函数会检查模板是否通过校验，以及是否被 tags / severity 等过滤条件排除。如果所有检查都通过，则会调用 `pkg/templates` 中的 `Parse` 函数，将模板 / 工作流解析并返回为已编译形式。

`Parse` 函数会编译模板中的全部请求，并基于这些请求创建 Executer，最终返回可运行的 Template / Workflow 结构。

接下来进入聚类模块，它的职责是将完全相同的 HTTP GET 请求聚合起来（因为很多模板会重复发送相同的 GET 请求，在大型扫描中这能显著减少请求数量）。

### pkg/operators

`operators` 包实现了 ManScan 的全部匹配与提取逻辑。

```go
// Operators contain the operators that can be applied on protocols
type Operators struct {
	Matchers []*matchers.Matcher
	Extractors []*extractors.Extractor
	MatchersCondition string
}
```

协议实现只需要嵌入上面的 `operators.Operators` 类型，就能复用 ManScan 的全部匹配 / 提取能力。

```go
// MatchFunc performs matching operation for a matcher on model and returns true or false.
type MatchFunc func(data map[string]interface{}, matcher *matchers.Matcher) (bool, []string)

// ExtractFunc performs extracting operation for an extractor on model and returns true or false.
type ExtractFunc func(data map[string]interface{}, matcher *extractors.Extractor) map[string]struct{}

// Execute executes the operators on data and returns a result structure
func (operators *Operators) Execute(data map[string]interface{}, match MatchFunc, extract ExtractFunc, isDebug bool) (*Result, bool)
```

这套流程的核心是 `Execute` 函数。它接收一个输入字典，以及 `Match` 和 `Extract` 函数，并返回一个 `Result` 结构，后续在 ManScan 执行中就依赖它判断是否命中结果。

```go
// Result is a result structure created from operators running on data.
type Result struct {
	Matched bool
	Extracted bool
	Matches map[string][]string
	Extracts map[string][]string
	OutputExtracts []string
	DynamicValues map[string]interface{}
	PayloadValues map[string]interface{}
}
```

对于单词、正则、jq、路径等内容的匹配和提取内部逻辑，定义在 `pkg/operators/matchers` 和 `pkg/operators/extractors` 中。如果你想进一步深入这一主题，建议重点阅读这些包。

### 模板执行

`pkg/core` 提供了执行模板 / 工作流的引擎机制。它暴露了 `Execute` 函数，负责执行任务，同时也承担模板聚类逻辑。用户也可以选择关闭聚类。

下面是一个使用 core 引擎的示例：

```go
engine := core.New(r.options)
engine.SetExecuterOptions(executerOpts)
results := engine.ExecuteWithOpts(finalTemplates, r.hmapInputProvider, true)
```

### 添加新协议

协议是 ManScan 引擎的核心。诸如 `http`、`dns` 等请求类型，本质上都是以协议请求的形式实现的。

一个协议必须实现前面在 `pkg/protocols` 中提到的 `Protocol` 和 `Request` 接口。下面我们以已有协议实现 `websocket` 为例，简要说明 ManScan 内部如何接入一个新协议。

`websocket` 协议的代码位于 `pkg/protocols/others/websocket`。

下面给出一个 websocket 实现的高层骨架，包含关键组成部分：

```go
package websocket

// Request is a request for the Websocket protocol
type Request struct {
	// Operators for the current request go here.
	operators.Operators `yaml:",inline,omitempty"`
	CompiledOperators   *operators.Operators `yaml:"-"`

	// description: |
	//   Address contains address for the request
	Address string `yaml:"address,omitempty" jsonschema:"title=address for the websocket request,description=Address contains address for the request"`

    // declarations here
}

// Compile compiles the request generators preparing any requests possible.
func (r *Request) Compile(options *protocols.ExecuterOptions) error {
	r.options = options

    // request compilation here as well as client creation
 
	if len(r.Matchers) > 0 || len(r.Extractors) > 0 {
		compiled := &r.Operators
		if err := compiled.Compile(); err != nil {
			return errors.Wrap(err, "could not compile operators")
		}
		r.CompiledOperators = compiled
	}
	return nil
}

// Requests returns the total number of requests the rule will perform
func (r *Request) Requests() int {
	if r.generator != nil {
		return r.generator.NewIterator().Total()
	}
	return 1
}

// GetID returns the ID for the request if any.
func (r *Request) GetID() string {
	return ""
}

// ExecuteWithResults executes the protocol requests and returns results instead of writing them.
func (r *Request) ExecuteWithResults(input string, dynamicValues, previous output.InternalEvent, callback protocols.OutputEventCallback) error {
    // payloads init here
	if err := r.executeRequestWithPayloads(input, hostname, value, previous, callback); err != nil {
		return err
	}
	return nil
}

// ExecuteWithResults executes the protocol requests and returns results instead of writing them.
func (r *Request) executeRequestWithPayloads(input, hostname string, dynamicValues, previous output.InternalEvent, callback protocols.OutputEventCallback) error {
	header := http.Header{}

    // make the actual request here after setting all options

	event := eventcreator.CreateEventWithAdditionalOptions(r, data, r.options.Options.Debug || r.options.Options.DebugResponse, func(internalWrappedEvent *output.InternalWrappedEvent) {
		internalWrappedEvent.OperatorsResult.PayloadValues = payloadValues
	})
	if r.options.Options.Debug || r.options.Options.DebugResponse {
		responseOutput := responseBuilder.String()
		gologger.Debug().Msgf("[%s] Dumped Websocket response for %s", r.options.TemplateID, input)
		gologger.Print().Msgf("%s", responsehighlighter.Highlight(event.OperatorsResult, responseOutput, r.options.Options.NoColor))
	}

	callback(event)
	return nil
}

func (r *Request) MakeResultEventItem(wrapped *output.InternalWrappedEvent) *output.ResultEvent {
	data := &output.ResultEvent{
		TemplateID:       types.ToString(r.options.TemplateID),
		TemplatePath:     types.ToString(r.options.TemplatePath),
		// ... setting more values for result event
	}
	return data
}

// Match performs matching operation for a matcher on model and returns:
// true and a list of matched snippets if the matcher type is supports it
// otherwise false and an empty string slice
func (r *Request) Match(data map[string]interface{}, matcher *matchers.Matcher) (bool, []string) {
	return protocols.MakeDefaultMatchFunc(data, matcher)
}

// Extract performs extracting operation for an extractor on model and returns true or false.
func (r *Request) Extract(data map[string]interface{}, matcher *extractors.Extractor) map[string]struct{} {
	return protocols.MakeDefaultExtractFunc(data, matcher)
}

// MakeResultEvent creates a result event from internal wrapped event
func (r *Request) MakeResultEvent(wrapped *output.InternalWrappedEvent) []*output.ResultEvent {
	return protocols.MakeDefaultResultEvent(r, wrapped)
}

// GetCompiledOperators returns a list of the compiled operators
func (r *Request) GetCompiledOperators() []*operators.Operators {
	return []*operators.Operators{r.CompiledOperators}
}

// Type returns the type of the protocol request
func (r *Request) Type() templateTypes.ProtocolType {
	return templateTypes.WebsocketProtocol
}
```

这类协议中的很多函数都偏样板化，因此 `providers` 包中提供了默认实现。像 `Match`、`Extract`、`MakeResultEvent`、`GetCompiledOperators` 等，在各协议中通常差异不大；如果没有特殊需求，复制默认实现即可。

`eventcreator` 包提供了 `CreateEventWithAdditionalOptions` 函数，可在请求执行后用于创建结果事件。

下面是为 ManScan 增加新协议的步骤说明：

1. 在 `pkg/protocols` 目录中加入协议实现。如果协议较小、可配置项不多，可以考虑放到 `pkg/protocols/others` 目录下。然后在 `pkg/templates/types/types.go` 中为新协议添加枚举值。

2. 将协议请求结构添加到 `Template` 结构体字段中。这一步在 `pkg/templates/templates.go` 中完成，同时补上对应的 import。

```go

import (
	...
	"ManScan/pkg/protocols/others/websocket"
)

// Template is a YAML input file which defines all the requests and
// other metadata for a template.
type Template struct {
	...
	// description: |
	//   Websocket contains the Websocket request to make in the template.
	RequestsWebsocket []*websocket.Request `yaml:"websocket,omitempty" json:"websocket,omitempty" jsonschema:"title=websocket requests to make,description=Websocket requests to make for the template"`
	...
}
```

同时，还要在同一个 `templates.go` 文件中的 `Type` 函数以及 `TemplateTypes` 数组里加入该协议。

```go
// TemplateTypes is a list of accepted template types
var TemplateTypes = []string{
	...
	"websocket",
}

// Type returns the type of the template
func (t *Template) Type() templateTypes.ProtocolType {
	...
	case len(t.RequestsWebsocket) > 0:
		return templateTypes.WebsocketProtocol
	default:
		return ""
	}
}
```

3. 在同目录的 `compile.go` 中，把协议请求加入 `Requests` 函数和 `compileProtocolRequests` 函数。

```go

// Requests return the total request count for the template
func (template *Template) Requests() int {
	return len(template.RequestsDNS) +
		...
		len(template.RequestsSSL) +
		len(template.RequestsWebsocket)
}


// compileProtocolRequests compiles all the protocol requests for the template
func (template *Template) compileProtocolRequests(options protocols.ExecuterOptions) error {
	...

	case len(template.RequestsWebsocket) > 0:
		requests = template.convertRequestToProtocolsRequest(template.RequestsWebsocket)
	}
	template.Executer = executer.NewExecuter(requests, &options)
	return nil
}
```

至此，你就完成了一个新协议在 ManScan 中的接入。下一步很推荐补充 `internal/tests/integration` 下的原生集成测试覆盖，并通过 `go test -tags=integration ./internal/tests/integration` 运行验证。

## Profiling 与 Tracing

为了分析 ManScan 的性能与资源使用情况，可以使用 `-profile-mem` 参数生成 CPU / 内存 profile 以及 trace 文件：

```bash
manscan -t manscan-templates/ -u https://example.com -profile-mem=manscan-$(git describe --tags)
```

这条命令会生成三个文件：

* `manscan.cpu`：CPU profile
* `manscan.mem`：内存（堆）profile
* `manscan.trace`：执行 trace

### 分析 CPU / 内存 Profile

* 在终端中查看 profile：

```bash
go tool pprof manscan.{cpu,mem}
```

* 显示处理 `N` 个目标的总体 CPU 时间：

```bash
go tool pprof -top manscan.cpu | grep "Total samples"
```

* 显示主要的内存消耗点：

```bash
go tool pprof -top manscan.mem | grep "$(go list -m)" | head -10
```

* 在浏览器中可视化 profile：

```bash
go tool pprof -http=:$(shuf -i 1000-99999 -n 1) manscan.{cpu,mem}
```

### 分析 Trace 文件

查看执行 trace：

```bash
go tool trace manscan.trace
```

这些工具可以帮助你定位性能瓶颈和内存泄漏，从而更有针对性地优化 ManScan 的代码库。

## 项目结构

- [pkg/reporting](./pkg/reporting) - ManScan 的报告模块
- [pkg/reporting/exporters/sarif](./pkg/reporting/exporters/sarif) - Sarif 结果导出器
- [pkg/reporting/exporters/markdown](./pkg/reporting/exporters/markdown) - Markdown 结果导出器
- [pkg/reporting/exporters/es](./pkg/reporting/exporters/es) - Elasticsearch 结果导出器
- [pkg/reporting/dedupe](./pkg/reporting/dedupe) - 结果去重模块
- [pkg/reporting/trackers/gitlab](./pkg/reporting/trackers/gitlab) - GitLab 问题跟踪导出器
- [pkg/reporting/trackers/jira](./pkg/reporting/trackers/jira) - Jira 问题跟踪导出器
- [pkg/reporting/trackers/github](./pkg/reporting/trackers/github) - GitHub 问题跟踪导出器
- [pkg/reporting/format](./pkg/reporting/format) - 结果格式化函数
- [pkg/parsers](./pkg/parsers) - 实现模板与工作流的加载、初始发现与校验
- [pkg/types](./pkg/types) - CLI 选项以及杂项辅助函数
- [pkg/progress](./pkg/progress) - 进度跟踪
- [pkg/operators](./pkg/operators) - ManScan 的 operators
- [pkg/operators/common/dsl](./pkg/operators/common/dsl) - ManScan YAML 语法的 DSL 函数
- [pkg/operators/matchers](./pkg/operators/matchers) - Matchers 实现
- [pkg/operators/extractors](./pkg/operators/extractors) - Extractors 实现
- [pkg/catalog](./pkg/catalog) - 从磁盘加载模板的辅助模块
- [pkg/catalog/config](./pkg/catalog/config) - 内部配置管理
- [pkg/catalog/loader](./pkg/catalog/loader) - 实现模板和工作流的加载与校验
- [pkg/catalog/loader/filter](./pkg/catalog/loader/filter) - 基于 tags 和路径过滤模板
- [pkg/output](./pkg/output) - ManScan 输出模块
- [pkg/workflows](./pkg/workflows) - 工作流执行逻辑与声明
- [pkg/utils](./pkg/utils) - 工具函数
- [pkg/model](./pkg/model) - 模板 `Info` 及其他辅助结构
- [pkg/templates](./pkg/templates) - 模板体系的核心入口
- [pkg/templates/cache](./pkg/templates/cache) - 模板缓存
- [pkg/protocols](./pkg/protocols) - 协议规范
- [pkg/protocols/file](./pkg/protocols/file) - File 协议
- [pkg/protocols/network](./pkg/protocols/network) - Network 协议
- [pkg/protocols/common/expressions](./pkg/protocols/common/expressions) - 表达式求值与模板变量支持
- [pkg/protocols/common/interactsh](./pkg/protocols/common/interactsh) - Interactsh 集成
- [pkg/protocols/common/generators](./pkg/protocols/common/generators) - 请求 payload 支持（Sniper 等）
- [pkg/protocols/common/executer](./pkg/protocols/common/executer) - 默认模板执行器
- [pkg/protocols/common/replacer](./pkg/protocols/common/replacer) - 模板替换辅助函数
- [pkg/protocols/common/helpers/eventcreator](./pkg/protocols/common/helpers/eventcreator) - 结果事件创建器
- [pkg/protocols/common/helpers/responsehighlighter](./pkg/protocols/common/helpers/responsehighlighter) - 调试响应高亮器
- [pkg/protocols/common/helpers/deserialization](./pkg/protocols/common/helpers/deserialization) - 反序列化辅助函数
- [pkg/protocols/common/hosterrorscache](./pkg/protocols/common/hosterrorscache) - 记录异常主机的错误缓存
- [pkg/protocols/offlinehttp](./pkg/protocols/offlinehttp) - 离线 HTTP 协议
- [pkg/protocols/http](./pkg/protocols/http) - HTTP 协议
- [pkg/protocols/http/race](./pkg/protocols/http/race) - HTTP Race 模块
- [pkg/protocols/http/raw](./pkg/protocols/http/raw) - 原始 HTTP 请求支持
- [pkg/protocols/headless](./pkg/protocols/headless) - Headless 模块
- [pkg/protocols/headless/engine](./pkg/protocols/headless/engine) - 内部 Headless 实现
- [pkg/protocols/dns](./pkg/protocols/dns) - DNS 协议
- [pkg/projectfile](./pkg/projectfile) - Project File 实现

### 备注

1. 匹配逻辑和中间输出机制目前仍然稍显复杂，后续可以继续简化。
