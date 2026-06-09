## 将 Nuclei 作为库使用

Nuclei 最初主要被构建为一个 CLI 工具，但随着越来越多用户希望在自己的自动化流程中将 nuclei 作为库来使用，我们在 v3 中加入了一个简化版的 Library/SDK。

### 安装

要将 nuclei 作为库添加到你的 Go 项目中，可以使用以下命令：

```bash
go get -u github.com/projectdiscovery/nuclei/v3/lib
```

或者在你的 Go 文件中添加下面的 import，让 IDE 帮你处理其余部分：

```go
import nuclei "github.com/projectdiscovery/nuclei/v3/lib"
```

## 使用 Nuclei Library/SDK 的基础示例

```go
// 创建带有选项的 nuclei 引擎
	ne, err := nuclei.NewNucleiEngine(
		nuclei.WithTemplateFilters(nuclei.TemplateFilters{Severity: "critical"}), // 仅运行 critical 严重级别的模板
	)
	if err != nil {
		panic(err)
	}
	// 加载目标，并可选择性地探测非 http/https 目标
	ne.LoadTargets([]string{"scanme.sh"}, false)
	err = ne.ExecuteWithCallback(nil)
	if err != nil {
		panic(err)
	}
	defer ne.Close()
```

## 使用 Nuclei Library/SDK 的高级示例

对于批处理等各种使用场景，你可能希望在 goroutine 中运行 nuclei，这可以通过使用 `nuclei.NewThreadSafeNucleiEngine` 来实现。

```go
	// 创建带有选项的 nuclei 引擎
	ne, err := nuclei.NewThreadSafeNucleiEngine()
	if err != nil{
        panic(err)
    }
	// 设置 waitgroup 以处理并发
	wg := &sync.WaitGroup{}

	// 扫描 1 = 在 scanme.sh 上运行 dns 模板
	wg.Add(1)
	go func() {
		defer wg.Done()
		err = ne.ExecuteNucleiWithOpts([]string{"scanme.sh"}, nuclei.WithTemplateFilters(nuclei.TemplateFilters{ProtocolTypes: "http"}))
		if err != nil {
            panic(err)
        }
	}()

	// 扫描 2 = 在 honey.scanme.sh 上运行 http 模板
	wg.Add(1)
	go func() {
		defer wg.Done()
		err = ne.ExecuteNucleiWithOpts([]string{"honey.scanme.sh"}, nuclei.WithTemplateFilters(nuclei.TemplateFilters{ProtocolTypes: "dns"}))
		if err != nil {
            panic(err)
        }
	}()

	// 等待所有扫描完成
	wg.Wait()
	defer ne.Close()
```

## 更多文档

有关 nuclei 库的完整文档，请参阅 [godoc](https://pkg.go.dev/github.com/projectdiscovery/nuclei/v3/lib)，其中包含所有可用的选项和方法。



### 注意

| :exclamation:  **Disclaimer**  |
|---------------------------------|
| **该项目仍在积极开发中**。后续发布版本中可能会包含破坏性变更。更新前请先查看发布变更日志。 |
| 该项目最初主要是作为独立 CLI 工具构建的。**将 nuclei 作为服务运行可能带来安全风险。** 建议谨慎使用，并配合额外的安全措施。 |