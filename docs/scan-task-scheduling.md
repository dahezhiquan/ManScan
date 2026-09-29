# 扫描任务调度说明

本文只说明创建扫描任务后，系统大概按什么顺序执行。想看代码细节时，再从文中提到的文件入口继续追。

## 一句话结论

一个扫描任务不是一个目标一个目标串行扫完。它会先做必要的前置探测，然后启动 ManScan 子进程执行模板扫描；多个目标、多个模板会按配置并发执行。

## 总流程

```text
创建任务
  -> 规范化目标和参数
  -> 写入 pending 任务
  -> 创建运行态目录和结果队列
  -> 后台启动任务
  -> 状态改为 running
  -> 扫描前域名存活和指纹探测
  -> 启动 ManScan 主扫描子进程
  -> 解析结果、日志和进度
  -> 写入漏洞、组件、任务结果
  -> 标记 success / failed / paused / cancelled
```

主要入口：

- 任务创建和调度：`server/internal/service/scan_task_service.go`
- 扫描前域名探测：`server/internal/service/scan_task_asset_domain.go`
- 主扫描 runner：`internal/runner/runner.go`
- 模板执行引擎：`pkg/core/`
- 自动模版映射：`pkg/protocols/common/automaticscan/`

## 任务状态

```text
pending
  -> running
       -> success
       -> failed
       -> paused -> resume -> running
       -> cancelled
```

- `pending`：任务已创建，等待后台执行。
- `running`：任务正在准备或扫描。
- `success`：扫描正常结束。
- `failed`：扫描准备或子进程执行失败。
- `paused`：用户暂停，保留断点。
- `cancelled`：用户取消，终止任务。

暂停会尽量让子进程安全退出并保留 `resume.cfg`。恢复时会复用原任务配置和断点继续执行。

## 运行时文件

服务端任务会在下面目录保存运行态：

```text
data/runtime/<task-id>/
```

常见文件：

- `targets.txt`：本次扫描目标列表。
- `events.jsonl`：任务日志和前端事件。
- `progress.json`：任务进度快照。
- `match.log`：命中结果去重日志。
- `error.log`：扫描错误日志。
- `asset-domain-fingerprints.json`：扫描前域名指纹缓存。
- `resume.cfg`：暂停恢复断点。

如果启用响应落盘，任务结束后还可能生成：

```text
data/responses/<task-id>/
data/responses/<task-id>.zip
```

## 扫描前域名探测

主扫描开始前，服务端会尝试做一次域名存活和 Wappalyzer 指纹探测。

会执行的条件：

- 有域名资产仓储。
- 任务目标不为空。
- 没有启用 `offline_http`。
- 没有启用 `disable_http_probe`。

这一阶段会做三件事：

1. 探测目标 HTTP/HTTPS 是否存活。
2. 对 HTTP 存活目标做 Wappalyzer 被动指纹识别。
3. 写入 `asset-domain-fingerprints.json`，供后续扫描复用。

这个缓存很重要：

- `http_alive=true`：表示 HTTP 探测成功，可复用 Wappalyzer 组件。
- `http_alive=false`：表示 HTTP 探测失败，后续会尽量跳过 HTTP/headless 模板，但不会跳过整个目标。

前置探测失败不会直接导致任务失败。除非任务被取消或上下文结束，否则主扫描会继续。

## 非自动扫描

`AutomaticScan=false` 时，用户选择什么漏洞模板，主扫描就执行什么漏洞模板。

如果扫描前域名探测可用，还会多做一次主动指纹：

```text
HTTP 存活目标
  -> 执行完整 tech,detect,favicon 指纹模板

HTTP 不存活目标
  -> 执行非 HTTP/headless 的 tech,detect,favicon 指纹模板
```

也就是说，HTTP 不存活目标不会被丢弃。它仍然可以继续做 TCP、Network、SSL、MySQL、Redis 等非 HTTP 指纹和漏洞扫描。

为了避免重复扫描，主漏洞扫描子进程会排除已经在前置阶段跑过的 `tech,detect,favicon` 指纹模板。

## 自动扫描

`AutomaticScan=true` 时，流程是“先识别组件，再按组件标签加载漏洞模板”。

单个目标的自动扫描流程：

```text
读取扫描前指纹缓存
  -> 命中则复用 Wappalyzer 组件
  -> 未命中才发 Wappalyzer 请求
执行 detection 指纹模板
合并 tags
过滤内部 detect 标签
按 tags 加载漏洞模板
执行该目标的漏洞扫描
```

自动扫描是目标级流水线：

- 多个目标会并发做指纹映射。
- 某个目标完成映射后，会立即启动该目标的漏洞扫描。
- 其他目标可以继续做指纹识别。

如果某个目标 `http_alive=false`：

- 不重复发 Wappalyzer 请求。
- detection 阶段过滤 HTTP/headless 指纹模板。
- 漏洞模板执行阶段也会跳过 HTTP/headless 模板。
- 非 HTTP 模板继续执行。

## 并发怎么理解

常用参数如下：

| 参数 | 默认值 | 作用 |
| --- | ---: | --- |
| `probe_concurrency` | `50` | 扫描前 HTTP/Wappalyzer 探测并发 |
| `bulk_size` | `25` | 目标并发规模 |
| `template_threads` | `25` | 普通模板并发规模 |
| `headless_bulk_size` | `10` | Headless 目标并发规模 |
| `headless_template_threads` | `10` | Headless 模板并发规模 |
| `rate_limit` | `150` | 全局请求速率 |
| `rate_limit_duration` | `1000ms` | 速率窗口 |

简单理解：

- 前置探测由 `probe_concurrency` 控制。
- 普通漏洞扫描通常是多个模板并发，每个模板再并发打多个目标。
- `scan_strategy=auto` 当前会落到 `template-spray`。
- Headless 有单独的目标并发和模板并发。
- 最终请求发送还会被 `rate_limit` 限速。

## 进度怎么看

进度里常见三类请求数：

- `total_requests`：预计总请求数。
- `requests`：逻辑完成进度。
- `actual_requests` / `real_requests`：实际发出的网络请求数。

自动扫描有一个特殊点：刚开始需要先识别组件，暂时不知道最终会加载多少漏洞模板。所以前端会先显示 `calculating`，等所有目标完成映射后再切到正常进度。

## 主机失败跳过

主扫描中有 HostErrorsCache，用来避免对明显不可达的 HTTP 主机继续发送大量请求。

默认配置：

| 参数 | 默认值 | 说明 |
| --- | ---: | --- |
| `max_host_error` | `30` | 同一主机连续失败达到阈值后跳过后续请求 |
| `no_host_errors` | `false` | 为 `true` 时关闭该机制 |

注意：

- 这是主扫描过程中的连续失败跳过机制。
- 扫描前 HTTP 探测失败不是同一个机制。
- 一次成功会重置该主机的连续失败计数。
- 已经发出的请求不会被强制撤回，跳过只影响后续调度。

如果想关闭主机失败跳过，服务端任务参数建议使用：

```json
{
  "no_host_errors": true
}
```

## 常见场景

### HTTP 服务存活，非自动扫描

```text
HTTP 探测成功
  -> Wappalyzer
  -> 完整主动指纹
  -> 执行用户选择的漏洞模板
```

### HTTP 不存活，但可能是 MySQL/TCP 服务

```text
HTTP 探测失败
  -> 写入 http_alive=false
  -> 主动指纹只保留非 HTTP 模板
  -> 漏洞扫描跳过 HTTP/headless 模板
  -> 继续执行非 HTTP 模板
```

### 自动扫描

```text
复用扫描前缓存
  -> 指纹模板识别 tags
  -> 按 tags 加载漏洞模板
  -> 单个目标映射完成后立即扫描
```

## 最后记住三点

1. 多目标不是串行扫完一个再扫下一个，多个阶段都有并发。
2. HTTP 不存活不代表目标被跳过，只是跳过 HTTP/headless 这类无效模板。
3. 自动扫描会先识别组件再决定漏洞模板，所以前期进度可能显示为 `calculating`。
