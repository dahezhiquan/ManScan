# 远程获取 CVE 文件名

使用 GitHub Git Trees API 读取 `CVEProject/cvelistV5` 的 `cves/` 目录元数据，无需克隆仓库，也不下载 CVE JSON 文件内容。工具使用 Go 标准库，不增加项目依赖。Go 版本遵循根目录 `go.mod`。

## 运行

在 ManScan 仓库根目录执行：

```bash
go run ./server/tools/cve_file_names > /tmp/cve-file-names.txt
```

标准输出只包含按字典序排序、去重后的 CVE 名称，每行一个，不含目录或 `.json` 后缀：

```text
CVE-1999-0001
CVE-1999-0002
```

默认读取 `main`，也可用 `-ref` 指定分支、标签或提交 SHA：

```bash
go run ./server/tools/cve_file_names -ref main > /tmp/cve-file-names.txt
go run ./server/tools/cve_file_names -h
```

`GITHUB_TOKEN` 是可选环境变量，默认不携带凭证。建议通过终端或密钥管理工具注入有此公开仓库读取权限的 GitHub Token，提高 API 限额；程序不提供命令行 Token 参数，也不输出 Token。匿名请求通常每小时 60 次，认证后的限额以 GitHub 当前策略为准。

程序先读取指定 ref 对应的根 Git Tree，再使用其中的 SHA 获取 `cves/` 子树，避免遍历期间分支更新造成版本混用。优先递归获取；若返回 `truncated=true`，丢弃该次不完整结果，改用非递归目录获取并继续拆分子树。非递归响应仍被截断、请求失败或响应格式异常时，程序报错并以非零状态退出，不输出已收集的部分列表。

每次 HTTP 请求超时为 60 秒，支持 `Ctrl+C` 取消。错误写入标准错误；遇到 403/429 请检查访问权限、`GITHUB_TOKEN` 和 GitHub API 限额后重试。程序在全部获取成功后才输出列表。

## 自动化测试

在仓库根目录执行，无需 GitHub Token 或外网连接：

```bash
go test -race -cover ./server/tools/cve_file_names
go vet ./server/tools/cve_file_names
```

测试通过本地 HTTP 测试服务器验证递归结果、截断后逐层回退、丢弃不完整数据、相对路径处理、非 CVE 文件过滤、去后缀、排序去重、空目录、异常 JSON、缺失目录、认证/限流错误、重定向拒绝及请求取消。

## 实际获取验证

先配置好可用的网络和可选的 `GITHUB_TOKEN`，再执行：

```bash
go run ./server/tools/cve_file_names > /tmp/cve-file-names.txt
```

确认上一条命令退出码为 0 后检查结果：

```bash
wc -l /tmp/cve-file-names.txt
head /tmp/cve-file-names.txt
LC_ALL=C sort -cu /tmp/cve-file-names.txt
awk '!/^CVE-[0-9][0-9][0-9][0-9]-[0-9]+$/ { bad = 1; print "异常行:", $0 } END { exit bad }' /tmp/cve-file-names.txt
```

预期文件非空、每行符合 `CVE-年份-编号`、无 `.json`、无重复且按字典序排列；后两条命令正常时不输出内容。行数随仓库更新变化，不应断言固定数量。这些检查验证输出格式，完整性依赖成功遍历所有 Git Tree，不能仅凭格式检查判断。
