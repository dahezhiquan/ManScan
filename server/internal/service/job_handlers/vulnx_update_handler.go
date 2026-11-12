package job_handlers

import (
	"archive/zip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"ManScan/server/internal/model/entity"
	"ManScan/server/internal/repository"
	"ManScan/server/internal/service"
)

const VulnxVulnerabilityUpdateJobType = "vulnx_vulnerability.sync"
const vulnxRequestMaxAttempts = 3
const vulnxRequestConcurrency = 8

type vulnxPartialFailureError struct {
	count int
	first error
}

func (e *vulnxPartialFailureError) Error() string {
	return fmt.Sprintf("%d 个 CVE 更新失败，首条错误：%v", e.count, e.first)
}

func (e *vulnxPartialFailureError) Unwrap() error { return e.first }

// VulnxVulnerabilityUpdateHandler 从最新 CVE 列表同步数据库缺失的 VulnX 漏洞情报。
type VulnxVulnerabilityUpdateHandler struct {
	rootDir string
	jobs    interface {
		FindByType(context.Context, string) (*entity.ScheduledJob, error)
	}
	apiKeys        service.ThirdPartyAPIKeyService
	rateLimiter    service.APIKeyRateLimiter
	repository     repository.VulnerabilityIntelligenceRepository
	clientFn       func(string) *VulnxClient
	githubClientFn func(string) *GitHubTreeClient
	fetchFn        func(context.Context, string) (*repository.VulnerabilityIntelligenceBundle, error)
	listFn         func(context.Context) ([]string, error)
}

// NewVulnxVulnerabilityUpdateHandler 创建 VulnX 新增漏洞更新任务处理器。
func NewVulnxVulnerabilityUpdateHandler(rootDir string, jobs interface {
	FindByType(context.Context, string) (*entity.ScheduledJob, error)
}, apiKeys service.ThirdPartyAPIKeyService, rateLimiter service.APIKeyRateLimiter, repo repository.VulnerabilityIntelligenceRepository) *VulnxVulnerabilityUpdateHandler {
	return &VulnxVulnerabilityUpdateHandler{rootDir: rootDir, jobs: jobs, apiKeys: apiKeys, rateLimiter: rateLimiter, repository: repo, clientFn: NewVulnxClient, githubClientFn: NewGitHubTreeClient}
}

func (h *VulnxVulnerabilityUpdateHandler) Type() string { return VulnxVulnerabilityUpdateJobType }

func (h *VulnxVulnerabilityUpdateHandler) Validate(config json.RawMessage) error {
	if len(config) == 0 {
		return nil
	}
	var value map[string]json.RawMessage
	if err := json.Unmarshal(config, &value); err != nil {
		return fmt.Errorf("VulnX 漏洞更新任务配置不是合法 JSON: %w", err)
	}
	if len(value) != 0 {
		return errors.New("VulnX 漏洞更新任务暂不支持自定义配置")
	}
	return nil
}

func (h *VulnxVulnerabilityUpdateHandler) Execute(ctx context.Context, job entity.ScheduledJob, run entity.ScheduledJobRun, progress service.ProgressReporter) error {
	if h.jobs == nil {
		return errors.New("CVE 列表任务配置仓储不可用")
	}
	githubJob, err := h.jobs.FindByType(ctx, CVEFileNamesJobType)
	if err != nil {
		return fmt.Errorf("读取 CVE 列表任务 API Key 配置失败: %w", err)
	}
	return h.ExecuteWithGitHubKey(ctx, job, run, progress, githubJob.APIKeyID)
}

// ExecuteWithGitHubKey uses the CVE-list job credential for GitHub and the job credential for VulnX.
func (h *VulnxVulnerabilityUpdateHandler) ExecuteWithGitHubKey(ctx context.Context, job entity.ScheduledJob, _ entity.ScheduledJobRun, progress service.ProgressReporter, githubKeyID *int64) error {
	if err := h.Validate(json.RawMessage(job.ConfigJSON)); err != nil {
		return err
	}
	if h.repository == nil {
		return errors.New("VulnX 漏洞更新仓储不可用")
	}
	if err := reportProgress(ctx, progress, 0, 0, "listing", "正在获取最新完整 CVE 列表"); err != nil {
		return err
	}
	list := h.listFn
	if list == nil {
		githubKey, keyErr := h.githubToken(ctx, githubKeyID)
		if keyErr != nil {
			return keyErr
		}
		githubClient := h.githubClientFn(githubKey)
		if githubKeyID != nil {
			if h.rateLimiter == nil {
				return errors.New("CVE 任务已配置 API Key，但限流服务不可用")
			}
			keyID := *githubKeyID
			githubClient.beforeRequest = func(ctx context.Context) error { return h.rateLimiter.Wait(ctx, keyID) }
		}
		list = func(ctx context.Context) ([]string, error) {
			return githubClient.ListCVEFileNames(ctx, "main")
		}
	}
	names, err := list(ctx)
	if err != nil {
		return fmt.Errorf("获取最新完整 CVE 列表失败: %w", err)
	}
	ids := normalizeCVEIDs(names)
	path := filepath.Join(h.rootDir, "data", "tmp", "cve_data", "cves.txt")
	if err := writeCVEFileNames(path, ids, progress, ctx); err != nil {
		return err
	}
	if err := reportProgress(ctx, progress, 0, int64(len(ids)), "checking", "正在与数据库核对已有 CVE"); err != nil {
		return err
	}
	existing := make(map[string]struct{})
	for start := 0; start < len(ids); start += 1000 {
		end := min(start+1000, len(ids))
		found, findErr := h.repository.FindExistingIDs(ctx, "vulnx", ids[start:end])
		if findErr != nil {
			return fmt.Errorf("查询数据库已有 CVE 失败: %w", findErr)
		}
		for id := range found {
			existing[id] = struct{}{}
		}
		if err := reportProgress(ctx, progress, int64(end), int64(len(ids)), "checking", fmt.Sprintf("已核对 %d/%d 个 CVE 编号", end, len(ids))); err != nil {
			return err
		}
	}
	missing := make([]string, 0, len(ids)-len(existing))
	for _, id := range ids {
		if _, ok := existing[id]; !ok {
			missing = append(missing, id)
		}
	}
	ids = missing
	if err := reportProgress(ctx, progress, int64(len(ids)), int64(len(ids)), "checking", fmt.Sprintf("最新 CVE 共 %d 个，数据库缺失 %d 个", len(names), len(ids))); err != nil {
		return err
	}
	errorPath := filepath.Join(h.rootDir, "data", "tmp", "cve_data", "vulnXerror.txt")
	errorDetailPath := filepath.Join(h.rootDir, "data", "tmp", "cve_data", "vulnXerrorDetail.log")
	if err := os.MkdirAll(filepath.Dir(errorPath), 0o750); err != nil {
		return fmt.Errorf("创建 VulnX 失败列表目录失败: %w", err)
	}
	errorFile, err := os.OpenFile(errorPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o640)
	if err != nil {
		return fmt.Errorf("创建 VulnX 失败列表失败: %w", err)
	}
	defer func() { _ = errorFile.Close() }()
	errorDetailFile, err := os.OpenFile(errorDetailPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o640)
	if err != nil {
		return fmt.Errorf("创建 VulnX 失败详情日志失败: %w", err)
	}
	defer func() { _ = errorDetailFile.Close() }()
	if err := reportProgress(ctx, progress, 0, int64(len(ids)), "fetching", "正在读取 VulnX 漏洞详情"); err != nil {
		return err
	}
	apiKey, err := h.apiKey(ctx, job.APIKeyID)
	if err != nil {
		return err
	}
	client := h.clientFn(apiKey)
	fetch := func(ctx context.Context, id string) (*repository.VulnerabilityIntelligenceBundle, error) {
		return client.Fetch(ctx, id)
	}
	if h.fetchFn != nil {
		fetch = h.fetchFn
	}
	if job.APIKeyID != nil {
		if h.rateLimiter == nil {
			return errors.New("VulnX 任务已配置 API Key，但限流服务不可用")
		}
		keyID := *job.APIKeyID
		client.BeforeRequest = func(ctx context.Context) error { return h.rateLimiter.Wait(ctx, keyID) }
	}
	type cveResult struct {
		id  string
		err error
	}
	workerCount := min(len(ids), vulnxRequestConcurrency)
	tasks := make(chan string)
	results := make(chan cveResult, len(ids))
	var workers sync.WaitGroup
	for range workerCount {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for id := range tasks {
				var itemErr error
				for attempt := 0; attempt < vulnxRequestMaxAttempts; attempt++ {
					if err := ctx.Err(); err != nil {
						itemErr = err
						break
					}
					bundle, fetchErr := fetch(ctx, id)
					if fetchErr == nil {
						fetchErr = h.repository.Replace(ctx, bundle)
					}
					if fetchErr == nil {
						itemErr = nil
						break
					}
					itemErr = fetchErr
				}
				results <- cveResult{id: id, err: itemErr}
			}
		}()
	}
	go func() {
		defer close(tasks)
		for _, id := range ids {
			select {
			case tasks <- id:
			case <-ctx.Done():
				return
			}
		}
	}()
	go func() {
		workers.Wait()
		close(results)
	}()
	completed := 0
	var progressErr error
	for result := range results {
		completed++
		if result.err != nil && ctx.Err() == nil {
			if _, err := fmt.Fprintln(errorFile, result.id); err != nil {
				return fmt.Errorf("写入 VulnX 失败列表失败: %w", err)
			}
			if err := errorFile.Sync(); err != nil {
				return fmt.Errorf("刷新 VulnX 失败列表失败: %w", err)
			}
			if _, err := fmt.Fprintf(errorDetailFile, "%s: %v\n", result.id, result.err); err != nil {
				return fmt.Errorf("写入 VulnX 失败详情日志失败: %w", err)
			}
			if err := errorDetailFile.Sync(); err != nil {
				return fmt.Errorf("刷新 VulnX 失败详情日志失败: %w", err)
			}
		}
		if progressErr == nil && ctx.Err() == nil {
			if err := reportProgress(ctx, progress, int64(completed), int64(len(ids)), "updating", fmt.Sprintf("已处理 %d/%d 个 CVE", completed, len(ids))); err != nil {
				progressErr = err
			}
		}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := errorFile.Close(); err != nil {
		return fmt.Errorf("关闭 VulnX 失败列表失败: %w", err)
	}
	if err := errorDetailFile.Close(); err != nil {
		return fmt.Errorf("关闭 VulnX 失败详情日志失败: %w", err)
	}
	remaining, err := h.retryFailedCVEs(ctx, errorPath, errorDetailPath, fetch, progress)
	if err != nil {
		return err
	}
	archivePath, err := writeVulnxErrorArchive(h.rootDir, errorPath, errorDetailPath)
	if err != nil {
		return err
	}
	if reporter, ok := progress.(service.OutputReporter); ok {
		if err := reporter.SetOutputPath(ctx, archivePath); err != nil {
			return fmt.Errorf("保存 VulnX 产物路径失败: %w", err)
		}
	}
	if progressErr != nil {
		return progressErr
	}
	if len(remaining) > 0 {
		return &vulnxPartialFailureError{count: len(remaining), first: fmt.Errorf("更新 %s 失败（补偿重试后仍未成功）", remaining[0])}
	}
	return reportProgress(ctx, progress, int64(len(ids)), int64(len(ids)), "finished", "VulnX 漏洞情报已更新")
}

func (h *VulnxVulnerabilityUpdateHandler) retryFailedCVEs(ctx context.Context, errorPath, errorDetailPath string, fetch func(context.Context, string) (*repository.VulnerabilityIntelligenceBundle, error), progress service.ProgressReporter) ([]string, error) {
	data, err := os.ReadFile(errorPath)
	if err != nil {
		return nil, fmt.Errorf("读取 VulnX 失败列表以执行补偿重试失败: %w", err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) == 1 && lines[0] == "" {
		return nil, nil
	}
	if err := reportProgress(ctx, progress, 0, int64(len(lines)), "retrying", fmt.Sprintf("正在补偿重试 %d 个失败 CVE", len(lines))); err != nil {
		return nil, err
	}
	detailData, err := os.ReadFile(errorDetailPath)
	if err != nil {
		return nil, fmt.Errorf("读取 VulnX 失败详情以执行补偿重试失败: %w", err)
	}
	detailByID := make(map[string]string, len(lines))
	for _, line := range strings.Split(strings.TrimSuffix(string(detailData), "\n"), "\n") {
		if separator := strings.Index(line, ": "); separator > 0 {
			detailByID[line[:separator]] = line
		}
	}
	remaining := make([]string, 0, len(lines))
	remainingDetails := make([]string, 0, len(lines))
	for index, id := range lines {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		var itemErr error
		for attempt := 0; attempt < vulnxRequestMaxAttempts; attempt++ {
			bundle, fetchErr := fetch(ctx, id)
			if fetchErr == nil {
				fetchErr = h.repository.Replace(ctx, bundle)
			}
			if fetchErr == nil {
				itemErr = nil
				break
			}
			itemErr = fetchErr
		}
		if itemErr != nil {
			remaining = append(remaining, id)
			if detail, ok := detailByID[id]; ok {
				remainingDetails = append(remainingDetails, detail)
			}
		}
		if err := reportProgress(ctx, progress, int64(index+1), int64(len(lines)), "retrying", fmt.Sprintf("已补偿重试 %d/%d 个失败 CVE", index+1, len(lines))); err != nil {
			return nil, err
		}
	}
	if err := writeFileAtomic(errorPath, joinLinesWithNewline(remaining), 0o640); err != nil {
		return nil, fmt.Errorf("更新 VulnX 失败列表失败: %w", err)
	}
	if err := writeFileAtomic(errorDetailPath, joinLinesWithNewline(remainingDetails), 0o640); err != nil {
		return nil, fmt.Errorf("更新 VulnX 失败详情日志失败: %w", err)
	}
	return remaining, nil
}

func joinLinesWithNewline(lines []string) []byte {
	if len(lines) == 0 {
		return nil
	}
	return []byte(strings.Join(lines, "\n") + "\n")
}

func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	temporary, err := os.CreateTemp(filepath.Dir(path), ".vulnx-failures-*.tmp")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	removeTemporary := true
	defer func() {
		_ = temporary.Close()
		if removeTemporary {
			_ = os.Remove(temporaryPath)
		}
	}()
	if _, err := temporary.Write(data); err != nil {
		return err
	}
	if err := temporary.Sync(); err != nil {
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Chmod(temporaryPath, mode); err != nil {
		return err
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return err
	}
	removeTemporary = false
	return nil
}

func (h *VulnxVulnerabilityUpdateHandler) githubToken(ctx context.Context, apiKeyID *int64) (string, error) {
	if apiKeyID == nil {
		return os.Getenv("GITHUB_TOKEN"), nil
	}
	if h.apiKeys == nil {
		return "", errors.New("CVE 任务已配置 API Key，但 API Key 服务不可用")
	}
	item, err := h.apiKeys.GetPlaintext(ctx, *apiKeyID)
	if err != nil {
		return "", fmt.Errorf("读取 GitHub API Key 失败: %w", err)
	}
	return item.Key, nil
}

func normalizeCVEIDs(names []string) []string {
	seen := make(map[string]struct{}, len(names))
	ids := make([]string, 0, len(names))
	for _, name := range names {
		id := strings.ToUpper(strings.TrimSpace(strings.TrimSuffix(name, ".json")))
		if !cveIDPattern.MatchString(id) {
			continue
		}
		if _, exists := seen[id]; exists {
			continue
		}
		seen[id] = struct{}{}
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

func writeVulnxErrorArchive(rootDir, errorPath, errorDetailPath string) (string, error) {
	archiveRelativePath := filepath.ToSlash(filepath.Join("data", "tmp", "cve_data", "vulnXerror.zip"))
	archivePath := filepath.Join(rootDir, filepath.FromSlash(archiveRelativePath))
	temporary, err := os.CreateTemp(filepath.Dir(archivePath), ".vulnx-error-*.zip")
	if err != nil {
		return "", fmt.Errorf("创建 VulnX 产物临时文件失败: %w", err)
	}
	temporaryPath := temporary.Name()
	removeTemporary := true
	defer func() {
		_ = temporary.Close()
		if removeTemporary {
			_ = os.Remove(temporaryPath)
		}
	}()
	archive := zip.NewWriter(temporary)
	for _, path := range []string{errorPath, errorDetailPath} {
		file, err := os.Open(path)
		if err != nil {
			return "", fmt.Errorf("读取 VulnX 产物文件失败: %w", err)
		}
		entry, err := archive.Create(filepath.Base(path))
		if err == nil {
			_, err = io.Copy(entry, file)
		}
		closeErr := file.Close()
		if err != nil {
			return "", fmt.Errorf("写入 VulnX 产物文件失败: %w", err)
		}
		if closeErr != nil {
			return "", fmt.Errorf("关闭 VulnX 产物文件失败: %w", closeErr)
		}
	}
	if err := archive.Close(); err != nil {
		return "", fmt.Errorf("关闭 VulnX 产物压缩包失败: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return "", fmt.Errorf("关闭 VulnX 产物临时文件失败: %w", err)
	}
	if err := os.Chmod(temporaryPath, 0o640); err != nil {
		return "", fmt.Errorf("设置 VulnX 产物权限失败: %w", err)
	}
	if err := os.Rename(temporaryPath, archivePath); err != nil {
		return "", fmt.Errorf("替换 VulnX 产物失败: %w", err)
	}
	removeTemporary = false
	return archiveRelativePath, nil
}

func (h *VulnxVulnerabilityUpdateHandler) apiKey(ctx context.Context, apiKeyID *int64) (string, error) {
	if apiKeyID != nil {
		if h.apiKeys == nil {
			return "", errors.New("VulnX 任务已配置 API Key，但 API Key 服务不可用")
		}
		item, err := h.apiKeys.GetPlaintext(ctx, *apiKeyID)
		if err != nil {
			return "", fmt.Errorf("读取 VulnX API Key 失败: %w", err)
		}
		return item.Key, nil
	}
	return strings.TrimSpace(os.Getenv("PDCP_API_KEY")), nil
}

var _ service.JobHandler = (*VulnxVulnerabilityUpdateHandler)(nil)
