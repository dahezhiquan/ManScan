package job_handlers

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"ManScan/server/internal/model/entity"
	"ManScan/server/internal/repository"
	"ManScan/server/internal/service"
)

const VulnxVulnerabilityUpdateJobType = "vulnx_vulnerability.sync"

// VulnxVulnerabilityUpdateHandler 从 cves.txt 全量同步 VulnX 漏洞情报。
type VulnxVulnerabilityUpdateHandler struct {
	rootDir     string
	apiKeys     service.ThirdPartyAPIKeyService
	rateLimiter service.APIKeyRateLimiter
	repository  repository.VulnerabilityIntelligenceRepository
	clientFn    func(string) *VulnxClient
	fetchFn     func(context.Context, string) (*repository.VulnerabilityIntelligenceBundle, error)
}

// NewVulnxVulnerabilityUpdateHandler 创建 VulnX 全量更新任务处理器。
func NewVulnxVulnerabilityUpdateHandler(rootDir string, apiKeys service.ThirdPartyAPIKeyService, rateLimiter service.APIKeyRateLimiter, repo repository.VulnerabilityIntelligenceRepository) *VulnxVulnerabilityUpdateHandler {
	return &VulnxVulnerabilityUpdateHandler{rootDir: rootDir, apiKeys: apiKeys, rateLimiter: rateLimiter, repository: repo, clientFn: NewVulnxClient}
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

func (h *VulnxVulnerabilityUpdateHandler) Execute(ctx context.Context, job entity.ScheduledJob, _ entity.ScheduledJobRun, progress service.ProgressReporter) error {
	if h.repository == nil {
		return errors.New("VulnX 漏洞更新仓储不可用")
	}
	path := filepath.Join(h.rootDir, "data", "tmp", "cve_data", "cves.txt")
	ids, err := readCVEIDs(path)
	if err != nil {
		return err
	}
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
	var firstErr error
	for index, id := range ids {
		if err := ctx.Err(); err != nil {
			return err
		}
		bundle, fetchErr := fetch(ctx, id)
		if fetchErr == nil {
			fetchErr = h.repository.Replace(ctx, bundle)
		}
		if fetchErr != nil && firstErr == nil {
			firstErr = fmt.Errorf("更新 %s 失败: %w", id, fetchErr)
		}
		if err := reportProgress(ctx, progress, int64(index+1), int64(len(ids)), "updating", fmt.Sprintf("已处理 %d/%d 个 CVE", index+1, len(ids))); err != nil {
			return err
		}
	}
	if firstErr != nil {
		return firstErr
	}
	return reportProgress(ctx, progress, int64(len(ids)), int64(len(ids)), "finished", "VulnX 漏洞情报已更新")
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

func readCVEIDs(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("打开 CVE 列表失败: %w", err)
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 64<<10), 1<<20)
	seen := make(map[string]struct{})
	ids := make([]string, 0)
	for scanner.Scan() {
		id := strings.ToUpper(strings.TrimSpace(scanner.Text()))
		if id == "" {
			continue
		}
		if !cveIDPattern.MatchString(id) {
			continue
		}
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		ids = append(ids, id)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("读取 CVE 列表失败: %w", err)
	}
	return ids, nil
}

var _ service.JobHandler = (*VulnxVulnerabilityUpdateHandler)(nil)
