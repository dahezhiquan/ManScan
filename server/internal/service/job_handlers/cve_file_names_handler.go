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
	"ManScan/server/internal/service"
)

const CVEFileNamesJobType = "cve_file_names.sync"

type cveFileNamesConfig struct {
	Ref string `json:"ref"`
}

// CVEFileNamesHandler 从 GitHub 获取 CVE 文件名并原子替换本地索引文件。
type CVEFileNamesHandler struct {
	rootDir     string
	apiKeys     service.ThirdPartyAPIKeyService
	clientFn    func(token string) *GitHubTreeClient
	rateLimiter service.APIKeyRateLimiter
}

// NewCVEFileNamesHandler 创建 CVE 文件名同步任务处理器。
func NewCVEFileNamesHandler(rootDir string, apiKeys service.ThirdPartyAPIKeyService, rateLimiter service.APIKeyRateLimiter) *CVEFileNamesHandler {
	return &CVEFileNamesHandler{rootDir: rootDir, apiKeys: apiKeys, clientFn: NewGitHubTreeClient, rateLimiter: rateLimiter}
}

func (h *CVEFileNamesHandler) Type() string { return CVEFileNamesJobType }

func (h *CVEFileNamesHandler) Validate(config json.RawMessage) error {
	var value cveFileNamesConfig
	if len(config) == 0 {
		return nil
	}
	if err := json.Unmarshal(config, &value); err != nil {
		return fmt.Errorf("CVE 文件名任务配置不是合法 JSON: %w", err)
	}
	if len(value.Ref) > 256 || strings.ContainsAny(value.Ref, "\r\n") {
		return errors.New("GitHub ref 不合法")
	}
	return nil
}

func (h *CVEFileNamesHandler) Execute(ctx context.Context, job entity.ScheduledJob, _ entity.ScheduledJobRun, progress service.ProgressReporter) error {
	var config cveFileNamesConfig
	if err := json.Unmarshal([]byte(job.ConfigJSON), &config); err != nil {
		return fmt.Errorf("解析 CVE 文件名任务配置失败: %w", err)
	}
	ref := strings.TrimSpace(config.Ref)
	if ref == "" {
		ref = "main"
	}

	if err := reportProgress(ctx, progress, 0, 0, "fetching", "正在从 GitHub 获取 CVE 列表"); err != nil {
		return err
	}
	token, err := h.githubToken(ctx, job.APIKeyID)
	if err != nil {
		return err
	}
	client := h.clientFn(token)
	if job.APIKeyID != nil {
		if h.rateLimiter == nil {
			return errors.New("CVE 任务已配置 API Key，但限流服务不可用")
		}
		apiKeyID := *job.APIKeyID
		client.beforeRequest = func(ctx context.Context) error {
			return h.rateLimiter.Wait(ctx, apiKeyID)
		}
	}
	names, err := client.ListCVEFileNames(ctx, ref)
	if err != nil {
		return fmt.Errorf("获取 GitHub CVE 列表失败: %w", err)
	}

	outputPath := filepath.Join(h.rootDir, "data", "tmp", "cve_data", "cves.txt")
	if err := writeCVEFileNames(outputPath, names, progress, ctx); err != nil {
		return err
	}
	if reporter, ok := progress.(service.OutputReporter); ok {
		if err := reporter.SetOutputPath(ctx, filepath.ToSlash(filepath.Join("data", "tmp", "cve_data", "cves.txt"))); err != nil {
			return fmt.Errorf("保存任务产出路径失败: %w", err)
		}
	}
	return reportProgress(ctx, progress, int64(len(names)), int64(len(names)), "finished", "CVE 列表已更新")
}

func (h *CVEFileNamesHandler) githubToken(ctx context.Context, apiKeyID *int64) (string, error) {
	if apiKeyID != nil {
		if h.apiKeys == nil {
			return "", errors.New("CVE 任务已配置 API Key，但 API Key 服务不可用")
		}
		item, err := h.apiKeys.GetPlaintext(ctx, *apiKeyID)
		if err != nil {
			return "", fmt.Errorf("读取 GitHub API Key 失败: %w", err)
		}
		return item.Key, nil
	}
	return os.Getenv("GITHUB_TOKEN"), nil
}

func writeCVEFileNames(outputPath string, names []string, progress service.ProgressReporter, ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	dir := filepath.Dir(outputPath)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return fmt.Errorf("创建 CVE 输出目录失败: %w", err)
	}
	temporary, err := os.CreateTemp(dir, ".cves-*.tmp")
	if err != nil {
		return fmt.Errorf("创建 CVE 临时文件失败: %w", err)
	}
	temporaryPath := temporary.Name()
	removeTemporary := true
	defer func() {
		_ = temporary.Close()
		if removeTemporary {
			_ = os.Remove(temporaryPath)
		}
	}()
	if err := temporary.Chmod(0o640); err != nil {
		return fmt.Errorf("设置 CVE 临时文件权限失败: %w", err)
	}
	writer := bufio.NewWriter(temporary)
	for index, name := range names {
		if err := ctx.Err(); err != nil {
			return err
		}
		if _, err := fmt.Fprintln(writer, name); err != nil {
			return fmt.Errorf("写入 CVE 文件名失败: %w", err)
		}
		if progress != nil && (index == 0 || (index+1)%1000 == 0 || index == len(names)-1) {
			if err := reportProgress(ctx, progress, int64(index+1), int64(len(names)), "writing", "正在写入 CVE 列表"); err != nil {
				return err
			}
		}
	}
	if err := writer.Flush(); err != nil {
		return fmt.Errorf("刷新 CVE 文件名失败: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("关闭 CVE 临时文件失败: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := os.Rename(temporaryPath, outputPath); err != nil {
		return fmt.Errorf("替换 CVE 文件失败: %w", err)
	}
	removeTemporary = false
	return nil
}

func reportProgress(ctx context.Context, progress service.ProgressReporter, current, total int64, phase, message string) error {
	if progress == nil {
		return nil
	}
	return progress.Report(ctx, current, total, phase, message)
}

var _ service.JobHandler = (*CVEFileNamesHandler)(nil)
