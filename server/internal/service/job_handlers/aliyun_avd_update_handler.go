package job_handlers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"ManScan/server/internal/model/entity"
	"ManScan/server/internal/repository"
	"ManScan/server/internal/service"
)

const AliyunAVDUpdateJobType = "aliyun_avd_vulnerability.sync"

type avdJobConfig struct {
	RequestDelayMS int `json:"request_delay_ms"`
	MaxPages       int `json:"max_pages"`
}

// AliyunAVDUpdateHandler 抓取阿里云高危列表中的无 CVE 漏洞详情并同步已确认字段。
type AliyunAVDUpdateHandler struct {
	rootDir    string
	repository repository.VulnerabilityIntelligenceRepository
	clientFn   func(time.Duration, int) *AVDClient
}

func NewAliyunAVDUpdateHandler(rootDir string, repo repository.VulnerabilityIntelligenceRepository) *AliyunAVDUpdateHandler {
	return &AliyunAVDUpdateHandler{rootDir: rootDir, repository: repo, clientFn: NewAVDClient}
}

func (h *AliyunAVDUpdateHandler) Type() string { return AliyunAVDUpdateJobType }

func (h *AliyunAVDUpdateHandler) Validate(raw json.RawMessage) error {
	var config avdJobConfig
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &config); err != nil {
			return fmt.Errorf("阿里云 AVD 任务配置不是合法 JSON: %w", err)
		}
	}
	if config.RequestDelayMS < 0 || config.RequestDelayMS > 60000 {
		return errors.New("request_delay_ms 必须在 0 到 60000 之间")
	}
	if config.MaxPages < 0 || config.MaxPages > aliyunAVDMaxPages {
		return fmt.Errorf("max_pages 必须在 0 到 %d 之间", aliyunAVDMaxPages)
	}
	return nil
}

func (h *AliyunAVDUpdateHandler) Execute(ctx context.Context, job entity.ScheduledJob, _ entity.ScheduledJobRun, progress service.ProgressReporter) error {
	var config avdJobConfig
	if err := json.Unmarshal([]byte(job.ConfigJSON), &config); err != nil {
		return fmt.Errorf("解析阿里云 AVD 任务配置失败: %w", err)
	}
	delay := time.Duration(config.RequestDelayMS) * time.Millisecond
	if config.RequestDelayMS == 0 {
		delay = aliyunAVDDefaultDelay
	}
	maxPages := config.MaxPages
	if maxPages == 0 {
		maxPages = aliyunAVDMaxPages
	}
	if err := reportProgress(ctx, progress, 0, 0, "fetching", "正在抓取阿里云高危漏洞列表及无 CVE 详情"); err != nil {
		return err
	}
	client := h.clientFn(delay, maxPages)
	collection, err := client.CollectNoCVE(ctx)
	if err != nil {
		return err
	}
	if h.repository == nil {
		return errors.New("阿里云 AVD 漏洞情报仓储不可用")
	}
	for index := range collection.Vulnerabilities {
		if err := ctx.Err(); err != nil {
			return err
		}
		bundle, mapErr := avdVulnerabilityBundle(&collection.Vulnerabilities[index])
		if mapErr == nil {
			mapErr = h.repository.UpsertAVD(ctx, bundle)
		}
		if mapErr != nil {
			collection.Errors = append(collection.Errors, fmt.Sprintf("%s database sync: %v", collection.Vulnerabilities[index].VulnerabilityID, mapErr))
		}
	}
	outputPath := filepath.Join(h.rootDir, "data", "tmp", "aliyun_avd", "no_cve_vulnerabilities.json")
	if err := writeAVDCollection(outputPath, collection); err != nil {
		return err
	}
	if reporter, ok := progress.(service.OutputReporter); ok {
		if err := reporter.SetOutputPath(ctx, filepath.ToSlash(filepath.Join("data", "tmp", "aliyun_avd", "no_cve_vulnerabilities.json"))); err != nil {
			return fmt.Errorf("保存阿里云 AVD 产物路径失败: %w", err)
		}
	}
	message := fmt.Sprintf("已抓取 %d 页列表，筛出 %d 条无 CVE 漏洞，成功获取 %d 条详情", collection.ListPages, collection.NoCVECandidateCount, len(collection.Vulnerabilities))
	if len(collection.Errors) > 0 {
		return fmt.Errorf("%s，%d 条详情失败，首条错误：%s", message, len(collection.Errors), collection.Errors[0])
	}
	return reportProgress(ctx, progress, int64(len(collection.Vulnerabilities)), int64(len(collection.Vulnerabilities)), "finished", message)
}

func avdVulnerabilityBundle(vuln *AVDVulnerability) (*repository.VulnerabilityIntelligenceBundle, error) {
	if vuln == nil || strings.TrimSpace(vuln.VulnerabilityID) == "" {
		return nil, errors.New("阿里云 AVD 漏洞编号为空")
	}
	var disclosureTime *time.Time
	if value := strings.TrimSpace(vuln.Disclosure); value != "" {
		disclosure, err := time.Parse("2006-01-02", value)
		if err != nil {
			return nil, fmt.Errorf("披露时间格式无效: %w", err)
		}
		disclosureTime = &disclosure
	}
	description := strings.TrimSpace(vuln.Description)
	remediation := strings.TrimSpace(vuln.Remediation)
	var descriptionValue, remediationValue *string
	if description != "" {
		descriptionValue = &description
	}
	if remediation != "" {
		remediationValue = &remediation
	}
	category := "non-cve"
	var severityValue, title *string
	if value := strings.TrimSpace(vuln.Severity); value != "" {
		severity := avdSeverity(value)
		severityValue = &severity
	}
	if value := strings.TrimSpace(vuln.Title); value != "" {
		title = &value
	}
	exploitStatus := strings.ToLower(vuln.ExploitStatus + " " + vuln.RiskMetrics.ExploitMaturity)
	var isAuth, isPatchAvailable, isPOC, isRemote *bool
	if value := strings.TrimSpace(vuln.RiskMetrics.PrivilegesRequired); value != "" {
		isAuth = valuePointer(strings.Contains(value, "权限") && !strings.Contains(value, "无需"))
	}
	if value := strings.TrimSpace(vuln.PatchStatus); value != "" {
		isPatchAvailable = valuePointer(!strings.Contains(value, "暂无"))
	}
	if value := strings.TrimSpace(vuln.ExploitStatus + " " + vuln.RiskMetrics.ExploitMaturity); value != "" {
		isPOC = valuePointer(strings.Contains(exploitStatus, "exp 已公开") || strings.Contains(exploitStatus, "poc 已公开"))
	}
	if value := strings.TrimSpace(vuln.RiskMetrics.AttackPath); value != "" {
		isRemote = valuePointer(strings.Contains(value, "远程"))
	}
	record := &entity.VulnerabilityIntelligenceRecord{
		Source:           "avd",
		VulnerabilityID:  vuln.VulnerabilityID,
		Category:         &category,
		CreatedAt:        disclosureTime,
		CVSSScore:        vuln.AliyunScore,
		Description:      descriptionValue,
		IsAuth:           isAuth,
		IsPatchAvailable: isPatchAvailable,
		IsPOC:            isPOC,
		IsRemote:         isRemote,
		Remediation:      remediationValue,
		Severity:         severityValue,
		VulName:          title,
	}
	articles := make([]entity.VulnerabilityIntelligenceArticle, 0, len(vuln.References))
	for _, reference := range vuln.References {
		reference = strings.TrimSpace(reference)
		if reference == "" {
			continue
		}
		articles = append(articles, entity.VulnerabilityIntelligenceArticle{
			VulnerabilityID: vuln.VulnerabilityID,
			Source:          valuePointer("avd"),
			URL:             reference,
		})
	}
	return &repository.VulnerabilityIntelligenceBundle{Record: record, Articles: articles}, nil
}

func valuePointer[T any](value T) *T { return &value }

func avdSeverity(value string) string {
	switch strings.TrimSpace(value) {
	case "严重", "Critical", "critical":
		return "critical"
	case "高危", "High", "high":
		return "high"
	case "中危", "Medium", "medium":
		return "medium"
	case "低危", "Low", "low":
		return "low"
	default:
		return "none"
	}
}

func writeAVDCollection(outputPath string, collection *AVDCollection) error {
	if collection == nil {
		return errors.New("阿里云 AVD 采集结果为空")
	}
	if err := os.MkdirAll(filepath.Dir(outputPath), 0o750); err != nil {
		return fmt.Errorf("创建阿里云 AVD 产物目录失败: %w", err)
	}
	data, err := json.MarshalIndent(collection, "", "  ")
	if err != nil {
		return fmt.Errorf("序列化阿里云 AVD 采集结果失败: %w", err)
	}
	temporary, err := os.CreateTemp(filepath.Dir(outputPath), ".avd-*.tmp")
	if err != nil {
		return fmt.Errorf("创建阿里云 AVD 临时产物失败: %w", err)
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
		return fmt.Errorf("设置阿里云 AVD 产物权限失败: %w", err)
	}
	if _, err := temporary.Write(data); err != nil {
		return fmt.Errorf("写入阿里云 AVD 产物失败: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		return fmt.Errorf("刷新阿里云 AVD 产物失败: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("关闭阿里云 AVD 临时产物失败: %w", err)
	}
	if err := os.Rename(temporaryPath, outputPath); err != nil {
		return fmt.Errorf("替换阿里云 AVD 产物失败: %w", err)
	}
	removeTemporary = false
	return nil
}

func avdOutputPath(rootDir string) string {
	return strings.TrimSpace(filepath.Join(rootDir, "data", "tmp", "aliyun_avd", "no_cve_vulnerabilities.json"))
}

var _ service.JobHandler = (*AliyunAVDUpdateHandler)(nil)
