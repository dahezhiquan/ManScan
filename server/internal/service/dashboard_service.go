package service

import (
	"context"
	"errors"
	"time"

	"ManScan/server/internal/model/dto"
	"ManScan/server/internal/model/entity"
	"ManScan/server/internal/pkg/logx"
	"ManScan/server/internal/repository"
)

// DashboardService 定义主页各区块的数据获取服务。
type DashboardService interface {
	GetOverview(ctx context.Context) (*dto.DashboardOverviewResponse, error)
	GetAssetRisks(ctx context.Context) (*dto.DashboardAssetRisksResponse, error)
	GetHostRankings(ctx context.Context) (*dto.DashboardHostRankingsResponse, error)
	GetServiceFingerprints(ctx context.Context) (*dto.DashboardServiceFingerprintsResponse, error)
}

type dashboardService struct {
	repository repository.DashboardRepository
	logger     *logx.Logger
}

// ErrDashboardUnavailable 表示主页数据暂时无法获取。
var ErrDashboardUnavailable = errors.New("仪表盘数据暂不可用")

const dashboardQueryTimeout = 5 * time.Second

// NewDashboardService 创建带查询时限的主页统计服务。
func NewDashboardService(repo repository.DashboardRepository, logger *logx.Logger) DashboardService {
	return &dashboardService{repository: repo, logger: logger}
}

// GetOverview 获取漏洞状态、未审核漏洞等级及高危开放端口数量。
func (dashboard *dashboardService) GetOverview(ctx context.Context) (*dto.DashboardOverviewResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, dashboardQueryTimeout)
	defer cancel()
	counts, err := dashboard.repository.ListVulnerabilityCounts(ctx)
	if err != nil {
		return nil, dashboard.queryError(ctx, "vulnerability_counts", err)
	}
	ports, err := dashboard.repository.CountHighRiskOpenPorts(ctx)
	if err != nil {
		return nil, dashboard.queryError(ctx, "high_risk_ports", err)
	}
	result := &dto.DashboardOverviewResponse{HighRiskOpenPorts: ports}
	for _, count := range counts {
		result.VulnerabilityStatus.Total += count.Count
		switch count.Status {
		case vulnerabilityStatusUnreviewed:
			result.VulnerabilityStatus.Unreviewed += count.Count
			result.PendingVulnerabilities.Total += count.Count
			switch count.Severity {
			case "critical":
				result.PendingVulnerabilities.Critical += count.Count
			case "high":
				result.PendingVulnerabilities.High += count.Count
			case "medium":
				result.PendingVulnerabilities.Medium += count.Count
			case "low":
				result.PendingVulnerabilities.Low += count.Count
			}
		case vulnerabilityStatusConfirmed:
			result.VulnerabilityStatus.Confirmed += count.Count
		case vulnerabilityStatusTicketed:
			result.VulnerabilityStatus.Ticketed += count.Count
		case vulnerabilityStatusFixed:
			result.VulnerabilityStatus.Fixed += count.Count
		case vulnerabilityStatusFalsePositive:
			result.VulnerabilityStatus.FalsePositive += count.Count
		case vulnerabilityStatusIgnored:
			result.VulnerabilityStatus.Ignored += count.Count
		}
	}
	return result, nil
}

// GetAssetRisks 获取主机与域名资产的最高风险等级分布。
func (dashboard *dashboardService) GetAssetRisks(ctx context.Context) (*dto.DashboardAssetRisksResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, dashboardQueryTimeout)
	defer cancel()
	hosts, err := dashboard.repository.FindHostRiskCounts(ctx)
	if err != nil {
		return nil, dashboard.queryError(ctx, "host_risks", err)
	}
	domains, err := dashboard.repository.FindDomainRiskCounts(ctx)
	if err != nil {
		return nil, dashboard.queryError(ctx, "domain_risks", err)
	}
	return &dto.DashboardAssetRisksResponse{Hosts: toDashboardAssetRiskCounts(hosts), Domains: toDashboardAssetRiskCounts(domains)}, nil
}

// GetHostRankings 获取主机漏洞数量与开放端口数量 Top10。
func (dashboard *dashboardService) GetHostRankings(ctx context.Context) (*dto.DashboardHostRankingsResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, dashboardQueryTimeout)
	defer cancel()
	vulnerabilities, err := dashboard.repository.ListTopHostVulnerabilities(ctx)
	if err != nil {
		return nil, dashboard.queryError(ctx, "host_vulnerability_rankings", err)
	}
	ports, err := dashboard.repository.ListTopHostPorts(ctx)
	if err != nil {
		return nil, dashboard.queryError(ctx, "host_port_rankings", err)
	}
	result := &dto.DashboardHostRankingsResponse{
		TopVulnerabilities: make([]dto.DashboardHostVulnerabilityRank, 0, len(vulnerabilities)),
		TopPorts:           make([]dto.DashboardHostPortRank, 0, len(ports)),
	}
	for _, host := range vulnerabilities {
		result.TopVulnerabilities = append(result.TopVulnerabilities, dto.DashboardHostVulnerabilityRank{IPAddress: host.IPAddress, VulnerabilityCount: host.Count})
	}
	for _, host := range ports {
		result.TopPorts = append(result.TopPorts, dto.DashboardHostPortRank{IPAddress: host.IPAddress, PortCount: host.Count})
	}
	return result, nil
}

// GetServiceFingerprints 获取域名应用与主机端口服务指纹数量 Top10。
func (dashboard *dashboardService) GetServiceFingerprints(ctx context.Context) (*dto.DashboardServiceFingerprintsResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, dashboardQueryTimeout)
	defer cancel()
	domains, err := dashboard.repository.ListTopDomainFingerprints(ctx)
	if err != nil {
		return nil, dashboard.queryError(ctx, "domain_fingerprints", err)
	}
	hosts, err := dashboard.repository.ListTopHostFingerprints(ctx)
	if err != nil {
		return nil, dashboard.queryError(ctx, "host_fingerprints", err)
	}
	result := &dto.DashboardServiceFingerprintsResponse{
		Domains: make([]dto.DashboardDomainFingerprintRank, 0, len(domains)),
		Hosts:   make([]dto.DashboardHostFingerprintRank, 0, len(hosts)),
	}
	for _, fingerprint := range domains {
		result.Domains = append(result.Domains, dto.DashboardDomainFingerprintRank{AppName: fingerprint.Fingerprint, Count: fingerprint.Count})
	}
	for _, fingerprint := range hosts {
		result.Hosts = append(result.Hosts, dto.DashboardHostFingerprintRank{ServiceName: fingerprint.Fingerprint, Count: fingerprint.Count})
	}
	return result, nil
}

func (dashboard *dashboardService) queryError(ctx context.Context, operation string, err error) error {
	if dashboard.logger != nil {
		dashboard.logger.Error("dashboard query failed", "operation", operation, "error", err, "context_error", ctx.Err())
	}
	return ErrDashboardUnavailable
}

func toDashboardAssetRiskCounts(counts entity.DashboardAssetRiskCount) dto.DashboardAssetRiskCounts {
	return dto.DashboardAssetRiskCounts{
		Critical: counts.Critical, High: counts.High, Medium: counts.Medium,
		Low: counts.Low, NoRisk: counts.NoRisk, Unknown: counts.Unknown,
	}
}
