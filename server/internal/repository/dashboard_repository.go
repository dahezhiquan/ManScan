package repository

import (
	"context"

	"ManScan/server/internal/model/entity"

	"gorm.io/gorm"
)

// DashboardRepository 定义主页统计所需的聚合查询。
type DashboardRepository interface {
	ListVulnerabilityCounts(ctx context.Context) ([]entity.DashboardVulnerabilityCount, error)
	CountHighRiskOpenPorts(ctx context.Context) (int64, error)
	FindHostRiskCounts(ctx context.Context) (entity.DashboardAssetRiskCount, error)
	FindDomainRiskCounts(ctx context.Context) (entity.DashboardAssetRiskCount, error)
	ListTopHostVulnerabilities(ctx context.Context) ([]entity.DashboardHostCount, error)
	ListTopHostPorts(ctx context.Context) ([]entity.DashboardHostCount, error)
	ListTopDomainFingerprints(ctx context.Context) ([]entity.DashboardFingerprintCount, error)
	ListTopHostFingerprints(ctx context.Context) ([]entity.DashboardFingerprintCount, error)
}

type dashboardRepository struct {
	db *gorm.DB
}

// NewDashboardRepository 创建主页聚合查询仓库。
func NewDashboardRepository(db *gorm.DB) DashboardRepository {
	return &dashboardRepository{db: db}
}

// ListVulnerabilityCounts 在一次查询中按状态和等级统计全部漏洞。
func (repo *dashboardRepository) ListVulnerabilityCounts(ctx context.Context) ([]entity.DashboardVulnerabilityCount, error) {
	counts := make([]entity.DashboardVulnerabilityCount, 0)
	err := repo.db.WithContext(ctx).Model(&entity.Vulnerability{}).
		Select("LOWER(COALESCE(status, '')) AS status, LOWER(COALESCE(severity, '')) AS severity, COUNT(*) AS count").
		Group("LOWER(COALESCE(status, '')), LOWER(COALESCE(severity, ''))").Scan(&counts).Error
	return counts, err
}

// CountHighRiskOpenPorts 统计存活的高危端口记录。
func (repo *dashboardRepository) CountHighRiskOpenPorts(ctx context.Context) (int64, error) {
	var count int64
	err := repo.db.WithContext(ctx).Model(&entity.AssetHostPort{}).
		Where("is_alive = ? AND is_high_risk_port = ?", true, true).Count(&count).Error
	return count, err
}

// FindHostRiskCounts 按有效漏洞的最高等级统计主机资产数量。
func (repo *dashboardRepository) FindHostRiskCounts(ctx context.Context) (entity.DashboardAssetRiskCount, error) {
	return repo.findAssetRiskCounts(ctx, "manscan_asset_host", "ip_address", "asset_host")
}

// FindDomainRiskCounts 按有效漏洞的最高等级统计域名资产数量。
func (repo *dashboardRepository) FindDomainRiskCounts(ctx context.Context) (entity.DashboardAssetRiskCount, error) {
	return repo.findAssetRiskCounts(ctx, "manscan_asset_domain", "domain", "asset_endpoint")
}

func (repo *dashboardRepository) findAssetRiskCounts(ctx context.Context, table, assetColumn, vulnerabilityColumn string) (entity.DashboardAssetRiskCount, error) {
	risks := repo.db.WithContext(ctx).Model(&entity.Vulnerability{}).
		Select(vulnerabilityColumn+` AS asset_key, MAX(CASE LOWER(COALESCE(severity, ''))
			WHEN 'critical' THEN 5 WHEN 'high' THEN 4 WHEN 'medium' THEN 3 WHEN 'low' THEN 2 ELSE 1 END) AS risk_rank`).
		Where(vulnerabilityColumn+" IS NOT NULL AND "+vulnerabilityColumn+" <> ''").
		Where("LOWER(COALESCE(status, '')) NOT IN ?", excludedAssetVulnerabilityStatuses).
		Group(vulnerabilityColumn)
	var counts entity.DashboardAssetRiskCount
	err := repo.db.WithContext(ctx).Table(table+" AS a").
		Joins("LEFT JOIN (?) AS v ON v.asset_key = a."+assetColumn, risks).
		Select(`COALESCE(SUM(CASE WHEN v.risk_rank = 5 THEN 1 ELSE 0 END), 0) AS critical,
			COALESCE(SUM(CASE WHEN v.risk_rank = 4 THEN 1 ELSE 0 END), 0) AS high,
			COALESCE(SUM(CASE WHEN v.risk_rank = 3 THEN 1 ELSE 0 END), 0) AS medium,
			COALESCE(SUM(CASE WHEN v.risk_rank = 2 THEN 1 ELSE 0 END), 0) AS low,
			COALESCE(SUM(CASE WHEN v.risk_rank IS NULL THEN 1 ELSE 0 END), 0) AS no_risk,
			COALESCE(SUM(CASE WHEN v.risk_rank = 1 THEN 1 ELSE 0 END), 0) AS unknown`).
		Scan(&counts).Error
	return counts, err
}

// ListTopHostVulnerabilities 返回所有状态漏洞数量最多的十个登记主机。
func (repo *dashboardRepository) ListTopHostVulnerabilities(ctx context.Context) ([]entity.DashboardHostCount, error) {
	counts := make([]entity.DashboardHostCount, 0)
	err := repo.db.WithContext(ctx).Table("manscan_vulnerabilities AS v").
		Joins("INNER JOIN manscan_asset_host AS h ON h.ip_address = v.asset_host").
		Select("h.ip_address AS ip_address, COUNT(*) AS count").
		Group("h.ip_address").Order("count DESC, h.ip_address ASC").Limit(10).Scan(&counts).Error
	return counts, err
}

// ListTopHostPorts 返回存活端口记录最多的十个登记主机。
func (repo *dashboardRepository) ListTopHostPorts(ctx context.Context) ([]entity.DashboardHostCount, error) {
	counts := make([]entity.DashboardHostCount, 0)
	err := repo.db.WithContext(ctx).Table("manscan_asset_host_port AS p").
		Joins("INNER JOIN manscan_asset_host AS h ON h.ip_address = p.ip_address").
		Where("p.is_alive = ?", true).
		Select("h.ip_address AS ip_address, COUNT(*) AS count").
		Group("h.ip_address").Order("count DESC, h.ip_address ASC").Limit(10).Scan(&counts).Error
	return counts, err
}

// ListTopDomainFingerprints 返回存活域名应用指纹数量 Top10。
func (repo *dashboardRepository) ListTopDomainFingerprints(ctx context.Context) ([]entity.DashboardFingerprintCount, error) {
	return repo.listTopFingerprints(ctx, "manscan_asset_domain_service_assets", "app_name")
}

// ListTopHostFingerprints 返回存活主机端口服务指纹数量 Top10。
func (repo *dashboardRepository) ListTopHostFingerprints(ctx context.Context) ([]entity.DashboardFingerprintCount, error) {
	return repo.listTopFingerprints(ctx, "manscan_asset_host_port", "service_name")
}

func (repo *dashboardRepository) listTopFingerprints(ctx context.Context, table, column string) ([]entity.DashboardFingerprintCount, error) {
	counts := make([]entity.DashboardFingerprintCount, 0)
	err := repo.db.WithContext(ctx).Table(table).Where("is_alive = ?", true).
		Where(column + " IS NOT NULL AND TRIM(" + column + ") <> ''").
		Select(column + " AS fingerprint, COUNT(*) AS count").Group(column).
		Order("count DESC, " + column + " ASC").Limit(10).Scan(&counts).Error
	return counts, err
}
