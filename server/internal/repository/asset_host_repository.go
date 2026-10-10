package repository

import (
	"context"
	"strings"
	"time"

	"ManScan/server/internal/model/dto"
	"ManScan/server/internal/model/entity"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

type AssetHostRepository interface {
	List(ctx context.Context, query dto.ListAssetHostsQuery) (*dto.PageResult[AssetHostListRecord], error)
	SyncObservations(ctx context.Context, observations []AssetHostObservation, observedAt time.Time) error
}

type assetHostRepository struct {
	db *gorm.DB
}

type AssetHostObservation struct {
	IPAddress string
	Region    string
	IsAlive   bool
}

type AssetHostListRecord struct {
	entity.AssetHost   `gorm:"embedded"`
	VulnerabilityCount int `gorm:"column:vulnerability_count"`
	CriticalCount      int `gorm:"column:critical_count"`
	HighCount          int `gorm:"column:high_count"`
	MediumCount        int `gorm:"column:medium_count"`
	LowCount           int `gorm:"column:low_count"`
	PortCount          int `gorm:"column:port_count"`
}

func NewAssetHostRepository(db *gorm.DB) AssetHostRepository {
	return &assetHostRepository{db: db}
}

func (r *assetHostRepository) List(ctx context.Context, query dto.ListAssetHostsQuery) (*dto.PageResult[AssetHostListRecord], error) {
	page := query.Page
	if page <= 0 {
		page = 1
	}
	pageSize := query.PageSize
	if pageSize <= 0 {
		pageSize = 10
	}

	baseQuery := r.applyListFilters(r.withAssetHostListStats(r.db.WithContext(ctx).Table("manscan_asset_host AS h")), query)
	var total int64
	if err := baseQuery.Count(&total).Error; err != nil {
		return nil, err
	}

	items := make([]AssetHostListRecord, 0)
	if err := r.applyListFilters(r.withAssetHostListStats(r.db.WithContext(ctx).Table("manscan_asset_host AS h")), query).
		Select(`h.*,
			COALESCE(v.vulnerability_count, 0) AS vulnerability_count,
			COALESCE(v.critical_count, 0) AS critical_count,
			COALESCE(v.high_count, 0) AS high_count,
			COALESCE(v.medium_count, 0) AS medium_count,
			COALESCE(v.low_count, 0) AS low_count,
			COALESCE(p.port_count, 0) AS port_count`).
		Order("h.last_alive_at DESC").
		Order("h.id DESC").
		Offset((page - 1) * pageSize).
		Limit(pageSize).
		Find(&items).Error; err != nil {
		return nil, err
	}

	totalPages := 0
	if total > 0 {
		totalPages = int((total + int64(pageSize) - 1) / int64(pageSize))
	}

	return &dto.PageResult[AssetHostListRecord]{
		Page:       page,
		PageSize:   pageSize,
		Total:      int(total),
		TotalPages: totalPages,
		Items:      items,
	}, nil
}

func (r *assetHostRepository) withAssetHostListStats(db *gorm.DB) *gorm.DB {
	return db.
		Joins(`LEFT JOIN (
			SELECT
				asset_host,
				COUNT(*) AS vulnerability_count,
				SUM(CASE WHEN LOWER(COALESCE(severity, '')) = 'critical' THEN 1 ELSE 0 END) AS critical_count,
				SUM(CASE WHEN LOWER(COALESCE(severity, '')) = 'high' THEN 1 ELSE 0 END) AS high_count,
				SUM(CASE WHEN LOWER(COALESCE(severity, '')) = 'medium' THEN 1 ELSE 0 END) AS medium_count,
				SUM(CASE WHEN LOWER(COALESCE(severity, '')) = 'low' THEN 1 ELSE 0 END) AS low_count
			FROM manscan_vulnerabilities
			WHERE asset_host IS NOT NULL AND asset_host <> ''
			GROUP BY asset_host
		) AS v ON v.asset_host = h.ip_address`).
		Joins("LEFT JOIN (SELECT ip_address, COUNT(*) AS port_count FROM manscan_asset_host_port WHERE ip_address <> '' AND is_alive = ? GROUP BY ip_address) AS p ON p.ip_address = h.ip_address", true)
}

func (r *assetHostRepository) applyListFilters(db *gorm.DB, query dto.ListAssetHostsQuery) *gorm.DB {
	if keyword := strings.TrimSpace(query.Keyword); keyword != "" {
		like := "%" + escapeLikeValue(strings.ToLower(keyword)) + "%"
		db = db.Where(
			"(LOWER(COALESCE(h.ip_address, '')) LIKE ? OR LOWER(COALESCE(h.os_type, '')) LIKE ? OR LOWER(COALESCE(h.related_domains, '')) LIKE ?)",
			like,
			like,
			like,
		)
	}
	if strings.TrimSpace(query.Owner) != "" {
		db = applyLikeAnyFilter(db, "h.owner", []string{query.Owner})
	}
	if strings.TrimSpace(query.OSType) != "" {
		db = applyLikeAnyFilter(db, "h.os_type", []string{query.OSType})
	}
	if strings.TrimSpace(query.Region) != "" {
		db = applyLikeAnyFilter(db, "h.region", []string{query.Region})
	}
	if strings.TrimSpace(query.AssetAddress) != "" {
		db = applyLikeAnyFilter(db, "h.ip_address", []string{query.AssetAddress})
	}
	if len(query.RiskLevels) > 0 {
		db = applyAssetRiskLevelFilter(db, query.RiskLevels)
	}
	if query.HasVulnerability != nil {
		if *query.HasVulnerability {
			db = db.Where("COALESCE(v.vulnerability_count, 0) > 0")
		} else {
			db = db.Where("COALESCE(v.vulnerability_count, 0) = 0")
		}
	}
	if query.HasPort != nil {
		if *query.HasPort {
			db = db.Where("COALESCE(p.port_count, 0) > 0")
		} else {
			db = db.Where("COALESCE(p.port_count, 0) = 0")
		}
	}
	if query.IsAlive != nil {
		db = db.Where("h.is_alive = ?", *query.IsAlive)
	}
	return db
}

func (r *assetHostRepository) SyncObservations(ctx context.Context, observations []AssetHostObservation, observedAt time.Time) error {
	observations = uniqueAssetHostObservations(observations)
	if len(observations) == 0 {
		return nil
	}
	if observedAt.IsZero() {
		observedAt = time.Now()
	}

	const batchSize = 500
	for start := 0; start < len(observations); start += batchSize {
		end := start + batchSize
		if end > len(observations) {
			end = len(observations)
		}
		batch := observations[start:end]
		items := make([]map[string]interface{}, 0, end-start)
		for _, observation := range batch {
			item := map[string]interface{}{
				"ip_address":      observation.IPAddress,
				"scan_created_at": observedAt,
				"last_alive_at":   observedAt,
				"is_alive":        observation.IsAlive,
				"region":          nil,
			}
			if observation.Region != "" {
				item["region"] = observation.Region
			}
			items = append(items, item)
		}
		if err := r.db.WithContext(ctx).
			Table("manscan_asset_host").
			Clauses(clause.OnConflict{
				Columns:   []clause.Column{{Name: "ip_address"}},
				DoUpdates: clause.AssignmentColumns([]string{"last_alive_at", "is_alive", "region"}),
			}).
			Create(&items).Error; err != nil {
			return err
		}
	}
	return nil
}

func uniqueAssetHostObservations(values []AssetHostObservation) []AssetHostObservation {
	result := make([]AssetHostObservation, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		value.IPAddress = strings.TrimSpace(value.IPAddress)
		value.Region = strings.TrimSpace(value.Region)
		if value.IPAddress == "" {
			continue
		}
		if _, ok := seen[value.IPAddress]; ok {
			continue
		}
		seen[value.IPAddress] = struct{}{}
		result = append(result, value)
	}
	return result
}
