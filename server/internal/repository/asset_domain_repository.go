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

type AssetDomainRepository interface {
	List(ctx context.Context, query dto.ListAssetDomainsQuery) (*dto.PageResult[entity.AssetDomain], error)
	SyncLiveness(ctx context.Context, aliveDomains, checkedDomains []string, observedAt time.Time) error
}

type assetDomainRepository struct {
	db *gorm.DB
}

const assetDomainRiskOrder = `CASE LOWER(COALESCE(a.risk_level, ''))
WHEN 'critical' THEN 1
WHEN 'high' THEN 2
WHEN 'medium' THEN 3
WHEN 'low' THEN 4
WHEN 'info' THEN 5
WHEN 'unknown' THEN 6
ELSE 7
END ASC`

func NewAssetDomainRepository(db *gorm.DB) AssetDomainRepository {
	return &assetDomainRepository{db: db}
}

func (r *assetDomainRepository) SyncLiveness(ctx context.Context, aliveDomains, checkedDomains []string, observedAt time.Time) error {
	aliveDomains = uniqueNonEmptyAssetDomains(aliveDomains)
	checkedDomains = uniqueNonEmptyAssetDomains(checkedDomains)
	if len(aliveDomains) == 0 && len(checkedDomains) == 0 {
		return nil
	}
	if observedAt.IsZero() {
		observedAt = time.Now()
	}

	return r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := upsertAliveAssetDomains(ctx, tx, aliveDomains, observedAt); err != nil {
			return err
		}
		notAliveDomains := assetDomainDifference(checkedDomains, aliveDomains)
		if len(notAliveDomains) == 0 {
			return nil
		}
		return tx.WithContext(ctx).
			Model(&entity.AssetDomain{}).
			Where("domain IN ?", notAliveDomains).
			Update("is_alive", false).Error
	})
}

func (r *assetDomainRepository) List(ctx context.Context, query dto.ListAssetDomainsQuery) (*dto.PageResult[entity.AssetDomain], error) {
	page := query.Page
	if page <= 0 {
		page = 1
	}
	pageSize := query.PageSize
	if pageSize <= 0 {
		pageSize = 10
	}

	baseQuery := r.applyListFilters(r.db.WithContext(ctx).Table("manscan_asset_domain AS a"), query)
	var total int64
	if err := baseQuery.Count(&total).Error; err != nil {
		return nil, err
	}

	items := make([]entity.AssetDomain, 0)
	if err := r.applyListFilters(r.db.WithContext(ctx).Table("manscan_asset_domain AS a"), query).
		Select("a.*").
		Order(assetDomainRiskOrder).
		Order("a.vulnerability_count DESC").
		Order("a.last_alive_at DESC").
		Order("a.id DESC").
		Offset((page - 1) * pageSize).
		Limit(pageSize).
		Find(&items).Error; err != nil {
		return nil, err
	}

	totalPages := 0
	if total > 0 {
		totalPages = int((total + int64(pageSize) - 1) / int64(pageSize))
	}

	return &dto.PageResult[entity.AssetDomain]{
		Page:       page,
		PageSize:   pageSize,
		Total:      int(total),
		TotalPages: totalPages,
		Items:      items,
	}, nil
}

func (r *assetDomainRepository) applyListFilters(db *gorm.DB, query dto.ListAssetDomainsQuery) *gorm.DB {
	if keyword := strings.TrimSpace(query.Keyword); keyword != "" {
		like := "%" + escapeLikeValue(strings.ToLower(keyword)) + "%"
		db = db.Where(
			"(LOWER(COALESCE(a.domain, '')) LIKE ? OR LOWER(COALESCE(a.title, '')) LIKE ?)",
			like,
			like,
		)
	}
	if strings.TrimSpace(query.Owner) != "" {
		db = applyLikeAnyFilter(db, "a.owner", []string{query.Owner})
	}
	if strings.TrimSpace(query.Region) != "" {
		db = applyLikeAnyFilter(db, "a.region", []string{query.Region})
	}
	if strings.TrimSpace(query.AssetAddress) != "" {
		db = applyLikeAnyFilter(db, "a.domain", []string{query.AssetAddress})
	}
	if strings.TrimSpace(query.RiskLevel) != "" {
		db = applyLowerInFilter(db, "a.risk_level", []string{query.RiskLevel})
	}
	if query.IsAlive != nil {
		db = db.Where("a.is_alive = ?", *query.IsAlive)
	}
	return db
}

func upsertAliveAssetDomains(ctx context.Context, db *gorm.DB, domains []string, observedAt time.Time) error {
	const batchSize = 500
	for start := 0; start < len(domains); start += batchSize {
		end := start + batchSize
		if end > len(domains) {
			end = len(domains)
		}
		items := make([]entity.AssetDomain, 0, end-start)
		for _, domain := range domains[start:end] {
			items = append(items, entity.AssetDomain{
				Domain:       domain,
				IsAlive:      true,
				FirstAliveAt: &observedAt,
				LastAliveAt:  &observedAt,
			})
		}
		if err := db.WithContext(ctx).
			Clauses(clause.OnConflict{
				Columns:   []clause.Column{{Name: "domain"}},
				DoNothing: true,
			}).
			Create(&items).Error; err != nil {
			return err
		}
		if err := db.WithContext(ctx).
			Model(&entity.AssetDomain{}).
			Where("domain IN ?", domains[start:end]).
			Updates(map[string]interface{}{
				"is_alive":       true,
				"first_alive_at": gorm.Expr("COALESCE(first_alive_at, ?)", observedAt),
				"last_alive_at":  observedAt,
			}).Error; err != nil {
			return err
		}
	}
	return nil
}

func assetDomainDifference(values, excludes []string) []string {
	excluded := make(map[string]struct{}, len(excludes))
	for _, value := range excludes {
		value = strings.TrimSpace(value)
		if value != "" {
			excluded[value] = struct{}{}
		}
	}
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := excluded[value]; ok {
			continue
		}
		result = append(result, value)
	}
	return result
}

func uniqueNonEmptyAssetDomains(values []string) []string {
	result := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	return result
}
