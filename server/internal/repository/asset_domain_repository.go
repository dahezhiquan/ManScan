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
	ListNetworkItems(ctx context.Context) ([]AssetDomainNetworkItem, error)
	SyncObservations(ctx context.Context, observations []AssetDomainObservation, checkedDomains []string, observedAt time.Time) error
	SyncServiceAssets(ctx context.Context, observations []AssetDomainServiceAssetObservation, checkedDomains []string, observedAt time.Time) error
}

type assetDomainRepository struct {
	db *gorm.DB
}

type AssetDomainObservation struct {
	Domain         string
	Region         string
	HTTPStatusCode uint
	Title          string
	Request        string
	Response       string
}

type AssetDomainNetworkItem struct {
	ItemName      string
	SmallCategory string
}

type AssetDomainServiceAssetObservation struct {
	Domain     string
	AppName    string
	AppVersion string
}

func NewAssetDomainRepository(db *gorm.DB) AssetDomainRepository {
	return &assetDomainRepository{db: db}
}

func (r *assetDomainRepository) ListNetworkItems(ctx context.Context) ([]AssetDomainNetworkItem, error) {
	items := make([]AssetDomainNetworkItem, 0)
	if err := r.db.WithContext(ctx).
		Model(&entity.AssetConfigCenter{}).
		Select("item_name, small_category").
		Where("big_category = ?", "network").
		Order("id ASC").
		Find(&items).Error; err != nil {
		return nil, err
	}
	return uniqueNonEmptyAssetDomainNetworkItems(items), nil
}

func (r *assetDomainRepository) SyncObservations(ctx context.Context, observations []AssetDomainObservation, checkedDomains []string, observedAt time.Time) error {
	observations = uniqueAssetDomainObservations(observations)
	checkedDomains = uniqueNonEmptyAssetDomains(checkedDomains)
	if len(observations) == 0 && len(checkedDomains) == 0 {
		return nil
	}
	if observedAt.IsZero() {
		observedAt = time.Now()
	}

	return r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := upsertAliveAssetDomainObservations(ctx, tx, observations, observedAt); err != nil {
			return err
		}
		aliveDomains := assetDomainObservationDomains(observations)
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

func (r *assetDomainRepository) SyncServiceAssets(ctx context.Context, observations []AssetDomainServiceAssetObservation, checkedDomains []string, observedAt time.Time) error {
	observations = uniqueAssetDomainServiceAssetObservations(observations)
	checkedDomains = uniqueNonEmptyAssetDomains(checkedDomains)
	if len(observations) == 0 && len(checkedDomains) == 0 {
		return nil
	}
	if observedAt.IsZero() {
		observedAt = time.Now()
	}

	return r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := upsertAssetDomainServiceAssets(ctx, tx, observations, observedAt); err != nil {
			return err
		}
		return markStaleAssetDomainServiceAssets(ctx, tx, observations, checkedDomains, observedAt)
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
	if query.IsAlive != nil {
		db = db.Where("a.is_alive = ?", *query.IsAlive)
	}
	return db
}

func upsertAssetDomainServiceAssets(ctx context.Context, db *gorm.DB, observations []AssetDomainServiceAssetObservation, observedAt time.Time) error {
	const batchSize = 500
	for start := 0; start < len(observations); start += batchSize {
		end := start + batchSize
		if end > len(observations) {
			end = len(observations)
		}
		batch := observations[start:end]
		items := make([]map[string]interface{}, 0, end-start)
		for _, observation := range batch {
			items = append(items, map[string]interface{}{
				"domain":         observation.Domain,
				"app_name":       observation.AppName,
				"app_version":    observation.AppVersion,
				"first_found_at": observedAt,
				"last_found_at":  observedAt,
				"is_alive":       true,
			})
		}
		if err := db.WithContext(ctx).
			Table("manscan_asset_domain_service_assets").
			Clauses(clause.OnConflict{
				Columns: []clause.Column{{Name: "domain"}, {Name: "app_name"}},
				DoUpdates: clause.Assignments(map[string]interface{}{
					"last_found_at": observedAt,
					"is_alive":      true,
				}),
			}).
			Create(&items).Error; err != nil {
			return err
		}
		if err := updateAssetDomainServiceAssetVersions(ctx, db, batch); err != nil {
			return err
		}
	}
	return nil
}

func updateAssetDomainServiceAssetVersions(ctx context.Context, db *gorm.DB, observations []AssetDomainServiceAssetObservation) error {
	var builder strings.Builder
	args := make([]interface{}, 0, len(observations)*3)
	builder.WriteString("CASE")
	for _, observation := range observations {
		if observation.AppVersion == "" {
			continue
		}
		builder.WriteString(" WHEN domain = ? AND app_name = ? THEN ?")
		args = append(args, observation.Domain, observation.AppName, observation.AppVersion)
	}
	if len(args) == 0 {
		return nil
	}
	builder.WriteString(" ELSE app_version END")

	domains := make([]string, 0, len(observations))
	appNames := make([]string, 0, len(observations))
	for _, observation := range observations {
		if observation.AppVersion == "" {
			continue
		}
		domains = append(domains, observation.Domain)
		appNames = append(appNames, observation.AppName)
	}
	return db.WithContext(ctx).
		Table("manscan_asset_domain_service_assets").
		Where("domain IN ? AND app_name IN ?", uniqueNonEmptyAssetDomains(domains), uniqueNonEmptyAssetDomains(appNames)).
		Update("app_version", gorm.Expr(builder.String(), args...)).Error
}

func markStaleAssetDomainServiceAssets(ctx context.Context, db *gorm.DB, observations []AssetDomainServiceAssetObservation, checkedDomains []string, observedAt time.Time) error {
	aliveAppsByDomain := make(map[string][]string)
	for _, observation := range observations {
		aliveAppsByDomain[observation.Domain] = append(aliveAppsByDomain[observation.Domain], observation.AppName)
	}

	for _, domain := range checkedDomains {
		query := db.WithContext(ctx).
			Table("manscan_asset_domain_service_assets").
			Where("domain = ? AND last_found_at < ?", domain, observedAt)
		if appNames := aliveAppsByDomain[domain]; len(appNames) > 0 {
			query = query.Where("app_name NOT IN ?", appNames)
		}
		if err := query.Update("is_alive", false).Error; err != nil {
			return err
		}
	}
	return nil
}

func upsertAliveAssetDomainObservations(ctx context.Context, db *gorm.DB, observations []AssetDomainObservation, observedAt time.Time) error {
	const batchSize = 500
	for start := 0; start < len(observations); start += batchSize {
		end := start + batchSize
		if end > len(observations) {
			end = len(observations)
		}
		batch := observations[start:end]
		items := make([]map[string]interface{}, 0, end-start)
		domains := make([]string, 0, end-start)
		for _, observation := range batch {
			domains = append(domains, observation.Domain)
			item := map[string]interface{}{
				"domain":           observation.Domain,
				"is_alive":         true,
				"first_alive_at":   observedAt,
				"last_alive_at":    observedAt,
				"region":           nil,
				"http_status_code": nil,
				"title":            nil,
				"request":          nil,
				"response":         nil,
			}
			if observation.Region != "" {
				item["region"] = observation.Region
			}
			if observation.HTTPStatusCode > 0 {
				item["http_status_code"] = observation.HTTPStatusCode
			}
			if observation.Title != "" {
				item["title"] = observation.Title
			}
			if observation.Request != "" {
				item["request"] = observation.Request
			}
			if observation.Response != "" {
				item["response"] = observation.Response
			}
			items = append(items, item)
		}
		if err := db.WithContext(ctx).
			Table("manscan_asset_domain").
			Clauses(clause.OnConflict{
				Columns: []clause.Column{{Name: "domain"}},
				DoUpdates: clause.Assignments(map[string]interface{}{
					"domain": gorm.Expr("domain"),
				}),
			}).
			Create(&items).Error; err != nil {
			return err
		}
		if err := db.WithContext(ctx).
			Model(&entity.AssetDomain{}).
			Where("domain IN ?", domains).
			Updates(map[string]interface{}{
				"is_alive":       true,
				"first_alive_at": gorm.Expr("COALESCE(first_alive_at, ?)", observedAt),
				"last_alive_at":  observedAt,
			}).Error; err != nil {
			return err
		}
		if err := updateAssetDomainObservationFields(ctx, db, batch, domains); err != nil {
			return err
		}
	}
	return nil
}

func updateAssetDomainObservationFields(ctx context.Context, db *gorm.DB, observations []AssetDomainObservation, domains []string) error {
	updates := map[string]interface{}{}
	if expr, ok := buildAssetDomainCaseExpr(observations, "http_status_code", func(observation AssetDomainObservation) (interface{}, bool) {
		if observation.HTTPStatusCode == 0 {
			return nil, false
		}
		return observation.HTTPStatusCode, true
	}); ok {
		updates["http_status_code"] = expr
	}
	if expr, ok := buildAssetDomainCaseExpr(observations, "region", func(observation AssetDomainObservation) (interface{}, bool) {
		if observation.Region == "" {
			return nil, false
		}
		return observation.Region, true
	}); ok {
		updates["region"] = expr
	}
	if expr, ok := buildAssetDomainCaseExpr(observations, "title", func(observation AssetDomainObservation) (interface{}, bool) {
		if observation.Title == "" {
			return nil, false
		}
		return observation.Title, true
	}); ok {
		updates["title"] = expr
	}
	if expr, ok := buildAssetDomainCaseExpr(observations, "request", func(observation AssetDomainObservation) (interface{}, bool) {
		if observation.Request == "" {
			return nil, false
		}
		return observation.Request, true
	}); ok {
		updates["request"] = expr
	}
	if expr, ok := buildAssetDomainCaseExpr(observations, "response", func(observation AssetDomainObservation) (interface{}, bool) {
		if observation.Response == "" {
			return nil, false
		}
		return observation.Response, true
	}); ok {
		updates["response"] = expr
	}
	if len(updates) == 0 {
		return nil
	}
	return db.WithContext(ctx).
		Model(&entity.AssetDomain{}).
		Where("domain IN ?", domains).
		Updates(updates).Error
}

func buildAssetDomainCaseExpr(observations []AssetDomainObservation, column string, valueOf func(AssetDomainObservation) (interface{}, bool)) (clause.Expr, bool) {
	var builder strings.Builder
	args := make([]interface{}, 0, len(observations)*2)
	builder.WriteString("CASE domain")
	for _, observation := range observations {
		value, ok := valueOf(observation)
		if !ok {
			continue
		}
		builder.WriteString(" WHEN ? THEN ?")
		args = append(args, observation.Domain, value)
	}
	if len(args) == 0 {
		return gorm.Expr(column), false
	}
	builder.WriteString(" ELSE ")
	builder.WriteString(column)
	builder.WriteString(" END")
	return gorm.Expr(builder.String(), args...), true
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

func assetDomainObservationDomains(observations []AssetDomainObservation) []string {
	result := make([]string, 0, len(observations))
	for _, observation := range observations {
		domain := strings.TrimSpace(observation.Domain)
		if domain != "" {
			result = append(result, domain)
		}
	}
	return result
}

func uniqueAssetDomainObservations(values []AssetDomainObservation) []AssetDomainObservation {
	result := make([]AssetDomainObservation, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		value.Domain = strings.TrimSpace(value.Domain)
		if value.Domain == "" {
			continue
		}
		if _, ok := seen[value.Domain]; ok {
			continue
		}
		seen[value.Domain] = struct{}{}
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

func uniqueAssetDomainServiceAssetObservations(values []AssetDomainServiceAssetObservation) []AssetDomainServiceAssetObservation {
	result := make([]AssetDomainServiceAssetObservation, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		value.Domain = strings.TrimSpace(value.Domain)
		value.AppName = strings.TrimSpace(value.AppName)
		value.AppVersion = strings.TrimSpace(value.AppVersion)
		if value.Domain == "" || value.AppName == "" {
			continue
		}
		key := value.Domain + "\x00" + value.AppName
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		result = append(result, value)
	}
	return result
}

func uniqueNonEmptyAssetDomainNetworkItems(values []AssetDomainNetworkItem) []AssetDomainNetworkItem {
	result := make([]AssetDomainNetworkItem, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		value.ItemName = strings.TrimSpace(value.ItemName)
		value.SmallCategory = strings.TrimSpace(value.SmallCategory)
		if value.ItemName == "" {
			continue
		}
		if _, ok := seen[value.ItemName]; ok {
			continue
		}
		seen[value.ItemName] = struct{}{}
		result = append(result, value)
	}
	return result
}
