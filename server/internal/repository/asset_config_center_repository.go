package repository

import (
	"context"
	"strings"

	"ManScan/server/internal/model/dto"
	"ManScan/server/internal/model/entity"

	"gorm.io/gorm"
)

type AssetConfigCenterRepository interface {
	Create(ctx context.Context, item *entity.AssetConfigCenter) error
	List(ctx context.Context, query dto.ListAssetConfigCentersQuery) (*dto.PageResult[entity.AssetConfigCenter], error)
	ListSmallCategoriesByBigCategories(ctx context.Context, bigCategories []string) ([]string, error)
	FindByID(ctx context.Context, itemID int64) (*entity.AssetConfigCenter, error)
	FindByItemName(ctx context.Context, itemName string) (*entity.AssetConfigCenter, error)
	Update(ctx context.Context, item *entity.AssetConfigCenter) error
	Delete(ctx context.Context, itemID int64) (int64, error)
}

type assetConfigCenterRepository struct {
	db *gorm.DB
}

func NewAssetConfigCenterRepository(db *gorm.DB) AssetConfigCenterRepository {
	return &assetConfigCenterRepository{db: db}
}

func (r *assetConfigCenterRepository) Create(ctx context.Context, item *entity.AssetConfigCenter) error {
	return r.db.WithContext(ctx).Create(item).Error
}

func (r *assetConfigCenterRepository) List(ctx context.Context, query dto.ListAssetConfigCentersQuery) (*dto.PageResult[entity.AssetConfigCenter], error) {
	page := query.Page
	if page <= 0 {
		page = 1
	}
	pageSize := query.PageSize
	if pageSize <= 0 {
		pageSize = 10
	}

	baseQuery := r.applyListFilters(r.db.WithContext(ctx).Table("manscan_asset_config_centers AS a"), query)
	var total int64
	if err := baseQuery.Count(&total).Error; err != nil {
		return nil, err
	}

	items := make([]entity.AssetConfigCenter, 0)
	if err := r.applyListFilters(r.db.WithContext(ctx).Table("manscan_asset_config_centers AS a"), query).
		Select("a.*").
		Order("a.big_category ASC").
		Order("a.small_category ASC").
		Order("a.item_name ASC").
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

	return &dto.PageResult[entity.AssetConfigCenter]{
		Page:       page,
		PageSize:   pageSize,
		Total:      int(total),
		TotalPages: totalPages,
		Items:      items,
	}, nil
}

func (r *assetConfigCenterRepository) ListSmallCategoriesByBigCategories(ctx context.Context, bigCategories []string) ([]string, error) {
	categories := cleanAssetConfigCenterCategoryValues(bigCategories)
	if len(categories) == 0 {
		return []string{}, nil
	}

	items := make([]string, 0)
	db := r.db.WithContext(ctx).Table("manscan_asset_config_centers AS a").
		Distinct("a.small_category").
		Where("a.small_category <> ''").
		Where("a.big_category IN ?", categories).
		Order("a.small_category ASC")
	if err := db.Pluck("a.small_category", &items).Error; err != nil {
		return nil, err
	}
	return items, nil
}

func (r *assetConfigCenterRepository) FindByID(ctx context.Context, itemID int64) (*entity.AssetConfigCenter, error) {
	var item entity.AssetConfigCenter
	if err := r.db.WithContext(ctx).First(&item, itemID).Error; err != nil {
		return nil, err
	}
	return &item, nil
}

func (r *assetConfigCenterRepository) FindByItemName(ctx context.Context, itemName string) (*entity.AssetConfigCenter, error) {
	var item entity.AssetConfigCenter
	if err := r.db.WithContext(ctx).Where("item_name = ?", itemName).First(&item).Error; err != nil {
		return nil, err
	}
	return &item, nil
}

func (r *assetConfigCenterRepository) Update(ctx context.Context, item *entity.AssetConfigCenter) error {
	return r.db.WithContext(ctx).Model(&entity.AssetConfigCenter{}).
		Where("id = ?", item.ID).
		Updates(map[string]interface{}{
			"item_name":      item.ItemName,
			"big_category":   item.BigCategory,
			"small_category": item.SmallCategory,
			"status":         item.Status,
			"description":    item.Description,
		}).Error
}

func (r *assetConfigCenterRepository) Delete(ctx context.Context, itemID int64) (int64, error) {
	result := r.db.WithContext(ctx).Delete(&entity.AssetConfigCenter{}, itemID)
	if result.Error != nil {
		return 0, result.Error
	}
	return result.RowsAffected, nil
}

func (r *assetConfigCenterRepository) applyListFilters(db *gorm.DB, query dto.ListAssetConfigCentersQuery) *gorm.DB {
	if len(query.ItemNames) > 0 {
		db = applyLikeAnyFilter(db, "a.item_name", query.ItemNames)
	}
	if len(query.BigCategories) > 0 {
		db = applyLikeAnyFilter(db, "a.big_category", query.BigCategories)
	}
	if len(query.SmallCategories) > 0 {
		db = applyLikeAnyFilter(db, "a.small_category", query.SmallCategories)
	}
	if len(query.Statuses) > 0 {
		db = applyLowerInFilter(db, "a.status", query.Statuses)
	}
	return db
}

func cleanAssetConfigCenterCategoryValues(values []string) []string {
	result := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			continue
		}
		if _, ok := seen[trimmed]; ok {
			continue
		}
		seen[trimmed] = struct{}{}
		result = append(result, trimmed)
	}
	return result
}
