package repository

import (
	"context"

	"ManScan/server/internal/model/dto"
	"ManScan/server/internal/model/entity"

	"gorm.io/gorm"
)

type AssetConfigCenterRepository interface {
	List(ctx context.Context, query dto.ListAssetConfigCentersQuery) (*dto.PageResult[entity.AssetConfigCenter], error)
}

type assetConfigCenterRepository struct {
	db *gorm.DB
}

func NewAssetConfigCenterRepository(db *gorm.DB) AssetConfigCenterRepository {
	return &assetConfigCenterRepository{db: db}
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
