package repository

import (
	"context"
	"fmt"
	"strings"

	"ManScan/server/internal/model/dto"
	"ManScan/server/internal/model/entity"

	"gorm.io/gorm"
)

type ThirdPartyAPIKeyRepository interface {
	Create(ctx context.Context, item *entity.ThirdPartyAPIKey) error
	List(ctx context.Context, query dto.ListThirdPartyAPIKeysQuery) (*dto.PageResult[entity.ThirdPartyAPIKey], error)
	FindByID(ctx context.Context, itemID int64) (*entity.ThirdPartyAPIKey, error)
	FindAIForce(ctx context.Context) (*entity.ThirdPartyAPIKey, error)
	Update(ctx context.Context, item *entity.ThirdPartyAPIKey, replaceKey bool) error
	Delete(ctx context.Context, itemID int64) (int64, error)
}

type thirdPartyAPIKeyRepository struct {
	db *gorm.DB
}

// NewThirdPartyAPIKeyRepository 创建第三方 API Key 存储实现。
func NewThirdPartyAPIKeyRepository(db *gorm.DB) ThirdPartyAPIKeyRepository {
	return &thirdPartyAPIKeyRepository{db: db}
}

// Create 保存已经加密的 API Key 及平台配置。
func (r *thirdPartyAPIKeyRepository) Create(ctx context.Context, item *entity.ThirdPartyAPIKey) error {
	return r.db.WithContext(ctx).Create(item).Error
}

// List 按 ID 倒序分页查询平台配置。
func (r *thirdPartyAPIKeyRepository) List(ctx context.Context, query dto.ListThirdPartyAPIKeysQuery) (*dto.PageResult[entity.ThirdPartyAPIKey], error) {
	page := query.Page
	if page <= 0 {
		page = 1
	}
	if page > 2147483647 {
		page = 2147483647
	}
	pageSize := query.PageSize
	if pageSize <= 0 {
		pageSize = 10
	}
	if pageSize > 100 {
		pageSize = 100
	}
	base := r.db.WithContext(ctx).Model(&entity.ThirdPartyAPIKey{})
	var total int64
	if err := base.Count(&total).Error; err != nil {
		return nil, err
	}
	items := make([]entity.ThirdPartyAPIKey, 0)
	if err := base.Order("id DESC").Offset((page - 1) * pageSize).Limit(pageSize).Find(&items).Error; err != nil {
		return nil, err
	}
	totalPages := 0
	if total > 0 {
		totalPages = int((total + int64(pageSize) - 1) / int64(pageSize))
	}
	return &dto.PageResult[entity.ThirdPartyAPIKey]{Page: page, PageSize: pageSize, Total: int(total), TotalPages: totalPages, Items: items}, nil
}

// FindByID 查询指定平台配置。
func (r *thirdPartyAPIKeyRepository) FindByID(ctx context.Context, itemID int64) (*entity.ThirdPartyAPIKey, error) {
	var item entity.ThirdPartyAPIKey
	if err := r.db.WithContext(ctx).First(&item, itemID).Error; err != nil {
		return nil, err
	}
	return &item, nil
}

// FindAIForce returns the unique API key record described as 原力平台.
func (r *thirdPartyAPIKeyRepository) FindAIForce(ctx context.Context) (*entity.ThirdPartyAPIKey, error) {
	var items []entity.ThirdPartyAPIKey
	err := r.db.WithContext(ctx).Find(&items).Error
	if err != nil {
		return nil, err
	}
	var matched *entity.ThirdPartyAPIKey
	for index := range items {
		if !strings.EqualFold(strings.TrimSpace(items[index].Description), "原力平台") {
			continue
		}
		if matched != nil {
			return nil, fmt.Errorf("原力平台存在多条密钥记录，请保留唯一记录")
		}
		matched = &items[index]
	}
	if matched == nil {
		return nil, gorm.ErrRecordNotFound
	}
	return matched, nil
}

// Update 更新平台元信息，并按需替换密文。
func (r *thirdPartyAPIKeyRepository) Update(ctx context.Context, item *entity.ThirdPartyAPIKey, replaceKey bool) error {
	updates := map[string]interface{}{
		"platform_url":          item.PlatformURL,
		"rate_limit_per_minute": item.RateLimitPerMinute,
		"description":           item.Description,
	}
	// 未提交新密钥时不写 encrypted_key，避免覆盖并发更新的密钥。
	if replaceKey {
		updates["encrypted_key"] = item.EncryptedKey
	}
	return r.db.WithContext(ctx).Model(&entity.ThirdPartyAPIKey{}).Where("id = ?", item.ID).Updates(updates).Error
}

// Delete 删除配置并返回实际删除数量。
func (r *thirdPartyAPIKeyRepository) Delete(ctx context.Context, itemID int64) (int64, error) {
	result := r.db.WithContext(ctx).Delete(&entity.ThirdPartyAPIKey{}, itemID)
	if result.Error != nil {
		return 0, result.Error
	}
	return result.RowsAffected, nil
}
