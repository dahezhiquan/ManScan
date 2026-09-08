package service

import (
	"context"
	"errors"
	"strings"

	"ManScan/server/internal/model/dto"
	"ManScan/server/internal/model/entity"
	"ManScan/server/internal/repository"

	"gorm.io/gorm"
)

type AssetConfigCenterService interface {
	Create(ctx context.Context, request dto.CreateAssetConfigCenterRequest) (*dto.AssetConfigCenterListItem, error)
	List(ctx context.Context, query dto.ListAssetConfigCentersQuery) (*dto.PageResult[dto.AssetConfigCenterListItem], error)
	SmallCategoryOptions(ctx context.Context, query dto.ListAssetConfigCenterSmallCategoryOptionsQuery) (*dto.AssetConfigCenterOptions, error)
	Update(ctx context.Context, itemID int64, request dto.UpdateAssetConfigCenterRequest) (*dto.AssetConfigCenterListItem, error)
	Delete(ctx context.Context, itemID int64) (*dto.DeleteAssetConfigCenterResponse, error)
}

type assetConfigCenterService struct {
	repository repository.AssetConfigCenterRepository
}

func NewAssetConfigCenterService(repo repository.AssetConfigCenterRepository) AssetConfigCenterService {
	return &assetConfigCenterService{repository: repo}
}

var ErrInvalidAssetConfigCenter = errors.New("资产配置中心参数不合法")
var ErrDuplicateAssetConfigCenterItemName = errors.New("资产配置中心项名称已存在")

const (
	assetConfigCenterStatusEnabled  = "enabled"
	assetConfigCenterStatusDisabled = "disabled"
)

func (s *assetConfigCenterService) Create(ctx context.Context, request dto.CreateAssetConfigCenterRequest) (*dto.AssetConfigCenterListItem, error) {
	item, err := buildAssetConfigCenterEntity(request.ItemName, request.BigCategory, request.SmallCategory, request.Status, request.Description)
	if err != nil {
		return nil, err
	}
	if err := s.ensureUniqueItemName(ctx, item.ItemName, 0); err != nil {
		return nil, err
	}
	if err := s.repository.Create(ctx, item); err != nil {
		return nil, err
	}

	result := toAssetConfigCenterListItem(*item)
	return &result, nil
}

func (s *assetConfigCenterService) List(ctx context.Context, query dto.ListAssetConfigCentersQuery) (*dto.PageResult[dto.AssetConfigCenterListItem], error) {
	page, err := s.repository.List(ctx, query)
	if err != nil {
		return nil, err
	}

	items := make([]dto.AssetConfigCenterListItem, 0, len(page.Items))
	for _, item := range page.Items {
		items = append(items, toAssetConfigCenterListItem(item))
	}

	return &dto.PageResult[dto.AssetConfigCenterListItem]{
		Page:       page.Page,
		PageSize:   page.PageSize,
		Total:      page.Total,
		TotalPages: page.TotalPages,
		Items:      items,
	}, nil
}

func (s *assetConfigCenterService) SmallCategoryOptions(ctx context.Context, query dto.ListAssetConfigCenterSmallCategoryOptionsQuery) (*dto.AssetConfigCenterOptions, error) {
	items, err := s.repository.ListSmallCategoriesByBigCategories(ctx, query.BigCategories)
	if err != nil {
		return nil, err
	}
	return &dto.AssetConfigCenterOptions{Items: items}, nil
}

func (s *assetConfigCenterService) Update(ctx context.Context, itemID int64, request dto.UpdateAssetConfigCenterRequest) (*dto.AssetConfigCenterListItem, error) {
	if itemID <= 0 {
		return nil, ErrInvalidAssetConfigCenter
	}
	if _, err := s.repository.FindByID(ctx, itemID); err != nil {
		return nil, err
	}

	item, err := buildAssetConfigCenterEntity(request.ItemName, request.BigCategory, request.SmallCategory, request.Status, request.Description)
	if err != nil {
		return nil, err
	}
	item.ID = itemID

	if err := s.ensureUniqueItemName(ctx, item.ItemName, itemID); err != nil {
		return nil, err
	}
	if err := s.repository.Update(ctx, item); err != nil {
		return nil, err
	}

	result := toAssetConfigCenterListItem(*item)
	return &result, nil
}

func (s *assetConfigCenterService) Delete(ctx context.Context, itemID int64) (*dto.DeleteAssetConfigCenterResponse, error) {
	if itemID <= 0 {
		return nil, ErrInvalidAssetConfigCenter
	}
	if _, err := s.repository.FindByID(ctx, itemID); err != nil {
		return nil, err
	}

	deletedCount, err := s.repository.Delete(ctx, itemID)
	if err != nil {
		return nil, err
	}
	return &dto.DeleteAssetConfigCenterResponse{
		ID:           itemID,
		DeletedCount: deletedCount,
	}, nil
}

func toAssetConfigCenterListItem(item entity.AssetConfigCenter) dto.AssetConfigCenterListItem {
	return dto.AssetConfigCenterListItem{
		ID:            item.ID,
		ItemName:      item.ItemName,
		BigCategory:   item.BigCategory,
		SmallCategory: item.SmallCategory,
		Status:        item.Status,
		Description:   derefString(item.Description),
	}
}

func buildAssetConfigCenterEntity(itemName, bigCategory, smallCategory, status, description string) (*entity.AssetConfigCenter, error) {
	item := &entity.AssetConfigCenter{
		ItemName:      strings.TrimSpace(itemName),
		BigCategory:   strings.TrimSpace(bigCategory),
		SmallCategory: strings.TrimSpace(smallCategory),
		Status:        normalizeAssetConfigCenterStatus(status),
		Description:   nullableTrimmedString(description),
	}
	if item.ItemName == "" || item.BigCategory == "" || item.SmallCategory == "" || !isValidAssetConfigCenterStatus(item.Status) {
		return nil, ErrInvalidAssetConfigCenter
	}
	return item, nil
}

func (s *assetConfigCenterService) ensureUniqueItemName(ctx context.Context, itemName string, currentID int64) error {
	existing, err := s.repository.FindByItemName(ctx, itemName)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil
		}
		return err
	}
	if existing.ID != currentID {
		return ErrDuplicateAssetConfigCenterItemName
	}
	return nil
}

func normalizeAssetConfigCenterStatus(status string) string {
	return strings.ToLower(strings.TrimSpace(status))
}

func isValidAssetConfigCenterStatus(status string) bool {
	switch status {
	case assetConfigCenterStatusEnabled, assetConfigCenterStatusDisabled:
		return true
	default:
		return false
	}
}

func nullableTrimmedString(value string) *string {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return nil
	}
	return &trimmed
}
