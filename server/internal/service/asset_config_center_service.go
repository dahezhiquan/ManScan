package service

import (
	"context"

	"ManScan/server/internal/model/dto"
	"ManScan/server/internal/model/entity"
	"ManScan/server/internal/repository"
)

type AssetConfigCenterService interface {
	List(ctx context.Context, query dto.ListAssetConfigCentersQuery) (*dto.PageResult[dto.AssetConfigCenterListItem], error)
}

type assetConfigCenterService struct {
	repository repository.AssetConfigCenterRepository
}

func NewAssetConfigCenterService(repo repository.AssetConfigCenterRepository) AssetConfigCenterService {
	return &assetConfigCenterService{repository: repo}
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
