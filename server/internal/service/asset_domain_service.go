package service

import (
	"context"

	"ManScan/server/internal/model/dto"
	"ManScan/server/internal/repository"
)

type AssetDomainService interface {
	List(ctx context.Context, query dto.ListAssetDomainsQuery) (*dto.PageResult[dto.AssetDomainListItem], error)
}

type assetDomainService struct {
	repository repository.AssetDomainRepository
}

func NewAssetDomainService(repo repository.AssetDomainRepository) AssetDomainService {
	return &assetDomainService{repository: repo}
}

func (s *assetDomainService) List(ctx context.Context, query dto.ListAssetDomainsQuery) (*dto.PageResult[dto.AssetDomainListItem], error) {
	page, err := s.repository.List(ctx, query)
	if err != nil {
		return nil, err
	}

	items := make([]dto.AssetDomainListItem, 0, len(page.Items))
	for _, item := range page.Items {
		items = append(items, toAssetDomainListItem(item))
	}

	return &dto.PageResult[dto.AssetDomainListItem]{
		Page:       page.Page,
		PageSize:   page.PageSize,
		Total:      page.Total,
		TotalPages: page.TotalPages,
		Items:      items,
	}, nil
}

func toAssetDomainListItem(item repository.AssetDomainListRecord) dto.AssetDomainListItem {
	return dto.AssetDomainListItem{
		ID:                 item.ID,
		Domain:             item.Domain,
		AssetAddress:       item.Domain,
		Owner:              derefString(item.Owner),
		Title:              derefString(item.Title),
		FirstAliveAt:       item.FirstAliveAt,
		LastAliveAt:        item.LastAliveAt,
		Region:             derefString(item.Region),
		RiskLevel:          assetDomainRiskLevel(item),
		HasForm:            item.HasForm,
		HasUpload:          item.HasUpload,
		HasAdmin:           item.HasAdmin,
		HasUCLogin:         item.HasUCLogin,
		HasBaiduLogin:      item.HasBaiduLogin,
		ScreenshotPath:     derefString(item.ScreenshotPath),
		ManualNote:         derefString(item.ManualNote),
		HTTPStatusCode:     item.HTTPStatusCode,
		Request:            derefString(item.Request),
		Response:           derefString(item.Response),
		IsAlive:            item.IsAlive,
		VulnerabilityCount: item.VulnerabilityCount,
		CriticalCount:      item.CriticalCount,
		HighCount:          item.HighCount,
		MediumCount:        item.MediumCount,
		LowCount:           item.LowCount,
		ComponentCount:     item.ComponentCount,
	}
}

func assetDomainRiskLevel(item repository.AssetDomainListRecord) string {
	switch {
	case item.CriticalCount > 0:
		return "critical"
	case item.HighCount > 0:
		return "high"
	case item.MediumCount > 0:
		return "medium"
	case item.LowCount > 0:
		return "low"
	case item.VulnerabilityCount > 0:
		return "unknown"
	default:
		return "info"
	}
}
