package service

import (
	"context"

	"ManScan/server/internal/model/dto"
	"ManScan/server/internal/repository"
)

type AssetDomainService interface {
	List(ctx context.Context, query dto.ListAssetDomainsQuery) (*dto.PageResult[dto.AssetDomainListItem], error)
	Detail(ctx context.Context, domain string) (*dto.AssetDomainDetail, error)
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

func (s *assetDomainService) Detail(ctx context.Context, domain string) (*dto.AssetDomainDetail, error) {
	detail, err := s.repository.Detail(ctx, domain)
	if err != nil {
		return nil, err
	}
	return toAssetDomainDetail(*detail), nil
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

func toAssetDomainDetail(item repository.AssetDomainDetailRecord) *dto.AssetDomainDetail {
	serviceAssets := make([]dto.AssetDomainServiceAssetItem, 0, len(item.ServiceAssets))
	for _, asset := range item.ServiceAssets {
		serviceAssets = append(serviceAssets, dto.AssetDomainServiceAssetItem{
			AppName:      asset.AppName,
			AppVersion:   asset.AppVersion,
			LastFoundAt:  asset.LastFoundAt,
			FirstFoundAt: asset.FirstFoundAt,
			IsAlive:      asset.IsAlive,
		})
	}

	titleHistories := make([]dto.AssetDomainTitleHistoryItem, 0, len(item.TitleHistories))
	for _, history := range item.TitleHistories {
		titleHistories = append(titleHistories, dto.AssetDomainTitleHistoryItem{
			HistoryTitle:        history.HistoryTitle,
			IsAlive:             history.IsAlive,
			FirstTitleCreatedAt: history.FirstTitleCreatedAt,
			LatestTitleAliveAt:  history.LatestTitleAliveAt,
		})
	}

	return &dto.AssetDomainDetail{
		Domain:             item.Domain,
		Owner:              derefString(item.Owner),
		Title:              derefString(item.Title),
		FirstAliveAt:       item.FirstAliveAt,
		LastAliveAt:        item.LastAliveAt,
		Region:             derefString(item.Region),
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
		RiskLevel:          assetDomainDetailRiskLevel(item),
		VulnerabilityCount: item.VulnerabilityCount,
		ServiceAssets:      serviceAssets,
		TitleHistories:     titleHistories,
	}
}

func assetDomainRiskLevel(item repository.AssetDomainListRecord) string {
	return assetRiskLevel(item.VulnerabilityCount, item.CriticalCount, item.HighCount, item.MediumCount, item.LowCount)
}

func assetDomainDetailRiskLevel(item repository.AssetDomainDetailRecord) string {
	return assetRiskLevel(item.VulnerabilityCount, item.CriticalCount, item.HighCount, item.MediumCount, item.LowCount)
}

func assetRiskLevel(vulnerabilityCount, criticalCount, highCount, mediumCount, lowCount int) string {
	switch {
	case criticalCount > 0:
		return "critical"
	case highCount > 0:
		return "high"
	case mediumCount > 0:
		return "medium"
	case lowCount > 0:
		return "low"
	case vulnerabilityCount > 0:
		return "unknown"
	default:
		return "info"
	}
}
