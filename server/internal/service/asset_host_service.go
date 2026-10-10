package service

import (
	"context"

	"ManScan/server/internal/model/dto"
	"ManScan/server/internal/repository"
)

type AssetHostService interface {
	List(ctx context.Context, query dto.ListAssetHostsQuery) (*dto.PageResult[dto.AssetHostListItem], error)
}

type assetHostService struct {
	repository repository.AssetHostRepository
}

func NewAssetHostService(repo repository.AssetHostRepository) AssetHostService {
	return &assetHostService{repository: repo}
}

func (s *assetHostService) List(ctx context.Context, query dto.ListAssetHostsQuery) (*dto.PageResult[dto.AssetHostListItem], error) {
	page, err := s.repository.List(ctx, query)
	if err != nil {
		return nil, err
	}

	items := make([]dto.AssetHostListItem, 0, len(page.Items))
	for _, item := range page.Items {
		items = append(items, toAssetHostListItem(item))
	}

	return &dto.PageResult[dto.AssetHostListItem]{
		Page:       page.Page,
		PageSize:   page.PageSize,
		Total:      page.Total,
		TotalPages: page.TotalPages,
		Items:      items,
	}, nil
}

func toAssetHostListItem(item repository.AssetHostListRecord) dto.AssetHostListItem {
	return dto.AssetHostListItem{
		ID:                 item.ID,
		IPAddress:          item.IPAddress,
		AssetAddress:       item.IPAddress,
		Region:             derefString(item.Region),
		Owner:              derefString(item.Owner),
		OSType:             derefString(item.OSType),
		OSVersion:          derefString(item.OSVersion),
		ScanCreatedAt:      item.ScanCreatedAt,
		LastAliveAt:        item.LastAliveAt,
		ManualNote:         derefString(item.ManualNote),
		IsAlive:            item.IsAlive,
		RelatedDomains:     derefString(item.RelatedDomains),
		RiskLevel:          assetHostRiskLevel(item),
		VulnerabilityCount: item.VulnerabilityCount,
		CriticalCount:      item.CriticalCount,
		HighCount:          item.HighCount,
		MediumCount:        item.MediumCount,
		LowCount:           item.LowCount,
		PortCount:          item.PortCount,
	}
}

func assetHostRiskLevel(item repository.AssetHostListRecord) string {
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
