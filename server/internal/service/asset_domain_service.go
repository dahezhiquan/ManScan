package service

import (
	"context"
	"encoding/base64"
	"errors"
	"strings"
	"unicode"
	"unicode/utf8"

	"ManScan/server/internal/model/dto"
	"ManScan/server/internal/repository"
)

type AssetDomainService interface {
	List(ctx context.Context, query dto.ListAssetDomainsQuery) (*dto.PageResult[dto.AssetDomainListItem], error)
	Detail(ctx context.Context, domain string) (*dto.AssetDomainDetail, error)
	UpdateManualNote(ctx context.Context, request dto.UpdateAssetDomainManualNoteRequest) (*dto.UpdateAssetDomainManualNoteResponse, error)
	LatestScreenshot(ctx context.Context, domain string) (*dto.AssetDomainScreenshot, error)
	ListScreenshots(ctx context.Context, query dto.ListAssetDomainScreenshotsQuery) (*dto.PageResult[dto.AssetDomainScreenshot], error)
}

type assetDomainService struct {
	repository           repository.AssetDomainRepository
	screenshotRepository repository.AssetDomainScreenshotRepository
}

var (
	ErrInvalidAssetDomain            = errors.New("域名资产地址不合法")
	ErrInvalidAssetManualNote        = errors.New("资产手工备注不合法")
	ErrInvalidAssetHostIPAddress     = errors.New("主机资产 IP 不合法")
	ErrAssetDomainScreenshotNotFound = errors.New("域名资产截图不存在")
)

const (
	maxAssetManualNoteRunes = 5000
	maxAssetDomainRunes     = 2048
)

func NewAssetDomainService(repo repository.AssetDomainRepository, screenshotRepo repository.AssetDomainScreenshotRepository) AssetDomainService {
	return &assetDomainService{repository: repo, screenshotRepository: screenshotRepo}
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

func (s *assetDomainService) UpdateManualNote(ctx context.Context, request dto.UpdateAssetDomainManualNoteRequest) (*dto.UpdateAssetDomainManualNoteResponse, error) {
	domain := strings.TrimSpace(request.Domain)
	if domain == "" {
		domain = strings.TrimSpace(request.AssetAddress)
	}
	if domain == "" {
		return nil, ErrInvalidAssetDomain
	}

	manualNote, noteValue, err := normalizeAssetManualNote(request.ManualNote)
	if err != nil {
		return nil, err
	}
	if err := s.repository.UpdateManualNote(ctx, domain, noteValue); err != nil {
		return nil, err
	}

	return &dto.UpdateAssetDomainManualNoteResponse{
		Domain:     domain,
		ManualNote: manualNote,
	}, nil
}

// LatestScreenshot returns the newest screenshot for a domain asset.
func (s *assetDomainService) LatestScreenshot(ctx context.Context, domain string) (*dto.AssetDomainScreenshot, error) {
	domain, err := normalizeAssetDomainScreenshotDomain(domain)
	if err != nil {
		return nil, err
	}
	record, err := s.screenshotRepository.Latest(ctx, domain)
	if err != nil {
		if errors.Is(err, repository.ErrAssetDomainScreenshotNotFound) {
			return nil, ErrAssetDomainScreenshotNotFound
		}
		return nil, err
	}
	item := toAssetDomainScreenshot(*record)
	return &item, nil
}

// ListScreenshots returns historical screenshots for a domain asset.
func (s *assetDomainService) ListScreenshots(ctx context.Context, query dto.ListAssetDomainScreenshotsQuery) (*dto.PageResult[dto.AssetDomainScreenshot], error) {
	domain, err := normalizeAssetDomainScreenshotDomain(query.Domain)
	if err != nil {
		return nil, err
	}
	page, err := s.screenshotRepository.List(ctx, domain, query.Page, query.PageSize)
	if err != nil {
		return nil, err
	}
	items := make([]dto.AssetDomainScreenshot, 0, len(page.Items))
	for _, record := range page.Items {
		items = append(items, toAssetDomainScreenshot(record))
	}
	return &dto.PageResult[dto.AssetDomainScreenshot]{
		Page: page.Page, PageSize: page.PageSize, Total: page.Total, TotalPages: page.TotalPages, Items: items,
	}, nil
}

func normalizeAssetDomainScreenshotDomain(domain string) (string, error) {
	domain = strings.TrimSpace(domain)
	if domain == "" || utf8.RuneCountInString(domain) > maxAssetDomainRunes {
		return "", ErrInvalidAssetDomain
	}
	for _, character := range domain {
		if unicode.IsControl(character) {
			return "", ErrInvalidAssetDomain
		}
	}
	return domain, nil
}

func toAssetDomainScreenshot(record repository.AssetDomainScreenshotRecord) dto.AssetDomainScreenshot {
	return dto.AssetDomainScreenshot{
		Domain:       record.Domain,
		CapturedDate: record.CapturedDate.Format("2006-01-02"),
		FileName:     record.FileName,
		ContentType:  record.ContentType,
		ImageBase64:  base64.StdEncoding.EncodeToString(record.Image),
	}
}

func normalizeAssetManualNote(value string) (string, *string, error) {
	manualNote := strings.TrimSpace(value)
	if utf8.RuneCountInString(manualNote) > maxAssetManualNoteRunes {
		return "", nil, ErrInvalidAssetManualNote
	}
	if manualNote == "" {
		return "", nil, nil
	}
	return manualNote, &manualNote, nil
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
