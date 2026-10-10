package service

import (
	"testing"
	"time"

	"ManScan/server/internal/model/entity"
	"ManScan/server/internal/repository"
)

func TestToAssetDomainListItemIncludesRequestAndResponse(t *testing.T) {
	request := "GET / HTTP/1.1\r\nHost: app.example.com\r\n\r\n"
	response := "HTTP/1.1 200 OK\r\n\r\nok"

	item := toAssetDomainListItem(repository.AssetDomainListRecord{
		AssetDomain: entity.AssetDomain{
			ID:       1,
			Domain:   "app.example.com:443",
			Request:  &request,
			Response: &response,
		},
		VulnerabilityCount: 2,
		CriticalCount:      1,
		HighCount:          2,
		MediumCount:        3,
		LowCount:           4,
		ComponentCount:     3,
	})

	if item.Request != request {
		t.Fatalf("Request = %q, want %q", item.Request, request)
	}
	if item.Response != response {
		t.Fatalf("Response = %q, want %q", item.Response, response)
	}
	if item.VulnerabilityCount != 2 || item.ComponentCount != 3 {
		t.Fatalf("counts = vulnerability:%d component:%d, want vulnerability:2 component:3", item.VulnerabilityCount, item.ComponentCount)
	}
	if item.CriticalCount != 1 || item.HighCount != 2 || item.MediumCount != 3 || item.LowCount != 4 {
		t.Fatalf("severity counts = critical:%d high:%d medium:%d low:%d, want critical:1 high:2 medium:3 low:4", item.CriticalCount, item.HighCount, item.MediumCount, item.LowCount)
	}
	if item.RiskLevel != "critical" {
		t.Fatalf("RiskLevel = %q, want critical", item.RiskLevel)
	}
	if got := assetDomainRiskLevel(repository.AssetDomainListRecord{VulnerabilityCount: 1}); got != "unknown" {
		t.Fatalf("assetDomainRiskLevel(unknown severity) = %q, want unknown", got)
	}
	if got := assetDomainRiskLevel(repository.AssetDomainListRecord{}); got != "info" {
		t.Fatalf("assetDomainRiskLevel(empty) = %q, want info", got)
	}
}

func TestToAssetDomainDetailIncludesRelatedAssetsAndTitleHistories(t *testing.T) {
	now := time.Date(2026, 10, 10, 10, 0, 0, 0, time.UTC)
	earlier := now.Add(-time.Hour)
	owner := "安全团队"
	title := "Example App"
	region := "生产区"
	request := "GET / HTTP/1.1\r\nHost: app.example.com\r\n\r\n"
	response := "HTTP/1.1 200 OK\r\n\r\nok"
	statusCode := uint(200)

	detail := toAssetDomainDetail(repository.AssetDomainDetailRecord{
		AssetDomain: entity.AssetDomain{
			Domain:         "app.example.com:443",
			Owner:          &owner,
			Title:          &title,
			FirstAliveAt:   &earlier,
			LastAliveAt:    &now,
			Region:         &region,
			HasForm:        true,
			HasAdmin:       true,
			HTTPStatusCode: &statusCode,
			Request:        &request,
			Response:       &response,
			IsAlive:        true,
		},
		VulnerabilityCount: 2,
		CriticalCount:      1,
		ServiceAssets: []entity.AssetDomainServiceAsset{
			{
				AppName:      "nginx",
				AppVersion:   "1.24",
				FirstFoundAt: earlier,
				LastFoundAt:  now,
				IsAlive:      true,
			},
		},
		TitleHistories: []entity.AssetDomainTitleHistory{
			{
				HistoryTitle:        "Example App",
				FirstTitleCreatedAt: earlier,
				LatestTitleAliveAt:  now,
				IsAlive:             true,
			},
		},
	})

	if detail.Domain != "app.example.com:443" || detail.Owner != owner || detail.Title != title || detail.Region != region {
		t.Fatalf("detail = %+v, want copied domain metadata", detail)
	}
	if !detail.HasForm || !detail.HasAdmin || !detail.IsAlive {
		t.Fatalf("detail booleans = %+v, want true values copied", detail)
	}
	if detail.HTTPStatusCode == nil || *detail.HTTPStatusCode != statusCode || detail.Request != request || detail.Response != response {
		t.Fatalf("probe fields = status:%v request:%q response:%q, want copied probe fields", detail.HTTPStatusCode, detail.Request, detail.Response)
	}
	if detail.RiskLevel != "critical" || detail.VulnerabilityCount != 2 {
		t.Fatalf("risk fields = level:%q count:%d, want critical/2", detail.RiskLevel, detail.VulnerabilityCount)
	}
	if len(detail.ServiceAssets) != 1 || detail.ServiceAssets[0].AppName != "nginx" || detail.ServiceAssets[0].AppVersion != "1.24" || !detail.ServiceAssets[0].IsAlive {
		t.Fatalf("service assets = %+v, want nginx detail", detail.ServiceAssets)
	}
	if len(detail.TitleHistories) != 1 || detail.TitleHistories[0].HistoryTitle != "Example App" || !detail.TitleHistories[0].IsAlive {
		t.Fatalf("title histories = %+v, want title detail", detail.TitleHistories)
	}
}
