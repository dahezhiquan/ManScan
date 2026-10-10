package service

import (
	"testing"
	"time"

	"ManScan/server/internal/model/entity"
	"ManScan/server/internal/repository"
)

func TestToAssetHostListItemReturnsRiskAndCounts(t *testing.T) {
	now := time.Date(2026, 10, 10, 10, 0, 0, 0, time.UTC)
	region := "生产区"
	owner := "安全团队"
	osType := "linux"
	osVersion := "5.15"
	relatedDomains := "app.example.com"

	item := toAssetHostListItem(repository.AssetHostListRecord{
		AssetHost: entity.AssetHost{
			ID:             1,
			IPAddress:      "10.72.160.123",
			Region:         &region,
			Owner:          &owner,
			OSType:         &osType,
			OSVersion:      &osVersion,
			ScanCreatedAt:  now,
			LastAliveAt:    &now,
			IsAlive:        true,
			RelatedDomains: &relatedDomains,
		},
		VulnerabilityCount: 3,
		HighCount:          1,
		MediumCount:        2,
		PortCount:          4,
	})

	if item.IPAddress != "10.72.160.123" || item.AssetAddress != "10.72.160.123" {
		t.Fatalf("host address = %q/%q, want ip address", item.IPAddress, item.AssetAddress)
	}
	if item.Region != region || item.Owner != owner || item.OSType != osType || item.OSVersion != osVersion || item.RelatedDomains != relatedDomains {
		t.Fatalf("item fields = %+v, want host metadata copied", item)
	}
	if item.RiskLevel != "high" {
		t.Fatalf("RiskLevel = %q, want high", item.RiskLevel)
	}
	if item.VulnerabilityCount != 3 || item.PortCount != 4 {
		t.Fatalf("counts = vulnerability:%d port:%d, want vulnerability:3 port:4", item.VulnerabilityCount, item.PortCount)
	}
	if got := assetHostRiskLevel(repository.AssetHostListRecord{VulnerabilityCount: 1}); got != "unknown" {
		t.Fatalf("assetHostRiskLevel(unknown severity) = %q, want unknown", got)
	}
	if got := assetHostRiskLevel(repository.AssetHostListRecord{}); got != "info" {
		t.Fatalf("assetHostRiskLevel(empty) = %q, want info", got)
	}
}
