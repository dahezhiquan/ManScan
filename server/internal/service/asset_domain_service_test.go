package service

import (
	"testing"

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
}
