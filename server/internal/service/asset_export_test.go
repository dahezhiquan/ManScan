package service

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"ManScan/server/internal/model/dto"
	"ManScan/server/internal/model/entity"
	"ManScan/server/internal/repository"

	"github.com/xuri/excelize/v2"
)

type exportDomainRepositoryStub struct {
	repository.AssetDomainRepository
	query   dto.ListAssetDomainsQuery
	records []repository.AssetDomainExportRecord
}

func (s *exportDomainRepositoryStub) EachFiltered(_ context.Context, query dto.ListAssetDomainsQuery, visit func(repository.AssetDomainExportRecord) error) error {
	s.query = query
	for _, record := range s.records {
		if err := visit(record); err != nil {
			return err
		}
	}
	return nil
}

type exportHostRepositoryStub struct {
	repository.AssetHostRepository
	query   dto.ListAssetHostsQuery
	records []repository.AssetHostExportRecord
}

func (s *exportHostRepositoryStub) EachFiltered(_ context.Context, query dto.ListAssetHostsQuery, visit func(repository.AssetHostExportRecord) error) error {
	s.query = query
	for _, record := range s.records {
		if err := visit(record); err != nil {
			return err
		}
	}
	return nil
}

func TestAssetDomainExportIncludesDetailsAndLongResponse(t *testing.T) {
	now := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	longResponse := strings.Repeat("HTTP response ", 1500)
	title := "=1+1"
	repo := &exportDomainRepositoryStub{records: []repository.AssetDomainExportRecord{{
		List: repository.AssetDomainListRecord{
			AssetDomain:        entity.AssetDomain{ID: 7, Domain: "app.example", Title: &title, Response: &longResponse, IsAlive: true},
			VulnerabilityCount: 2, ComponentCount: 1,
		},
		ServiceAssets:  []entity.AssetDomainServiceAsset{{Domain: "app.example", AppName: "nginx", LastFoundAt: now, FirstFoundAt: now, IsAlive: true}},
		TitleHistories: []entity.AssetDomainTitleHistory{{Domain: "app.example", HistoryTitle: "Portal", FirstTitleCreatedAt: now, LatestTitleAliveAt: now}},
	}}}
	query := dto.ListAssetDomainsQuery{Page: 4, PageSize: 1, Owner: "team"}
	var output bytes.Buffer
	if err := NewAssetDomainService(repo, nil).Export(context.Background(), query, &output); err != nil {
		t.Fatalf("Export() error = %v", err)
	}
	if repo.query.Page != 4 || repo.query.Owner != "team" {
		t.Fatalf("query = %+v", repo.query)
	}
	book, err := excelize.OpenReader(&output)
	if err != nil {
		t.Fatalf("OpenReader() error = %v", err)
	}
	defer book.Close()
	values := assetExportValues(t, book, "domain_assets")
	if len(values) != len(domainExportHeaders) || values["domain"] != "app.example" || values["component_count"] != "1" {
		t.Fatalf("values = %+v", values)
	}
	if _, ok := values["id"]; ok {
		t.Fatal("id was exported")
	}
	if _, ok := values["asset_address"]; ok {
		t.Fatal("duplicate asset_address was exported")
	}
	if values["response"] != "[see large_fields]" {
		t.Fatalf("response = %q", values["response"])
	}
	var services []dto.AssetDomainServiceAssetItem
	if err := json.Unmarshal([]byte(values["service_assets"]), &services); err != nil || len(services) != 1 || services[0].AppName != "nginx" {
		t.Fatalf("service_assets = %q, error = %v", values["service_assets"], err)
	}
	var histories []dto.AssetDomainTitleHistoryItem
	if err := json.Unmarshal([]byte(values["title_histories"]), &histories); err != nil || len(histories) != 1 || histories[0].HistoryTitle != "Portal" {
		t.Fatalf("title_histories = %q, error = %v", values["title_histories"], err)
	}
	parts, err := book.GetRows("large_fields")
	if err != nil {
		t.Fatalf("GetRows(large_fields) error = %v", err)
	}
	var reconstructed strings.Builder
	for _, part := range parts[1:] {
		if part[0] != "2" || part[1] != "response" {
			t.Fatalf("large field part = %v", part)
		}
		reconstructed.WriteString(part[3])
	}
	if reconstructed.String() != longResponse {
		t.Fatalf("response length = %d, want %d", reconstructed.Len(), len(longResponse))
	}
	if formula, err := book.GetCellFormula("domain_assets", "C2"); err != nil || formula != "" {
		t.Fatalf("title formula = %q, error = %v", formula, err)
	}
}

func TestAssetHostExportIncludesPorts(t *testing.T) {
	now := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	serviceName := "https"
	repo := &exportHostRepositoryStub{records: []repository.AssetHostExportRecord{{
		List: repository.AssetHostListRecord{
			AssetHost: entity.AssetHost{ID: 8, IPAddress: "192.0.2.1", ScanCreatedAt: now, IsAlive: true},
			PortCount: 1, HighCount: 1, VulnerabilityCount: 1,
		},
		Ports: []entity.AssetHostPort{{IPAddress: "192.0.2.1", PortProtocol: "tcp", PortNumber: 443, ServiceName: &serviceName, PortCreatedAt: now, IsAlive: true}},
	}}}
	var output bytes.Buffer
	if err := NewAssetHostService(repo).Export(context.Background(), dto.ListAssetHostsQuery{Keyword: "192.0"}, &output); err != nil {
		t.Fatalf("Export() error = %v", err)
	}
	if repo.query.Keyword != "192.0" {
		t.Fatalf("query = %+v", repo.query)
	}
	book, err := excelize.OpenReader(&output)
	if err != nil {
		t.Fatalf("OpenReader() error = %v", err)
	}
	defer book.Close()
	values := assetExportValues(t, book, "host_assets")
	if len(values) != len(hostExportHeaders) || values["ip_address"] != "192.0.2.1" || values["risk_level"] != "high" || values["port_count"] != "1" {
		t.Fatalf("values = %+v", values)
	}
	if _, ok := values["asset_address"]; ok {
		t.Fatal("duplicate asset_address was exported")
	}
	var ports []dto.AssetHostPortDetailItem
	if err := json.Unmarshal([]byte(values["ports"]), &ports); err != nil || len(ports) != 1 || ports[0].PortNumber != 443 || ports[0].ServiceName != "https" {
		t.Fatalf("ports = %q, error = %v", values["ports"], err)
	}
}

func assetExportValues(t *testing.T, book *excelize.File, sheet string) map[string]string {
	t.Helper()
	rows, err := book.GetRows(sheet)
	if err != nil || len(rows) != 2 || len(rows[0]) != len(rows[1]) {
		t.Fatalf("GetRows(%s) = %+v, %v", sheet, rows, err)
	}
	values := make(map[string]string, len(rows[0]))
	for index, name := range rows[0] {
		values[name] = rows[1][index]
	}
	return values
}
