package handler

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"

	"ManScan/server/internal/model/dto"
	"ManScan/server/internal/service"
)

type domainExportServiceStub struct {
	service.AssetDomainService
	query  dto.ListAssetDomainsQuery
	called bool
}

func (s *domainExportServiceStub) Export(_ context.Context, query dto.ListAssetDomainsQuery, output io.Writer) error {
	s.called = true
	s.query = query
	_, err := io.WriteString(output, "domain-xlsx")
	return err
}

type hostExportServiceStub struct {
	service.AssetHostService
	query  dto.ListAssetHostsQuery
	called bool
}

func (s *hostExportServiceStub) Export(_ context.Context, query dto.ListAssetHostsQuery, output io.Writer) error {
	s.called = true
	s.query = query
	_, err := io.WriteString(output, "host-xlsx")
	return err
}

func TestAssetDomainExportDownloadsFilteredWorkbook(t *testing.T) {
	svc := &domainExportServiceStub{}
	h := NewAssetDomainHandler(svc)
	recorder := serveAssetDomainHandlerRequest(http.MethodGet,
		"/export?page=3&page_size=1&keyword=portal&owner=team&risk_level=high&risk_level=critical&has_component=false&is_alive=true", h.Export)
	if recorder.Code != http.StatusOK || recorder.Body.String() != "domain-xlsx" {
		t.Fatalf("response = %d %q", recorder.Code, recorder.Body.String())
	}
	if !svc.called || svc.query.Page != 0 || svc.query.PageSize != 0 || svc.query.Keyword != "portal" || svc.query.Owner != "team" || len(svc.query.RiskLevels) != 2 || svc.query.HasComponent == nil || *svc.query.HasComponent || svc.query.IsAlive == nil || !*svc.query.IsAlive {
		t.Fatalf("query = %+v", svc.query)
	}
	if got := recorder.Header().Get("Content-Type"); got != "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet" {
		t.Fatalf("Content-Type = %q", got)
	}
	if got := recorder.Header().Get("Content-Disposition"); !strings.Contains(got, "domain-assets-") || !strings.Contains(got, ".xlsx") {
		t.Fatalf("Content-Disposition = %q", got)
	}
	invalid := serveAssetDomainHandlerRequest(http.MethodGet, "/export?has_component=invalid", h.Export)
	if invalid.Code != http.StatusBadRequest {
		t.Fatalf("invalid filter status = %d", invalid.Code)
	}
}

func TestAssetHostExportDownloadsFilteredWorkbook(t *testing.T) {
	svc := &hostExportServiceStub{}
	h := NewAssetHostHandler(svc)
	recorder := serveAssetDomainHandlerRequest(http.MethodGet,
		"/export?page=4&page_size=1&keyword=192.0&os_type=linux&has_port=true&has_vulnerability=false", h.Export)
	if recorder.Code != http.StatusOK || recorder.Body.String() != "host-xlsx" {
		t.Fatalf("response = %d %q", recorder.Code, recorder.Body.String())
	}
	if !svc.called || svc.query.Page != 0 || svc.query.PageSize != 0 || svc.query.Keyword != "192.0" || svc.query.OSType != "linux" || svc.query.HasPort == nil || !*svc.query.HasPort || svc.query.HasVulnerability == nil || *svc.query.HasVulnerability {
		t.Fatalf("query = %+v", svc.query)
	}
	if got := recorder.Header().Get("Content-Disposition"); !strings.Contains(got, "host-assets-") || !strings.Contains(got, ".xlsx") {
		t.Fatalf("Content-Disposition = %q", got)
	}
	invalid := serveAssetDomainHandlerRequest(http.MethodGet, "/export?has_port=invalid", h.Export)
	if invalid.Code != http.StatusBadRequest {
		t.Fatalf("invalid filter status = %d", invalid.Code)
	}
}
