package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"ManScan/server/internal/model/dto"
	"ManScan/server/internal/service"

	"github.com/gin-gonic/gin"
)

func TestAssetDomainHandlerLatestScreenshot(t *testing.T) {
	t.Parallel()

	svc := &assetDomainServiceStub{
		latestScreenshot: &dto.AssetDomainScreenshot{Domain: "app.example.com", CapturedDate: "2026-10-15", ImageBase64: "aW1hZ2U="},
	}
	handler := NewAssetDomainHandler(svc)
	recorder := serveAssetDomainHandlerRequest(http.MethodGet, "/screenshots/latest?domain=app.example.com", handler.LatestScreenshot)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status code = %d, want 200", recorder.Code)
	}
	if svc.latestScreenshotDomain != "app.example.com" {
		t.Fatalf("service domain = %q, want app.example.com", svc.latestScreenshotDomain)
	}
}

func TestAssetDomainHandlerLatestScreenshotErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		path       string
		serviceErr error
		wantStatus int
		wantCode   int
	}{
		{name: "empty domain", path: "/screenshots/latest", wantStatus: http.StatusBadRequest, wantCode: 40001},
		{name: "invalid domain", path: "/screenshots/latest?domain=bad", serviceErr: service.ErrInvalidAssetDomain, wantStatus: http.StatusBadRequest, wantCode: 40001},
		{name: "not found", path: "/screenshots/latest?domain=missing", serviceErr: service.ErrAssetDomainScreenshotNotFound, wantStatus: http.StatusNotFound, wantCode: 40401},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			svc := &assetDomainServiceStub{latestScreenshotErr: test.serviceErr}
			handler := NewAssetDomainHandler(svc)
			recorder := serveAssetDomainHandlerRequest(http.MethodGet, test.path, handler.LatestScreenshot)
			if recorder.Code != test.wantStatus {
				t.Fatalf("status code = %d, want %d", recorder.Code, test.wantStatus)
			}
			var envelope struct {
				Code int `json:"code"`
			}
			if err := json.Unmarshal(recorder.Body.Bytes(), &envelope); err != nil {
				t.Fatalf("decode response: %v", err)
			}
			if envelope.Code != test.wantCode {
				t.Fatalf("code = %d, want %d", envelope.Code, test.wantCode)
			}
		})
	}
}

func TestAssetDomainHandlerListScreenshotsParsesPagination(t *testing.T) {
	t.Parallel()

	svc := &assetDomainServiceStub{
		screenshotPage: &dto.PageResult[dto.AssetDomainScreenshot]{Page: 2, PageSize: 5, Items: []dto.AssetDomainScreenshot{}},
	}
	handler := NewAssetDomainHandler(svc)
	recorder := serveAssetDomainHandlerRequest(http.MethodGet, "/screenshots?domain=app.example.com&page=2&page_size=5", handler.ListScreenshots)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status code = %d, want 200", recorder.Code)
	}
	if svc.screenshotQuery == nil || svc.screenshotQuery.Domain != "app.example.com" || svc.screenshotQuery.Page != 2 || svc.screenshotQuery.PageSize != 5 {
		t.Fatalf("query = %+v, want parsed domain/page/page_size", svc.screenshotQuery)
	}

	invalidRecorder := serveAssetDomainHandlerRequest(http.MethodGet, "/screenshots?domain=app.example.com&page_size=21", handler.ListScreenshots)
	if invalidRecorder.Code != http.StatusBadRequest {
		t.Fatalf("invalid page_size status = %d, want 400", invalidRecorder.Code)
	}
}

func serveAssetDomainHandlerRequest(method, path string, handlerFunc gin.HandlerFunc) *httptest.ResponseRecorder {
	router := gin.New()
	routePath, _, _ := strings.Cut(path, "?")
	router.Handle(method, routePath, handlerFunc)
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequest(method, path, nil))
	return recorder
}

type assetDomainServiceStub struct {
	latestScreenshot       *dto.AssetDomainScreenshot
	latestScreenshotErr    error
	latestScreenshotDomain string
	screenshotPage         *dto.PageResult[dto.AssetDomainScreenshot]
	screenshotPageErr      error
	screenshotQuery        *dto.ListAssetDomainScreenshotsQuery
}

func (s *assetDomainServiceStub) List(context.Context, dto.ListAssetDomainsQuery) (*dto.PageResult[dto.AssetDomainListItem], error) {
	return nil, nil
}

func (s *assetDomainServiceStub) Detail(context.Context, string) (*dto.AssetDomainDetail, error) {
	return nil, nil
}

func (s *assetDomainServiceStub) UpdateManualNote(context.Context, dto.UpdateAssetDomainManualNoteRequest) (*dto.UpdateAssetDomainManualNoteResponse, error) {
	return nil, nil
}

func (s *assetDomainServiceStub) LatestScreenshot(_ context.Context, domain string) (*dto.AssetDomainScreenshot, error) {
	s.latestScreenshotDomain = domain
	return s.latestScreenshot, s.latestScreenshotErr
}

func (s *assetDomainServiceStub) ListScreenshots(_ context.Context, query dto.ListAssetDomainScreenshotsQuery) (*dto.PageResult[dto.AssetDomainScreenshot], error) {
	queryCopy := query
	s.screenshotQuery = &queryCopy
	return s.screenshotPage, s.screenshotPageErr
}
