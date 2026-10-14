package handler

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"ManScan/server/internal/model/dto"

	"github.com/gin-gonic/gin"
)

type dashboardServiceStub struct {
	err error
}

func (stub dashboardServiceStub) GetOverview(context.Context) (*dto.DashboardOverviewResponse, error) {
	return &dto.DashboardOverviewResponse{}, stub.err
}

func (stub dashboardServiceStub) GetAssetRisks(context.Context) (*dto.DashboardAssetRisksResponse, error) {
	return &dto.DashboardAssetRisksResponse{}, stub.err
}

func (stub dashboardServiceStub) GetHostRankings(context.Context) (*dto.DashboardHostRankingsResponse, error) {
	return &dto.DashboardHostRankingsResponse{TopVulnerabilities: []dto.DashboardHostVulnerabilityRank{}, TopPorts: []dto.DashboardHostPortRank{}}, stub.err
}

func (stub dashboardServiceStub) GetServiceFingerprints(context.Context) (*dto.DashboardServiceFingerprintsResponse, error) {
	return &dto.DashboardServiceFingerprintsResponse{Domains: []dto.DashboardDomainFingerprintRank{}, Hosts: []dto.DashboardHostFingerprintRank{}}, stub.err
}

func TestDashboardHandlerResponses(t *testing.T) {
	gin.SetMode(gin.TestMode)
	for _, serviceErr := range []error{nil, errors.New("secret SQL database error")} {
		handler := NewDashboardHandler(dashboardServiceStub{err: serviceErr})
		for name, method := range map[string]gin.HandlerFunc{
			"overview": handler.GetOverview, "asset-risks": handler.GetAssetRisks,
			"host-rankings": handler.GetHostRankings, "service-fingerprints": handler.GetServiceFingerprints,
		} {
			t.Run(name+"/"+http.StatusText(dashboardExpectedStatus(serviceErr)), func(t *testing.T) {
				router := gin.New()
				router.GET("/dashboard", method)
				recorder := httptest.NewRecorder()
				router.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/dashboard", nil))
				body := recorder.Body.String()
				if recorder.Code != dashboardExpectedStatus(serviceErr) || strings.Contains(body, "secret SQL") {
					t.Fatalf("status = %d, body = %s", recorder.Code, body)
				}
				if serviceErr != nil && !strings.Contains(body, `"code":50301`) {
					t.Fatalf("missing business error code: %s", body)
				}
				if serviceErr == nil && (!strings.Contains(body, `"code":0`) || !strings.Contains(body, `"data":{`)) {
					t.Fatalf("invalid success envelope: %s", body)
				}
			})
		}
	}
}

func dashboardExpectedStatus(err error) int {
	if err != nil {
		return http.StatusServiceUnavailable
	}
	return http.StatusOK
}
