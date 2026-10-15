package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"ManScan/server/internal/model/dto"
	"ManScan/server/internal/pkg/logx"
	"ManScan/server/internal/service"

	"github.com/gin-gonic/gin"
)

func TestNewRouterRegistersVulnerabilityStatusRoutes(t *testing.T) {
	gin.SetMode(gin.TestMode)

	router := NewRouter(nil, noopAuthHandler{}, noopAuthService{}, noopTemplateHandler{}, noopScanTaskHandler{}, noopVulnerabilityHandler{}, noopAssetDomainHandler{}, noopAssetHostHandler{}, noopAssetConfigCenterHandler{}, noopSettingHandler{}, noopDashboardHandler{})
	routes := router.Routes()
	assertRouteRegistered(t, routes, "GET", "/api/v1/dashboard/overview")
	assertRouteRegistered(t, routes, "GET", "/api/v1/dashboard/asset-risks")
	assertRouteRegistered(t, routes, "GET", "/api/v1/dashboard/host-rankings")
	assertRouteRegistered(t, routes, "GET", "/api/v1/dashboard/service-fingerprints")

	assertRouteRegistered(t, routes, "GET", "/api/v1/auth/challenge")
	assertRouteRegistered(t, routes, "POST", "/api/v1/auth/login")
	assertRouteRegistered(t, routes, "POST", "/api/v1/auth/logout")
	assertRouteRegistered(t, routes, "GET", "/api/v1/auth/me")
	assertRouteRegistered(t, routes, "GET", "/api/v1/users")
	assertRouteRegistered(t, routes, "POST", "/api/v1/users")
	assertRouteRegistered(t, routes, "PUT", "/api/v1/users/:username")
	assertRouteRegistered(t, routes, "DELETE", "/api/v1/users/:username")
	assertRouteRegistered(t, routes, "DELETE", "/api/v1/vulnerabilities")
	assertRouteRegistered(t, routes, "PATCH", "/api/v1/vulnerabilities/status")
	assertRouteRegistered(t, routes, "PATCH", "/api/v1/vulnerabilities/:id/status")
	assertRouteRegistered(t, routes, "GET", "/api/v1/domain-assets")
	assertRouteRegistered(t, routes, "GET", "/api/v1/domain-assets/detail")
	assertRouteRegistered(t, routes, "GET", "/api/v1/domain-assets/screenshots/latest")
	assertRouteRegistered(t, routes, "GET", "/api/v1/domain-assets/screenshots")
	assertRouteRegistered(t, routes, "PATCH", "/api/v1/domain-assets/manual-note")
	assertRouteRegistered(t, routes, "GET", "/api/v1/host-assets")
	assertRouteRegistered(t, routes, "GET", "/api/v1/host-assets/detail")
	assertRouteRegistered(t, routes, "PATCH", "/api/v1/host-assets/manual-note")
	assertRouteRegistered(t, routes, "GET", "/api/v1/asset-config-centers")
	assertRouteRegistered(t, routes, "GET", "/api/v1/asset-config-centers/options/small-categories")
	assertRouteRegistered(t, routes, "POST", "/api/v1/asset-config-centers")
	assertRouteRegistered(t, routes, "PUT", "/api/v1/asset-config-centers/:id")
	assertRouteRegistered(t, routes, "DELETE", "/api/v1/asset-config-centers/:id")
	assertRouteRegistered(t, routes, "GET", "/api/v1/settings/theme")
	assertRouteRegistered(t, routes, "PUT", "/api/v1/settings/theme")
	assertRouteRegistered(t, routes, "DELETE", "/api/v1/scans")
	assertRouteRegistered(t, routes, "GET", "/api/v1/scans/:id/config")
	assertRouteRegistered(t, routes, "GET", "/api/v1/scans/:id/responses/archive")
	assertRouteRegistered(t, routes, "GET", "/api/v1/scans/:id/raw-logs/archive")
}

func assertRouteRegistered(t *testing.T, routes gin.RoutesInfo, method, path string) {
	t.Helper()

	for _, route := range routes {
		if route.Method == method && route.Path == path {
			return
		}
	}
	t.Fatalf("route %s %s is not registered", method, path)
}

func TestDashboardRoutesRequireAuthentication(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := NewRouter(logx.New(), noopAuthHandler{}, noopAuthService{}, noopTemplateHandler{}, noopScanTaskHandler{}, noopVulnerabilityHandler{}, noopAssetDomainHandler{}, noopAssetHostHandler{}, noopAssetConfigCenterHandler{}, noopSettingHandler{}, noopDashboardHandler{})
	for _, path := range []string{"overview", "asset-risks", "host-rankings", "service-fingerprints"} {
		recorder := httptest.NewRecorder()
		router.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/api/v1/dashboard/"+path, nil))
		if recorder.Code != http.StatusUnauthorized {
			t.Fatalf("path %s status = %d, want 401", path, recorder.Code)
		}
	}
}

type noopAuthHandler struct{}

type noopDashboardHandler struct{}

func (noopDashboardHandler) GetOverview(*gin.Context)            {}
func (noopDashboardHandler) GetAssetRisks(*gin.Context)          {}
func (noopDashboardHandler) GetHostRankings(*gin.Context)        {}
func (noopDashboardHandler) GetServiceFingerprints(*gin.Context) {}

func (noopAuthHandler) Challenge(*gin.Context) {}
func (noopAuthHandler) Login(*gin.Context)     {}
func (noopAuthHandler) Logout(*gin.Context)    {}
func (noopAuthHandler) Me(*gin.Context)        {}
func (noopAuthHandler) ListUsers(*gin.Context) {}
func (noopAuthHandler) CreateUser(*gin.Context) {
}
func (noopAuthHandler) UpdateUser(*gin.Context) {
}
func (noopAuthHandler) DeleteUser(*gin.Context) {
}

type noopAuthService struct{}

func (noopAuthService) Challenge(context.Context, string) (*dto.AuthChallengeResponse, error) {
	return nil, nil
}

func (noopAuthService) Login(context.Context, dto.LoginRequest, string, string) (*dto.LoginResponse, error) {
	return nil, nil
}

func (noopAuthService) Authenticate(context.Context, string) (*service.AuthenticatedUser, error) {
	return nil, service.ErrUnauthorized
}

func (noopAuthService) Logout(context.Context, string) (*dto.LogoutResponse, error) {
	return nil, nil
}

func (noopAuthService) CurrentUser(context.Context, int64) (*dto.UserInfo, error) {
	return nil, nil
}

func (noopAuthService) ListUsers(context.Context, dto.ListUsersQuery) (*dto.PageResult[dto.UserListItem], error) {
	return nil, nil
}

func (noopAuthService) CreateUser(context.Context, dto.CreateUserRequest) (*dto.UserListItem, error) {
	return nil, nil
}

func (noopAuthService) UpdateUser(context.Context, string, dto.UpdateUserRequest) (*dto.UserListItem, error) {
	return nil, nil
}

func (noopAuthService) DeleteUser(context.Context, string) (*dto.DeleteUserResponse, error) {
	return nil, nil
}

type noopTemplateHandler struct{}

func (noopTemplateHandler) List(*gin.Context)      {}
func (noopTemplateHandler) Detail(*gin.Context)    {}
func (noopTemplateHandler) Tags(*gin.Context)      {}
func (noopTemplateHandler) Protocols(*gin.Context) {}
func (noopTemplateHandler) Stats(*gin.Context)     {}

type noopScanTaskHandler struct{}

func (noopScanTaskHandler) Create(*gin.Context)      {}
func (noopScanTaskHandler) Rescan(*gin.Context)      {}
func (noopScanTaskHandler) Delete(*gin.Context)      {}
func (noopScanTaskHandler) Pause(*gin.Context)       {}
func (noopScanTaskHandler) Resume(*gin.Context)      {}
func (noopScanTaskHandler) Cancel(*gin.Context)      {}
func (noopScanTaskHandler) List(*gin.Context)        {}
func (noopScanTaskHandler) NameOptions(*gin.Context) {}
func (noopScanTaskHandler) Stats(*gin.Context)       {}
func (noopScanTaskHandler) Get(*gin.Context)         {}
func (noopScanTaskHandler) GetConfig(*gin.Context)   {}
func (noopScanTaskHandler) Logs(*gin.Context)        {}
func (noopScanTaskHandler) Stream(*gin.Context)      {}
func (noopScanTaskHandler) DownloadResponsesArchive(*gin.Context) {
}
func (noopScanTaskHandler) DownloadRawLogsArchive(*gin.Context) {
}

type noopVulnerabilityHandler struct{}

func (noopVulnerabilityHandler) List(*gin.Context)              {}
func (noopVulnerabilityHandler) Detail(*gin.Context)            {}
func (noopVulnerabilityHandler) UpdateStatus(*gin.Context)      {}
func (noopVulnerabilityHandler) BatchUpdateStatus(*gin.Context) {}
func (noopVulnerabilityHandler) Delete(*gin.Context)            {}

type noopAssetDomainHandler struct{}

func (noopAssetDomainHandler) List(*gin.Context)             {}
func (noopAssetDomainHandler) Detail(*gin.Context)           {}
func (noopAssetDomainHandler) UpdateManualNote(*gin.Context) {}
func (noopAssetDomainHandler) LatestScreenshot(*gin.Context) {}
func (noopAssetDomainHandler) ListScreenshots(*gin.Context)  {}

type noopAssetHostHandler struct{}

func (noopAssetHostHandler) List(*gin.Context)             {}
func (noopAssetHostHandler) Detail(*gin.Context)           {}
func (noopAssetHostHandler) UpdateManualNote(*gin.Context) {}

type noopAssetConfigCenterHandler struct{}

func (noopAssetConfigCenterHandler) Create(*gin.Context)               {}
func (noopAssetConfigCenterHandler) List(*gin.Context)                 {}
func (noopAssetConfigCenterHandler) SmallCategoryOptions(*gin.Context) {}
func (noopAssetConfigCenterHandler) Update(*gin.Context)               {}
func (noopAssetConfigCenterHandler) Delete(*gin.Context)               {}

type noopSettingHandler struct{}

func (noopSettingHandler) GetTheme(*gin.Context)    {}
func (noopSettingHandler) UpdateTheme(*gin.Context) {}
