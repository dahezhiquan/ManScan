package api

import (
	"testing"

	"github.com/gin-gonic/gin"
)

func TestNewRouterRegistersVulnerabilityStatusRoutes(t *testing.T) {
	gin.SetMode(gin.TestMode)

	router := NewRouter(nil, noopTemplateHandler{}, noopScanTaskHandler{}, noopVulnerabilityHandler{})
	routes := router.Routes()

	assertRouteRegistered(t, routes, "DELETE", "/api/v1/vulnerabilities")
	assertRouteRegistered(t, routes, "PATCH", "/api/v1/vulnerabilities/status")
	assertRouteRegistered(t, routes, "PATCH", "/api/v1/vulnerabilities/:id/status")
	assertRouteRegistered(t, routes, "DELETE", "/api/v1/scans")
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
func (noopScanTaskHandler) Logs(*gin.Context)        {}
func (noopScanTaskHandler) Stream(*gin.Context)      {}

type noopVulnerabilityHandler struct{}

func (noopVulnerabilityHandler) List(*gin.Context)              {}
func (noopVulnerabilityHandler) Detail(*gin.Context)            {}
func (noopVulnerabilityHandler) UpdateStatus(*gin.Context)      {}
func (noopVulnerabilityHandler) BatchUpdateStatus(*gin.Context) {}
func (noopVulnerabilityHandler) Delete(*gin.Context)            {}
