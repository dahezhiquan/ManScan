package api

import (
	"ManScan/server/internal/handler"
	"ManScan/server/internal/middleware"
	"ManScan/server/internal/pkg/logx"
	"ManScan/server/internal/service"

	"github.com/gin-gonic/gin"
)

func NewRouter(
	logger *logx.Logger,
	authHandler handler.AuthHandler,
	authService service.AuthService,
	templateHandler handler.TemplateHandler,
	scanTaskHandler handler.ScanTaskHandler,
	vulnerabilityHandler handler.VulnerabilityHandler,
	assetDomainHandler handler.AssetDomainHandler,
	assetHostHandler handler.AssetHostHandler,
	assetConfigCenterHandler handler.AssetConfigCenterHandler,
) *gin.Engine {
	router := gin.New()
	router.Use(gin.Recovery())
	router.Use(middleware.Logger(logger))

	v1 := router.Group("/api/v1")

	v1.POST("/auth/login", authHandler.Login)

	protected := v1.Group("")
	protected.Use(middleware.JWTAuth(authService))
	protected.POST("/auth/logout", authHandler.Logout)
	protected.GET("/auth/me", authHandler.Me)

	protected.GET("/templates", templateHandler.List)
	protected.GET("/templates/:id", templateHandler.Detail)
	protected.GET("/templates/options/tags", templateHandler.Tags)
	protected.GET("/templates/options/protocols", templateHandler.Protocols)
	protected.GET("/templates/stats", templateHandler.Stats)

	protected.GET("/vulnerabilities", vulnerabilityHandler.List)
	protected.DELETE("/vulnerabilities", vulnerabilityHandler.Delete)
	protected.PATCH("/vulnerabilities/status", vulnerabilityHandler.BatchUpdateStatus)
	protected.PATCH("/vulnerabilities/:id/status", vulnerabilityHandler.UpdateStatus)
	protected.GET("/vulnerabilities/:id", vulnerabilityHandler.Detail)

	protected.GET("/domain-assets", assetDomainHandler.List)
	protected.GET("/domain-assets/detail", assetDomainHandler.Detail)
	protected.GET("/host-assets", assetHostHandler.List)
	protected.GET("/host-assets/detail", assetHostHandler.Detail)

	protected.GET("/asset-config-centers", assetConfigCenterHandler.List)
	protected.GET("/asset-config-centers/options/small-categories", assetConfigCenterHandler.SmallCategoryOptions)
	protected.POST("/asset-config-centers", assetConfigCenterHandler.Create)
	protected.PUT("/asset-config-centers/:id", assetConfigCenterHandler.Update)
	protected.DELETE("/asset-config-centers/:id", assetConfigCenterHandler.Delete)

	protected.GET("/scans", scanTaskHandler.List)
	protected.GET("/scans/stats", scanTaskHandler.Stats)
	protected.GET("/scans/options/names", scanTaskHandler.NameOptions)
	protected.DELETE("/scans", scanTaskHandler.Delete)
	protected.POST("/scans", scanTaskHandler.Create)
	protected.POST("/scans/:id/rescan", scanTaskHandler.Rescan)
	protected.POST("/scans/:id/pause", scanTaskHandler.Pause)
	protected.POST("/scans/:id/resume", scanTaskHandler.Resume)
	protected.POST("/scans/:id/cancel", scanTaskHandler.Cancel)
	protected.GET("/scans/:id", scanTaskHandler.Get)
	protected.GET("/scans/:id/logs", scanTaskHandler.Logs)
	protected.GET("/scans/:id/responses/archive", scanTaskHandler.DownloadResponsesArchive)
	protected.GET("/scans/:id/raw-logs/archive", scanTaskHandler.DownloadRawLogsArchive)
	protected.GET("/scans/:id/stream", scanTaskHandler.Stream)

	return router
}
