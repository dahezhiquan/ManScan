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
	thirdPartyAPIKeyHandler handler.ThirdPartyAPIKeyHandler,
	settingHandler handler.SettingHandler,
	dashboardHandler handler.DashboardHandler,
	scheduledJobHandlers ...handler.ScheduledJobHandler,
) *gin.Engine {
	router := gin.New()
	router.Use(gin.Recovery())
	router.Use(middleware.Logger(logger))

	v1 := router.Group("/api/v1")

	v1.GET("/auth/challenge", authHandler.Challenge)
	v1.POST("/auth/login", authHandler.Login)

	protected := v1.Group("")
	protected.Use(middleware.JWTAuth(authService))
	protected.GET("/dashboard/overview", dashboardHandler.GetOverview)
	protected.GET("/dashboard/asset-risks", dashboardHandler.GetAssetRisks)
	protected.GET("/dashboard/host-rankings", dashboardHandler.GetHostRankings)
	protected.GET("/dashboard/service-fingerprints", dashboardHandler.GetServiceFingerprints)
	protected.POST("/auth/logout", authHandler.Logout)
	protected.GET("/auth/me", authHandler.Me)
	protected.GET("/users", authHandler.ListUsers)
	protected.POST("/users", authHandler.CreateUser)
	protected.PUT("/users/:username", authHandler.UpdateUser)
	protected.DELETE("/users/:username", authHandler.DeleteUser)

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
	protected.GET("/domain-assets/screenshots/latest", assetDomainHandler.LatestScreenshot)
	protected.GET("/domain-assets/screenshots", assetDomainHandler.ListScreenshots)
	protected.PATCH("/domain-assets/manual-note", assetDomainHandler.UpdateManualNote)
	protected.GET("/host-assets", assetHostHandler.List)
	protected.GET("/host-assets/detail", assetHostHandler.Detail)
	protected.PATCH("/host-assets/manual-note", assetHostHandler.UpdateManualNote)

	protected.GET("/asset-config-centers", assetConfigCenterHandler.List)
	protected.GET("/asset-config-centers/options/small-categories", assetConfigCenterHandler.SmallCategoryOptions)
	protected.POST("/asset-config-centers", assetConfigCenterHandler.Create)
	protected.PUT("/asset-config-centers/:id", assetConfigCenterHandler.Update)
	protected.DELETE("/asset-config-centers/:id", assetConfigCenterHandler.Delete)
	protected.GET("/third-party-api-keys", thirdPartyAPIKeyHandler.List)
	protected.GET("/third-party-api-keys/:id", thirdPartyAPIKeyHandler.Get)
	protected.GET("/third-party-api-keys/:id/plaintext", thirdPartyAPIKeyHandler.GetPlaintext)
	protected.POST("/third-party-api-keys", thirdPartyAPIKeyHandler.Create)
	protected.PUT("/third-party-api-keys/:id", thirdPartyAPIKeyHandler.Update)
	protected.DELETE("/third-party-api-keys/:id", thirdPartyAPIKeyHandler.Delete)
	if len(scheduledJobHandlers) > 0 && scheduledJobHandlers[0] != nil {
		scheduledJobHandler := scheduledJobHandlers[0]
		protected.GET("/scheduled-jobs", scheduledJobHandler.List)
		protected.GET("/scheduled-jobs/:id", scheduledJobHandler.Get)
		protected.POST("/scheduled-jobs", scheduledJobHandler.Create)
		protected.PUT("/scheduled-jobs/:id", scheduledJobHandler.Update)
		protected.POST("/scheduled-jobs/:id/stop", scheduledJobHandler.Stop)
		protected.DELETE("/scheduled-jobs/:id", scheduledJobHandler.Delete)
		protected.POST("/scheduled-jobs/:id/trigger", scheduledJobHandler.Trigger)
		protected.GET("/scheduled-jobs/:id/runs", scheduledJobHandler.ListRuns)
		protected.GET("/scheduled-job-runs/:run_id", scheduledJobHandler.GetRun)
		protected.GET("/scheduled-job-runs/:run_id/output", scheduledJobHandler.DownloadRunOutput)
	}

	protected.GET("/settings/theme", settingHandler.GetTheme)
	protected.PUT("/settings/theme", settingHandler.UpdateTheme)

	protected.GET("/scans", scanTaskHandler.List)
	protected.GET("/scans/stats", scanTaskHandler.Stats)
	protected.GET("/scans/options/names", scanTaskHandler.NameOptions)
	protected.DELETE("/scans", scanTaskHandler.Delete)
	protected.POST("/scans", scanTaskHandler.Create)
	protected.POST("/scans/:id/rescan", scanTaskHandler.Rescan)
	protected.POST("/scans/:id/pause", scanTaskHandler.Pause)
	protected.POST("/scans/:id/resume", scanTaskHandler.Resume)
	protected.POST("/scans/:id/cancel", scanTaskHandler.Cancel)
	protected.GET("/scans/:id/config", scanTaskHandler.GetConfig)
	protected.GET("/scans/:id", scanTaskHandler.Get)
	protected.GET("/scans/:id/logs", scanTaskHandler.Logs)
	protected.GET("/scans/:id/responses/archive", scanTaskHandler.DownloadResponsesArchive)
	protected.GET("/scans/:id/raw-logs/archive", scanTaskHandler.DownloadRawLogsArchive)
	protected.GET("/scans/:id/stream", scanTaskHandler.Stream)

	return router
}
