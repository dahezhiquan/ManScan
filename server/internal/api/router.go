package api

import (
	"ManScan/server/internal/handler"
	"ManScan/server/internal/middleware"
	"ManScan/server/internal/pkg/logx"

	"github.com/gin-gonic/gin"
)

func NewRouter(
	logger *logx.Logger,
	templateHandler handler.TemplateHandler,
	scanTaskHandler handler.ScanTaskHandler,
	vulnerabilityHandler handler.VulnerabilityHandler,
) *gin.Engine {
	router := gin.New()
	router.Use(gin.Recovery())
	router.Use(middleware.Logger(logger))

	v1 := router.Group("/api/v1")

	v1.GET("/templates", templateHandler.List)
	v1.GET("/templates/:id", templateHandler.Detail)
	v1.GET("/templates/options/tags", templateHandler.Tags)
	v1.GET("/templates/options/protocols", templateHandler.Protocols)
	v1.GET("/templates/stats", templateHandler.Stats)

	v1.GET("/vulnerabilities", vulnerabilityHandler.List)
	v1.GET("/vulnerabilities/:id", vulnerabilityHandler.Detail)

	v1.GET("/scans", scanTaskHandler.List)
	v1.GET("/scans/stats", scanTaskHandler.Stats)
	v1.GET("/scans/options/names", scanTaskHandler.NameOptions)
	v1.POST("/scans", scanTaskHandler.Create)
	v1.POST("/scans/:id/pause", scanTaskHandler.Pause)
	v1.POST("/scans/:id/resume", scanTaskHandler.Resume)
	v1.POST("/scans/:id/cancel", scanTaskHandler.Cancel)
	v1.GET("/scans/:id", scanTaskHandler.Get)
	v1.GET("/scans/:id/logs", scanTaskHandler.Logs)
	v1.GET("/scans/:id/stream", scanTaskHandler.Stream)

	return router
}
