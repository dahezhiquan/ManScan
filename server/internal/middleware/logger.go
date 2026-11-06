package middleware

import (
	"net/http"
	"time"

	"ManScan/server/internal/pkg/logx"

	"github.com/gin-gonic/gin"
)

func Logger(logger *logx.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		startedAt := time.Now()
		c.Next()
		latency := time.Since(startedAt)
		status := c.Writer.Status()
		route := c.FullPath()
		if !shouldLogHTTPRequest(c.Request.Method, route, status, latency) {
			return
		}
		if route == "" {
			route = "<unmatched>"
		}

		logger.Info(
			"http request",
			"method", c.Request.Method,
			"path", route,
			"status", status,
			"latency_ms", latency.Milliseconds(),
			"client_ip", c.ClientIP(),
		)
	}
}

func shouldLogHTTPRequest(method, route string, status int, latency time.Duration) bool {
	if method != http.MethodGet || status < http.StatusOK || status >= http.StatusMultipleChoices || latency >= time.Second {
		return true
	}
	switch route {
	case "/api/v1/scans", "/api/v1/scans/stats", "/api/v1/scans/:id":
		return false
	default:
		return true
	}
}
