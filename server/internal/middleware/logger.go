package middleware

import (
	"time"

	"ManScan/server/internal/pkg/logx"

	"github.com/gin-gonic/gin"
)

func Logger(logger *logx.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		startedAt := time.Now()
		c.Next()

		logger.Info(
			"http request",
			"method", c.Request.Method,
			"path", c.Request.URL.Path,
			"status", c.Writer.Status(),
			"latency_ms", time.Since(startedAt).Milliseconds(),
			"client_ip", c.ClientIP(),
		)
	}
}
