package middleware

import (
	"time"

	"github.com/OmniSurg/omnisurg-go-common/logger"
	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog"
)

// Logger middleware attaches a request scoped logger (with request_id) to the
// gin context and emits one structured access log line per request after the
// handler returns. The base logger comes from the service's boot path.
func Logger(base zerolog.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		reqID := c.GetString(RequestIDKey)
		scoped := logger.WithRequestID(base, reqID)
		ctx := logger.IntoContext(c.Request.Context(), scoped)
		c.Request = c.Request.WithContext(ctx)

		c.Next()

		status := c.Writer.Status()
		latency := time.Since(start)
		event := scoped.Info()
		if status >= 500 {
			event = scoped.Error()
		} else if status >= 400 {
			event = scoped.Warn()
		}
		event.
			Str("method", c.Request.Method).
			Str("path", c.Request.URL.Path).
			Int("status", status).
			Dur("latency", latency).
			Str("client_ip", c.ClientIP()).
			Msg("request")
	}
}
