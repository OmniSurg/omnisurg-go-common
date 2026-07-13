package middleware

import (
	"net/http"

	"github.com/OmniSurg/omnisurg-go-common/logger"
	"github.com/gin-gonic/gin"
)

// Recovery converts panics into 500 INTERNAL_ERROR responses with the
// platform error envelope. It never lets a panic crash the worker.
// It logs the panic through the request scoped logger (if one is on the
// context) so the entry carries service, request_id, and tenant_id fields.
func Recovery() gin.HandlerFunc {
	return func(c *gin.Context) {
		defer func() {
			if r := recover(); r != nil {
				log := logger.FromContext(c.Request.Context())
				log.Error().
					Interface("panic", r).
					Str("path", c.Request.URL.Path).
					Str("method", c.Request.Method).
					Msg("panic recovered")
				c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
					"success": false,
					"error": gin.H{
						"code":    "INTERNAL_ERROR",
						"message": "An unexpected error occurred.",
					},
				})
			}
		}()
		c.Next()
	}
}
