package middleware

import (
	"crypto/subtle"

	"github.com/gin-gonic/gin"
)

// InternalAPIKey middleware guards service to service routes. It checks the
// X-Internal-Key header against the configured value using a constant time
// comparison. Mismatch returns 401 AUTH_UNAUTHORIZED.
func InternalAPIKey(expected string) gin.HandlerFunc {
	return func(c *gin.Context) {
		got := c.GetHeader("X-Internal-Key")
		if got == "" {
			abortUnauthorised(c, "missing internal key")
			return
		}
		if subtle.ConstantTimeCompare([]byte(got), []byte(expected)) != 1 {
			abortUnauthorised(c, "invalid internal key")
			return
		}
		c.Next()
	}
}
