// Package middleware exposes the OmniSurg Gin middleware chain.
package middleware

import (
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// RequestIDKey is the gin context key that carries the request id.
const RequestIDKey = "omnisurg.request_id"

// RequestIDHeader is the canonical header that carries the request id.
const RequestIDHeader = "X-Request-ID"

// RequestID middleware reads the incoming X-Request-ID header (or generates a
// fresh UUID if absent), stores it on the gin context, and stamps it on the
// response header so callers can correlate logs with their original request.
func RequestID() gin.HandlerFunc {
	return func(c *gin.Context) {
		id := c.GetHeader(RequestIDHeader)
		if id == "" {
			id = uuid.NewString()
		}
		c.Set(RequestIDKey, id)
		c.Header(RequestIDHeader, id)
		c.Next()
	}
}
