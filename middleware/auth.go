package middleware

import (
	"net/http"
	"strings"

	ojwt "github.com/OmniSurg/omnisurg-go-common/jwt"
	"github.com/OmniSurg/omnisurg-go-common/tenant"
	"github.com/gin-gonic/gin"
)

// JWTAuth verifies the Bearer token on the Authorization header. On success
// it stores the caller identity on the gin context via the tenant package and
// proceeds. On any failure it aborts with 401 AUTH_UNAUTHORIZED.
func JWTAuth(secret string) gin.HandlerFunc {
	return func(c *gin.Context) {
		header := c.GetHeader("Authorization")
		if header == "" {
			abortUnauthorised(c, "missing authorization header")
			return
		}
		parts := strings.SplitN(header, " ", 2)
		if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
			abortUnauthorised(c, "invalid authorization format")
			return
		}
		claims, err := ojwt.Verify(parts[1], secret)
		if err != nil {
			abortUnauthorised(c, "invalid or expired token")
			return
		}
		tenant.Set(c, tenant.Identity{
			TenantID:     claims.TenantID,
			BranchID:     claims.BranchID,
			UserID:       claims.Subject,
			Role:         claims.Role,
			ProviderRole: claims.ProviderRole,
			MFAVerified:  claims.MFAVerified,
		})
		// Also stash the raw verified token on the request Go context so any
		// downstream code reading c.Request.Context() (for example a
		// service-to-service gate) can forward the ORIGINAL signed JWT. This is
		// additive: the identity above stays the authoritative source for RBAC.
		c.Request = c.Request.WithContext(WithJWT(c.Request.Context(), parts[1]))
		c.Next()
	}
}

func abortUnauthorised(c *gin.Context, message string) {
	c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
		"success": false,
		"error": gin.H{
			"code":    "AUTH_UNAUTHORIZED",
			"message": message,
		},
	})
}
