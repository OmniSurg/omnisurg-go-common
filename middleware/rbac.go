package middleware

import (
	"net/http"

	"github.com/OmniSurg/omnisurg-go-common/tenant"
	"github.com/gin-gonic/gin"
)

// RequireRole aborts with 403 AUTH_FORBIDDEN unless the caller identity set by
// JWTAuth matches an allowed role on either its tenant role (id.Role) or its
// platform provider role (id.ProviderRole). JWTAuth must run earlier in the
// chain so the identity is present on the gin context. Pass at least one
// allowed role; an empty allow-list fails closed and rejects every caller.
func RequireRole(allowed ...string) gin.HandlerFunc {
	set := make(map[string]struct{}, len(allowed))
	for _, r := range allowed {
		set[r] = struct{}{}
	}
	return func(c *gin.Context) {
		id, ok := tenant.Get(c)
		if !ok {
			abortForbidden(c, "no identity on request")
			return
		}
		_, roleOK := set[id.Role]
		_, providerOK := set[id.ProviderRole]
		if !roleOK && !(id.ProviderRole != "" && providerOK) {
			abortForbidden(c, "role not permitted for this operation")
			return
		}
		c.Next()
	}
}

func abortForbidden(c *gin.Context, message string) {
	c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
		"success": false,
		"error": gin.H{
			"code":    "AUTH_FORBIDDEN",
			"message": message,
		},
	})
}
