// Package tenant carries the authenticated caller's identity on the gin
// context. Middleware sets the Identity once after JWT verification; handlers
// and downstream code read it via Get or the typed shortcuts.
package tenant

import "github.com/gin-gonic/gin"

const ctxKey = "omnisurg.identity"

// Identity is the OmniSurg caller summary derived from the JWT.
type Identity struct {
	TenantID     string
	BranchID     string
	UserID       string
	Role         string
	ProviderRole string
	MFAVerified  bool
}

// Set stores the identity on the gin context.
func Set(c *gin.Context, id Identity) {
	c.Set(ctxKey, id)
}

// Get returns the identity stored on the gin context, and whether one was set.
func Get(c *gin.Context) (Identity, bool) {
	v, exists := c.Get(ctxKey)
	if !exists {
		return Identity{}, false
	}
	id, ok := v.(Identity)
	return id, ok
}

// TenantIDOr returns the stored tenant id, or fallback if no identity is set.
func TenantIDOr(c *gin.Context, fallback string) string {
	id, ok := Get(c)
	if !ok {
		return fallback
	}
	return id.TenantID
}
