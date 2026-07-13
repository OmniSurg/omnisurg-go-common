package middleware_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	mw "github.com/OmniSurg/omnisurg-go-common/middleware"
	"github.com/OmniSurg/omnisurg-go-common/tenant"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

func rbacRouter(role string, allowed ...string) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	// Simulate JWTAuth having set the identity.
	r.Use(func(c *gin.Context) {
		if role != "" {
			tenant.Set(c, tenant.Identity{UserID: "u-1", TenantID: "t-1", Role: role})
		}
		c.Next()
	})
	r.GET("/x", mw.RequireRole(allowed...), func(c *gin.Context) { c.String(200, "ok") })
	return r
}

func TestRequireRoleAllowsListedRole(t *testing.T) {
	w := httptest.NewRecorder()
	rbacRouter("practice_admin", "practice_admin", "reception").ServeHTTP(
		w, httptest.NewRequest("GET", "/x", nil))
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "ok", w.Body.String())
}

func TestRequireRoleRejectsUnlistedRole(t *testing.T) {
	w := httptest.NewRecorder()
	rbacRouter("clinician_ophthalmologist", "practice_admin").ServeHTTP(
		w, httptest.NewRequest("GET", "/x", nil))
	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.Contains(t, w.Body.String(), "AUTH_FORBIDDEN")
}

func TestRequireRoleRejectsMissingIdentity(t *testing.T) {
	w := httptest.NewRecorder()
	rbacRouter("", "practice_admin").ServeHTTP(
		w, httptest.NewRequest("GET", "/x", nil))
	assert.Equal(t, http.StatusForbidden, w.Code)
}

func TestRequireRoleAllowsProviderRole(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(func(c *gin.Context) {
		tenant.Set(c, tenant.Identity{UserID: "p-1", TenantID: "t-1", ProviderRole: "provider_super_admin"})
		c.Next()
	})
	r.GET("/x", mw.RequireRole("provider_super_admin"), func(c *gin.Context) { c.String(200, "ok") })
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/x", nil))
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "ok", w.Body.String())
}

func TestRequireRoleRejectsUnlistedProviderRole(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(func(c *gin.Context) {
		tenant.Set(c, tenant.Identity{UserID: "p-1", TenantID: "t-1", ProviderRole: "provider_billing"})
		c.Next()
	})
	r.GET("/x", mw.RequireRole("provider_super_admin"), func(c *gin.Context) { c.String(200, "ok") })
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/x", nil))
	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.Contains(t, w.Body.String(), "AUTH_FORBIDDEN")
}
