package tenant_test

import (
	"net/http/httptest"
	"testing"

	"github.com/OmniSurg/omnisurg-go-common/tenant"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newContext() *gin.Context {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	return c
}

func TestSetGet(t *testing.T) {
	c := newContext()
	tenant.Set(c, tenant.Identity{
		TenantID:     "tenant-a",
		BranchID:     "branch-1",
		UserID:       "user-x",
		Role:         "reception",
		ProviderRole: "",
		MFAVerified:  true,
	})

	got, ok := tenant.Get(c)
	require.True(t, ok)
	assert.Equal(t, "tenant-a", got.TenantID)
	assert.Equal(t, "branch-1", got.BranchID)
	assert.Equal(t, "user-x", got.UserID)
	assert.Equal(t, "reception", got.Role)
	assert.True(t, got.MFAVerified)
}

func TestGetWhenAbsent(t *testing.T) {
	c := newContext()
	_, ok := tenant.Get(c)
	assert.False(t, ok)
}

func TestTenantIDShortcut(t *testing.T) {
	c := newContext()
	tenant.Set(c, tenant.Identity{TenantID: "tenant-a"})
	assert.Equal(t, "tenant-a", tenant.TenantIDOr(c, ""))
}

func TestTenantIDDefaultWhenAbsent(t *testing.T) {
	c := newContext()
	assert.Equal(t, "fallback", tenant.TenantIDOr(c, "fallback"))
}
