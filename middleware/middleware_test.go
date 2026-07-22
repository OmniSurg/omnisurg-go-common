package middleware_test

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	ojwt "github.com/OmniSurg/omnisurg-go-common/jwt"
	"github.com/OmniSurg/omnisurg-go-common/logger"
	mw "github.com/OmniSurg/omnisurg-go-common/middleware"
	"github.com/OmniSurg/omnisurg-go-common/tenant"
	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testSecret = "test-secret"

func newRouter(t *testing.T, sink *bytes.Buffer) *gin.Engine {
	t.Helper()
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(mw.RequestID())
	// Logger middleware must run before Recovery so Recovery can read the
	// request scoped logger from the gin context when a panic occurs.
	r.Use(mw.Logger(logger.New(logger.Options{Service: "test", Level: zerolog.InfoLevel, Writer: sink, Production: true})))
	r.Use(mw.Recovery())
	return r
}

func TestRequestIDInjectsHeader(t *testing.T) {
	var sink bytes.Buffer
	r := newRouter(t, &sink)
	r.GET("/x", func(c *gin.Context) {
		c.String(200, c.GetString(mw.RequestIDKey))
	})
	req := httptest.NewRequest("GET", "/x", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.NotEmpty(t, w.Body.String())
	assert.Equal(t, w.Body.String(), w.Header().Get("X-Request-ID"))
}

func TestRequestIDPreservesIncomingHeader(t *testing.T) {
	var sink bytes.Buffer
	r := newRouter(t, &sink)
	r.GET("/x", func(c *gin.Context) {
		c.String(200, c.GetString(mw.RequestIDKey))
	})
	req := httptest.NewRequest("GET", "/x", nil)
	req.Header.Set("X-Request-ID", "supplied-123")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, "supplied-123", w.Body.String())
	assert.Equal(t, "supplied-123", w.Header().Get("X-Request-ID"))
}

func TestRecoveryReturns500(t *testing.T) {
	var sink bytes.Buffer
	r := newRouter(t, &sink)
	r.GET("/boom", func(c *gin.Context) {
		panic("oops")
	})
	req := httptest.NewRequest("GET", "/boom", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.Contains(t, w.Body.String(), "INTERNAL_ERROR")
}

func TestJWTAuthRejectsMissingHeader(t *testing.T) {
	var sink bytes.Buffer
	r := newRouter(t, &sink)
	r.GET("/p", mw.JWTAuth(testSecret), func(c *gin.Context) {
		c.String(200, "ok")
	})
	req := httptest.NewRequest("GET", "/p", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Contains(t, w.Body.String(), "AUTH_UNAUTHORIZED")
}

func TestJWTAuthRejectsBadToken(t *testing.T) {
	var sink bytes.Buffer
	r := newRouter(t, &sink)
	r.GET("/p", mw.JWTAuth(testSecret), func(c *gin.Context) {
		c.String(200, "ok")
	})
	req := httptest.NewRequest("GET", "/p", nil)
	req.Header.Set("Authorization", "Bearer garbage")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestJWTAuthPassesAndSetsIdentity(t *testing.T) {
	var sink bytes.Buffer
	r := newRouter(t, &sink)
	r.GET("/p", mw.JWTAuth(testSecret), func(c *gin.Context) {
		id, ok := tenant.Get(c)
		require.True(t, ok)
		assert.Equal(t, "tenant-a", id.TenantID)
		c.String(200, id.UserID)
	})

	tok, err := ojwt.Sign(ojwt.Claims{
		Subject:  "u-1",
		TenantID: "tenant-a",
		BranchID: "b-1",
		Role:     "reception",
	}, testSecret, time.Hour)
	require.NoError(t, err)

	req := httptest.NewRequest("GET", "/p", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "u-1", w.Body.String())
}

func TestJWTAuthStashesRawTokenOnRequestContext(t *testing.T) {
	var sink bytes.Buffer
	r := newRouter(t, &sink)
	var (
		gotToken string
		gotOK    bool
	)
	r.GET("/p", mw.JWTAuth(testSecret), func(c *gin.Context) {
		// Downstream code (for example a service-to-service gate) reads the raw
		// token from the request Go context, not from gin, so it can forward the
		// ORIGINAL signed JWT even when the call did not arrive over gRPC.
		gotToken, gotOK = mw.JWTFromContext(c.Request.Context())
		c.String(200, "ok")
	})

	tok, err := ojwt.Sign(ojwt.Claims{
		Subject:  "u-1",
		TenantID: "tenant-a",
		BranchID: "b-1",
		Role:     "reception",
	}, testSecret, time.Hour)
	require.NoError(t, err)

	req := httptest.NewRequest("GET", "/p", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.True(t, gotOK, "JWTAuth must stash the raw token on the request context")
	assert.Equal(t, tok, gotToken, "the stashed token must be the exact raw JWT")
}

func TestJWTFromContextAbsentWhenUnset(t *testing.T) {
	_, ok := mw.JWTFromContext(context.Background())
	assert.False(t, ok, "JWTFromContext returns false when no token was stashed")
}

func TestInternalAPIKeyRejectsMissing(t *testing.T) {
	var sink bytes.Buffer
	r := newRouter(t, &sink)
	r.GET("/i", mw.InternalAPIKey("secret-key"), func(c *gin.Context) {
		c.String(200, "ok")
	})
	req := httptest.NewRequest("GET", "/i", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestInternalAPIKeyAcceptsMatching(t *testing.T) {
	var sink bytes.Buffer
	r := newRouter(t, &sink)
	r.GET("/i", mw.InternalAPIKey("secret-key"), func(c *gin.Context) {
		c.String(200, "ok")
	})
	req := httptest.NewRequest("GET", "/i", nil)
	req.Header.Set("X-Internal-Key", "secret-key")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "ok", w.Body.String())
}
