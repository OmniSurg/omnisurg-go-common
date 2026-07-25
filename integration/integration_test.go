package integration_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	ojwt "github.com/OmniSurg/omnisurg-go-common/jwt"
	"github.com/OmniSurg/omnisurg-go-common/logger"
	mw "github.com/OmniSurg/omnisurg-go-common/middleware"
	pg "github.com/OmniSurg/omnisurg-go-common/postgres"
	"github.com/OmniSurg/omnisurg-go-common/tenant"
	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	tcpg "github.com/testcontainers/testcontainers-go/modules/postgres"
)

const secret = "integration-secret"

func TestEndToEndChain(t *testing.T) {
	ctx := context.Background()
	container, err := tcpg.Run(ctx,
		"postgres:16-alpine",
		tcpg.WithDatabase("omnisurg_int"),
		tcpg.WithUsername("test"),
		tcpg.WithPassword("test"),
		tcpg.BasicWaitStrategies(),
	)
	require.NoError(t, err)
	defer func() { _ = container.Terminate(ctx) }()

	dsn, err := container.ConnectionString(ctx, "sslmode=disable")
	require.NoError(t, err)

	// Open a superuser pool to set up schema and roles.
	// Superusers bypass RLS even with FORCE ROW LEVEL SECURITY, so all RLS
	// queries must run as a non-superuser app_user role.
	superPool, err := pg.OpenPool(ctx, pg.Options{DSN: dsn})
	require.NoError(t, err)
	defer superPool.Close()

	// Create a non-superuser role for the application pool.
	_, err = superPool.Exec(ctx, `
		CREATE ROLE app_user LOGIN PASSWORD 'app_pass';
		GRANT CONNECT ON DATABASE omnisurg_int TO app_user;
	`)
	require.NoError(t, err)

	// Schema with RLS.
	_, err = superPool.Exec(ctx, `
		CREATE TABLE patients (id text PRIMARY KEY, tenant_id uuid NOT NULL);
		ALTER TABLE patients ENABLE ROW LEVEL SECURITY;
		CREATE POLICY p ON patients USING (tenant_id::text = current_setting('app.tenant_id', true));
		ALTER TABLE patients FORCE ROW LEVEL SECURITY;
		GRANT SELECT, INSERT ON patients TO app_user;
		INSERT INTO patients VALUES
		  ('a', '11111111-1111-1111-1111-111111111111'),
		  ('b', '22222222-2222-2222-2222-222222222222');
	`)
	require.NoError(t, err)

	// Build DSN for the non-superuser app role.
	appDSN := strings.Replace(dsn, "test:test@", "app_user:app_pass@", 1)
	pool, err := pg.OpenPool(ctx, pg.Options{DSN: appDSN})
	require.NoError(t, err)
	defer pool.Close()

	gin.SetMode(gin.TestMode)
	base := logger.New(logger.Options{Service: "int", Level: zerolog.InfoLevel, Production: true})
	r := gin.New()
	r.Use(mw.RequestID(), mw.Logger(base), mw.Recovery())

	// Protected route that counts patients for the caller's tenant.
	r.GET("/patients/count", mw.JWTAuth(secret), func(c *gin.Context) {
		id, ok := tenant.Get(c)
		if !ok {
			c.JSON(500, gin.H{"error": "no identity"})
			return
		}
		var count int
		err := pg.WithTenant(c.Request.Context(), pool, id.TenantID, func(ctx context.Context, conn pg.Conn) error {
			return conn.QueryRow(ctx, "SELECT COUNT(*) FROM patients").Scan(&count)
		})
		if err != nil {
			c.JSON(500, gin.H{"error": err.Error()})
			return
		}
		c.JSON(200, gin.H{"count": count})
	})

	tenantAToken, err := ojwt.Sign(ojwt.Claims{
		Subject: "u-1", TenantID: "11111111-1111-1111-1111-111111111111",
		BranchID: "b-1", Role: "reception",
	}, secret, time.Hour)
	require.NoError(t, err)
	tenantBToken, err := ojwt.Sign(ojwt.Claims{
		Subject: "u-2", TenantID: "22222222-2222-2222-2222-222222222222",
		BranchID: "b-2", Role: "reception",
	}, secret, time.Hour)
	require.NoError(t, err)

	doCount := func(token string) (int, int) {
		req := httptest.NewRequest("GET", "/patients/count", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		return w.Code, parseCount(t, w.Body.Bytes())
	}

	statusA, countA := doCount(tenantAToken)
	statusB, countB := doCount(tenantBToken)

	assert.Equal(t, http.StatusOK, statusA)
	assert.Equal(t, 1, countA, "tenant A must see exactly its own row")
	assert.Equal(t, http.StatusOK, statusB)
	assert.Equal(t, 1, countB, "tenant B must see exactly its own row")
}

func parseCount(t *testing.T, body []byte) int {
	t.Helper()
	// Minimal parse to avoid pulling in encoding/json with sprintf trickery.
	// Body is {"count":N}; locate the colon plus digits.
	for i := 0; i < len(body)-1; i++ {
		if body[i] == ':' {
			// scan digits
			n := 0
			for j := i + 1; j < len(body) && body[j] >= '0' && body[j] <= '9'; j++ {
				n = n*10 + int(body[j]-'0')
			}
			return n
		}
	}
	t.Fatalf("could not parse count from %s", string(body))
	return -1
}
