package postgres_test

import (
	"context"
	"strings"
	"testing"
	"time"

	pg "github.com/OmniSurg/omnisurg-go-common/postgres"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWithTenantSetsGUCForConnLifetime(t *testing.T) {
	dsn, stop := startPG(t)
	defer stop()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Open a superuser pool to set up the schema and roles.
	superPool, err := pg.OpenPool(ctx, pg.Options{DSN: dsn})
	require.NoError(t, err)
	defer superPool.Close()

	const tenantA = "11111111-1111-1111-1111-111111111111"
	const tenantB = "22222222-2222-2222-2222-222222222222"

	// Create a non-superuser app role for RLS-enforced queries.
	// RLS bypasses superusers even with FORCE ROW LEVEL SECURITY.
	_, err = superPool.Exec(ctx, `
		CREATE ROLE app_user LOGIN PASSWORD 'app_pass';
		GRANT CONNECT ON DATABASE omnisurg_test TO app_user;
	`)
	require.NoError(t, err)

	// Create the RLS-enabled table as superuser then grant access to app_user.
	_, err = superPool.Exec(ctx, `
		CREATE TABLE patients (id text PRIMARY KEY, tenant_id uuid NOT NULL);
		ALTER TABLE patients ENABLE ROW LEVEL SECURITY;
		CREATE POLICY patients_tenant_scope ON patients
		  USING (tenant_id::text = current_setting('app.tenant_id', true));
		ALTER TABLE patients FORCE ROW LEVEL SECURITY;
		GRANT SELECT, INSERT ON patients TO app_user;
		INSERT INTO patients(id, tenant_id) VALUES ('a', '`+tenantA+`'), ('b', '`+tenantB+`');
	`)
	require.NoError(t, err)

	// Build a DSN for the non-superuser app role.
	appDSN := strings.Replace(dsn, "test:test@", "app_user:app_pass@", 1)
	appPool, err := pg.OpenPool(ctx, pg.Options{DSN: appDSN})
	require.NoError(t, err)
	defer appPool.Close()

	// As tenant A: must see exactly one row, id 'a'.
	var count int
	require.NoError(t, pg.WithTenant(ctx, appPool, tenantA, func(ctx context.Context, conn pg.Conn) error {
		return conn.QueryRow(ctx, "SELECT COUNT(*) FROM patients").Scan(&count)
	}))
	assert.Equal(t, 1, count, "tenant A must see exactly one row")

	// As tenant B: must see exactly one row, id 'b'.
	require.NoError(t, pg.WithTenant(ctx, appPool, tenantB, func(ctx context.Context, conn pg.Conn) error {
		return conn.QueryRow(ctx, "SELECT COUNT(*) FROM patients WHERE id = 'b'").Scan(&count)
	}))
	assert.Equal(t, 1, count, "tenant B must see exactly one row")

	// Without WithTenant: GUC is empty, RLS yields zero rows.
	require.NoError(t, appPool.QueryRow(ctx, "SELECT COUNT(*) FROM patients").Scan(&count))
	assert.Equal(t, 0, count, "no tenant: RLS hides every row")
}
