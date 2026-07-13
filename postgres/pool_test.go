package postgres_test

import (
	"context"
	"testing"
	"time"

	pg "github.com/OmniSurg/omnisurg-go-common/postgres"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	tcpg "github.com/testcontainers/testcontainers-go/modules/postgres"
)

func startPG(t *testing.T) (string, func()) {
	t.Helper()
	ctx := context.Background()
	container, err := tcpg.Run(ctx,
		"postgres:16-alpine",
		tcpg.WithDatabase("omnisurg_test"),
		tcpg.WithUsername("test"),
		tcpg.WithPassword("test"),
		tcpg.BasicWaitStrategies(),
	)
	require.NoError(t, err)
	dsn, err := container.ConnectionString(ctx, "sslmode=disable")
	require.NoError(t, err)
	return dsn, func() { _ = container.Terminate(ctx) }
}

func TestOpenPoolReturnsHealthy(t *testing.T) {
	dsn, stop := startPG(t)
	defer stop()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	pool, err := pg.OpenPool(ctx, pg.Options{DSN: dsn})
	require.NoError(t, err)
	defer pool.Close()

	var got int
	require.NoError(t, pool.QueryRow(ctx, "SELECT 1").Scan(&got))
	assert.Equal(t, 1, got)
}

func TestBeforeAcquireResetsGUC(t *testing.T) {
	dsn, stop := startPG(t)
	defer stop()
	ctx := context.Background()

	pool, err := pg.OpenPool(ctx, pg.Options{DSN: dsn})
	require.NoError(t, err)
	defer pool.Close()

	// Acquire a connection, set the GUC, release.
	conn, err := pool.Acquire(ctx)
	require.NoError(t, err)
	_, err = conn.Exec(ctx, "SET app.tenant_id = 'tenant-leak-test'")
	require.NoError(t, err)
	conn.Release()

	// Next acquire must see an empty GUC because BeforeAcquire resets.
	conn2, err := pool.Acquire(ctx)
	require.NoError(t, err)
	defer conn2.Release()
	var current string
	require.NoError(t, conn2.QueryRow(ctx,
		"SELECT current_setting('app.tenant_id', true)",
	).Scan(&current))
	assert.Equal(t, "", current, "tenant_id GUC must reset between checkouts")
}
