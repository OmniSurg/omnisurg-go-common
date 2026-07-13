package postgres

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Conn is the subset of pgxpool.Conn that callers of WithTenant need.
type Conn interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
	Begin(ctx context.Context) (pgx.Tx, error)
}

// WithTenant acquires a connection, sets the app.tenant_id GUC for its
// lifetime, runs fn, and releases. RLS policies referencing
// current_setting('app.tenant_id') will see the supplied tenantID.
// After release, BeforeAcquire and AfterRelease both reset the GUC so the
// next checkout starts clean.
//
// tenantID is set via set_config(name, value, false) which is session level
// (not SET LOCAL, which would require a transaction). The connection's
// lifetime is bounded by this function and the pool hooks RESET on every
// release plus checkout, so the GUC cannot leak.
func WithTenant(ctx context.Context, pool *pgxpool.Pool, tenantID string, fn func(ctx context.Context, conn Conn) error) error {
	if pool == nil {
		return fmt.Errorf("postgres.WithTenant: pool is nil")
	}
	if tenantID == "" {
		return fmt.Errorf("postgres.WithTenant: tenantID is empty")
	}
	if fn == nil {
		return fmt.Errorf("postgres.WithTenant: fn is nil")
	}
	conn, err := pool.Acquire(ctx)
	if err != nil {
		return fmt.Errorf("postgres.WithTenant: acquire: %w", err)
	}
	defer conn.Release()

	if _, err := conn.Exec(ctx, "SELECT set_config('app.tenant_id', $1, false)", tenantID); err != nil {
		return fmt.Errorf("postgres.WithTenant: set GUC: %w", err)
	}
	return fn(ctx, conn.Conn())
}
