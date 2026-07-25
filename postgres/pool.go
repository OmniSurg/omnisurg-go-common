// Package postgres provides the OmniSurg pgxpool factory. The factory wires
// PrepareConn and AfterRelease hooks that reset the app.tenant_id GUC on
// every connection checkout and release, which keeps RLS isolation watertight
// across pooled connections. Services compose their repositories on top of
// the pool plus WithTenant which sets the GUC for the duration of a scoped
// callback.
package postgres

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Options drive pool construction.
type Options struct {
	// DSN is the connection string (postgres://user:pass@host:port/db?sslmode=...).
	DSN string
	// MinConns is the pool's idle floor. Defaults to 2 when zero.
	MinConns int32
	// MaxConns is the pool's ceiling. Defaults to 20 when zero.
	MaxConns int32
	// MaxConnLifetime caps the age of a connection. Defaults to 30 minutes.
	MaxConnLifetime time.Duration
	// ConnectTimeout caps the initial connect plus ping. Defaults to 10 seconds.
	ConnectTimeout time.Duration
}

// OpenPool parses the DSN, applies defaults, and connects with the lifecycle
// hooks that enforce the OmniSurg tenant isolation contract.
func OpenPool(ctx context.Context, opts Options) (*pgxpool.Pool, error) {
	if opts.DSN == "" {
		return nil, fmt.Errorf("postgres.OpenPool: DSN is required")
	}
	cfg, err := pgxpool.ParseConfig(opts.DSN)
	if err != nil {
		return nil, fmt.Errorf("postgres.OpenPool: parse config: %w", err)
	}
	if opts.MinConns == 0 {
		opts.MinConns = 2
	}
	if opts.MaxConns == 0 {
		opts.MaxConns = 20
	}
	if opts.MaxConnLifetime == 0 {
		opts.MaxConnLifetime = 30 * time.Minute
	}
	if opts.ConnectTimeout == 0 {
		opts.ConnectTimeout = 10 * time.Second
	}
	cfg.MinConns = opts.MinConns
	cfg.MaxConns = opts.MaxConns
	cfg.MaxConnLifetime = opts.MaxConnLifetime

	// PrepareConn runs before every checkout and resets the app.tenant_id GUC
	// so a pooled connection never carries a prior request's tenant scope. A
	// failed reset returns false with a nil error, which destroys the tainted
	// connection and retries the acquisition on a fresh one, so a connection
	// that cannot be scrubbed is never handed to a caller. This is the exact
	// behaviour pgx runs for the now deprecated BeforeAcquire hook, which it
	// internally adapts to a PrepareConn returning (result, nil); using
	// PrepareConn directly keeps the RLS reset on the non deprecated hook.
	cfg.PrepareConn = func(c context.Context, conn *pgx.Conn) (bool, error) {
		ctxR, cancel := context.WithTimeout(c, 2*time.Second)
		defer cancel()
		_, err := conn.Exec(ctxR, "RESET app.tenant_id")
		return err == nil, nil
	}
	cfg.AfterRelease = func(conn *pgx.Conn) bool {
		ctxR, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_, err := conn.Exec(ctxR, "RESET app.tenant_id")
		return err == nil
	}

	connCtx, cancel := context.WithTimeout(ctx, opts.ConnectTimeout)
	defer cancel()

	pool, err := pgxpool.NewWithConfig(connCtx, cfg)
	if err != nil {
		return nil, fmt.Errorf("postgres.OpenPool: new pool: %w", err)
	}
	if err := pool.Ping(connCtx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("postgres.OpenPool: ping: %w", err)
	}
	return pool, nil
}
