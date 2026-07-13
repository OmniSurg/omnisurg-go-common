// Package logger wraps zerolog with OmniSurg conventions: JSON in production,
// console in dev, and request scoped fields (request_id, tenant_id, user_id,
// service). Every service constructs one base logger at boot and derives
// per request loggers via WithRequestID / WithTenantID / WithUserID.
package logger

import (
	"context"
	"io"
	"os"
	"time"

	"github.com/rs/zerolog"
)

// Options drive the base logger construction.
type Options struct {
	// Service is the name field stamped on every log line.
	Service string
	// Level filters which events are emitted (Info in prod, Debug in dev).
	Level zerolog.Level
	// Writer is the sink. Defaults to os.Stderr when nil.
	Writer io.Writer
	// Production: when true, emit JSON only. When false, also pipe through the
	// ConsoleWriter for human readable output. Tests typically set this true.
	Production bool
}

// New builds the base logger.
func New(opts Options) zerolog.Logger {
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnixMs
	w := opts.Writer
	if w == nil {
		w = os.Stderr
	}
	if !opts.Production {
		w = zerolog.ConsoleWriter{Out: w, TimeFormat: time.RFC3339}
	}
	log := zerolog.New(w).Level(opts.Level).With().
		Timestamp().
		Str("service", opts.Service).
		Logger()
	return log
}

// WithRequestID returns a child logger with the request_id field bound.
func WithRequestID(l zerolog.Logger, id string) zerolog.Logger {
	return l.With().Str("request_id", id).Logger()
}

// WithTenantID returns a child logger with the tenant_id field bound.
func WithTenantID(l zerolog.Logger, id string) zerolog.Logger {
	return l.With().Str("tenant_id", id).Logger()
}

// WithUserID returns a child logger with the user_id field bound.
func WithUserID(l zerolog.Logger, id string) zerolog.Logger {
	return l.With().Str("user_id", id).Logger()
}

type ctxKey struct{}

// IntoContext stores a logger in the context for downstream handlers.
func IntoContext(ctx context.Context, l zerolog.Logger) context.Context {
	return context.WithValue(ctx, ctxKey{}, l)
}

// FromContext returns the logger stored in the context, or a no-op logger
// (discarder) if none is present. Never returns nil.
func FromContext(ctx context.Context) zerolog.Logger {
	if l, ok := ctx.Value(ctxKey{}).(zerolog.Logger); ok {
		return l
	}
	return zerolog.New(io.Discard)
}
