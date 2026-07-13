package logger_test

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/OmniSurg/omnisurg-go-common/logger"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewEmitsJSON(t *testing.T) {
	var buf bytes.Buffer
	log := logger.New(logger.Options{
		Service:    "patient-service",
		Level:      zerolog.InfoLevel,
		Writer:     &buf,
		Production: true,
	})
	log.Info().Msg("hello")

	var payload map[string]any
	require.NoError(t, json.Unmarshal(buf.Bytes(), &payload))
	assert.Equal(t, "patient-service", payload["service"])
	assert.Equal(t, "info", payload["level"])
	assert.Equal(t, "hello", payload["message"])
}

func TestFromContextReturnsAttached(t *testing.T) {
	var buf bytes.Buffer
	base := logger.New(logger.Options{Service: "svc", Level: zerolog.InfoLevel, Writer: &buf, Production: true})
	ctx := logger.IntoContext(context.Background(), base)

	got := logger.FromContext(ctx)
	require.NotNil(t, got)
	got.Info().Msg("retrieved")

	assert.Contains(t, buf.String(), "retrieved")
}

func TestFromContextFallbackIsNoop(t *testing.T) {
	got := logger.FromContext(context.Background())
	require.NotNil(t, got)
	// Should not panic and should write to a discarder.
	got.Info().Msg("dropped")
}

func TestWithRequestIDAddsField(t *testing.T) {
	var buf bytes.Buffer
	base := logger.New(logger.Options{Service: "svc", Level: zerolog.InfoLevel, Writer: &buf, Production: true})
	scoped := logger.WithRequestID(base, "req-123")
	scoped.Info().Msg("inside")

	var payload map[string]any
	require.NoError(t, json.Unmarshal(buf.Bytes(), &payload))
	assert.Equal(t, "req-123", payload["request_id"])
}

func TestWithTenantIDAddsField(t *testing.T) {
	var buf bytes.Buffer
	base := logger.New(logger.Options{Service: "svc", Level: zerolog.InfoLevel, Writer: &buf, Production: true})
	scoped := logger.WithTenantID(base, "tenant-abc")
	scoped.Info().Msg("inside")

	var payload map[string]any
	require.NoError(t, json.Unmarshal(buf.Bytes(), &payload))
	assert.Equal(t, "tenant-abc", payload["tenant_id"])
}

func TestProductionOptionsDisablesConsole(t *testing.T) {
	var buf bytes.Buffer
	log := logger.New(logger.Options{
		Service:    "svc",
		Level:      zerolog.InfoLevel,
		Writer:     &buf,
		Production: true,
	})
	log.Info().Msg("hello")
	// JSON only, never the ConsoleWriter pipe characters.
	assert.False(t, strings.Contains(buf.String(), "|"))
}
