package config_test

import (
	"os"
	"testing"

	"github.com/OmniSurg/omnisurg-go-common/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fixture struct {
	Port int    `envconfig:"FIX_PORT" default:"8080"`
	Name string `envconfig:"FIX_NAME" required:"true"`
}

func TestLoadFromEnv(t *testing.T) {
	t.Setenv("FIX_NAME", "patient-service")
	t.Setenv("FIX_PORT", "9090")

	var cfg fixture
	require.NoError(t, config.Load(&cfg, ""))
	assert.Equal(t, 9090, cfg.Port)
	assert.Equal(t, "patient-service", cfg.Name)
}

func TestLoadAppliesDefaults(t *testing.T) {
	t.Setenv("FIX_NAME", "x")

	var cfg fixture
	require.NoError(t, config.Load(&cfg, ""))
	assert.Equal(t, 8080, cfg.Port)
}

func TestLoadFailsOnMissingRequired(t *testing.T) {
	os.Unsetenv("FIX_NAME")
	var cfg fixture
	err := config.Load(&cfg, "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "FIX_NAME")
}

func TestLoadReadsDotEnvIfPresent(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/.env"
	require.NoError(t, os.WriteFile(path, []byte("FIX_NAME=from-dotenv\nFIX_PORT=7070\n"), 0o600))

	os.Unsetenv("FIX_NAME")
	os.Unsetenv("FIX_PORT")
	var cfg fixture
	require.NoError(t, config.Load(&cfg, path))
	assert.Equal(t, "from-dotenv", cfg.Name)
	assert.Equal(t, 7070, cfg.Port)
}

// secretsFixture models a real service config: a JWT secret, a KEK, plus the
// environment field the boot-time secret-divergence assertion gates on.
type secretsFixture struct {
	JWTSecret string `envconfig:"OMNISURG_JWT_SECRET" required:"true"`
	KEKBase64 string `envconfig:"OMNISURG_KEK_BASE64" required:"true"`
	Env       string `envconfig:"OMNISURG_ENV" default:"local"`
}

// kekLessFixture models a service that does not encrypt PII: it has a JWT
// secret and an environment field but no KEK. The assertion must not
// false-positive on the absent KEK field.
type kekLessFixture struct {
	JWTSecret string `envconfig:"OMNISURG_JWT_SECRET" required:"true"`
	Env       string `envconfig:"OMNISURG_ENV" default:"local"`
}

// The committed local-dev values (see omnisurg-infrastructure compose defaults).
const (
	localDevJWT = "local-dev-secret-change-me"
	localDevKEK = "bG9jYWwtZGV2LWtlay0wMDAwMDAwMDAwMDAwMDAwMDA="
	strongJWT   = "9f3c1a7e2b8d4f60a1c5e93726d048bb51fa2c9e7d6034185a2f7b0c9e1d4a68"
	strongKEK   = "c3Ryb25nLXByb2Qta2VrLXZhbHVlLW5vdC1sb2NhbC0wMDAwMDA="
)

func TestConfigRejectsPlaceholderOrLocalSecretsInProduction(t *testing.T) {
	cases := []struct {
		name       string
		jwt        string
		kek        string
		wantErrVar string
	}{
		{"local-dev jwt rejected", localDevJWT, strongKEK, "OMNISURG_JWT_SECRET"},
		{"local-dev kek rejected", strongJWT, localDevKEK, "OMNISURG_KEK_BASE64"},
		{"local-dev jwt padded rejected", "  " + localDevJWT + "  ", strongKEK, "OMNISURG_JWT_SECRET"},
		{"local-dev kek padded rejected", strongJWT, "\t" + localDevKEK + "\n", "OMNISURG_KEK_BASE64"},
		{"placeholder changeme jwt rejected", "changeme", strongKEK, "OMNISURG_JWT_SECRET"},
		{"placeholder change-me kek rejected", strongJWT, "change-me", "OMNISURG_KEK_BASE64"},
		{"placeholder your-secret-here jwt rejected", "your-secret-here", strongKEK, "OMNISURG_JWT_SECRET"},
		{"mixed-case placeholder CHANGEME jwt rejected", "CHANGEME", strongKEK, "OMNISURG_JWT_SECRET"},
		{"mixed-case placeholder Change-Me kek rejected", strongJWT, "Change-Me", "OMNISURG_KEK_BASE64"},
		{"whitespace-only jwt rejected", "   ", strongKEK, "OMNISURG_JWT_SECRET"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("OMNISURG_ENV", "production")
			t.Setenv("OMNISURG_JWT_SECRET", tc.jwt)
			t.Setenv("OMNISURG_KEK_BASE64", tc.kek)

			var cfg secretsFixture
			err := config.Load(&cfg, "")
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.wantErrVar)
			// The error must never leak the secret value itself.
			assert.NotContains(t, err.Error(), tc.jwt)
			assert.NotContains(t, err.Error(), tc.kek)
		})
	}
}

func TestConfigRejectsEmptyGuardedSecretIsCaughtByRequired(t *testing.T) {
	// An empty required secret is rejected by envconfig before the assertion
	// even runs, so Load must still error and name the var. This proves the
	// empty case fails closed in a non-local env.
	t.Setenv("OMNISURG_ENV", "production")
	t.Setenv("OMNISURG_JWT_SECRET", "")
	t.Setenv("OMNISURG_KEK_BASE64", strongKEK)

	var cfg secretsFixture
	err := config.Load(&cfg, "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "OMNISURG_JWT_SECRET")
}

func TestConfigAcceptsStrongSecretsInProduction(t *testing.T) {
	t.Setenv("OMNISURG_ENV", "production")
	t.Setenv("OMNISURG_JWT_SECRET", strongJWT)
	t.Setenv("OMNISURG_KEK_BASE64", strongKEK)

	var cfg secretsFixture
	require.NoError(t, config.Load(&cfg, ""))
	assert.Equal(t, strongJWT, cfg.JWTSecret)
	assert.Equal(t, strongKEK, cfg.KEKBase64)
}

func TestConfigAllowsLocalDevSecretsInLocalEnv(t *testing.T) {
	t.Setenv("OMNISURG_ENV", "local")
	t.Setenv("OMNISURG_JWT_SECRET", localDevJWT)
	t.Setenv("OMNISURG_KEK_BASE64", localDevKEK)

	var cfg secretsFixture
	require.NoError(t, config.Load(&cfg, ""))
	assert.Equal(t, localDevJWT, cfg.JWTSecret)
	assert.Equal(t, localDevKEK, cfg.KEKBase64)
}

func TestConfigAllowsLocalDevSecretsWhenEnvUnset(t *testing.T) {
	// Unset OMNISURG_ENV means local (the default), so the check is a no-op.
	os.Unsetenv("OMNISURG_ENV")
	t.Setenv("OMNISURG_JWT_SECRET", localDevJWT)
	t.Setenv("OMNISURG_KEK_BASE64", localDevKEK)

	var cfg secretsFixture
	require.NoError(t, config.Load(&cfg, ""))
	assert.Equal(t, localDevJWT, cfg.JWTSecret)
}

func TestConfigDoesNotFalsePositiveOnKekLessServiceInProduction(t *testing.T) {
	// A service with no KEK field and a strong JWT secret loads cleanly in
	// production; the absent KEK is simply not checked.
	t.Setenv("OMNISURG_ENV", "production")
	t.Setenv("OMNISURG_JWT_SECRET", strongJWT)

	var cfg kekLessFixture
	require.NoError(t, config.Load(&cfg, ""))
	assert.Equal(t, strongJWT, cfg.JWTSecret)
}

func TestConfigRejectsLocalDevJWTForKekLessServiceInProduction(t *testing.T) {
	t.Setenv("OMNISURG_ENV", "production")
	t.Setenv("OMNISURG_JWT_SECRET", localDevJWT)

	var cfg kekLessFixture
	err := config.Load(&cfg, "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "OMNISURG_JWT_SECRET")
	assert.NotContains(t, err.Error(), localDevJWT)
}

func TestConfigEnforcesInMixedCaseEnv(t *testing.T) {
	// A non-local env is matched case insensitively, so "Production" still
	// enforces the assertion.
	t.Setenv("OMNISURG_ENV", "Production")
	t.Setenv("OMNISURG_JWT_SECRET", localDevJWT)
	t.Setenv("OMNISURG_KEK_BASE64", strongKEK)

	var cfg secretsFixture
	err := config.Load(&cfg, "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "OMNISURG_JWT_SECRET")
}

// baseConfig is meant to be EMBEDDED (anonymous) in a service config. envconfig
// recurses into it, so the guard must too.
type baseConfig struct {
	JWTSecret string `envconfig:"OMNISURG_JWT_SECRET" required:"true"`
	KEKBase64 string `envconfig:"OMNISURG_KEK_BASE64" required:"true"`
}

// embeddedFixture hides the guarded secrets inside an embedded struct.
type embeddedFixture struct {
	baseConfig
	Env string `envconfig:"OMNISURG_ENV" default:"local"`
}

// secretBlock is meant to be a NAMED nested field.
type secretBlock struct {
	JWTSecret string `envconfig:"OMNISURG_JWT_SECRET" required:"true"`
	KEKBase64 string `envconfig:"OMNISURG_KEK_BASE64" required:"true"`
}

// namedNestedFixture hides the guarded secrets inside a named nested struct.
type namedNestedFixture struct {
	Secrets secretBlock
	Env     string `envconfig:"OMNISURG_ENV" default:"local"`
}

// ptrNestedFixture hides the guarded secrets behind a pointer-to-struct.
type ptrNestedFixture struct {
	Secrets *secretBlock
	Env     string `envconfig:"OMNISURG_ENV" default:"local"`
}

// kekLessNestedBlock has only a JWT secret (no KEK) nested.
type kekLessNestedBlock struct {
	JWTSecret string `envconfig:"OMNISURG_JWT_SECRET" required:"true"`
}

type kekLessNestedFixture struct {
	Secrets kekLessNestedBlock
	Env     string `envconfig:"OMNISURG_ENV" default:"local"`
}

func TestConfigRejectsLocalDevSecretInEmbeddedStructInProduction(t *testing.T) {
	t.Setenv("OMNISURG_ENV", "production")
	t.Setenv("OMNISURG_JWT_SECRET", localDevJWT)
	t.Setenv("OMNISURG_KEK_BASE64", strongKEK)

	var cfg embeddedFixture
	err := config.Load(&cfg, "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "OMNISURG_JWT_SECRET")
	assert.NotContains(t, err.Error(), localDevJWT)
}

func TestConfigRejectsLocalDevSecretInNamedNestedStructInProduction(t *testing.T) {
	t.Setenv("OMNISURG_ENV", "production")
	t.Setenv("OMNISURG_JWT_SECRET", strongJWT)
	t.Setenv("OMNISURG_KEK_BASE64", localDevKEK)

	var cfg namedNestedFixture
	err := config.Load(&cfg, "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "OMNISURG_KEK_BASE64")
	assert.NotContains(t, err.Error(), localDevKEK)
}

func TestConfigRejectsLocalDevSecretBehindPointerNestedStructInProduction(t *testing.T) {
	t.Setenv("OMNISURG_ENV", "production")
	t.Setenv("OMNISURG_JWT_SECRET", localDevJWT)
	t.Setenv("OMNISURG_KEK_BASE64", strongKEK)

	var cfg ptrNestedFixture
	err := config.Load(&cfg, "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "OMNISURG_JWT_SECRET")
}

func TestConfigAcceptsStrongSecretsInNestedStructInProduction(t *testing.T) {
	t.Setenv("OMNISURG_ENV", "production")
	t.Setenv("OMNISURG_JWT_SECRET", strongJWT)
	t.Setenv("OMNISURG_KEK_BASE64", strongKEK)

	var cfg namedNestedFixture
	require.NoError(t, config.Load(&cfg, ""))
	assert.Equal(t, strongJWT, cfg.Secrets.JWTSecret)
	assert.Equal(t, strongKEK, cfg.Secrets.KEKBase64)
}

func TestConfigDoesNotFalsePositiveOnKekLessNestedServiceInProduction(t *testing.T) {
	t.Setenv("OMNISURG_ENV", "production")
	t.Setenv("OMNISURG_JWT_SECRET", strongJWT)

	var cfg kekLessNestedFixture
	require.NoError(t, config.Load(&cfg, ""))
	assert.Equal(t, strongJWT, cfg.Secrets.JWTSecret)
}
