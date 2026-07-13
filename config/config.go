// Package config wraps envconfig plus optional godotenv loading. Every service
// defines its own Config struct with envconfig tags and calls Load. The
// optional dotenvPath parameter loads a .env file before reading the
// environment so locally developed services pick up overrides without
// polluting the global shell.
package config

import (
	"errors"
	"fmt"
	"os"
	"reflect"
	"strings"

	"github.com/joho/godotenv"
	"github.com/kelseyhightower/envconfig"
)

// guardedSecretVars are the envconfig keys whose value must never be a
// placeholder or the committed local-dev value in an internet-facing
// environment. A field is guarded purely by its envconfig tag, so a service
// that lacks one of these fields (for example a service that does not encrypt
// PII has no KEK) is simply never checked for it.
var guardedSecretVars = map[string]bool{
	"OMNISURG_JWT_SECRET": true,
	"OMNISURG_KEK_BASE64": true,
}

// placeholderSecrets are obvious not-yet-set values. Matched case
// insensitively against the trimmed secret.
var placeholderSecrets = map[string]bool{
	"":                 true,
	"changeme":         true,
	"change-me":        true,
	"your-secret-here": true,
}

// localDevSecrets are the committed local-dev values from the infrastructure
// compose defaults. They are safe in the local developer stack but must never
// reach staging or production. Matched exactly (case sensitive) against the
// secret because these are concrete configured values, not human placeholders.
var localDevSecrets = map[string]bool{
	"local-dev-secret-change-me":                   true, // OMNISURG_JWT_SECRET default
	"bG9jYWwtZGV2LWtlay0wMDAwMDAwMDAwMDAwMDAwMDA=": true, // OMNISURG_KEK_BASE64 default
}

// Load reads dotenvPath (if non empty and file exists) into the process
// environment, then populates cfg via envconfig.Process. Returns a descriptive
// error if either step fails. cfg must be a non nil pointer to a struct.
func Load(cfg any, dotenvPath string) error {
	if cfg == nil {
		return errors.New("config.Load: cfg must not be nil")
	}
	if dotenvPath != "" {
		if _, statErr := os.Stat(dotenvPath); statErr == nil {
			if err := godotenv.Load(dotenvPath); err != nil {
				return fmt.Errorf("config.Load: read dotenv %s: %w", dotenvPath, err)
			}
		}
	}
	if err := envconfig.Process("", cfg); err != nil {
		return fmt.Errorf("config.Load: process env: %w", err)
	}
	if err := assertSecretsSafe(cfg); err != nil {
		return err
	}
	return nil
}

// assertSecretsSafe fails closed at boot in any internet-facing environment if
// a guarded secret (see guardedSecretVars) is empty, a known placeholder, or
// the committed local-dev value. It is a no-op in the local environment so the
// developer stack keeps working with the committed dev values.
//
// The environment is read from OMNISURG_ENV (empty is treated as local). The
// check is intentionally driven off os.Getenv rather than a struct field so it
// holds even for a config struct that does not surface the environment.
//
// The walk mirrors envconfig.Process, which recurses into named nested,
// anonymous (embedded), and pointer-to-struct fields. If the guard only
// inspected top-level fields, a service that placed a guarded secret inside an
// embedded BaseConfig would be populated by envconfig yet never validated, a
// silent fail-open. walkGuardedSecrets therefore descends the same way.
func assertSecretsSafe(cfg any) error {
	env := strings.TrimSpace(os.Getenv("OMNISURG_ENV"))
	if env == "" || strings.EqualFold(env, "local") {
		// Local (or unset) legitimately uses the committed dev values.
		return nil
	}

	v := reflect.ValueOf(cfg)
	// Unreachable after a successful envconfig.Process (it requires a non-nil
	// pointer to a struct); kept as a belt-and-suspenders guard so a future
	// caller with a different cfg shape cannot bypass the control by panicking.
	if v.Kind() != reflect.Pointer || v.IsNil() {
		return nil
	}
	v = v.Elem()
	if v.Kind() != reflect.Struct {
		return nil // unreachable after a successful envconfig.Process
	}
	return walkGuardedSecrets(v)
}

// walkGuardedSecrets recursively validates every string field tagged with a
// guarded envconfig key, descending into named nested, embedded (anonymous),
// and pointer-to-struct fields exactly as envconfig.Process does. It never
// reads unexported fields via Interface(); it uses reflect.Value.String() on
// the string leaves, which is panic-safe for any Value kind.
func walkGuardedSecrets(v reflect.Value) error {
	t := v.Type()
	for i := 0; i < t.NumField(); i++ {
		field := t.Field(i)
		fv := v.Field(i)

		switch field.Type.Kind() {
		case reflect.String:
			// The envconfig tag may carry options (key,option); take the key.
			key := strings.SplitN(field.Tag.Get("envconfig"), ",", 2)[0]
			if !guardedSecretVars[key] {
				continue
			}
			if isUnsafeSecret(fv.String()) {
				// Never include the secret value itself in the message.
				return fmt.Errorf(
					"config.Load: %s is a placeholder or local-dev value; set a strong per-environment secret",
					key,
				)
			}
		case reflect.Struct:
			if err := walkGuardedSecrets(fv); err != nil {
				return err
			}
		case reflect.Pointer:
			// Descend into a populated pointer-to-struct (envconfig allocates
			// these when it fills a nested pointer config block).
			if !fv.IsNil() && fv.Elem().Kind() == reflect.Struct {
				if err := walkGuardedSecrets(fv.Elem()); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// isUnsafeSecret reports whether a guarded secret value must be rejected in a
// non-local environment: empty, a known human placeholder, or a committed
// local-dev value. Whitespace is never significant in these secrets, so the
// value is trimmed before both the placeholder and the local-dev match.
func isUnsafeSecret(value string) bool {
	trimmed := strings.TrimSpace(value)
	if placeholderSecrets[strings.ToLower(trimmed)] {
		return true
	}
	return localDevSecrets[trimmed]
}
