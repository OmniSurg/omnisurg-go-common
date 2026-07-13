// Package jwt issues and verifies OmniSurg JWTs. Phase 1 uses HS256 with a
// shared secret. The Claims struct is the canonical platform claim set; every
// service reads tenant_id, branch_id, role, and provider_role from this shape.
package jwt

import (
	"errors"
	"fmt"
	"time"

	gjwt "github.com/golang-jwt/jwt/v5"
)

// Claims is the OmniSurg JWT payload.
type Claims struct {
	Subject      string `json:"sub"`
	TenantID     string `json:"tenant_id"`
	BranchID     string `json:"branch_id"`
	Role         string `json:"role"`
	ProviderRole string `json:"provider_role,omitempty"`
	MFAVerified  bool   `json:"mfa_verified"`
	gjwt.RegisteredClaims
}

// Sign issues a signed HS256 token whose validity window is now plus ttl.
// Returns an error if Subject is empty or signing fails.
func Sign(c Claims, secret string, ttl time.Duration) (string, error) {
	if c.Subject == "" {
		return "", errors.New("jwt.Sign: subject is required")
	}
	if secret == "" {
		return "", errors.New("jwt.Sign: secret is required")
	}
	now := time.Now().UTC()
	c.RegisteredClaims.IssuedAt = gjwt.NewNumericDate(now)
	c.RegisteredClaims.NotBefore = gjwt.NewNumericDate(now)
	c.RegisteredClaims.ExpiresAt = gjwt.NewNumericDate(now.Add(ttl))

	token := gjwt.NewWithClaims(gjwt.SigningMethodHS256, c)
	signed, err := token.SignedString([]byte(secret))
	if err != nil {
		return "", fmt.Errorf("jwt.Sign: sign token: %w", err)
	}
	return signed, nil
}

// Verify parses and validates a token. It rejects unexpected algorithms (only
// HS256 is accepted) and expired tokens.
func Verify(token, secret string) (Claims, error) {
	if token == "" {
		return Claims{}, errors.New("jwt.Verify: token is empty")
	}
	if secret == "" {
		return Claims{}, errors.New("jwt.Verify: secret is empty")
	}
	parsed, err := gjwt.ParseWithClaims(token, &Claims{}, func(t *gjwt.Token) (any, error) {
		if _, ok := t.Method.(*gjwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("jwt.Verify: unexpected signing method %v", t.Header["alg"])
		}
		return []byte(secret), nil
	}, gjwt.WithValidMethods([]string{"HS256"}))
	if err != nil {
		return Claims{}, fmt.Errorf("jwt.Verify: %w", err)
	}
	claims, ok := parsed.Claims.(*Claims)
	if !ok || !parsed.Valid {
		return Claims{}, errors.New("jwt.Verify: invalid token")
	}
	return *claims, nil
}
