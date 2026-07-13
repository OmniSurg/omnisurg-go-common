package jwt_test

import (
	"testing"
	"time"

	ojwt "github.com/OmniSurg/omnisurg-go-common/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testSecret = "test-secret-do-not-use-in-production"

func freshClaims() ojwt.Claims {
	return ojwt.Claims{
		Subject:      "user-123",
		TenantID:     "tenant-abc",
		BranchID:     "branch-1",
		Role:         "reception",
		ProviderRole: "",
		MFAVerified:  true,
	}
}

func TestSignAndVerify(t *testing.T) {
	in := freshClaims()
	token, err := ojwt.Sign(in, testSecret, time.Hour)
	require.NoError(t, err)
	require.NotEmpty(t, token)

	out, err := ojwt.Verify(token, testSecret)
	require.NoError(t, err)
	assert.Equal(t, in.Subject, out.Subject)
	assert.Equal(t, in.TenantID, out.TenantID)
	assert.Equal(t, in.BranchID, out.BranchID)
	assert.Equal(t, in.Role, out.Role)
	assert.Equal(t, in.MFAVerified, out.MFAVerified)
}

func TestVerifyRejectsAlteredSignature(t *testing.T) {
	token, err := ojwt.Sign(freshClaims(), testSecret, time.Hour)
	require.NoError(t, err)

	// Replace the last signature byte with one guaranteed to differ from the
	// original, so the tamper is deterministic (a plain "A" would be a no-op
	// whenever the signature already ended in "A").
	last := token[len(token)-1]
	replacement := byte('A')
	if last == replacement {
		replacement = 'B'
	}
	bad := token[:len(token)-1] + string(replacement)
	_, err = ojwt.Verify(bad, testSecret)
	require.Error(t, err)
}

func TestVerifyRejectsExpired(t *testing.T) {
	token, err := ojwt.Sign(freshClaims(), testSecret, -time.Minute)
	require.NoError(t, err)
	_, err = ojwt.Verify(token, testSecret)
	require.Error(t, err)
}

func TestVerifyRejectsAlgNone(t *testing.T) {
	// Hand crafted alg=none token (header + body + empty signature).
	noneToken := "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJ4In0."
	_, err := ojwt.Verify(noneToken, testSecret)
	require.Error(t, err)
}

func TestRequiredFields(t *testing.T) {
	bad := ojwt.Claims{Subject: ""}
	_, err := ojwt.Sign(bad, testSecret, time.Hour)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "subject")
}
