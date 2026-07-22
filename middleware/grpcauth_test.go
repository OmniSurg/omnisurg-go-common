package middleware_test

import (
	"context"
	"testing"
	"time"

	ojwt "github.com/OmniSurg/omnisurg-go-common/jwt"
	mw "github.com/OmniSurg/omnisurg-go-common/middleware"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

func signTestJWT(t *testing.T, claims ojwt.Claims) string {
	t.Helper()
	tok, err := ojwt.Sign(claims, testSecret, time.Hour)
	require.NoError(t, err)
	return tok
}

// invoke runs the interceptor against an incoming-metadata context and a
// passthrough handler that records the identity it observed.
func invoke(t *testing.T, opts mw.InterceptorOptions, md metadata.MD, fullMethod string) (mw.GRPCIdentity, bool, error) {
	t.Helper()
	interceptor := mw.UnaryServerInterceptor(opts)
	ctx := metadata.NewIncomingContext(context.Background(), md)

	var gotID mw.GRPCIdentity
	var gotOK bool
	handler := func(ctx context.Context, req any) (any, error) {
		gotID, gotOK = mw.IdentityFromContext(ctx)
		return "ok", nil
	}
	_, err := interceptor(ctx, nil, &grpc.UnaryServerInfo{FullMethod: fullMethod}, handler)
	return gotID, gotOK, err
}

// TestInterceptorStashesRawTokenOnContext proves the gRPC inbound path exposes
// the verified raw token through the same context helper as the HTTP path, so a
// downstream gate forwards the ORIGINAL token uniformly on either transport.
func TestInterceptorStashesRawTokenOnContext(t *testing.T) {
	tok := signTestJWT(t, ojwt.Claims{
		Subject:  "11111111-1111-1111-1111-111111111111",
		TenantID: "00000000-0000-0000-0000-000000000001",
		Role:     "practice_admin",
	})
	md := metadata.Pairs(mw.MetadataKeyJWT, tok)
	interceptor := mw.UnaryServerInterceptor(mw.InterceptorOptions{JWTSecret: testSecret, RequireTenant: true})
	ctx := metadata.NewIncomingContext(context.Background(), md)

	var gotToken string
	var gotOK bool
	handler := func(ctx context.Context, req any) (any, error) {
		gotToken, gotOK = mw.JWTFromContext(ctx)
		return "ok", nil
	}
	_, err := interceptor(ctx, nil, &grpc.UnaryServerInfo{FullMethod: "/omnisurg.clinical.v1.ClinicalService/GetVisitClinicalStatus"}, handler)
	require.NoError(t, err)
	assert.True(t, gotOK, "the interceptor must stash the verified raw token on the context")
	assert.Equal(t, tok, gotToken)
}

func TestInterceptorVerifiesJWTAndExtractsIdentity(t *testing.T) {
	tok := signTestJWT(t, ojwt.Claims{
		Subject:      "11111111-1111-1111-1111-111111111111",
		TenantID:     "00000000-0000-0000-0000-000000000001",
		BranchID:     "22222222-2222-2222-2222-222222222222",
		Role:         "practice_admin",
		ProviderRole: "",
		MFAVerified:  true,
	})
	md := metadata.Pairs(mw.MetadataKeyJWT, tok)

	id, ok, err := invoke(t, mw.InterceptorOptions{JWTSecret: testSecret, RequireTenant: true}, md, "/omnisurg.tenant.v1.TenantService/GetBranch")
	require.NoError(t, err)
	require.True(t, ok)
	assert.Equal(t, "00000000-0000-0000-0000-000000000001", id.TenantID)
	assert.Equal(t, "22222222-2222-2222-2222-222222222222", id.BranchID)
	assert.Equal(t, "11111111-1111-1111-1111-111111111111", id.UserID)
	assert.Equal(t, "practice_admin", id.Role)
	assert.True(t, id.MFAVerified)
	assert.NotEmpty(t, id.RequestID, "a request id is generated when absent")
}

func TestInterceptorRejectsInvalidJWTOnTenantScopedCall(t *testing.T) {
	md := metadata.Pairs(mw.MetadataKeyJWT, "not-a-jwt")
	_, _, err := invoke(t, mw.InterceptorOptions{JWTSecret: testSecret, RequireTenant: true}, md, "/omnisurg.tenant.v1.TenantService/GetBranch")
	require.Error(t, err)
	assert.Equal(t, codes.Unauthenticated, status.Code(err))
}

func TestInterceptorRejectsJWTSignedWithWrongSecret(t *testing.T) {
	tok, err := ojwt.Sign(ojwt.Claims{Subject: "u", TenantID: "00000000-0000-0000-0000-000000000001", Role: "reception"}, "the-wrong-secret", time.Hour)
	require.NoError(t, err)
	md := metadata.Pairs(mw.MetadataKeyJWT, tok)
	_, _, ierr := invoke(t, mw.InterceptorOptions{JWTSecret: testSecret, RequireTenant: true}, md, "/omnisurg.tenant.v1.TenantService/GetBranch")
	require.Error(t, ierr)
	assert.Equal(t, codes.Unauthenticated, status.Code(ierr))
}

// The system-caller fallback to discrete keys is now gated behind an explicit
// opt-in plus a matching internal token (finding #1). With both present, the
// discrete keys are honored for a system initiated RPC that has no end user JWT.
func TestInterceptorFallsBackToDiscreteKeysForAuthorisedSystemCaller(t *testing.T) {
	md := metadata.MD{}
	md.Set(mw.MetadataKeyInternalToken, "shared-internal-token")
	md.Set(mw.MetadataKeyTenantID, "00000000-0000-0000-0000-000000000009")
	md.Set(mw.MetadataKeyActorID, "33333333-3333-3333-3333-333333333333")
	md.Set(mw.MetadataKeyActorRole, "provider_super_admin")

	id, ok, err := invoke(t, mw.InterceptorOptions{
		JWTSecret:         testSecret,
		RequireTenant:     true,
		AllowSystemCaller: true,
		InternalAuthToken: "shared-internal-token",
	}, md, "/omnisurg.tenant.v1.TenantService/ListTenants")
	require.NoError(t, err)
	require.True(t, ok)
	assert.Equal(t, "00000000-0000-0000-0000-000000000009", id.TenantID)
	assert.Equal(t, "33333333-3333-3333-3333-333333333333", id.UserID)
	assert.Equal(t, "provider_super_admin", id.Role)
}

func TestInterceptorRejectsMissingTenantOnTenantScopedCall(t *testing.T) {
	_, _, err := invoke(t, mw.InterceptorOptions{JWTSecret: testSecret, RequireTenant: true}, metadata.MD{}, "/omnisurg.tenant.v1.TenantService/GetBranch")
	require.Error(t, err)
	assert.Equal(t, codes.Unauthenticated, status.Code(err))
}

func TestInterceptorAllowsMissingTenantWhenRequireTenantFalse(t *testing.T) {
	id, ok, err := invoke(t, mw.InterceptorOptions{JWTSecret: testSecret, RequireTenant: false}, metadata.MD{}, "/omnisurg.currency.v1.CurrencyService/GetLatestRate")
	require.NoError(t, err)
	require.True(t, ok)
	assert.Empty(t, id.TenantID)
	assert.NotEmpty(t, id.RequestID, "request id is generated even with no tenant")
}

func TestInterceptorPropagatesIncomingRequestID(t *testing.T) {
	md := metadata.Pairs(mw.MetadataKeyRequestID, "req-abc-123")
	id, _, err := invoke(t, mw.InterceptorOptions{JWTSecret: testSecret, RequireTenant: false}, md, "/omnisurg.currency.v1.CurrencyService/GetLatestRate")
	require.NoError(t, err)
	assert.Equal(t, "req-abc-123", id.RequestID)
}

func TestInterceptorSkipsHealthService(t *testing.T) {
	// No metadata at all; the health Check RPC must still pass the gate.
	_, _, err := invoke(t, mw.InterceptorOptions{JWTSecret: testSecret, RequireTenant: true}, metadata.MD{}, "/grpc.health.v1.Health/Check")
	require.NoError(t, err)
}

func TestIdentityFromContextAbsent(t *testing.T) {
	_, ok := mw.IdentityFromContext(context.Background())
	assert.False(t, ok)
}

// Finding #2: a mesh auth interceptor with no JWT secret is never a valid
// runtime state. Construction must fail loud at boot, not silently fall through
// to the unverified discrete-key path.
func TestUnaryServerInterceptorPanicsOnEmptyJWTSecret(t *testing.T) {
	assert.Panics(t, func() {
		mw.UnaryServerInterceptor(mw.InterceptorOptions{JWTSecret: "", RequireTenant: true})
	}, "construction must panic when JWTSecret is empty")
}

// Finding #1: by default (AllowSystemCaller false) the unverified discrete
// identity keys must NOT be trusted. A no-JWT caller spoofing a provider role
// and a victim tenant id on a tenant-scoped call gets rejected, never a
// provider identity.
func TestInterceptorIgnoresDiscreteKeysByDefaultTenantScoped(t *testing.T) {
	md := metadata.MD{}
	md.Set(mw.MetadataKeyTenantID, "00000000-0000-0000-0000-000000000009")
	md.Set(mw.MetadataKeyActorID, "33333333-3333-3333-3333-333333333333")
	md.Set(mw.MetadataKeyActorRole, "provider_super_admin")
	md.Set(mw.MetadataKeyProviderRole, "provider_super_admin")

	_, _, err := invoke(t, mw.InterceptorOptions{JWTSecret: testSecret, RequireTenant: true}, md, "/omnisurg.tenant.v1.TenantService/ListTenants")
	require.Error(t, err)
	assert.Equal(t, codes.Unauthenticated, status.Code(err), "spoofed discrete keys must not satisfy a tenant-scoped call")
}

// Finding #1: on a RequireTenant:false call, spoofed discrete keys are still
// ignored by default; the caller passes through with an EMPTY identity, never
// the spoofed provider role or victim tenant.
func TestInterceptorIgnoresDiscreteKeysByDefaultPublicRead(t *testing.T) {
	md := metadata.MD{}
	md.Set(mw.MetadataKeyTenantID, "00000000-0000-0000-0000-000000000009")
	md.Set(mw.MetadataKeyActorRole, "provider_super_admin")

	id, ok, err := invoke(t, mw.InterceptorOptions{JWTSecret: testSecret, RequireTenant: false}, md, "/omnisurg.currency.v1.CurrencyService/GetLatestRate")
	require.NoError(t, err)
	require.True(t, ok)
	assert.Empty(t, id.TenantID, "spoofed tenant must not be trusted")
	assert.Empty(t, id.Role, "spoofed role must not be trusted")
	assert.Empty(t, id.ProviderRole, "spoofed provider role must not be trusted")
}

// Finding #1: with AllowSystemCaller on AND a matching internal token, the
// discrete keys ARE honored. This is the future service-to-service path.
func TestInterceptorHonoursDiscreteKeysWithMatchingInternalToken(t *testing.T) {
	md := metadata.MD{}
	md.Set(mw.MetadataKeyInternalToken, "shared-internal-token")
	md.Set(mw.MetadataKeyTenantID, "00000000-0000-0000-0000-000000000009")
	md.Set(mw.MetadataKeyActorID, "33333333-3333-3333-3333-333333333333")
	md.Set(mw.MetadataKeyActorRole, "provider_super_admin")
	md.Set(mw.MetadataKeyProviderRole, "provider_super_admin")

	id, ok, err := invoke(t, mw.InterceptorOptions{
		JWTSecret:         testSecret,
		RequireTenant:     true,
		AllowSystemCaller: true,
		InternalAuthToken: "shared-internal-token",
	}, md, "/omnisurg.tenant.v1.TenantService/ListTenants")
	require.NoError(t, err)
	require.True(t, ok)
	assert.Equal(t, "00000000-0000-0000-0000-000000000009", id.TenantID)
	assert.Equal(t, "33333333-3333-3333-3333-333333333333", id.UserID)
	assert.Equal(t, "provider_super_admin", id.Role)
	assert.Equal(t, "provider_super_admin", id.ProviderRole)
}

// Finding #1: AllowSystemCaller on but the internal token is wrong -> discrete
// keys are ignored (treated as no identity). On a tenant-scoped call that means
// Unauthenticated.
func TestInterceptorIgnoresDiscreteKeysWhenInternalTokenWrong(t *testing.T) {
	md := metadata.MD{}
	md.Set(mw.MetadataKeyInternalToken, "the-wrong-token")
	md.Set(mw.MetadataKeyTenantID, "00000000-0000-0000-0000-000000000009")
	md.Set(mw.MetadataKeyActorRole, "provider_super_admin")

	_, _, err := invoke(t, mw.InterceptorOptions{
		JWTSecret:         testSecret,
		RequireTenant:     true,
		AllowSystemCaller: true,
		InternalAuthToken: "shared-internal-token",
	}, md, "/omnisurg.tenant.v1.TenantService/ListTenants")
	require.Error(t, err)
	assert.Equal(t, codes.Unauthenticated, status.Code(err))
}

// Finding #1: AllowSystemCaller on but the internal token is absent -> discrete
// keys are ignored.
func TestInterceptorIgnoresDiscreteKeysWhenInternalTokenAbsent(t *testing.T) {
	md := metadata.MD{}
	md.Set(mw.MetadataKeyTenantID, "00000000-0000-0000-0000-000000000009")
	md.Set(mw.MetadataKeyActorRole, "provider_super_admin")

	id, ok, err := invoke(t, mw.InterceptorOptions{
		JWTSecret:         testSecret,
		RequireTenant:     false,
		AllowSystemCaller: true,
		InternalAuthToken: "shared-internal-token",
	}, md, "/omnisurg.currency.v1.CurrencyService/GetLatestRate")
	require.NoError(t, err)
	require.True(t, ok)
	assert.Empty(t, id.TenantID, "no internal token means discrete keys are not trusted")
	assert.Empty(t, id.Role)
}

// Finding #1 (currency preservation): RequireTenant:false + no JWT + no discrete
// keys still passes through with an empty identity. This is currency's public
// FX read and tenant-service's public by-domain lookup.
func TestInterceptorPublicReadPassesWithEmptyIdentity(t *testing.T) {
	id, ok, err := invoke(t, mw.InterceptorOptions{JWTSecret: testSecret, RequireTenant: false}, metadata.MD{}, "/omnisurg.currency.v1.CurrencyService/GetLatestRate")
	require.NoError(t, err)
	require.True(t, ok)
	assert.Empty(t, id.TenantID)
	assert.Empty(t, id.Role)
	assert.NotEmpty(t, id.RequestID)
}

// Finding #1: a valid JWT is authoritative regardless of AllowSystemCaller or
// any discrete keys present. The JWT identity wins; discrete keys never elevate.
func TestInterceptorValidJWTWinsOverDiscreteKeys(t *testing.T) {
	tok := signTestJWT(t, ojwt.Claims{
		Subject:  "11111111-1111-1111-1111-111111111111",
		TenantID: "00000000-0000-0000-0000-000000000001",
		Role:     "reception",
	})
	md := metadata.Pairs(mw.MetadataKeyJWT, tok)
	md.Set(mw.MetadataKeyInternalToken, "shared-internal-token")
	md.Set(mw.MetadataKeyTenantID, "00000000-0000-0000-0000-000000000009")
	md.Set(mw.MetadataKeyActorRole, "provider_super_admin")

	id, ok, err := invoke(t, mw.InterceptorOptions{
		JWTSecret:         testSecret,
		RequireTenant:     true,
		AllowSystemCaller: true,
		InternalAuthToken: "shared-internal-token",
	}, md, "/omnisurg.tenant.v1.TenantService/GetBranch")
	require.NoError(t, err)
	require.True(t, ok)
	assert.Equal(t, "00000000-0000-0000-0000-000000000001", id.TenantID, "JWT tenant wins")
	assert.Equal(t, "reception", id.Role, "JWT role wins, not the spoofed provider role")
	assert.Empty(t, id.ProviderRole)
}

// Finding #6: more than one x-omnisurg-jwt value is malformed and must be
// rejected, not silently resolved to vals[0].
func TestInterceptorRejectsMultipleJWTValues(t *testing.T) {
	tok := signTestJWT(t, ojwt.Claims{
		Subject:  "11111111-1111-1111-1111-111111111111",
		TenantID: "00000000-0000-0000-0000-000000000001",
		Role:     "reception",
	})
	md := metadata.MD{}
	md.Append(mw.MetadataKeyJWT, tok)
	md.Append(mw.MetadataKeyJWT, tok)

	_, _, err := invoke(t, mw.InterceptorOptions{JWTSecret: testSecret, RequireTenant: true}, md, "/omnisurg.tenant.v1.TenantService/GetBranch")
	require.Error(t, err)
	assert.Equal(t, codes.Unauthenticated, status.Code(err))
}
