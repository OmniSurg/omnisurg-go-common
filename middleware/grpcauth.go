package middleware

import (
	"context"
	"crypto/subtle"
	"strings"

	ojwt "github.com/OmniSurg/omnisurg-go-common/jwt"
	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// gRPC metadata keys (lowercase hyphenated, the gRPC convention). These are the
// single source of truth shared by every service adapter and the admin-bff.
const (
	// MetadataKeyJWT carries the original signed browser JWT. The interceptor
	// VERIFIES it with the JWT secret and derives the identity from its claims.
	// This is the authoritative identity source in Phase 1 (ADR 0002).
	MetadataKeyJWT = "x-omnisurg-jwt"
	// MetadataKeyRequestID carries the request id, propagated end to end and
	// generated when absent.
	MetadataKeyRequestID = "x-omnisurg-request-id"
	// The discrete identity keys are a fallback for system initiated RPCs that
	// have no end user JWT to forward (cron, events). They are read ONLY when no
	// verified JWT is present, only when the interceptor is built with
	// AllowSystemCaller true AND the caller proves it is an internal mesh peer by
	// presenting MetadataKeyInternalToken matching InterceptorOptions.InternalAuthToken,
	// and they never override a verified JWT.
	MetadataKeyTenantID     = "x-omnisurg-tenant-id"
	MetadataKeyBranchID     = "x-omnisurg-branch-id"
	MetadataKeyActorID      = "x-omnisurg-actor-id"
	MetadataKeyActorRole    = "x-omnisurg-actor-role"
	MetadataKeyProviderRole = "x-omnisurg-provider-role"
	// MetadataKeyInternalToken carries the shared internal mesh token that
	// authorises the discrete-key system-caller path. It is the gRPC analogue of
	// the REST X-Internal-Key header guarded by InternalAPIKey. Compared in
	// constant time against InterceptorOptions.InternalAuthToken.
	MetadataKeyInternalToken = "x-omnisurg-internal-token"
	// MetadataKeyIdempotency carries an optional idempotency key for idempotent
	// mutations (eg CreateBranch), passed through the same path the REST handler
	// uses.
	MetadataKeyIdempotency = "x-idempotency-key"
)

// healthServicePrefix is the gRPC method prefix for the standard health server.
// The interceptor skips identity enforcement for it so the existing health
// server keeps working on the same grpc.Server (ADR 0002).
const healthServicePrefix = "/grpc.health.v1.Health/"

// GRPCIdentity is the authenticated caller summary derived from gRPC metadata.
// It mirrors tenant.Identity plus the request id, so a per service adapter maps
// it to its service.Caller exactly as the REST callerFrom does for the gin path.
type GRPCIdentity struct {
	TenantID     string
	BranchID     string
	UserID       string
	Role         string
	ProviderRole string
	MFAVerified  bool
	RequestID    string
}

// InterceptorOptions configures the shared unary server interceptor.
type InterceptorOptions struct {
	// JWTSecret is the HS256 secret used to verify the forwarded JWT. Required;
	// construction panics when empty because a mesh auth interceptor with no key
	// is never a valid runtime state.
	JWTSecret string
	// RequireTenant rejects a tenant scoped RPC that arrives with no usable
	// tenant id. Tenant scoped services set this true; platform data services
	// (eg currency FX reads) set it false.
	RequireTenant bool
	// AllowSystemCaller enables the unverified discrete-key fallback path for
	// system initiated RPCs that carry no end user JWT (cron, events, future
	// service to service callers). It is opt-in and OFF by default: with it off
	// the discrete identity keys are never trusted, so a caller cannot spoof a
	// tenant or role. In Phase 1 every service receives BFF forwarded user JWTs,
	// so this stays false everywhere.
	AllowSystemCaller bool
	// InternalAuthToken is the shared secret a system caller must present under
	// MetadataKeyInternalToken to unlock the discrete-key path. Compared in
	// constant time. Only consulted when AllowSystemCaller is true.
	InternalAuthToken string
}

type grpcIdentityCtxKey struct{}

// UnaryServerInterceptor returns the shared gRPC server interceptor. It is the
// gRPC analogue of middleware.JWTAuth plus middleware.RequestID: it reads the
// incoming metadata, generates or propagates the request id, verifies the
// forwarded JWT (or, only for an explicitly enabled internal mesh peer that
// presents a matching internal token, falls back to the discrete identity keys),
// enforces tenant presence per InterceptorOptions, and stashes a
// typed GRPCIdentity on the context for the adapter to read. Per method RBAC
// stays in the service layer or the adapter, not here.
func UnaryServerInterceptor(opts InterceptorOptions) grpc.UnaryServerInterceptor {
	// Fail closed at boot: an interceptor with no JWT secret could only verify
	// nothing, so it is never a valid runtime state. Panic here rather than
	// silently degrade the mesh auth boundary.
	if opts.JWTSecret == "" {
		panic("middleware.UnaryServerInterceptor: JWTSecret is required")
	}
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		md, _ := metadata.FromIncomingContext(ctx)

		requestID := firstOrEmpty(md, MetadataKeyRequestID)
		if requestID == "" {
			requestID = uuid.NewString()
		}
		// Echo the request id on the response trailer for caller correlation.
		_ = grpc.SetTrailer(ctx, metadata.Pairs(MetadataKeyRequestID, requestID))

		// The health server bypasses identity enforcement entirely.
		if strings.HasPrefix(info.FullMethod, healthServicePrefix) {
			return handler(ctx, req)
		}

		id := GRPCIdentity{RequestID: requestID}

		jwtVals := md.Get(MetadataKeyJWT)
		if len(jwtVals) > 1 {
			// Multiple JWT values are malformed: a forwarded request carries
			// exactly one signed token. Picking vals[0] would let a caller smuggle
			// a second token, so reject outright.
			return nil, status.Error(codes.Unauthenticated, "malformed credentials")
		}

		if len(jwtVals) == 1 && jwtVals[0] != "" {
			claims, err := ojwt.Verify(jwtVals[0], opts.JWTSecret)
			if err != nil {
				return nil, status.Error(codes.Unauthenticated, "invalid or expired token")
			}
			id.TenantID = claims.TenantID
			id.BranchID = claims.BranchID
			id.UserID = claims.Subject
			id.Role = claims.Role
			id.ProviderRole = claims.ProviderRole
			id.MFAVerified = claims.MFAVerified
			// Stash the verified raw token on the context under the SAME key the
			// HTTP JWTAuth path uses, so a downstream gate forwards the ORIGINAL
			// token uniformly on either inbound transport. Only the verified
			// token is stashed; the discrete-key fallback below carries no JWT.
			ctx = WithJWT(ctx, jwtVals[0])
		} else if opts.AllowSystemCaller && internalTokenMatches(md, opts.InternalAuthToken) {
			// System initiated fallback: discrete, unverified identity keys. Read
			// ONLY for an explicitly enabled service that proves it is an internal
			// mesh peer via a constant-time matched internal token. Without both,
			// these keys are ignored so a caller cannot spoof a tenant or role.
			id.TenantID = firstOrEmpty(md, MetadataKeyTenantID)
			id.BranchID = firstOrEmpty(md, MetadataKeyBranchID)
			id.UserID = firstOrEmpty(md, MetadataKeyActorID)
			id.Role = firstOrEmpty(md, MetadataKeyActorRole)
			id.ProviderRole = firstOrEmpty(md, MetadataKeyProviderRole)
		}

		if opts.RequireTenant && id.TenantID == "" {
			return nil, status.Error(codes.Unauthenticated, "tenant context is required")
		}

		ctx = context.WithValue(ctx, grpcIdentityCtxKey{}, id)
		return handler(ctx, req)
	}
}

// IdentityFromContext returns the GRPCIdentity the interceptor stashed, and
// whether one was present.
func IdentityFromContext(ctx context.Context) (GRPCIdentity, bool) {
	id, ok := ctx.Value(grpcIdentityCtxKey{}).(GRPCIdentity)
	return id, ok
}

// IdempotencyKeyFromIncoming returns the idempotency key carried in the incoming
// metadata, or empty when absent. Adapters use it for idempotent mutations.
func IdempotencyKeyFromIncoming(ctx context.Context) string {
	md, _ := metadata.FromIncomingContext(ctx)
	return firstOrEmpty(md, MetadataKeyIdempotency)
}

// internalTokenMatches reports whether the incoming metadata carries an internal
// mesh token equal to expected, using a constant-time comparison to avoid timing
// leaks (same discipline as middleware.InternalAPIKey on the REST path). An empty
// expected token never matches, so a misconfigured AllowSystemCaller cannot open
// the discrete-key path by accident.
func internalTokenMatches(md metadata.MD, expected string) bool {
	if expected == "" {
		return false
	}
	got := firstOrEmpty(md, MetadataKeyInternalToken)
	if got == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(got), []byte(expected)) == 1
}

func firstOrEmpty(md metadata.MD, key string) string {
	vals := md.Get(key)
	if len(vals) == 0 {
		return ""
	}
	return vals[0]
}
