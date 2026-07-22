package middleware

import "context"

// jwtCtxKey is the private context key under which the raw signed JWT is stored.
type jwtCtxKey struct{}

// WithJWT returns a copy of ctx carrying the raw signed JWT. Both inbound
// transports stash the token here after verification: the HTTP JWTAuth
// middleware (onto the request Go context) and the gRPC UnaryServerInterceptor
// (onto the handler context). Downstream code that must forward the ORIGINAL
// token to another service (the platform D1 model) reads it back with
// JWTFromContext regardless of which transport the request arrived on, so a
// service-to-service gate no longer needs to reach into inbound gRPC metadata
// (which is absent on the HTTP path).
func WithJWT(ctx context.Context, rawToken string) context.Context {
	return context.WithValue(ctx, jwtCtxKey{}, rawToken)
}

// JWTFromContext returns the raw signed JWT stashed by WithJWT and whether one
// was present and non empty. The raw token is a credential and is never logged.
func JWTFromContext(ctx context.Context) (string, bool) {
	v, ok := ctx.Value(jwtCtxKey{}).(string)
	if !ok || v == "" {
		return "", false
	}
	return v, true
}
