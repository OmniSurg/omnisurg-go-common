package errors

import (
	"errors"
	"net/http"

	commonv1 "github.com/OmniSurg/omnisurg-proto/gen/go/omnisurg/common/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/anypb"
)

// ToStatus maps a domain error to a gRPC status error. It is the gRPC analogue
// of the REST respondError: an *AppError carries its stable Code, Message, and
// HTTPStatus, which ToStatus translates into the matching gRPC code and packs
// into an ErrorEnvelope status detail so the BFF surfaces the same shape the
// REST path returns. A non AppError maps to codes.Internal so an unexpected
// programmer error never leaks across the wire as a permissive code. nil in
// returns nil out.
func ToStatus(err error) error {
	if err == nil {
		return nil
	}
	var app *AppError
	if !errors.As(err, &app) || app == nil {
		return status.Error(codes.Internal, "internal error")
	}

	st := status.New(httpToCode(app.HTTPStatus), app.Message)
	env := &commonv1.ErrorEnvelope{
		Code:    app.Code,
		Message: app.Message,
		Details: fieldViolations(app.Details),
	}
	if withDetails, derr := st.WithDetails(env); derr == nil {
		return withDetails.Err()
	}
	// If detail packing fails for any reason, still return the coded status so
	// the caller gets the right gRPC code rather than a degraded Internal.
	return st.Err()
}

// httpToCode maps the AppError HTTP status to the closest gRPC code.
func httpToCode(httpStatus int) codes.Code {
	switch httpStatus {
	case http.StatusBadRequest, http.StatusUnprocessableEntity:
		return codes.InvalidArgument
	case http.StatusUnauthorized:
		return codes.Unauthenticated
	case http.StatusForbidden:
		return codes.PermissionDenied
	case http.StatusNotFound:
		return codes.NotFound
	case http.StatusConflict:
		return codes.AlreadyExists
	case http.StatusTooManyRequests:
		return codes.ResourceExhausted
	default:
		return codes.Internal
	}
}

// fieldViolations converts the AppError Details payload into the proto detail
// list. Services carry validation details as []map[string]string with "field"
// and "issue" keys (the same shape respondError serialises to JSON), so ToStatus
// recognises that shape. Any other Details shape is ignored for the wire detail
// (it stays available on the AppError for local logging).
func fieldViolations(details any) []*anypb.Any {
	rows, ok := details.([]map[string]string)
	if !ok {
		return nil
	}
	out := make([]*anypb.Any, 0, len(rows))
	for _, row := range rows {
		fv := &commonv1.FieldViolation{Field: row["field"], Issue: row["issue"]}
		packed, perr := anypb.New(fv)
		if perr != nil {
			continue
		}
		out = append(out, packed)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
