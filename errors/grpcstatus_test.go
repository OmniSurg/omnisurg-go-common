package errors_test

import (
	"errors"
	"net/http"
	"testing"

	apperr "github.com/OmniSurg/omnisurg-go-common/errors"
	commonv1 "github.com/OmniSurg/omnisurg-proto/gen/go/omnisurg/common/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestToStatusMapsHTTPStatusToCode(t *testing.T) {
	cases := []struct {
		name     string
		http     int
		wantCode codes.Code
	}{
		{"bad request", http.StatusBadRequest, codes.InvalidArgument},
		{"unprocessable", http.StatusUnprocessableEntity, codes.InvalidArgument},
		{"unauthorized", http.StatusUnauthorized, codes.Unauthenticated},
		{"forbidden", http.StatusForbidden, codes.PermissionDenied},
		{"not found", http.StatusNotFound, codes.NotFound},
		{"conflict", http.StatusConflict, codes.AlreadyExists},
		{"too many requests", http.StatusTooManyRequests, codes.ResourceExhausted},
		{"internal", http.StatusInternalServerError, codes.Internal},
		{"bad gateway", http.StatusBadGateway, codes.Internal},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := apperr.New("SOME_CODE", "some message", tc.http)
			out := apperr.ToStatus(in)
			st, ok := status.FromError(out)
			require.True(t, ok)
			assert.Equal(t, tc.wantCode, st.Code())
		})
	}
}

func TestToStatusNilReturnsNil(t *testing.T) {
	assert.NoError(t, apperr.ToStatus(nil))
}

func TestToStatusNonAppErrorIsInternal(t *testing.T) {
	out := apperr.ToStatus(errors.New("raw boom"))
	st, ok := status.FromError(out)
	require.True(t, ok)
	assert.Equal(t, codes.Internal, st.Code())
}

func TestToStatusWrappedAppErrorIsUnwrapped(t *testing.T) {
	base := apperr.New("PATIENT_NOT_FOUND", "patient does not exist", http.StatusNotFound)
	wrapped := apperr.Wrap(base, "service: get patient")
	out := apperr.ToStatus(wrapped)
	st, ok := status.FromError(out)
	require.True(t, ok)
	assert.Equal(t, codes.NotFound, st.Code())
}

func TestToStatusCarriesCodeAndMessage(t *testing.T) {
	in := apperr.New("BRANCH_NOT_FOUND", "branch does not exist in this tenant", http.StatusNotFound)
	out := apperr.ToStatus(in)
	st, ok := status.FromError(out)
	require.True(t, ok)
	assert.Equal(t, "branch does not exist in this tenant", st.Message())

	// the stable code rides in the ErrorEnvelope detail
	var env *commonv1.ErrorEnvelope
	for _, d := range st.Details() {
		if e, isEnv := d.(*commonv1.ErrorEnvelope); isEnv {
			env = e
		}
	}
	require.NotNil(t, env, "expected an ErrorEnvelope in the status details")
	assert.Equal(t, "BRANCH_NOT_FOUND", env.GetCode())
	assert.Equal(t, "branch does not exist in this tenant", env.GetMessage())
}

func TestToStatusPacksFieldViolations(t *testing.T) {
	in := apperr.New("VALIDATION_FAILED", "the request body is invalid", http.StatusUnprocessableEntity).
		WithDetails([]map[string]string{
			{"field": "name", "issue": "must not be empty"},
			{"field": "subdomain", "issue": "too short"},
		})
	out := apperr.ToStatus(in)
	st, ok := status.FromError(out)
	require.True(t, ok)
	assert.Equal(t, codes.InvalidArgument, st.Code())

	var env *commonv1.ErrorEnvelope
	for _, d := range st.Details() {
		if e, isEnv := d.(*commonv1.ErrorEnvelope); isEnv {
			env = e
		}
	}
	require.NotNil(t, env)
	require.Len(t, env.GetDetails(), 2)
}
