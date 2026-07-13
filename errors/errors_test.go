package errors_test

import (
	"errors"
	"net/http"
	"testing"

	apperr "github.com/OmniSurg/omnisurg-go-common/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAppErrorImplementsError(t *testing.T) {
	var err error = &apperr.AppError{Code: "X", Message: "y", HTTPStatus: 400}
	require.Error(t, err)
	assert.Equal(t, "y", err.Error())
}

func TestNew(t *testing.T) {
	e := apperr.New("PATIENT_NOT_FOUND", "the patient does not exist", http.StatusNotFound)
	require.NotNil(t, e)
	assert.Equal(t, "PATIENT_NOT_FOUND", e.Code)
	assert.Equal(t, http.StatusNotFound, e.HTTPStatus)
}

func TestWithDetails(t *testing.T) {
	base := apperr.New("VALIDATION_FAILED", "request invalid", http.StatusUnprocessableEntity)
	withDetails := base.WithDetails(map[string]string{"field": "amount", "issue": "must be > 0"})
	require.NotNil(t, withDetails)
	assert.Equal(t, "VALIDATION_FAILED", withDetails.Code)
	assert.NotNil(t, withDetails.Details)
	// Original must not be mutated.
	assert.Nil(t, base.Details)
}

func TestIsMatchesSentinelByCode(t *testing.T) {
	sentinel := apperr.New("VALIDATION_FAILED", "request invalid", http.StatusUnprocessableEntity)
	// A copy carrying details must still match the sentinel via errors.Is.
	withDetails := sentinel.WithDetails(map[string]string{"field": "email", "issue": "required"})
	assert.True(t, errors.Is(withDetails, sentinel))
	// A wrapped copy must also match through the chain.
	wrapped := apperr.Wrap(withDetails, "outer")
	assert.True(t, errors.Is(wrapped, sentinel))
	// A different code must not match.
	other := apperr.New("USER_NOT_FOUND", "missing", http.StatusNotFound)
	assert.False(t, errors.Is(other, sentinel))
	// A plain error must not match.
	assert.False(t, errors.Is(errors.New("plain"), sentinel))
}

func TestAsAppError(t *testing.T) {
	root := apperr.New("FOO", "bar", http.StatusBadRequest)
	wrapped := apperr.Wrap(root, "outer context")
	var got *apperr.AppError
	require.True(t, errors.As(wrapped, &got))
	assert.Equal(t, "FOO", got.Code)
}

func TestWrapPreservesUnderlyingChain(t *testing.T) {
	sentinel := errors.New("io: closed")
	wrapped := apperr.Wrap(sentinel, "reading patient row")
	assert.True(t, errors.Is(wrapped, sentinel))
}

func TestIsAppError(t *testing.T) {
	app := apperr.New("X", "y", http.StatusBadRequest)
	plain := errors.New("plain")
	assert.True(t, apperr.IsAppError(app))
	assert.False(t, apperr.IsAppError(plain))
	assert.False(t, apperr.IsAppError(nil))
}

func TestStatusOf(t *testing.T) {
	app := apperr.New("X", "y", http.StatusTeapot)
	assert.Equal(t, http.StatusTeapot, apperr.StatusOf(app))
	assert.Equal(t, http.StatusInternalServerError, apperr.StatusOf(errors.New("plain")))
	assert.Equal(t, http.StatusInternalServerError, apperr.StatusOf(nil))
}
