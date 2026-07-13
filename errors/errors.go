// Package errors defines the OmniSurg platform error model.
// All services return errors of type *AppError to the handler layer.
// Internal errors are wrapped with fmt.Errorf and only converted to AppError
// at the handler boundary.
package errors

import (
	"errors"
	"fmt"
	"net/http"
)

// AppError is the canonical OmniSurg error returned across service boundaries.
// Code is a stable machine readable identifier prefixed by the service domain
// (eg PATIENT_NOT_FOUND, INVOICE_ALREADY_FISCALISED). Message is a human
// readable description safe to return to API callers. HTTPStatus is the HTTP
// response code the handler layer should emit. Details carries optional
// structured data (eg field level validation errors).
type AppError struct {
	Code       string
	Message    string
	HTTPStatus int
	Details    any
	cause      error
}

// Error returns the human readable message and satisfies the error interface.
func (e *AppError) Error() string {
	if e == nil {
		return ""
	}
	return e.Message
}

// Unwrap returns the underlying cause so errors.Is and errors.As traverse the
// chain. AppError is itself a terminal type for AppError detection.
func (e *AppError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.cause
}

// Is reports whether target is an AppError carrying the same Code. This lets
// errors.Is match a sentinel against a copy produced by WithDetails or
// WithCause, both of which return a new pointer. Matching by Code keeps the
// predefined sentinels usable as errors.Is targets across the platform.
func (e *AppError) Is(target error) bool {
	if e == nil {
		return false
	}
	var other *AppError
	if !errors.As(target, &other) || other == nil {
		return false
	}
	return e.Code == other.Code
}

// WithDetails returns a copy of the receiver with Details set. The receiver is
// not mutated; predefined error sentinels stay constant.
func (e *AppError) WithDetails(d any) *AppError {
	if e == nil {
		return nil
	}
	out := *e
	out.Details = d
	return &out
}

// WithCause attaches an underlying error to the receiver. Like WithDetails it
// returns a copy.
func (e *AppError) WithCause(cause error) *AppError {
	if e == nil {
		return nil
	}
	out := *e
	out.cause = cause
	return &out
}

// New builds a fresh AppError. Predefined errors per service use this
// constructor at package init time.
func New(code, message string, httpStatus int) *AppError {
	return &AppError{Code: code, Message: message, HTTPStatus: httpStatus}
}

// Wrap returns a fmt.Errorf style wrap that keeps any underlying AppError
// reachable via errors.As, while annotating the chain with context for logs.
// Use Wrap inside service or repository layers; convert to AppError at the
// handler boundary.
func Wrap(err error, context string) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%s: %w", context, err)
}

// IsAppError reports whether err is or wraps an *AppError.
func IsAppError(err error) bool {
	if err == nil {
		return false
	}
	var app *AppError
	return errors.As(err, &app)
}

// StatusOf returns the HTTP status code an AppError carries, or 500 for any
// other error (including nil, which is treated as an unexpected programmer
// mistake).
func StatusOf(err error) int {
	if err == nil {
		return http.StatusInternalServerError
	}
	var app *AppError
	if errors.As(err, &app) && app != nil {
		return app.HTTPStatus
	}
	return http.StatusInternalServerError
}
