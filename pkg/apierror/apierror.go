// Package apierror provides standardized API error handling.
// These error types can be used across all API handlers for consistent error responses.
package apierror

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
)

// Code represents an error code.
type Code string

// Standard error codes.
const (
	CodeBadRequest          Code = "BAD_REQUEST"
	CodeUnauthorized        Code = "UNAUTHORIZED"
	CodeForbidden           Code = "FORBIDDEN"
	CodeNotFound            Code = "NOT_FOUND"
	CodeConflict            Code = "CONFLICT"
	CodeUnprocessableEntity Code = "UNPROCESSABLE_ENTITY"
	CodeInternalError       Code = "INTERNAL_ERROR"
	CodeServiceUnavailable  Code = "SERVICE_UNAVAILABLE"
	CodeValidationFailed    Code = "VALIDATION_FAILED"
	CodeRateLimitExceeded   Code = "RATE_LIMIT_EXCEEDED"
)

// Error represents a standardized API error.
type Error struct {
	// HTTP status code
	Status int `json:"-"`

	// Machine-readable error code
	Code Code `json:"code"`

	// Human-readable error message
	Message string `json:"message"`

	// Additional error details (optional)
	Details any `json:"details,omitempty"`

	// Internal error (not exposed to client)
	Err error `json:"-"`
}

// Error implements the error interface.
func (e *Error) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("%s: %s: %v", e.Code, e.Message, e.Err)
	}
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

// Unwrap returns the underlying error.
func (e *Error) Unwrap() error {
	return e.Err
}

// MarshalJSON implements json.Marshaler.
func (e *Error) MarshalJSON() ([]byte, error) {
	type alias Error
	return json.Marshal(&struct {
		*alias
		Error string `json:"error"`
	}{
		alias: (*alias)(e),
		Error: string(e.Code),
	})
}

// Response represents the error response structure.
type Response struct {
	Error     string `json:"error"`
	Code      Code   `json:"code"`
	Message   string `json:"message"`
	Details   any    `json:"details,omitempty"`
	RequestID string `json:"request_id,omitempty"`
}

// ToResponse converts the error to a response structure.
func (e *Error) ToResponse() Response {
	return Response{
		Error:   string(e.Code),
		Code:    e.Code,
		Message: e.Message,
		Details: e.Details,
	}
}

// ToResponseWithRequestID converts the error to a response with request ID.
func (e *Error) ToResponseWithRequestID(requestID string) Response {
	return Response{
		Error:     string(e.Code),
		Code:      e.Code,
		Message:   e.Message,
		Details:   e.Details,
		RequestID: requestID,
	}
}

// WriteJSON writes the error as JSON to the response writer.
func (e *Error) WriteJSON(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(e.Status)
	_ = json.NewEncoder(w).Encode(e.ToResponse())
}

// WriteJSONWithRequestID writes the error as JSON with request ID.
func (e *Error) WriteJSONWithRequestID(w http.ResponseWriter, requestID string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Request-ID", requestID)
	w.WriteHeader(e.Status)
	_ = json.NewEncoder(w).Encode(e.ToResponseWithRequestID(requestID))
}

// Constructor functions

// New creates a new API error.
func New(status int, code Code, message string) *Error {
	return &Error{
		Status:  status,
		Code:    code,
		Message: message,
	}
}

// Wrap wraps an existing error with API error context.
func Wrap(err error, status int, code Code, message string) *Error {
	return &Error{
		Status:  status,
		Code:    code,
		Message: message,
		Err:     err,
	}
}

// WithDetails adds details to the error.
func (e *Error) WithDetails(details any) *Error {
	e.Details = details
	return e
}

// WithError adds an internal error.
func (e *Error) WithError(err error) *Error {
	e.Err = err
	return e
}

// Pre-defined error constructors

// BadRequest creates a 400 Bad Request error.
func BadRequest(message string) *Error {
	return New(http.StatusBadRequest, CodeBadRequest, message)
}

// Unauthorized creates a 401 Unauthorized error.
func Unauthorized(message string) *Error {
	if message == "" {
		message = "Authentication required"
	}
	return New(http.StatusUnauthorized, CodeUnauthorized, message)
}

// Forbidden creates a 403 Forbidden error.
func Forbidden(message string) *Error {
	if message == "" {
		message = "Access denied"
	}
	return New(http.StatusForbidden, CodeForbidden, message)
}

// NotFound creates a 404 Not Found error.
func NotFound(resource string) *Error {
	message := "Resource not found"
	if resource != "" {
		message = fmt.Sprintf("%s not found", resource)
	}
	return New(http.StatusNotFound, CodeNotFound, message)
}

// Conflict creates a 409 Conflict error.
func Conflict(message string) *Error {
	return New(http.StatusConflict, CodeConflict, message)
}

// ValidationFailed creates a 422 Unprocessable Entity error.
func ValidationFailed(message string, details any) *Error {
	return &Error{
		Status:  http.StatusUnprocessableEntity,
		Code:    CodeValidationFailed,
		Message: message,
		Details: details,
	}
}

// InternalError creates a 500 Internal Server Error.
func InternalError(err error) *Error {
	return &Error{
		Status:  http.StatusInternalServerError,
		Code:    CodeInternalError,
		Message: "An internal error occurred",
		Err:     err,
	}
}

// InternalServerError creates a 500 Internal Server Error with a message.
func InternalServerError(message string) *Error {
	if message == "" {
		message = "An internal error occurred"
	}
	return New(http.StatusInternalServerError, CodeInternalError, message)
}

// ServiceUnavailable creates a 503 Service Unavailable error.
func ServiceUnavailable(message string) *Error {
	if message == "" {
		message = "Service temporarily unavailable"
	}
	return New(http.StatusServiceUnavailable, CodeServiceUnavailable, message)
}

// RateLimitExceeded creates a 429 Too Many Requests error.
func RateLimitExceeded() *Error {
	return New(http.StatusTooManyRequests, CodeRateLimitExceeded, "Rate limit exceeded")
}

// TooManyRequests creates a 429 error with a custom message.
func TooManyRequests(message string) *Error {
	return New(http.StatusTooManyRequests, CodeRateLimitExceeded, message)
}

// Helper functions

// IsAPIError checks if an error is an API error.
func IsAPIError(err error) bool {
	var apiErr *Error
	return errors.As(err, &apiErr)
}

// FromError converts any error to an API error.
func FromError(err error) *Error {
	if err == nil {
		return nil
	}

	// Already an API error
	var apiErr *Error
	if errors.As(err, &apiErr) {
		return apiErr
	}

	// Wrap unknown error as internal error
	return InternalError(err)
}

// ValidationError represents a field validation error.
type ValidationError struct {
	Field   string `json:"field"`
	Message string `json:"message"`
}

// ValidationErrors is a collection of validation errors.
type ValidationErrors []ValidationError

// Add adds a validation error.
func (v *ValidationErrors) Add(field, message string) {
	*v = append(*v, ValidationError{Field: field, Message: message})
}

// HasErrors returns true if there are validation errors.
func (v ValidationErrors) HasErrors() bool {
	return len(v) > 0
}

// ToAPIError converts validation errors to an API error.
func (v ValidationErrors) ToAPIError() *Error {
	return ValidationFailed("Validation failed", v)
}

// SafeBadRequest creates a 400 error with a safe, generic message.
// The actual error is stored internally for logging but not exposed.
// Use this instead of BadRequest(err.Error()) to prevent information leakage.
func SafeBadRequest(err error) *Error {
	return &Error{
		Status:  http.StatusBadRequest,
		Code:    CodeBadRequest,
		Message: "Invalid request",
		Err:     err,
	}
}

// SafeConflict creates a 409 error with a safe, generic message.
// Use this instead of Conflict(err.Error()) to prevent information leakage.
func SafeConflict(err error) *Error {
	return &Error{
		Status:  http.StatusConflict,
		Code:    CodeConflict,
		Message: "Resource conflict",
		Err:     err,
	}
}

// SafeForbidden creates a 403 error with a safe, generic message.
// Use this instead of Forbidden(err.Error()) to prevent information leakage.
func SafeForbidden(err error) *Error {
	return &Error{
		Status:  http.StatusForbidden,
		Code:    CodeForbidden,
		Message: "Access denied",
		Err:     err,
	}
}

// SafeUnauthorized creates a 401 error with a safe, generic message.
// Use this instead of Unauthorized(err.Error()) to prevent information leakage.
func SafeUnauthorized(err error) *Error {
	return &Error{
		Status:  http.StatusUnauthorized,
		Code:    CodeUnauthorized,
		Message: "Authentication failed",
		Err:     err,
	}
}
