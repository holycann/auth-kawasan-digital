package errors

import (
	"fmt"
	"runtime"
	"strings"
)

// ErrorType defines different categories of errors
type ErrorType string

const (
	// Standard error types
	ErrValidation       ErrorType = "VALIDATION_ERROR"
	ErrNotFound         ErrorType = "NOT_FOUND"
	ErrInternal         ErrorType = "INTERNAL_ERROR"
	ErrAuthentication   ErrorType = "AUTH_ERROR"
	ErrAuthorization    ErrorType = "AUTHORIZATION_ERROR"
	ErrDatabase         ErrorType = "DATABASE_ERROR"
	ErrNetwork          ErrorType = "NETWORK_ERROR"
	ErrConfiguration    ErrorType = "CONFIG_ERROR"
	ErrConflict         ErrorType = "CONFLICT_ERROR"
	ErrUnauthorized     ErrorType = "UNAUTHORIZED_ERROR"
	ErrBadRequest       ErrorType = "BAD_REQUEST_ERROR"
	ErrTimeout          ErrorType = "TIMEOUT_ERROR"
	ErrCanceled         ErrorType = "CANCELED_ERROR"
	ErrForbidden        ErrorType = "FORBIDDEN_ERROR"
	ErrMethodNotAllowed ErrorType = "METHOD_NOT_ALLOWED_ERROR"
)

// CustomError represents a structured error with additional context
type CustomError struct {
	Type        ErrorType
	Message     []string
	Err         error
	Trace       []string
	Context     map[string]interface{}
	Recoverable bool
}

// Error implements the error interface
func (e *CustomError) Error() string {
	return fmt.Sprintf("%s: %s", e.Type, strings.Join(e.Message, "; "))
}

// Unwrap allows error unwrapping
func (e *CustomError) Unwrap() error {
	return e.Err
}

// New creates a new CustomError with enhanced options
func New(
	errorType ErrorType,
	message string,
	err error,
	opts ...func(*CustomError),
) *CustomError {
	customErr := &CustomError{
		Type:        errorType,
		Message:     []string{message},
		Err:         err,
		Trace:       captureStackTrace(),
		Context:     make(map[string]interface{}),
		Recoverable: false,
	}

	// Apply optional configurations
	for _, opt := range opts {
		opt(customErr)
	}

	return customErr
}

// WithContext adds additional context to the error
func WithContext(key string, value interface{}) func(*CustomError) {
	return func(e *CustomError) {
		e.Context[key] = value
	}
}

// Recoverable marks the error as potentially recoverable
func Recoverable() func(*CustomError) {
	return func(e *CustomError) {
		e.Recoverable = true
	}
}

// Wrap adds context to an existing error
func Wrap(err error, errorType ErrorType, message string, opts ...func(*CustomError)) *CustomError {
	if err == nil {
		return nil
	}

	// If it's already a CustomError, update its context and add new options
	if customErr, ok := err.(*CustomError); ok {
		// Append new message to existing messages instead of replacing
		customErr.Message = append(customErr.Message, message)
		customErr.Type = errorType

		// Apply additional options
		for _, opt := range opts {
			opt(customErr)
		}

		return customErr
	}

	// Append the original error message to the custom error message
	fullMessage := message
	if err != nil {
		fullMessage += ": " + err.Error()
	}

	return New(errorType, fullMessage, err, opts...)
}

// captureStackTrace captures the current stack trace with more detailed information
func captureStackTrace() []string {
	var trace []string
	for i := 1; ; i++ {
		pc, file, line, ok := runtime.Caller(i)
		if !ok {
			break
		}
		fn := runtime.FuncForPC(pc)

		// Shorten file path to last two directories
		parts := strings.Split(file, "/")
		var shortenedPath string
		if len(parts) > 2 {
			shortenedPath = strings.Join(parts[len(parts)-2:], "/")
		} else {
			shortenedPath = file
		}

		trace = append(trace, fmt.Sprintf("%s:%d %s", shortenedPath, line, fn.Name()))
	}
	return trace
}

// Is checks if an error matches a specific error type
func Is(err error, errorType ErrorType) bool {
	if customErr, ok := err.(*CustomError); ok {
		return customErr.Type == errorType
	}
	return false
}
