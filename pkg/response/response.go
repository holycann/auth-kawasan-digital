package response

import (
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/holycann/auth-kawasan-digital/pkg/errors"
)

// ResponseOption allows for optional configuration of responses
type ResponseOption func(*APIResponse)

// APIResponse is the standard structure for all API SSO responses
type APIResponse struct {
	// Status of the SSO response (success/error)
	Success bool `json:"success"`

	// Unique request identifier for SSO tracing
	RequestID uuid.UUID `json:"request_id"`

	// Timestamp of the SSO response
	Timestamp time.Time `json:"timestamp"`

	// Human-readable SSO message
	Message string `json:"message,omitempty"`

	// Detailed SSO error information (only populated for error responses)
	Error *ErrorDetails `json:"error,omitempty"`

	// Actual SSO response data
	Data interface{} `json:"data,omitempty"`

	// Additional SSO metadata
	Metadata map[string]interface{} `json:"metadata,omitempty"`
}

// ErrorDetails provides structured SSO error information
type ErrorDetails struct {
	// Machine-readable SSO error code
	Code string `json:"code,omitempty"`

	// Detailed SSO error description
	Details string `json:"details,omitempty"`
}

// WithMetadata adds custom metadata to the SSO response
func WithMetadata(key string, value interface{}) ResponseOption {
	return func(resp *APIResponse) {
		if resp.Metadata == nil {
			resp.Metadata = make(map[string]interface{})
		}
		resp.Metadata[key] = value
	}
}

// Success creates a flexible successful SSO API response
func Success(c *gin.Context, statusCode int, data interface{}, message string, opts ...ResponseOption) {
	resp := &APIResponse{
		Success:   true,
		RequestID: uuid.New(),
		Timestamp: time.Now().UTC(),
		Message:   message,
		Data:      data,
		Metadata:  make(map[string]interface{}),
	}

	// Apply optional configurations
	for _, opt := range opts {
		opt(resp)
	}

	c.JSON(statusCode, resp)
}

// Error creates a standardized error response from a CustomError for SSO
func Error(c *gin.Context, err *errors.CustomError, opts ...ResponseOption) {
	errorMessage := err.Error()
	var lastError string
	if errorMessage != "" {
		lastErrorParts := strings.Split(errorMessage, ";")
		lastError = strings.TrimSpace(lastErrorParts[len(lastErrorParts)-1])

		if lastError != "" {
			lastErrorParts = strings.Split(lastError, ":")
			lastError = strings.TrimSpace(lastErrorParts[len(lastErrorParts)-1])
		}
	}

	resp := &APIResponse{
		Success:   false,
		RequestID: uuid.New(),
		Timestamp: time.Now().UTC(),
		Message:   lastError,
		Metadata:  make(map[string]interface{}),
	}

	// Determine status code based on SSO error type
	var statusCode int
	switch err.Type {
	case errors.ErrValidation, errors.ErrBadRequest:
		statusCode = http.StatusBadRequest
	case errors.ErrNotFound:
		statusCode = http.StatusNotFound
	case errors.ErrAuthentication, errors.ErrUnauthorized:
		statusCode = http.StatusUnauthorized
	case errors.ErrAuthorization, errors.ErrForbidden:
		statusCode = http.StatusForbidden
	default:
		statusCode = http.StatusInternalServerError
	}

	// Create comprehensive SSO error details
	resp.Error = &ErrorDetails{
		Code:    string(err.Type),
		Details: err.Error(),
	}

	// Add any additional context from the error
	for k, v := range err.Context {
		resp.Metadata[k] = v
	}

	// Apply optional configurations
	for _, opt := range opts {
		opt(resp)
	}

	c.JSON(statusCode, resp)
}

// SuccessOK is a shorthand for successful SSO OK responses
func SuccessOK(c *gin.Context, data interface{}, message string, opts ...ResponseOption) {
	Success(c, http.StatusOK, data, message, opts...)
}

// BadRequest generates a 400 Bad Request error response for SSO
func BadRequest(c *gin.Context, errorCode string, message string, details string) {
	customErr := errors.New(
		errors.ErrValidation,
		message,
		nil,
		errors.WithContext("details", details),
	)
	Error(c, customErr)
}

// Unauthorized generates a 401 Unauthorized error response for SSO
func Unauthorized(c *gin.Context, errorCode string, message string, details string) {
	customErr := errors.New(
		errors.ErrAuthentication,
		message,
		nil,
		errors.WithContext("details", details),
	)
	Error(c, customErr)
}

// Forbidden generates a 403 Forbidden error response for SSO
func Forbidden(c *gin.Context, errorCode string, message string, details string) {
	customErr := errors.New(
		errors.ErrAuthorization,
		message,
		nil,
		errors.WithContext("details", details),
	)
	Error(c, customErr)
}

// NotFound generates a 404 Not Found error response for SSO
func NotFound(c *gin.Context, errorCode string, message string, details string) {
	customErr := errors.New(
		errors.ErrNotFound,
		message,
		nil,
		errors.WithContext("details", details),
	)
	Error(c, customErr)
}
