package response

import (
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/holycann/sso-kawasan-digital/pkg/errors"
)

// ResponseOption allows for optional configuration of responses
type ResponseOption func(*APIResponse)

// APIResponse is the standard structure for all API responses
type APIResponse struct {
	// Status of the response (success/error)
	Success bool `json:"success"`

	// Unique request identifier for tracing
	RequestID uuid.UUID `json:"request_id"`

	// Timestamp of the response
	Timestamp time.Time `json:"timestamp"`

	// Human-readable message
	Message string `json:"message,omitempty"`

	// Detailed error information (only populated for error responses)
	Error *ErrorDetails `json:"error,omitempty"`

	// Pagination information (optional)
	Pagination *Pagination `json:"pagination,omitempty"`

	// Actual response data
	Data interface{} `json:"data,omitempty"`

	// Additional metadata
	Metadata map[string]interface{} `json:"metadata,omitempty"`
}

// ErrorDetails provides structured error information
type ErrorDetails struct {
	// Machine-readable error code
	Code string `json:"code,omitempty"`

	// Detailed error description
	Details string `json:"details,omitempty"`

	// Trace information for debugging
	Trace []string `json:"trace,omitempty"`

	// Indicates if the error is potentially recoverable
	Recoverable bool `json:"recoverable,omitempty"`
}

// Pagination represents standard pagination metadata
type Pagination struct {
	Total       int  `json:"total"`
	Page        int  `json:"page"`
	PerPage     int  `json:"per_page"`
	TotalPages  int  `json:"total_pages"`
	HasNextPage bool `json:"has_next_page"`
}

// WithMetadata adds custom metadata to the response
func WithMetadata(key string, value interface{}) ResponseOption {
	return func(resp *APIResponse) {
		if resp.Metadata == nil {
			resp.Metadata = make(map[string]interface{})
		}
		resp.Metadata[key] = value
	}
}

// WithPagination adds pagination information to the response
func WithPagination(total, page, perPage int) ResponseOption {
	return func(resp *APIResponse) {
		totalPages := (total + perPage - 1) / perPage
		resp.Pagination = &Pagination{
			Total:       total,
			Page:        page,
			PerPage:     perPage,
			TotalPages:  totalPages,
			HasNextPage: page < totalPages,
		}
	}
}

// Success creates a flexible successful API response
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

// Error creates a standardized error response from a CustomError
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

	// Determine status code based on error type
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
	case errors.ErrDatabase,
		errors.ErrNetwork,
		errors.ErrConfiguration,
		errors.ErrInternal,
		errors.ErrTimeout,
		errors.ErrCanceled:
		statusCode = http.StatusInternalServerError
	case errors.ErrConflict:
		statusCode = http.StatusConflict
	case errors.ErrMethodNotAllowed:
		statusCode = http.StatusMethodNotAllowed
	default:
		statusCode = http.StatusInternalServerError
	}

	// Create comprehensive error details
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

// SuccessCreated is a shorthand for successful creation responses
func SuccessCreated(c *gin.Context, data interface{}, message string, opts ...ResponseOption) {
	Success(c, http.StatusCreated, data, message, opts...)
}

// SuccessOK is a shorthand for successful OK responses
func SuccessOK(c *gin.Context, data interface{}, message string, opts ...ResponseOption) {
	Success(c, http.StatusOK, data, message, opts...)
}

// BadRequest generates a 400 Bad Request error response
func BadRequest(c *gin.Context, errorCode string, message string, details string) {
	customErr := errors.New(
		errors.ErrValidation,
		message,
		nil,
		errors.WithContext("details", details),
	)
	Error(c, customErr)
}

// Unauthorized generates a 401 Unauthorized error response
func Unauthorized(c *gin.Context, errorCode string, message string, details string) {
	customErr := errors.New(
		errors.ErrAuthentication,
		message,
		nil,
		errors.WithContext("details", details),
	)
	Error(c, customErr)
}

// Forbidden generates a 403 Forbidden error response
func Forbidden(c *gin.Context, errorCode string, message string, details string) {
	customErr := errors.New(
		errors.ErrAuthorization,
		message,
		nil,
		errors.WithContext("details", details),
	)
	Error(c, customErr)
}

// NotFound generates a 404 Not Found error response
func NotFound(c *gin.Context, errorCode string, message string, details string) {
	customErr := errors.New(
		errors.ErrNotFound,
		message,
		nil,
		errors.WithContext("details", details),
	)
	Error(c, customErr)
}

// Conflict generates a 409 Conflict error response
func Conflict(c *gin.Context, errorCode string, message string, details string) {
	customErr := errors.New(
		errors.ErrValidation,
		message,
		nil,
		errors.WithContext("details", details),
	)
	Error(c, customErr)
}

// InternalServerError generates a 500 Internal Server Error response
func InternalServerError(c *gin.Context, errorCode string, message string, details string) {
	customErr := errors.New(
		errors.ErrInternal,
		message,
		nil,
		errors.WithContext("details", details),
	)
	Error(c, customErr)
}
