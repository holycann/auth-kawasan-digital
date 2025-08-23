package base

import (
	"fmt"
	"mime/multipart"
	"reflect"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/holycann/sso-kawasan-digital/pkg/errors"
	"github.com/holycann/sso-kawasan-digital/pkg/logger"
	"github.com/holycann/sso-kawasan-digital/pkg/response"
	"github.com/holycann/sso-kawasan-digital/pkg/validator"
)

// BaseHandler provides common handler functionality
type BaseHandler struct {
	logger *logger.Logger
}

// NewBaseHandler creates a new base handler
func NewBaseHandler(logger *logger.Logger) *BaseHandler {
	return &BaseHandler{
		logger: logger,
	}
}

// ValidateRequest validates the input request struct
func (h *BaseHandler) ValidateRequest(c *gin.Context, request interface{}) error {
	// Bind JSON/form data
	if err := c.ShouldBind(request); err != nil {
		return errors.New(
			errors.ErrValidation,
			"Invalid request data",
			err,
			errors.WithContext("binding_error", err.Error()),
		)
	}

	// Validate struct
	if err := validator.ValidateStruct(reflect.ValueOf(request).Elem().Interface()); err != nil {
		return errors.Wrap(
			err,
			errors.ErrValidation,
			"Validation failed",
			errors.WithContext("validation_errors", err.Error()),
		)
	}

	return nil
}

// ValidateUUID checks if a UUID is valid
func (h *BaseHandler) ValidateUUID(id string, fieldName string) (uuid.UUID, error) {
	parsedUUID, err := uuid.Parse(id)
	if err != nil {
		return uuid.Nil, errors.New(
			errors.ErrValidation,
			fmt.Sprintf("Invalid %s", fieldName),
			err,
			errors.WithContext("invalid_uuid", id),
		)
	}
	return parsedUUID, nil
}

// HandleSuccess sends a successful response
func (h *BaseHandler) HandleSuccess(c *gin.Context, data interface{}, message string, opts ...response.ResponseOption) {
	response.SuccessOK(c, data, message, opts...)
}

// HandleCreated sends a successful creation response
func (h *BaseHandler) HandleCreated(c *gin.Context, data interface{}, message string, opts ...response.ResponseOption) {
	response.SuccessCreated(c, data, message, opts...)
}

// HandleError handles and logs errors with enhanced error handling
func (h *BaseHandler) HandleError(c *gin.Context, err error) {
	// If it's not a CustomError, wrap it
	// Log the error with detailed context
	h.logger.Error("Handler error",
		"error", err.Error(),
	)

	var customErr *errors.CustomError
	switch e := err.(type) {
	case *errors.CustomError:
		customErr = e
	default:
		customErr = errors.New(
			errors.ErrInternal,
			"An unexpected error occurred",
			err,
			errors.WithContext("original_error", err.Error()),
		)
	}

	// Send error response
	response.Error(c, customErr)
}

// HandlePagination adds pagination to the response
func (h *BaseHandler) HandlePagination(
	c *gin.Context,
	data interface{},
	total int,
	opts ListOptions,
) {
	// Use the new WithPagination option
	h.HandleSuccess(
		c,
		data,
		"Data retrieved successfully",
		response.WithPagination(total, opts.Page, opts.PerPage),
	)
}

// HandleFileUpload handles file upload with validation and enhanced error handling
func (h *BaseHandler) HandleFileUpload(
	c *gin.Context,
	fieldName string,
	maxSizeBytes int64,
	allowedTypes []string,
) (*multipart.FileHeader, error) {
	file, err := c.FormFile(fieldName)
	if err != nil {
		return nil, errors.New(
			errors.ErrValidation,
			fmt.Sprintf("Failed to upload %s", fieldName),
			err,
			errors.WithContext("upload_error", err.Error()),
		)
	}

	// Check file size
	if file.Size > maxSizeBytes {
		return nil, errors.New(
			errors.ErrValidation,
			fmt.Sprintf("%s exceeds maximum size", fieldName),
			fmt.Errorf("file size %d bytes, max allowed %d", file.Size, maxSizeBytes),
			errors.WithContext("file_size", file.Size),
			errors.WithContext("max_size", maxSizeBytes),
		)
	}

	// Check file type
	if len(allowedTypes) > 0 {
		fileType := file.Header.Get("Content-Type")
		allowed := false
		for _, allowedType := range allowedTypes {
			if fileType == allowedType {
				allowed = true
				break
			}
		}
		if !allowed {
			return nil, errors.New(
				errors.ErrValidation,
				fmt.Sprintf("Invalid %s type", fieldName),
				fmt.Errorf("file type %s not allowed", fileType),
				errors.WithContext("file_type", fileType),
				errors.WithContext("allowed_types", allowedTypes),
			)
		}
	}

	return file, nil
}
