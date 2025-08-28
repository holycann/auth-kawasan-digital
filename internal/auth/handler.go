package auth

import (
	"github.com/gin-gonic/gin"
	"github.com/holycann/auth-kawasan-digital/configs"
	"github.com/holycann/auth-kawasan-digital/pkg/errors"
	"github.com/holycann/auth-kawasan-digital/pkg/logger"
	"github.com/holycann/auth-kawasan-digital/pkg/metrics"
	"github.com/holycann/auth-kawasan-digital/pkg/response"
)

// AuthHandler manages HTTP handlers for authentication operations
type AuthHandler struct {
	config  *configs.Config
	service *AuthService
	logger  *logger.Logger
}

// NewAuthHandler creates a new authentication handler
func NewAuthHandler(config *configs.Config, service *AuthService, log *logger.Logger) *AuthHandler {
	return &AuthHandler{
		config:  config,
		service: service,
		logger:  log,
	}
}

// Register handles user registration HTTP endpoint
func (h *AuthHandler) Register(c *gin.Context) {
	// Record registration attempt
	metrics.RegistrationAttempts.WithLabelValues("POST", "attempt").Inc()

	var req AuthRegister
	if err := c.ShouldBindJSON(&req); err != nil {
		// Record registration failure
		metrics.RegistrationAttempts.WithLabelValues("POST", "binding_error").Inc()

		h.logger.Error("Registration binding failed", "error", err)
		response.BadRequest(c, "registration_error", "Invalid request body", err.Error())
		return
	}

	// Check if the current user is an admin (if needed for role assignment)
	isAdmin := c.GetString("role") == "admin"

	// Set default role to user if not specified or if user is not an admin
	if req.Role == "" || !isAdmin {
		req.Role = "authenticated"
	}

	resp, err := h.service.Register(c.Request.Context(), req)
	if err != nil {
		// Record registration failure
		metrics.RegistrationAttempts.WithLabelValues("POST", "service_error").Inc()

		h.logger.Error("Registration failed", "error", err)
		response.Error(c, err.(*errors.CustomError))
		return
	}

	// Record successful registration
	metrics.RegistrationAttempts.WithLabelValues("POST", "success").Inc()

	response.SuccessOK(c, resp, "User registered successfully")
}

// Login handles user login HTTP endpoint
func (h *AuthHandler) Login(c *gin.Context) {
	// Record login attempt
	metrics.LoginAttempts.WithLabelValues("POST", "attempt").Inc()

	var req Credentials
	if err := c.ShouldBindJSON(&req); err != nil {
		// Record login failure
		metrics.LoginFailures.WithLabelValues("POST", "binding_error").Inc()

		h.logger.Error("Login binding failed", "error", err)
		response.BadRequest(c, "login_error", "Invalid request body", err.Error())
		return
	}

	resp, err := h.service.Login(c.Request.Context(), req)
	if err != nil {
		// Record login failure
		metrics.LoginFailures.WithLabelValues("POST", "service_error").Inc()

		h.logger.Error("Login failed", "error", err)
		response.Error(c, err.(*errors.CustomError))
		return
	}

	// Record successful login
	metrics.LoginAttempts.WithLabelValues("POST", "success").Inc()

	// Set refresh token as HTTP-only cookie
	c.SetCookie("refresh_token", resp.RefreshToken,
		int(resp.ExpiresAt),
		"/",
		h.config.CORS.Domain,
		h.config.Environment == "production",
		true,
	)

	// Remove refresh token from response
	resp.RefreshToken = ""

	response.SuccessOK(c, resp, "User logged in successfully")
}

// ResetPassword handles password reset request HTTP endpoint
func (h *AuthHandler) ResetPassword(c *gin.Context) {
	var req struct {
		Email string `json:"email" validate:"required,email"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		h.logger.Error("Password reset binding failed", "error", err)
		response.BadRequest(c, "reset_password_error", "Invalid request body", err.Error())
		return
	}

	err := h.service.ResetPassword(c.Request.Context(), req.Email)
	if err != nil {
		h.logger.Error("Password reset failed", "error", err)
		response.Error(c, err.(*errors.CustomError))
		return
	}

	response.SuccessOK(c, nil, "Password reset link sent successfully")
}

// Logout handles user logout HTTP endpoint
func (h *AuthHandler) Logout(c *gin.Context) {
	err := h.service.Logout(c.Request.Context())
	if err != nil {
		h.logger.Error("Logout failed", "error", err)
		response.Error(c, err.(*errors.CustomError))
		return
	}

	// Clear the refresh token cookie
	c.SetCookie("refresh_token", "", -1, "/", h.config.CORS.Domain, h.config.Environment == "production", true)

	response.SuccessOK(c, nil, "User logged out successfully")
}

// RefreshToken handles token renewal HTTP endpoint
func (h *AuthHandler) RefreshToken(c *gin.Context) {
	// Get refresh token from HTTP-only cookie
	refreshToken, err := c.Cookie("refresh_token")
	if err != nil {
		h.logger.Error("Token refresh failed", "error", "no refresh token")
		response.BadRequest(c, "refresh_token_error", "No refresh token found", "")
		return
	}

	resp, err := h.service.RefreshToken(c.Request.Context(), refreshToken)
	if err != nil {
		h.logger.Error("Token refresh failed", "error", err)
		response.Error(c, err.(*errors.CustomError))
		return
	}

	// Set new refresh token as HTTP-only cookie
	c.SetCookie("refresh_token", resp.RefreshToken,
		int(resp.ExpiresAt),
		"/",
		h.config.CORS.Domain,
		h.config.Environment == "production",
		true,
	)

	// Remove refresh token from response
	resp.RefreshToken = ""

	response.SuccessOK(c, resp, "Token refreshed successfully")
}
