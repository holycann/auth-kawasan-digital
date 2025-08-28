package middleware

import (
	"strings"
	"time"

	"github.com/MicahParks/keyfunc"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v4"

	"github.com/holycann/auth-kawasan-digital/pkg/errors"
	"github.com/holycann/auth-kawasan-digital/pkg/logger"
	"github.com/holycann/auth-kawasan-digital/pkg/response"
	"github.com/supabase-community/auth-go"
)

// Middleware handles JWT token authentication and validation
type Middleware struct {
	supabaseAuth auth.Client
	jwks         *keyfunc.JWKS
	logger       *logger.Logger
}

// UserContext represents the authenticated user's context
type UserContext struct {
	ID    string
	Email string
	Role  string
	Badge string
}

// NewMiddleware creates a new JWT middleware instance
func NewMiddleware(
	supabaseAuth auth.Client,
	jwks *keyfunc.JWKS,
	logger *logger.Logger,
) *Middleware {
	return &Middleware{
		supabaseAuth: supabaseAuth,
		jwks:         jwks,
		logger:       logger,
	}
}

// VerifyJWT validates the JWT token from the Authorization header
func (m *Middleware) VerifyJWT() gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			m.handleAuthError(c, "Missing authorization token",
				errors.WithContext("authorization_header", "missing"))
			return
		}

		tokenString := strings.TrimPrefix(authHeader, "Bearer ")
		if tokenString == authHeader {
			m.handleAuthError(c, "Invalid token format",
				errors.WithContext("token_format", "invalid"))
			return
		}

		token, err := jwt.Parse(tokenString, m.jwks.Keyfunc)
		if err != nil || !token.Valid {
			m.handleAuthError(c, "Invalid token",
				errors.WithContext("token_validation", "failed"),
				errors.WithContext("error", err.Error()))
			return
		}

		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			m.handleAuthError(c, "Invalid token claims",
				errors.WithContext("token_claims", "invalid"))
			return
		}

		// Check token expiration
		exp, ok := claims["exp"].(float64)
		if !ok {
			m.handleAuthError(c, "Token expiration not found",
				errors.WithContext("token_claims", "missing_expiration"))
			return
		}

		if time.Now().Unix() > int64(exp) {
			m.handleAuthError(c, "Token has expired",
				errors.WithContext("token_validation", "expired"))
			return
		}

		userID, _ := claims["sub"].(string)
		email, _ := claims["email"].(string)
		role, _ := claims["role"].(string)

		// Set user context
		c.Set("user_id", userID)
		c.Set("email", email)
		c.Set("role", role)

		c.Next()
	}
}

// handleAuthError handles authentication errors with standardized response
func (m *Middleware) handleAuthError(c *gin.Context, message string, opts ...func(*errors.CustomError)) {
	errors.New(
		errors.ErrAuthentication,
		message,
		nil,
		opts...,
	)
	response.Unauthorized(c, "auth_error", message, "")
	c.Abort()
}
