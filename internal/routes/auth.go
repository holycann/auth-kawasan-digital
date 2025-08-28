package routes

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/holycann/auth-kawasan-digital/internal/auth"
	"github.com/holycann/auth-kawasan-digital/internal/middleware"
)

// AuthRoutes sets up authentication-related routes
func AuthRoutes(
	r *gin.RouterGroup,
	jwtMiddleware *middleware.Middleware,
	rateLimiter *middleware.RateLimiter,
	authHandler *auth.AuthHandler,
) {
	// Public routes (with rate limiting)
	publicGroup := r.Group("/auth")
	{
		// Apply rate limiting to public routes
		publicGroup.POST("/register", func(c *gin.Context) {
			rateLimiter.Handle(func(w http.ResponseWriter, r *http.Request) {
				authHandler.Register(c)
			})(c.Writer, c.Request)
		})
		publicGroup.POST("/login", func(c *gin.Context) {
			rateLimiter.Handle(func(w http.ResponseWriter, r *http.Request) {
				authHandler.Login(c)
			})(c.Writer, c.Request)
		})
		publicGroup.POST("/reset-password", func(c *gin.Context) {
			rateLimiter.Handle(func(w http.ResponseWriter, r *http.Request) {
				authHandler.ResetPassword(c)
			})(c.Writer, c.Request)
		})
		publicGroup.POST("/refresh-token", func(c *gin.Context) {
			rateLimiter.Handle(func(w http.ResponseWriter, r *http.Request) {
				authHandler.RefreshToken(c)
			})(c.Writer, c.Request)
		})
	}

	// Protected routes (require JWT authentication)
	protectedGroup := r.Group("/auth")
	protectedGroup.Use(jwtMiddleware.VerifyJWT())
	{
		protectedGroup.POST("/logout", authHandler.Logout)
		// protectedGroup.POST("/mfa/setup", authHandler.MultiFactorSetup)
	}
}
