package middleware

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"golang.org/x/time/rate"
)

var (
	ErrRateLimitExceeded = errors.New("rate limit exceeded")
)

// ClientFingerprint represents a unique client identifier
type ClientFingerprint struct {
	IP             string
	UserAgent      string
	AcceptLanguage string
	DeviceType     string
}

// RateLimiterConfig defines configuration for rate limiting
type RateLimiterConfig struct {
	// Maximum number of requests allowed per duration
	MaxRequests int
	// Time duration for rate limit window
	Duration time.Duration
	// Custom fingerprint generator function
	FingerprintGenerator func(*http.Request) ClientFingerprint
	// Whether to use default fingerprinting
	UseDefaultFingerprint bool
}

// DefaultRateLimiterConfig provides sensible defaults
func DefaultRateLimiterConfig() RateLimiterConfig {
	return RateLimiterConfig{
		MaxRequests:           100,
		Duration:              time.Minute,
		UseDefaultFingerprint: true,
	}
}

// RateLimiter manages rate limiting for different request keys
type RateLimiter struct {
	config     RateLimiterConfig
	limiters   map[string]*rate.Limiter
	mu         sync.RWMutex
	globalRate *rate.Limiter
}

// generateFingerprint creates a unique identifier for a client
func (rl *RateLimiter) generateFingerprint(r *http.Request) string {
	// Use custom fingerprint generator if provided
	if rl.config.FingerprintGenerator != nil {
		fp := rl.config.FingerprintGenerator(r)
		return rl.hashFingerprint(fp)
	}

	// Default fingerprinting if enabled
	if rl.config.UseDefaultFingerprint {
		fp := ClientFingerprint{
			IP:             rl.extractIP(r),
			UserAgent:      r.UserAgent(),
			AcceptLanguage: r.Header.Get("Accept-Language"),
			DeviceType:     rl.detectDeviceType(r),
		}
		return rl.hashFingerprint(fp)
	}

	// Fallback to UUID if no fingerprinting is configured
	return uuid.New().String()
}

// extractIP safely extracts IP address from request
func (rl *RateLimiter) extractIP(r *http.Request) string {
	// Check for X-Forwarded-For header (common with proxies)
	forwarded := r.Header.Get("X-Forwarded-For")
	if forwarded != "" {
		// Take the first IP in the list
		return strings.TrimSpace(strings.Split(forwarded, ",")[0])
	}

	// Fallback to RemoteAddr
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return ""
	}
	return ip
}

// detectDeviceType attempts to determine device type from User-Agent
func (rl *RateLimiter) detectDeviceType(r *http.Request) string {
	ua := strings.ToLower(r.UserAgent())

	// Simple device type detection
	switch {
	case strings.Contains(ua, "mobile"):
		return "mobile"
	case strings.Contains(ua, "tablet"):
		return "tablet"
	case strings.Contains(ua, "android"):
		return "android"
	case strings.Contains(ua, "iphone") || strings.Contains(ua, "ipad"):
		return "ios"
	case strings.Contains(ua, "windows"):
		return "desktop_windows"
	case strings.Contains(ua, "macintosh"):
		return "desktop_mac"
	case strings.Contains(ua, "linux"):
		return "desktop_linux"
	default:
		return "unknown"
	}
}

// hashFingerprint creates a consistent hash from client fingerprint
func (rl *RateLimiter) hashFingerprint(fp ClientFingerprint) string {
	// Combine fingerprint components
	fpString := fmt.Sprintf("%s|%s|%s|%s",
		fp.IP,
		fp.UserAgent,
		fp.AcceptLanguage,
		fp.DeviceType,
	)

	// Create SHA-256 hash
	hash := sha256.Sum256([]byte(fpString))
	return hex.EncodeToString(hash[:])
}

// NewRateLimiter creates a new rate limiter with given configuration
func NewRateLimiter(cfg RateLimiterConfig) *RateLimiter {
	// Use default config if not provided
	if cfg.MaxRequests == 0 {
		cfg = DefaultRateLimiterConfig()
	}

	// Create global rate limiter
	globalLimiter := rate.NewLimiter(
		rate.Limit(float64(cfg.MaxRequests)/float64(cfg.Duration.Seconds())),
		cfg.MaxRequests,
	)

	return &RateLimiter{
		config:     cfg,
		limiters:   make(map[string]*rate.Limiter),
		globalRate: globalLimiter,
	}
}

// getLimiter gets or creates a rate limiter for a specific key
func (rl *RateLimiter) getLimiter(key string) *rate.Limiter {
	rl.mu.RLock()
	limiter, exists := rl.limiters[key]
	rl.mu.RUnlock()

	if exists {
		return limiter
	}

	rl.mu.Lock()
	defer rl.mu.Unlock()

	// Double-check locking
	if limiter, exists := rl.limiters[key]; exists {
		return limiter
	}

	// Create new limiter with same configuration as global
	newLimiter := rate.NewLimiter(
		rate.Limit(float64(rl.config.MaxRequests)/float64(rl.config.Duration.Seconds())),
		rl.config.MaxRequests,
	)
	rl.limiters[key] = newLimiter
	return newLimiter
}

// Handle is the middleware function for rate limiting
func (rl *RateLimiter) Handle(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		// Check global rate limit first
		if err := rl.globalRate.Wait(ctx); err != nil {
			http.Error(w, ErrRateLimitExceeded.Error(), http.StatusTooManyRequests)
			return
		}

		// Generate client fingerprint
		key := rl.generateFingerprint(r)
		if key == "" {
			// If no key could be generated, skip specific rate limiting
			next.ServeHTTP(w, r)
			return
		}

		// Get limiter for this specific key
		limiter := rl.getLimiter(key)

		// Wait for rate limit or return error
		if err := limiter.Wait(ctx); err != nil {
			http.Error(w, ErrRateLimitExceeded.Error(), http.StatusTooManyRequests)
			return
		}

		// Continue to next handler if rate limit is not exceeded
		next.ServeHTTP(w, r)
	}
}

// Middleware function to easily create rate limiter
func RateLimiterMiddleware(cfg RateLimiterConfig) func(http.HandlerFunc) http.HandlerFunc {
	rateLimiter := NewRateLimiter(cfg)
	return rateLimiter.Handle
}
