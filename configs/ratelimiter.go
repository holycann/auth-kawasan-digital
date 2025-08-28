package configs

import "time"

type RateLimiterConfig struct {
	MaxRequests int
	Duration    time.Duration
	Enabled     bool
}

func loadRateLimiterConfig() RateLimiterConfig {
	return RateLimiterConfig{
		MaxRequests: getEnvAsInt("RATE_LIMIT_MAX_REQUESTS", 100),
		Duration:    time.Duration(getEnvAsInt("RATE_LIMIT_DURATION_SECONDS", 60)) * time.Second,
		Enabled:     getEnvAsBool("RATE_LIMIT_ENABLED", true),
	}
}
