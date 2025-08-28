package configs

import (
	"fmt"
	"os"

	"github.com/joho/godotenv"
)

type Config struct {
	Environment string
	Server      ServerConfig
	CORS        CORSConfig
	Supabase    SupabaseConfig
	Database    DatabaseConfig
	Logging     LoggingConfig
	RateLimiter RateLimiterConfig
}

func LoadConfig() (*Config, error) {
	env := os.Getenv("APP_ENV")

	if env == "" {
		env = "local"
	}

	envFile := fmt.Sprintf(".env.%s", env)

	if err := godotenv.Load(envFile); err != nil {
		fmt.Printf("No %s file found, fallback to .env\n", envFile)
		_ = godotenv.Load(".env")
	}

	config := &Config{
		Environment: getEnv("APP_ENV", "development"),
		Server:      loadServerConfig(),
		CORS:        loadCORSConfig(),
		Supabase:    loadSupabaseConfig(),
		Database:    loadDatabaseConfig(),
		Logging:     loadLoggingConfig(),
		RateLimiter: loadRateLimiterConfig(),
	}

	createDirIfNotExists(config.Logging.FilePath)

	return config, nil
}
