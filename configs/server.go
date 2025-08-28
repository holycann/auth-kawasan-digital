package configs

type ServerConfig struct {
	Host            string
	Port            int
	ReadTimeout     int
	WriteTimeout    int
	ShutdownTimeout int
}

type CORSConfig struct {
	CORSEnabled      bool
	Domain           string
	AllowedOrigins   []string
	AllowedMethods   []string
	AllowedHeaders   []string
	ExposedHeaders   []string
	AllowCredentials bool
	MaxAge           int
}

func loadServerConfig() ServerConfig {
	return ServerConfig{
		Host:            getEnv("SERVER_HOST", "0.0.0.0"),
		Port:            getEnvAsInt("SERVER_PORT", 8080),
		ReadTimeout:     getEnvAsInt("SERVER_READ_TIMEOUT", 15),
		WriteTimeout:    getEnvAsInt("SERVER_WRITE_TIMEOUT", 15),
		ShutdownTimeout: getEnvAsInt("SERVER_SHUTDOWN_TIMEOUT", 30),
	}
}

func loadCORSConfig() CORSConfig {
	return CORSConfig{
		CORSEnabled:      getEnvAsBool("CORS_ENABLED", true),
		Domain:           getEnv("CORS_DOMAIN", ""),
		AllowedOrigins:   getEnvAsStringSlice("CORS_ALLOWED_ORIGINS", []string{"*"}),
		AllowedMethods:   getEnvAsStringSlice("CORS_ALLOWED_METHODS", []string{"GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"}),
		AllowedHeaders:   getEnvAsStringSlice("CORS_ALLOWED_HEADERS", []string{"Origin", "Content-Type", "Accept", "Authorization"}),
		ExposedHeaders:   getEnvAsStringSlice("CORS_EXPOSED_HEADERS", []string{}),
		AllowCredentials: getEnvAsBool("CORS_ALLOW_CREDENTIALS", false),
		MaxAge:           getEnvAsInt("CORS_MAX_AGE", 0),
	}
}
