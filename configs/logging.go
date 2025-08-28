package configs

type LoggingConfig struct {
	Level      string
	FilePath   string
	MaxSize    int
	MaxBackups int
	MaxAge     int
	Compress   bool
}

func loadLoggingConfig() LoggingConfig {
	return LoggingConfig{
		FilePath:   getEnv("LOG_FILE_PATH", "./logs/app.log"),
		MaxSize:    getEnvAsInt("LOG_MAX_SIZE", 100),
		MaxBackups: getEnvAsInt("LOG_MAX_BACKUPS", 3),
		MaxAge:     getEnvAsInt("LOG_MAX_AGE", 28),
		Compress:   getEnvAsBool("LOG_COMPRESS", true),
	}
}
