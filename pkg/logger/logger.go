package logger

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"

	"github.com/lmittmann/tint"
	"gopkg.in/natefinch/lumberjack.v2"
)

// LogLevel defines available log levels
type LogLevel int

const (
	DebugLevel LogLevel = iota
	InfoLevel
	WarnLevel
	ErrorLevel
	FatalLevel
)

// LoggerConfig contains logger configuration
type LoggerConfig struct {
	// Log file configuration
	Path       string
	MaxSize    int  // Maximum log file size in MB
	MaxBackups int  // Maximum number of log file backups
	MaxAge     int  // Maximum age of log file in days
	Compress   bool // Whether old log files will be compressed

	// Logging configuration
	Level       LogLevel // Minimum log level to be recorded
	Development bool     // Development mode for more detailed logs
}

// Logger is a wrapper for slog with additional features
type Logger struct {
	logger     *slog.Logger
	config     LoggerConfig
	mu         sync.Mutex
	fileWriter *lumberjack.Logger
}

// NewLogger creates a new Logger instance with the given configuration
func NewLogger(cfg LoggerConfig) *Logger {
	// Validate and set default configuration
	cfg = validateConfig(cfg)

	// Prepare file writer
	fileWriter := &lumberjack.Logger{
		Filename:   cfg.Path,
		MaxSize:    cfg.MaxSize,
		MaxBackups: cfg.MaxBackups,
		MaxAge:     cfg.MaxAge,
		Compress:   cfg.Compress,
	}

	// Combine file writer and stdout
	multiWriter := io.MultiWriter(os.Stdout, fileWriter)

	// Create handler with tint for color and format
	handler := createHandler(multiWriter, cfg)

	// Create logger
	slogLogger := slog.New(handler)

	return &Logger{
		logger:     slogLogger,
		config:     cfg,
		fileWriter: fileWriter,
	}
}

// validateConfig validates and sets default logger configuration
func validateConfig(cfg LoggerConfig) LoggerConfig {
	// Set defaults if not specified
	if cfg.Path == "" {
		cfg.Path = filepath.Join("logs", "app.log")
	}

	// Create log directory if it doesn't exist
	if err := os.MkdirAll(filepath.Dir(cfg.Path), 0755); err != nil {
		fmt.Printf("Failed to create log directory: %v\n", err)
	}

	// Default configuration
	if cfg.MaxSize == 0 {
		cfg.MaxSize = 100 // 100 MB
	}
	if cfg.MaxBackups == 0 {
		cfg.MaxBackups = 3
	}
	if cfg.MaxAge == 0 {
		cfg.MaxAge = 30 // 30 days
	}

	return cfg
}

// createHandler creates a log handler with customized options
func createHandler(writer io.Writer, cfg LoggerConfig) slog.Handler {
	// Determine log level
	var level slog.Level
	switch cfg.Level {
	case DebugLevel:
		level = slog.LevelDebug
	case InfoLevel:
		level = slog.LevelInfo
	case WarnLevel:
		level = slog.LevelWarn
	case ErrorLevel:
		level = slog.LevelError
	default:
		level = slog.LevelInfo
	}

	// Handler options
	opts := &tint.Options{
		Level:      level,
		TimeFormat: "2006-01-02 15:04:05",
	}

	// Add development options
	if cfg.Development {
		opts.AddSource = true
	}

	return tint.NewHandler(writer, opts)
}

// withCallerInfo adds caller information to the log
func (l *Logger) withCallerInfo(args ...any) []any {
	if l.config.Development {
		// Get caller information
		_, file, line, ok := runtime.Caller(2)
		if ok {
			callerInfo := fmt.Sprintf("%s:%d", shortenPath(file), line)
			args = append([]any{slog.String("caller", callerInfo)}, args...)
		}
	}
	return args
}

// shortenPath shortens file path
func shortenPath(path string) string {
	// Get last 2 directories
	parts := strings.Split(path, string(os.PathSeparator))
	if len(parts) > 2 {
		return filepath.Join(parts[len(parts)-2], parts[len(parts)-1])
	}
	return path
}

// Debug logs a debug message
func (l *Logger) Debug(msg string, args ...any) {
	if l.config.Level <= DebugLevel {
		l.mu.Lock()
		defer l.mu.Unlock()
		l.logger.Debug(msg, l.withCallerInfo(args...)...)
	}
}

// Info logs an info message
func (l *Logger) Info(msg string, args ...any) {
	if l.config.Level <= InfoLevel {
		l.mu.Lock()
		defer l.mu.Unlock()
		l.logger.Info(msg, l.withCallerInfo(args...)...)
	}
}

// Warn logs a warning message
func (l *Logger) Warn(msg string, args ...any) {
	if l.config.Level <= WarnLevel {
		l.mu.Lock()
		defer l.mu.Unlock()
		l.logger.Warn(msg, l.withCallerInfo(args...)...)
	}
}

// Error logs an error message
func (l *Logger) Error(msg string, args ...any) {
	if l.config.Level <= ErrorLevel {
		l.mu.Lock()
		defer l.mu.Unlock()
		l.logger.Error(msg, l.withCallerInfo(args...)...)
	}
}

// Fatal logs a fatal message and exits the program
func (l *Logger) Fatal(msg string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.logger.Error(msg, l.withCallerInfo(args...)...)
	os.Exit(1)
}

// Rotate performs manual log file rotation
func (l *Logger) Rotate() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.fileWriter.Rotate()
}

// Close closes and cleans up logger resources
func (l *Logger) Close() error {
	return l.fileWriter.Close()
}

// Example of default configuration usage
func DefaultLogger() *Logger {
	return NewLogger(LoggerConfig{
		Path:        filepath.Join("logs", "app.log"),
		Level:       InfoLevel,
		Development: false,
	})
}

// DevelopmentLogger creates a logger for development mode
func DevelopmentLogger() *Logger {
	return NewLogger(LoggerConfig{
		Path:        filepath.Join("logs", "dev.log"),
		Level:       DebugLevel,
		Development: true,
	})
}
