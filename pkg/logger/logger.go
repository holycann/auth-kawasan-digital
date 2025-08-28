package logger

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/lmittmann/tint"
	"gopkg.in/natefinch/lumberjack.v2"
)

// LogLevel maps to standard slog levels for simplicity
type LogLevel slog.Level

const (
	DebugLevel = LogLevel(slog.LevelDebug)
	InfoLevel  = LogLevel(slog.LevelInfo)
	WarnLevel  = LogLevel(slog.LevelWarn)
	ErrorLevel = LogLevel(slog.LevelError)
	FatalLevel = LogLevel(slog.LevelError + 1)
)

// LoggerConfig contains logger configuration
type LoggerConfig struct {
	Path        string
	Level       LogLevel
	Development bool
	MaxSize     int
	MaxBackups  int
	MaxAge      int
	Compress    bool
}

// Logger wraps slog with additional features
type Logger struct {
	logger     *slog.Logger
	fileWriter *lumberjack.Logger
}

// NewLogger creates a new Logger instance
func NewLogger(cfg LoggerConfig) *Logger {
	// Set default configuration
	if cfg.Path == "" {
		cfg.Path = filepath.Join("logs", "app.log")
	}

	// Ensure log directory exists
	if err := os.MkdirAll(filepath.Dir(cfg.Path), 0755); err != nil {
		fmt.Printf("Failed to create log directory: %v\n", err)
	}

	// Default log file settings
	fileWriter := &lumberjack.Logger{
		Filename:   cfg.Path,
		MaxSize:    cfg.MaxSize,
		MaxBackups: cfg.MaxBackups,
		MaxAge:     cfg.MaxAge,
		Compress:   cfg.Compress,
	}

	// Use defaults if not set
	if fileWriter.MaxSize == 0 {
		fileWriter.MaxSize = 100
	}
	if fileWriter.MaxBackups == 0 {
		fileWriter.MaxBackups = 3
	}
	if fileWriter.MaxAge == 0 {
		fileWriter.MaxAge = 30
	}

	// Combine file and stdout
	multiWriter := io.MultiWriter(os.Stdout, fileWriter)

	// Create handler
	opts := &tint.Options{
		Level:      slog.Level(cfg.Level),
		TimeFormat: "2006-01-02 15:04:05",
	}

	if cfg.Development {
		opts.AddSource = true
	}

	handler := tint.NewHandler(multiWriter, opts)
	slogLogger := slog.New(handler)

	return &Logger{
		logger:     slogLogger,
		fileWriter: fileWriter,
	}
}

// log is a generic logging method to reduce code duplication
func (l *Logger) log(level slog.Level, msg string, args ...any) {
	handler := l.logger.Handler()
	if handler.Enabled(context.Background(), level) {
		pc, file, line, _ := runtime.Caller(2)
		funcName := runtime.FuncForPC(pc).Name()

		// Add caller info for development mode
		if opts, ok := handler.(interface{ Options() *tint.Options }); ok {
			tintOpts := opts.Options()
			if tintOpts.AddSource {
				callerInfo := fmt.Sprintf("%s:%d (%s)", shortenPath(file), line, funcName)
				args = append([]any{slog.String("caller", callerInfo)}, args...)
			}
		}

		switch level {
		case slog.LevelDebug:
			l.logger.Debug(msg, args...)
		case slog.LevelInfo:
			l.logger.Info(msg, args...)
		case slog.LevelWarn:
			l.logger.Warn(msg, args...)
		case slog.LevelError:
			l.logger.Error(msg, args...)
		}
	}
}

// Debug logs a debug message
func (l *Logger) Debug(msg string, args ...any) {
	l.log(slog.LevelDebug, msg, args...)
}

// Info logs an info message
func (l *Logger) Info(msg string, args ...any) {
	l.log(slog.LevelInfo, msg, args...)
}

// Warn logs a warning message
func (l *Logger) Warn(msg string, args ...any) {
	l.log(slog.LevelWarn, msg, args...)
}

// Error logs an error message
func (l *Logger) Error(msg string, args ...any) {
	l.log(slog.LevelError, msg, args...)
}

// Fatal logs a fatal message and exits the program
func (l *Logger) Fatal(msg string, args ...any) {
	l.log(slog.LevelError, msg, args...)
	os.Exit(1)
}

// Rotate performs manual log file rotation
func (l *Logger) Rotate() error {
	return l.fileWriter.Rotate()
}

// Close closes and cleans up logger resources
func (l *Logger) Close() error {
	return l.fileWriter.Close()
}

// shortenPath shortens file path
func shortenPath(path string) string {
	parts := strings.Split(path, string(os.PathSeparator))
	if len(parts) > 2 {
		return filepath.Join(parts[len(parts)-2], parts[len(parts)-1])
	}
	return path
}

// DefaultLogger creates a standard logger
func DefaultLogger() *Logger {
	return NewLogger(LoggerConfig{
		Path:  filepath.Join("logs", "app.log"),
		Level: InfoLevel,
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
