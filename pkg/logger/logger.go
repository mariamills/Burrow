// Package logger provides a thin structured logging wrapper.
// In production this would wrap slog (Go 1.21+) or zerolog.
// We use slog here since it's stdlib as of Go 1.21.
package logger

import (
	"log/slog"
	"os"
)

var log *slog.Logger

func init() {
	log = slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))
}

// SetLevel configures the minimum log level.
func SetLevel(level string) {
	var l slog.Level
	switch level {
	case "debug":
		l = slog.LevelDebug
	case "warn":
		l = slog.LevelWarn
	case "error":
		l = slog.LevelError
	default:
		l = slog.LevelInfo
	}
	log = slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: l}))
}

func Info(msg string, args ...any)  { log.Info(msg, args...) }
func Warn(msg string, args ...any)  { log.Warn(msg, args...) }
func Error(msg string, args ...any) { log.Error(msg, args...) }
func Debug(msg string, args ...any) { log.Debug(msg, args...) }
