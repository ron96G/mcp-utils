package log

import (
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/ron96g/mcp-utils/pkg/config"

	"github.com/pkg/errors"
	"github.com/rs/zerolog"
)

var (
	L *Logger
)

type Logger struct {
	*zerolog.Logger
}

func getOutput(s string) io.Writer {
	switch s {
	case "stdout":
		return os.Stdout
	case "stderr":
		return os.Stderr
	default:
		panic(fmt.Errorf("invalid output '%s'", s))
	}
}

func Init(cfg config.LoggingConfig) {
	logLevel, err := zerolog.ParseLevel(cfg.Level)
	if err != nil {
		panic(errors.Wrapf(err, "invalid loglevel '%s'", cfg.Level))
	}
	zerolog.SetGlobalLevel(logLevel)

	baseLogger := zerolog.New(getOutput(cfg.Output))
	loggerBuilder := baseLogger.With().Timestamp()
	if cfg.ServiceName != "" {
		loggerBuilder.Str("service_name", cfg.ServiceName)
	}
	if cfg.ServiceVersion != "" {
		loggerBuilder.Str("service_version", cfg.ServiceVersion)
	}
	logger := loggerBuilder.Logger()
	L = &Logger{
		Logger: &logger,
	}
}

func (l *Logger) LogOAuthEvent(event, clientID, grantType string, success bool, details map[string]interface{}) {
	logEvent := l.Info()
	if !success {
		logEvent = l.Error()
	}

	logEvent = logEvent.
		Str("event", event).
		Str("client_id", clientID).
		Str("grant_type", grantType).
		Bool("success", success)

	for key, value := range details {
		logEvent = logEvent.Interface(key, value)
	}

	logEvent.Msg("OAuth event")
}

func (l *Logger) LogSecurityEvent(event, clientIP, userAgent string, severity string, details map[string]interface{}) {
	var logEvent *zerolog.Event

	switch strings.ToLower(severity) {
	case "critical", "high":
		logEvent = l.Error()
	case "medium":
		logEvent = l.Warn()
	default:
		logEvent = l.Info()
	}

	logEvent = logEvent.
		Str("event_type", "security").
		Str("event", event).
		Str("client_ip", clientIP).
		Str("user_agent", userAgent).
		Str("severity", severity)

	for key, value := range details {
		logEvent = logEvent.Interface(key, value)
	}

	logEvent.Msg("Security event")
}

func (l *Logger) LogRequest(method, path, clientIP, userAgent string, statusCode int, duration time.Duration) {
	l.Info().
		Str("method", method).
		Str("path", path).
		Str("client_ip", clientIP).
		Str("user_agent", userAgent).
		Int("status_code", statusCode).
		Dur("duration", duration).
		Msg("HTTP request processed")
}

func WithComponent(name string) *Logger {
	logger := L.With().Str("component", name).Logger()
	return &Logger{
		Logger: &logger,
	}
}
