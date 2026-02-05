package logger

import (
	"context"
	"io"
	"log/slog"
	"os"
	"strings"
	"time"
)

// Logger wraps slog.Logger with additional functionality.
type Logger struct {
	*slog.Logger
}

// Config holds logger configuration.
type Config struct {
	Level  string
	Format string
	Output io.Writer

	// Sampling configuration for high-traffic production environments
	Sampling SamplingConfig

	// Async configuration for non-blocking logging
	Async AsyncConfig
}

// DefaultConfig returns the default logger configuration.
func DefaultConfig() Config {
	return Config{
		Level:  "info",
		Format: "json",
		Output: os.Stdout,
	}
}

// New creates a new Logger instance.
func New(cfg Config) *Logger {
	level := parseLevel(cfg.Level)

	opts := &slog.HandlerOptions{
		Level:       level,
		AddSource:   level == slog.LevelDebug,
		ReplaceAttr: sanitizeAttr, // Mask sensitive data
	}

	output := cfg.Output
	if output == nil {
		output = os.Stdout
	}

	// Create base handler
	var handler slog.Handler
	switch strings.ToLower(cfg.Format) {
	case "text":
		handler = slog.NewTextHandler(output, opts)
	default:
		handler = slog.NewJSONHandler(output, opts)
	}

	// Apply sampling middleware if enabled
	handler = NewSamplingHandler(handler, cfg.Sampling)

	return &Logger{
		Logger: slog.New(handler),
	}
}

// sensitiveKeys contains keys that should be masked in logs.
// This list is comprehensive to prevent accidental credential leakage.
var sensitiveKeys = map[string]bool{
	// Authentication & Authorization
	"password":      true,
	"passwd":        true,
	"pwd":           true,
	"secret":        true,
	"token":         true,
	"authorization": true,
	"auth":          true,
	"bearer":        true,
	"api_key":       true,
	"apikey":        true,
	"api-key":       true,
	"private_key":   true,
	"privatekey":    true,
	"private-key":   true,
	"access_token":  true,
	"refresh_token": true,
	"id_token":      true,
	"jwt":           true,
	"cookie":        true,
	"session":       true,
	"session_id":    true,
	"sessionid":     true,
	"csrf":          true,
	"xsrf":          true,

	// Cloud & Service Credentials
	"aws_access_key":        true,
	"aws_secret_key":        true,
	"aws_secret_access_key": true,
	"gcp_credentials":       true,
	"azure_client_secret":   true,
	"service_account_key":   true,
	"client_secret":         true,
	"clientsecret":          true,

	// Database & Connection Strings
	"connection_string": true,
	"connectionstring":  true,
	"dsn":               true,
	"database_url":      true,
	"db_password":       true,
	"redis_password":    true,
	"redis_url":         true,

	// SSH & Certificates
	"ssh_key":         true,
	"sshkey":          true,
	"ssh_private_key": true,
	"certificate":     true,
	"cert":            true,
	"private_cert":    true,
	"signing_key":     true,
	"encryption_key":  true,
	"decryption_key":  true,
	"master_key":      true,
	"kms_key":         true,

	// Third-party Service Tokens
	"github_token":   true,
	"gitlab_token":   true,
	"slack_token":    true,
	"webhook_secret": true,
	"signing_secret": true,
	"app_secret":     true,

	// Personal Information
	"credit_card": true,
	"creditcard":  true,
	"ssn":         true,
	"social":      true, // social security
	"email":       true,
	"phone":       true,
	"address":     true,
	"dob":         true, // date of birth

	// Encryption & Hashing
	"hash":         true,
	"salt":         true,
	"iv":           true, // initialization vector
	"nonce":        true,
	"encrypted":    true,
	"ciphertext":   true,
	"plaintext":    true,
	"credential":   true,
	"credentials":  true,
	"installation": true, // GitHub App installation tokens
}

// sanitizeAttr masks sensitive values in log attributes.
func sanitizeAttr(_ []string, a slog.Attr) slog.Attr {
	key := strings.ToLower(a.Key)

	// Check if this key should be masked
	if sensitiveKeys[key] {
		return slog.String(a.Key, "[REDACTED]")
	}

	// Check for partial matches (e.g., "db_password", "jwt_secret")
	for sensitive := range sensitiveKeys {
		if strings.Contains(key, sensitive) {
			return slog.String(a.Key, "[REDACTED]")
		}
	}

	// Mask Authorization header values
	if key == "authorization" || strings.HasSuffix(key, "_token") {
		if str, ok := a.Value.Any().(string); ok {
			if len(str) > 10 {
				return slog.String(a.Key, str[:10]+"...[REDACTED]")
			}
			return slog.String(a.Key, "[REDACTED]")
		}
	}

	return a
}

// NewDefault creates a new Logger with default configuration.
func NewDefault() *Logger {
	return New(DefaultConfig())
}

// NewDevelopment creates a logger configured for development.
func NewDevelopment() *Logger {
	return New(Config{
		Level:  "debug",
		Format: "text",
		Output: os.Stdout,
	})
}

// NewProduction creates a logger configured for production.
// Includes sampling to reduce log volume in high-traffic environments.
func NewProduction() *Logger {
	return New(Config{
		Level:  "info",
		Format: "json",
		Output: os.Stdout,
		Sampling: SamplingConfig{
			Enabled:   true,
			Tick:      time.Second,
			Threshold: 100, // First 100 identical logs per second
			Rate:      0.1, // Then 10% of remaining
			ErrorRate: 1.0, // Always log errors
		},
	})
}

// NewProductionWithConfig creates a production logger with custom sampling config.
func NewProductionWithConfig(sampling SamplingConfig) *Logger {
	return New(Config{
		Level:    "info",
		Format:   "json",
		Output:   os.Stdout,
		Sampling: sampling,
	})
}

// NewNop creates a no-op logger that discards all output.
// Useful for testing or when logging is not needed.
func NewNop() *Logger {
	return New(Config{
		Level:  "error", // Only errors (which we won't emit)
		Format: "json",
		Output: io.Discard,
	})
}

// With returns a new Logger with the given attributes.
func (l *Logger) With(args ...any) *Logger {
	return &Logger{
		Logger: l.Logger.With(args...),
	}
}

// Context keys for type safety - must match middleware keys.
type ContextKey string

const (
	ContextKeyRequestID ContextKey = "request_id"
	ContextKeyUserID    ContextKey = "user_id"
)

// WithContext returns a new Logger with context values.
func (l *Logger) WithContext(ctx context.Context) *Logger {
	// Extract common context values
	logger := l.Logger

	// Use safe type assertion to avoid panics
	if requestID, ok := ctx.Value(ContextKeyRequestID).(string); ok && requestID != "" {
		logger = logger.With(slog.String("request_id", requestID))
	}

	if userID, ok := ctx.Value(ContextKeyUserID).(string); ok && userID != "" {
		logger = logger.With(slog.String("user_id", userID))
	}

	return &Logger{Logger: logger}
}

// WithError returns a new Logger with the error attribute.
func (l *Logger) WithError(err error) *Logger {
	return &Logger{
		Logger: l.Logger.With(slog.Any("error", err)),
	}
}

// WithField returns a new Logger with a single field.
func (l *Logger) WithField(key string, value any) *Logger {
	return &Logger{
		Logger: l.Logger.With(slog.Any(key, value)),
	}
}

// WithFields returns a new Logger with multiple fields.
func (l *Logger) WithFields(fields map[string]any) *Logger {
	args := make([]any, 0, len(fields)*2)
	for k, v := range fields {
		args = append(args, slog.Any(k, v))
	}
	return &Logger{
		Logger: l.Logger.With(args...),
	}
}

// Stdlib returns the underlying *slog.Logger for use with standard library.
func (l *Logger) Stdlib() *slog.Logger {
	return l.Logger
}

// SetDefault sets this logger as the default slog logger.
func (l *Logger) SetDefault() {
	slog.SetDefault(l.Logger)
}

// Helper functions

func parseLevel(level string) slog.Level {
	switch strings.ToLower(level) {
	case "debug":
		return slog.LevelDebug
	case "info":
		return slog.LevelInfo
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

// Context key type for type safety.
type contextKey string

const (
	loggerKey contextKey = "logger"
)

// ToContext adds the logger to the context.
func ToContext(ctx context.Context, logger *Logger) context.Context {
	return context.WithValue(ctx, loggerKey, logger)
}

// FromContext retrieves the logger from the context.
func FromContext(ctx context.Context) *Logger {
	if logger, ok := ctx.Value(loggerKey).(*Logger); ok {
		return logger
	}
	return NewDefault()
}
