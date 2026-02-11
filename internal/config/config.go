package config

import (
	"fmt"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"
)

// Environment constants
const (
	EnvProduction = "production"
)

// Config holds all application configuration.
type Config struct {
	App        AppConfig
	Server     ServerConfig
	GRPC       GRPCConfig
	Database   DatabaseConfig
	Redis      RedisConfig
	Log        LogConfig
	Auth       AuthConfig
	OAuth      OAuthConfig
	Keycloak   KeycloakConfig
	CORS       CORSConfig
	RateLimit  RateLimitConfig
	SMTP       SMTPConfig
	Worker     WorkerConfig
	Encryption EncryptionConfig
	AITriage   AITriageConfig
}

// AppConfig holds application-level configuration.
type AppConfig struct {
	Name  string
	Env   string
	Debug bool
}

// ServerConfig holds HTTP server configuration.
type ServerConfig struct {
	Host            string
	Port            int
	ReadTimeout     time.Duration
	WriteTimeout    time.Duration
	RequestTimeout  time.Duration // Per-request handler timeout
	ShutdownTimeout time.Duration
	MaxBodySize     int64
}

// GRPCConfig holds gRPC server configuration.
type GRPCConfig struct {
	Port int
}

// DatabaseConfig holds database configuration.
type DatabaseConfig struct {
	Host            string
	Port            int
	User            string
	Password        string
	Name            string
	SSLMode         string
	MaxOpenConns    int
	MaxIdleConns    int
	ConnMaxLifetime time.Duration
}

// RedisConfig holds Redis configuration.
type RedisConfig struct {
	Host          string
	Port          int
	Password      string
	DB            int
	PoolSize      int
	MinIdleConns  int
	DialTimeout   time.Duration
	ReadTimeout   time.Duration
	WriteTimeout  time.Duration
	TLSEnabled    bool
	TLSSkipVerify bool
	MaxRetries    int
	MinRetryDelay time.Duration
	MaxRetryDelay time.Duration
}

// LogConfig holds logging configuration.
type LogConfig struct {
	Level  string
	Format string

	// Sampling configuration for high-traffic production environments
	SamplingEnabled   bool    // Enable log sampling (default: false for dev, true for prod)
	SamplingThreshold int     // First N identical logs per second (default: 100)
	SamplingRate      float64 // Sample rate after threshold, 0.0-1.0 (default: 0.1 = 10%)
	ErrorSamplingRate float64 // Sample rate for errors, 0.0-1.0 (default: 1.0 = 100%)

	// HTTP logging configuration
	SkipHealthLogs     bool // Skip logging health check endpoints (default: true in prod)
	SlowRequestSeconds int  // Log requests slower than this as warnings (default: 5)
}

// AuthProvider represents the authentication provider type.
type AuthProvider string

const (
	// AuthProviderLocal uses built-in email/password authentication.
	AuthProviderLocal AuthProvider = "local"
	// AuthProviderOIDC uses external OIDC provider (Keycloak).
	AuthProviderOIDC AuthProvider = "oidc"
	// AuthProviderHybrid allows both local and OIDC authentication.
	AuthProviderHybrid AuthProvider = "hybrid"
)

// IsValid checks if the auth provider is valid.
func (p AuthProvider) IsValid() bool {
	switch p {
	case AuthProviderLocal, AuthProviderOIDC, AuthProviderHybrid:
		return true
	default:
		return false
	}
}

// SupportsLocal returns true if local auth is supported.
func (p AuthProvider) SupportsLocal() bool {
	return p == AuthProviderLocal || p == AuthProviderHybrid
}

// SupportsOIDC returns true if OIDC auth is supported.
func (p AuthProvider) SupportsOIDC() bool {
	return p == AuthProviderOIDC || p == AuthProviderHybrid
}

// AuthConfig holds authentication configuration.
type AuthConfig struct {
	// Provider determines which authentication methods are available.
	// Values: "local", "oidc", "hybrid"
	Provider AuthProvider

	// JWT settings for local auth
	JWTSecret            string        // Secret key for signing JWTs (required for local/hybrid)
	JWTIssuer            string        // Token issuer claim
	AccessTokenDuration  time.Duration // Access token lifetime (default: 15m)
	RefreshTokenDuration time.Duration // Refresh token lifetime (default: 7d)
	SessionDuration      time.Duration // Session lifetime (default: 30d)

	// Password policy
	PasswordMinLength      int  // Minimum password length (default: 8)
	PasswordRequireUpper   bool // Require uppercase letter
	PasswordRequireLower   bool // Require lowercase letter
	PasswordRequireNumber  bool // Require number
	PasswordRequireSpecial bool // Require special character

	// Security settings
	MaxLoginAttempts  int           // Max failed attempts before lockout (default: 5)
	LockoutDuration   time.Duration // Account lockout duration (default: 15m)
	MaxActiveSessions int           // Max concurrent sessions per user (default: 10)

	// Registration settings
	AllowRegistration        bool // Allow new user registration (default: true)
	RequireEmailVerification bool // Require email verification (default: true)

	// Email verification/reset token settings
	EmailVerificationDuration time.Duration // Email verification token lifetime (default: 24h)
	PasswordResetDuration     time.Duration // Password reset token lifetime (default: 1h)

	// Cookie settings for tokens (security best practice)
	CookieSecure           bool   // Use Secure flag (HTTPS only) - should be true in production
	CookieDomain           string // Cookie domain (empty = current host)
	CookieSameSite         string // SameSite policy: "strict", "lax", or "none"
	AccessTokenCookieName  string // Cookie name for access token (default: "auth_token")
	RefreshTokenCookieName string // Cookie name for refresh token (default: "refresh_token")
	TenantCookieName       string // Cookie name for tenant (default: "app_tenant")
}

// OAuthConfig holds OAuth/Social login configuration.
type OAuthConfig struct {
	// Enabled controls whether OAuth login is enabled
	Enabled bool

	// FrontendCallbackURL is the frontend URL for OAuth callbacks
	// e.g., "http://localhost:3000/auth/callback"
	FrontendCallbackURL string

	// StateSecret is used to sign OAuth state tokens for CSRF protection
	StateSecret string

	// StateDuration is how long OAuth state tokens are valid
	StateDuration time.Duration

	// Providers
	Google    OAuthProviderConfig
	GitHub    OAuthProviderConfig
	Microsoft OAuthProviderConfig
}

// OAuthProviderConfig holds configuration for a single OAuth provider.
type OAuthProviderConfig struct {
	Enabled      bool
	ClientID     string
	ClientSecret string
	// Scopes are the OAuth scopes to request (optional, defaults provided)
	Scopes []string
}

// IsConfigured returns true if the provider is properly configured.
func (c *OAuthProviderConfig) IsConfigured() bool {
	return c.Enabled && c.ClientID != "" && c.ClientSecret != ""
}

// HasAnyProvider returns true if any OAuth provider is enabled.
func (c *OAuthConfig) HasAnyProvider() bool {
	return c.Google.IsConfigured() || c.GitHub.IsConfigured() || c.Microsoft.IsConfigured()
}

// SMTPConfig holds SMTP configuration for sending emails.
type SMTPConfig struct {
	Host       string
	Port       int
	User       string
	Password   string
	From       string
	FromName   string
	TLS        bool
	SkipVerify bool
	Enabled    bool
	BaseURL    string // Frontend base URL for email links (e.g., https://app.openctem.io)
	Timeout    time.Duration
}

// IsConfigured returns true if SMTP is properly configured.
func (c *SMTPConfig) IsConfigured() bool {
	return c.Enabled && c.Host != "" && c.Port > 0 && c.From != ""
}

// KeycloakConfig holds Keycloak authentication configuration.
type KeycloakConfig struct {
	// BaseURL is the Keycloak server URL (e.g., "https://keycloak.example.com")
	BaseURL string
	// Realm is the Keycloak realm name
	Realm string
	// ClientID is the expected audience in tokens (optional, for audience validation)
	ClientID string
	// JWKSRefreshInterval is how often to refresh JWKS keys
	JWKSRefreshInterval time.Duration
	// HTTPTimeout is the timeout for HTTP requests to Keycloak
	HTTPTimeout time.Duration
}

// JWKSURL returns the JWKS endpoint URL.
func (c *KeycloakConfig) JWKSURL() string {
	return fmt.Sprintf("%s/realms/%s/protocol/openid-connect/certs", c.BaseURL, c.Realm)
}

// IssuerURL returns the expected token issuer URL.
func (c *KeycloakConfig) IssuerURL() string {
	return fmt.Sprintf("%s/realms/%s", c.BaseURL, c.Realm)
}

// CORSConfig holds CORS configuration.
type CORSConfig struct {
	AllowedOrigins []string
	AllowedMethods []string
	AllowedHeaders []string
	MaxAge         int
}

// RateLimitConfig holds rate limiting configuration.
type RateLimitConfig struct {
	Enabled         bool
	RequestsPerSec  float64
	Burst           int
	CleanupInterval time.Duration
}

// WorkerConfig holds worker/agent management configuration.
// Deprecated: Use AgentConfig instead. This alias is kept for backward compatibility.
type WorkerConfig = AgentConfig

// AgentConfig holds agent management configuration.
type AgentConfig struct {
	// HeartbeatTimeout is the duration after which an agent is marked as inactive
	// if no heartbeat is received. Default: 5 minutes.
	HeartbeatTimeout time.Duration

	// HealthCheckInterval is how often to check for stale agents.
	// Default: 1 minute.
	HealthCheckInterval time.Duration

	// Enabled controls whether agent health checking is enabled.
	// Default: true.
	Enabled bool

	// LoadBalancing holds configuration for agent load balancing weights.
	LoadBalancing LoadBalancingConfig
}

// LoadBalancingConfig holds weights for agent load balancing score computation.
// The load score formula: score = (JobWeight * job_load) + (CPUWeight * cpu) +
//
//	(MemoryWeight * memory) + (DiskIOWeight * disk_io) + (NetworkWeight * network)
//
// All weights should sum to 1.0 for meaningful percentage-based scoring.
// Lower score = better candidate for receiving new jobs.
type LoadBalancingConfig struct {
	// JobWeight is the weight for job load factor (current_jobs/max_jobs * 100).
	// Default: 0.30 (30%)
	JobWeight float64

	// CPUWeight is the weight for CPU usage percentage.
	// Default: 0.40 (40%) - CPU is typically the most important metric
	CPUWeight float64

	// MemoryWeight is the weight for memory usage percentage.
	// Default: 0.15 (15%)
	MemoryWeight float64

	// DiskIOWeight is the weight for disk I/O score.
	// Default: 0.10 (10%)
	DiskIOWeight float64

	// NetworkWeight is the weight for network I/O score.
	// Default: 0.05 (5%)
	NetworkWeight float64

	// MaxDiskThroughputMBPS is the maximum expected disk throughput in MB/s.
	// Used to normalize disk I/O metrics to a 0-100 scale.
	// Default: 500 (500 MB/s combined read+write)
	MaxDiskThroughputMBPS float64

	// MaxNetworkThroughputMBPS is the maximum expected network throughput in MB/s.
	// Used to normalize network metrics to a 0-100 scale.
	// Default: 1000 (1 Gbps combined rx+tx)
	MaxNetworkThroughputMBPS float64
}

// EncryptionConfig holds encryption configuration for sensitive data.
type EncryptionConfig struct {
	// Key is the encryption key for AES-256-GCM encryption of sensitive data.
	// Must be exactly 32 bytes (256 bits) when decoded.
	// Can be provided as:
	// - Raw 32-byte key
	// - Hex-encoded (64 characters)
	// - Base64-encoded (44 characters)
	Key string

	// KeyFormat specifies the format of the encryption key.
	// Values: "raw", "hex", "base64"
	// Default: auto-detected based on key length
	KeyFormat string
}

// IsConfigured returns true if encryption is configured.
func (c *EncryptionConfig) IsConfigured() bool {
	return c.Key != ""
}

// AITriageConfig holds AI triage configuration for the platform.
// This is the platform-level configuration. Tenant-specific settings
// are stored in tenant.Settings.AI.
type AITriageConfig struct {
	// Enabled controls whether AI triage feature is available platform-wide.
	Enabled bool

	// Platform AI Provider Configuration
	// Used when tenants choose "platform" mode (don't provide their own keys)
	PlatformProvider string // "claude", "openai", or "gemini"
	PlatformModel    string // e.g., "claude-3-5-sonnet-20241022", "gemini-1.5-pro"
	AnthropicAPIKey  string // Platform's Anthropic API key
	OpenAIAPIKey     string // Platform's OpenAI API key
	GeminiAPIKey     string // Platform's Google Gemini API key

	// Rate Limiting
	MaxConcurrentJobs int // Max concurrent AI triage jobs
	RateLimitRPM      int // Rate limit per minute
	TimeoutSeconds    int // Timeout for AI API calls
	MaxTokens         int // Max tokens per request

	// LLM Parameters
	Temperature float64 // Temperature for LLM (0.0-1.0, lower = more deterministic)

	// Default Auto-Triage Settings (can be overridden per tenant)
	DefaultAutoTriageEnabled    bool
	DefaultAutoTriageSeverities []string
	DefaultAutoTriageDelay      time.Duration

	// Stuck Job Recovery Settings
	RecoveryEnabled       bool          // Enable background recovery for stuck jobs
	RecoveryInterval      time.Duration // How often to check for stuck jobs (default: 5 minutes)
	RecoveryStuckDuration time.Duration // How long before a job is considered stuck (default: 15 minutes)
	RecoveryBatchSize     int           // Max jobs to recover per run (default: 50)
}

// IsConfigured returns true if AI triage is properly configured.
// This checks if at least one LLM provider API key is set.
// Note: The Enabled field is deprecated - feature availability is now controlled
// by the module's is_active field in the database.
func (c *AITriageConfig) IsConfigured() bool {
	// Need at least one provider API key configured
	return c.AnthropicAPIKey != "" || c.OpenAIAPIKey != "" || c.GeminiAPIKey != ""
}

// Load loads configuration from environment variables.
func Load() (*Config, error) {
	cfg := &Config{
		App: AppConfig{
			Name:  getEnv("APP_NAME", "openctem"),
			Env:   getEnv("APP_ENV", "development"),
			Debug: getEnvBool("APP_DEBUG", false), // Default false for safety
		},
		Server: ServerConfig{
			Host:            getEnv("SERVER_HOST", "0.0.0.0"),
			Port:            getEnvInt("SERVER_PORT", 8080),
			ReadTimeout:     getEnvDuration("SERVER_READ_TIMEOUT", 15*time.Second),
			WriteTimeout:    getEnvDuration("SERVER_WRITE_TIMEOUT", 15*time.Second),
			RequestTimeout:  getEnvDuration("SERVER_REQUEST_TIMEOUT", 30*time.Second), // Per-request timeout
			ShutdownTimeout: getEnvDuration("SERVER_SHUTDOWN_TIMEOUT", 30*time.Second),
			MaxBodySize:     getEnvInt64("SERVER_MAX_BODY_SIZE", 1<<20), // 1MB default
		},
		GRPC: GRPCConfig{
			Port: getEnvInt("GRPC_PORT", 9090),
		},
		Database: DatabaseConfig{
			Host:            getEnv("DB_HOST", "localhost"),
			Port:            getEnvInt("DB_PORT", 5432),
			User:            getEnv("DB_USER", "openctem"),
			Password:        getEnv("DB_PASSWORD", "secret"),
			Name:            getEnv("DB_NAME", "openctem"),
			SSLMode:         getEnv("DB_SSLMODE", "disable"),
			MaxOpenConns:    getEnvInt("DB_MAX_OPEN_CONNS", 25),
			MaxIdleConns:    getEnvInt("DB_MAX_IDLE_CONNS", 5),
			ConnMaxLifetime: getEnvDuration("DB_CONN_MAX_LIFETIME", 5*time.Minute),
		},
		Redis: RedisConfig{
			Host:          getEnv("REDIS_HOST", "localhost"),
			Port:          getEnvInt("REDIS_PORT", 6379),
			Password:      getEnv("REDIS_PASSWORD", ""),
			DB:            getEnvInt("REDIS_DB", 0),
			PoolSize:      getEnvInt("REDIS_POOL_SIZE", 10),
			MinIdleConns:  getEnvInt("REDIS_MIN_IDLE_CONNS", 2),
			DialTimeout:   getEnvDuration("REDIS_DIAL_TIMEOUT", 5*time.Second),
			ReadTimeout:   getEnvDuration("REDIS_READ_TIMEOUT", 3*time.Second),
			WriteTimeout:  getEnvDuration("REDIS_WRITE_TIMEOUT", 3*time.Second),
			TLSEnabled:    getEnvBool("REDIS_TLS_ENABLED", false),
			TLSSkipVerify: getEnvBool("REDIS_TLS_SKIP_VERIFY", false),
			MaxRetries:    getEnvInt("REDIS_MAX_RETRIES", 3),
			MinRetryDelay: getEnvDuration("REDIS_MIN_RETRY_DELAY", 100*time.Millisecond),
			MaxRetryDelay: getEnvDuration("REDIS_MAX_RETRY_DELAY", 3*time.Second),
		},
		Log: LogConfig{
			Level:              getEnv("LOG_LEVEL", "info"), // Default info for safety
			Format:             getEnv("LOG_FORMAT", "json"),
			SamplingEnabled:    getEnvBool("LOG_SAMPLING_ENABLED", false),   // Enable via env for production
			SamplingThreshold:  getEnvInt("LOG_SAMPLING_THRESHOLD", 100),    // First 100 identical logs/sec
			SamplingRate:       getEnvFloat("LOG_SAMPLING_RATE", 0.1),       // Then 10%
			ErrorSamplingRate:  getEnvFloat("LOG_ERROR_SAMPLING_RATE", 1.0), // Always log errors
			SkipHealthLogs:     getEnvBool("LOG_SKIP_HEALTH", true),         // Skip health endpoints
			SlowRequestSeconds: getEnvInt("LOG_SLOW_REQUEST_SECONDS", 5),    // Warn on slow requests
		},
		Auth: AuthConfig{
			Provider:                  AuthProvider(getEnv("AUTH_PROVIDER", "oidc")), // Default to OIDC for backward compatibility
			JWTSecret:                 getEnv("AUTH_JWT_SECRET", ""),
			JWTIssuer:                 getEnv("AUTH_JWT_ISSUER", "api"),
			AccessTokenDuration:       getEnvDuration("AUTH_ACCESS_TOKEN_DURATION", 15*time.Minute),
			RefreshTokenDuration:      getEnvDuration("AUTH_REFRESH_TOKEN_DURATION", 7*24*time.Hour),
			SessionDuration:           getEnvDuration("AUTH_SESSION_DURATION", 30*24*time.Hour),
			PasswordMinLength:         getEnvInt("AUTH_PASSWORD_MIN_LENGTH", 8),
			PasswordRequireUpper:      getEnvBool("AUTH_PASSWORD_REQUIRE_UPPERCASE", true),
			PasswordRequireLower:      getEnvBool("AUTH_PASSWORD_REQUIRE_LOWERCASE", true),
			PasswordRequireNumber:     getEnvBool("AUTH_PASSWORD_REQUIRE_NUMBER", true),
			PasswordRequireSpecial:    getEnvBool("AUTH_PASSWORD_REQUIRE_SPECIAL", false),
			MaxLoginAttempts:          getEnvInt("AUTH_MAX_LOGIN_ATTEMPTS", 5),
			LockoutDuration:           getEnvDuration("AUTH_LOCKOUT_DURATION", 15*time.Minute),
			MaxActiveSessions:         getEnvInt("AUTH_MAX_ACTIVE_SESSIONS", 10),
			AllowRegistration:         getEnvBool("AUTH_ALLOW_REGISTRATION", true),
			RequireEmailVerification:  getEnvBool("AUTH_REQUIRE_EMAIL_VERIFICATION", true),
			EmailVerificationDuration: getEnvDuration("AUTH_EMAIL_VERIFICATION_DURATION", 24*time.Hour),
			PasswordResetDuration:     getEnvDuration("AUTH_PASSWORD_RESET_DURATION", 1*time.Hour),
			CookieSecure:              getEnvBool("AUTH_COOKIE_SECURE", false),                   // Set true in production
			CookieDomain:              getEnv("AUTH_COOKIE_DOMAIN", ""),                          // Empty = current host
			CookieSameSite:            getEnv("AUTH_COOKIE_SAMESITE", "lax"),                     // "strict", "lax", or "none"
			AccessTokenCookieName:     getEnv("AUTH_ACCESS_TOKEN_COOKIE_NAME", "auth_token"),     // Cookie name for access token
			RefreshTokenCookieName:    getEnv("AUTH_REFRESH_TOKEN_COOKIE_NAME", "refresh_token"), // Cookie name for refresh token
			TenantCookieName:          getEnv("AUTH_TENANT_COOKIE_NAME", "app_tenant"),           // Cookie name for tenant
		},
		Keycloak: KeycloakConfig{
			BaseURL:             getEnv("KEYCLOAK_BASE_URL", "http://localhost:8080"),
			Realm:               getEnv("KEYCLOAK_REALM", "openctem"),
			ClientID:            getEnv("KEYCLOAK_CLIENT_ID", ""),
			JWKSRefreshInterval: getEnvDuration("KEYCLOAK_JWKS_REFRESH_INTERVAL", 1*time.Hour),
			HTTPTimeout:         getEnvDuration("KEYCLOAK_HTTP_TIMEOUT", 10*time.Second),
		},
		CORS: CORSConfig{
			AllowedOrigins: getEnvSlice("CORS_ALLOWED_ORIGINS", []string{"*"}),
			AllowedMethods: getEnvSlice("CORS_ALLOWED_METHODS", []string{"GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"}),
			AllowedHeaders: getEnvSlice("CORS_ALLOWED_HEADERS", []string{"Accept", "Authorization", "Content-Type", "X-Request-ID", "X-Admin-API-Key"}),
			MaxAge:         getEnvInt("CORS_MAX_AGE", 86400),
		},
		RateLimit: RateLimitConfig{
			Enabled:         getEnvBool("RATE_LIMIT_ENABLED", true),
			RequestsPerSec:  getEnvFloat("RATE_LIMIT_RPS", 100),
			Burst:           getEnvInt("RATE_LIMIT_BURST", 200),
			CleanupInterval: getEnvDuration("RATE_LIMIT_CLEANUP", 1*time.Minute),
		},
		SMTP: SMTPConfig{
			Enabled:    getEnvBool("SMTP_ENABLED", false),
			Host:       getEnv("SMTP_HOST", ""),
			Port:       getEnvInt("SMTP_PORT", 587),
			User:       getEnv("SMTP_USER", ""),
			Password:   getEnv("SMTP_PASSWORD", ""),
			From:       getEnv("SMTP_FROM", ""),
			FromName:   getEnv("SMTP_FROM_NAME", "OpenCTEM"),
			TLS:        getEnvBool("SMTP_TLS", true),
			SkipVerify: getEnvBool("SMTP_SKIP_VERIFY", false),
			BaseURL:    getEnv("SMTP_BASE_URL", "http://localhost:3000"), // Frontend URL for email links
			Timeout:    getEnvDuration("SMTP_TIMEOUT", 30*time.Second),
		},
		OAuth: OAuthConfig{
			Enabled:             getEnvBool("OAUTH_ENABLED", true),
			FrontendCallbackURL: getEnv("OAUTH_FRONTEND_CALLBACK_URL", "http://localhost:3000/auth/callback"),
			StateSecret:         getEnv("OAUTH_STATE_SECRET", ""),
			StateDuration:       getEnvDuration("OAUTH_STATE_DURATION", 10*time.Minute),
			Google: OAuthProviderConfig{
				Enabled:      getEnvBool("OAUTH_GOOGLE_ENABLED", false),
				ClientID:     getEnv("OAUTH_GOOGLE_CLIENT_ID", ""),
				ClientSecret: getEnv("OAUTH_GOOGLE_CLIENT_SECRET", ""),
				Scopes:       getEnvSlice("OAUTH_GOOGLE_SCOPES", []string{"openid", "email", "profile"}),
			},
			GitHub: OAuthProviderConfig{
				Enabled:      getEnvBool("OAUTH_GITHUB_ENABLED", false),
				ClientID:     getEnv("OAUTH_GITHUB_CLIENT_ID", ""),
				ClientSecret: getEnv("OAUTH_GITHUB_CLIENT_SECRET", ""),
				Scopes:       getEnvSlice("OAUTH_GITHUB_SCOPES", []string{"read:user", "user:email"}),
			},
			Microsoft: OAuthProviderConfig{
				Enabled:      getEnvBool("OAUTH_MICROSOFT_ENABLED", false),
				ClientID:     getEnv("OAUTH_MICROSOFT_CLIENT_ID", ""),
				ClientSecret: getEnv("OAUTH_MICROSOFT_CLIENT_SECRET", ""),
				Scopes:       getEnvSlice("OAUTH_MICROSOFT_SCOPES", []string{"openid", "email", "profile", "User.Read"}),
			},
		},
		Worker: WorkerConfig{
			Enabled:             getEnvBool("WORKER_HEALTH_CHECK_ENABLED", true),
			HeartbeatTimeout:    getEnvDuration("WORKER_HEARTBEAT_TIMEOUT", 5*time.Minute),
			HealthCheckInterval: getEnvDuration("WORKER_HEALTH_CHECK_INTERVAL", 1*time.Minute),
			LoadBalancing: LoadBalancingConfig{
				JobWeight:                getEnvFloat("AGENT_LB_JOB_WEIGHT", 0.30),
				CPUWeight:                getEnvFloat("AGENT_LB_CPU_WEIGHT", 0.40),
				MemoryWeight:             getEnvFloat("AGENT_LB_MEMORY_WEIGHT", 0.15),
				DiskIOWeight:             getEnvFloat("AGENT_LB_DISK_IO_WEIGHT", 0.10),
				NetworkWeight:            getEnvFloat("AGENT_LB_NETWORK_WEIGHT", 0.05),
				MaxDiskThroughputMBPS:    getEnvFloat("AGENT_LB_MAX_DISK_THROUGHPUT_MBPS", 500.0),
				MaxNetworkThroughputMBPS: getEnvFloat("AGENT_LB_MAX_NETWORK_THROUGHPUT_MBPS", 1000.0),
			},
		},
		Encryption: EncryptionConfig{
			Key:       getEnv("APP_ENCRYPTION_KEY", ""),
			KeyFormat: getEnv("APP_ENCRYPTION_KEY_FORMAT", ""),
		},
		AITriage: AITriageConfig{
			Enabled:                     getEnvBool("AI_TRIAGE_ENABLED", false),
			PlatformProvider:            getEnv("AI_PLATFORM_PROVIDER", "claude"),
			PlatformModel:               getEnv("AI_PLATFORM_MODEL", "claude-sonnet-4-20250514"),
			AnthropicAPIKey:             getEnv("ANTHROPIC_API_KEY", ""),
			OpenAIAPIKey:                getEnv("OPENAI_API_KEY", ""),
			GeminiAPIKey:                getEnv("GEMINI_API_KEY", ""),
			MaxConcurrentJobs:           getEnvInt("AI_MAX_CONCURRENT_JOBS", 10),
			RateLimitRPM:                getEnvInt("AI_RATE_LIMIT_RPM", 60),
			TimeoutSeconds:              getEnvInt("AI_TIMEOUT_SECONDS", 30),
			MaxTokens:                   getEnvInt("AI_MAX_TOKENS", 4096),
			Temperature:                 getEnvFloat("AI_TEMPERATURE", 0.1),
			DefaultAutoTriageEnabled:    getEnvBool("AI_AUTO_TRIAGE_DEFAULT_ENABLED", false),
			DefaultAutoTriageSeverities: getEnvSlice("AI_AUTO_TRIAGE_DEFAULT_SEVERITIES", []string{"critical", "high"}),
			DefaultAutoTriageDelay:      getEnvDuration("AI_AUTO_TRIAGE_DELAY", 60*time.Second),
			RecoveryEnabled:             getEnvBool("AI_TRIAGE_RECOVERY_ENABLED", true),
			RecoveryInterval:            getEnvDuration("AI_TRIAGE_RECOVERY_INTERVAL", 5*time.Minute),
			RecoveryStuckDuration:       getEnvDuration("AI_TRIAGE_RECOVERY_STUCK_DURATION", 15*time.Minute),
			RecoveryBatchSize:           getEnvInt("AI_TRIAGE_RECOVERY_BATCH_SIZE", 50),
		},
	}

	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	return cfg, nil
}

// Validate validates the configuration.
func (c *Config) Validate() error {
	if err := c.validateBasic(); err != nil {
		return err
	}
	if c.App.Env == EnvProduction {
		return c.validateProduction()
	}
	return nil
}

// validateBasic validates basic configuration regardless of environment.
func (c *Config) validateBasic() error {
	if c.Server.Port < 1 || c.Server.Port > 65535 {
		return fmt.Errorf("invalid server port: %d", c.Server.Port)
	}
	if c.Database.Host == "" {
		return fmt.Errorf("database host is required")
	}
	if err := c.validateAuth(); err != nil {
		return err
	}
	if err := c.validateEncryption(); err != nil {
		return err
	}
	if err := c.validateLog(); err != nil {
		return err
	}
	return nil
}

// validateLog validates logging configuration.
func (c *Config) validateLog() error {
	// Validate log level
	validLevels := map[string]bool{
		"debug": true, "DEBUG": true,
		"info": true, "INFO": true,
		"warn": true, "WARN": true,
		"error": true, "ERROR": true,
	}
	if c.Log.Level != "" && !validLevels[c.Log.Level] {
		return fmt.Errorf("invalid LOG_LEVEL: %s (must be debug, info, warn, or error)", c.Log.Level)
	}

	// Validate log format
	validFormats := map[string]bool{
		"json": true, "JSON": true,
		"text": true, "TEXT": true,
		"": true, // Empty is allowed (defaults to json)
	}
	if !validFormats[c.Log.Format] {
		return fmt.Errorf("invalid LOG_FORMAT: %s (must be json or text)", c.Log.Format)
	}

	// Validate sampling rate bounds
	if c.Log.SamplingRate < 0.0 || c.Log.SamplingRate > 1.0 {
		return fmt.Errorf("LOG_SAMPLING_RATE must be between 0.0 and 1.0, got %f", c.Log.SamplingRate)
	}

	// Validate error sampling rate bounds
	if c.Log.ErrorSamplingRate < 0.0 || c.Log.ErrorSamplingRate > 1.0 {
		return fmt.Errorf("LOG_ERROR_SAMPLING_RATE must be between 0.0 and 1.0, got %f", c.Log.ErrorSamplingRate)
	}

	// Validate sampling threshold
	if c.Log.SamplingThreshold < 0 {
		return fmt.Errorf("LOG_SAMPLING_THRESHOLD must be non-negative, got %d", c.Log.SamplingThreshold)
	}

	// Validate slow request threshold
	if c.Log.SlowRequestSeconds < 0 {
		return fmt.Errorf("LOG_SLOW_REQUEST_SECONDS must be non-negative, got %d", c.Log.SlowRequestSeconds)
	}

	return nil
}

// validateEncryption validates encryption configuration.
func (c *Config) validateEncryption() error {
	// Encryption key is optional in development, required in production
	if c.Encryption.Key == "" {
		if c.App.Env == EnvProduction {
			return fmt.Errorf("APP_ENCRYPTION_KEY is required in production")
		}
		return nil
	}

	// Validate key format and length
	keyLen := len(c.Encryption.Key)
	format := c.Encryption.KeyFormat

	// Auto-detect format if not specified
	if format == "" {
		switch {
		case keyLen == 32:
			format = "raw"
		case keyLen == 64:
			format = "hex"
		case keyLen == 44:
			format = "base64"
		default:
			return fmt.Errorf("APP_ENCRYPTION_KEY has invalid length %d (expected 32 raw, 64 hex, or 44 base64)", keyLen)
		}
		c.Encryption.KeyFormat = format
	}

	// Validate format
	switch format {
	case "raw":
		if keyLen != 32 {
			return fmt.Errorf("APP_ENCRYPTION_KEY with format 'raw' must be exactly 32 bytes, got %d", keyLen)
		}
	case "hex":
		if keyLen != 64 {
			return fmt.Errorf("APP_ENCRYPTION_KEY with format 'hex' must be exactly 64 characters, got %d", keyLen)
		}
	case "base64":
		if keyLen != 44 {
			return fmt.Errorf("APP_ENCRYPTION_KEY with format 'base64' must be exactly 44 characters, got %d", keyLen)
		}
	default:
		return fmt.Errorf("APP_ENCRYPTION_KEY_FORMAT must be 'raw', 'hex', or 'base64', got '%s'", format)
	}

	return nil
}

// validateAuth validates authentication configuration.
func (c *Config) validateAuth() error {
	if !c.Auth.Provider.IsValid() {
		return fmt.Errorf("invalid AUTH_PROVIDER: %s (must be 'local', 'oidc', or 'hybrid')", c.Auth.Provider)
	}

	// Local auth requires JWT secret
	if c.Auth.Provider.SupportsLocal() {
		if c.Auth.JWTSecret == "" {
			return fmt.Errorf("AUTH_JWT_SECRET is required when using local or hybrid authentication")
		}
		if len(c.Auth.JWTSecret) < 32 {
			return fmt.Errorf("AUTH_JWT_SECRET must be at least 32 characters")
		}
		if c.Auth.PasswordMinLength < 6 {
			return fmt.Errorf("AUTH_PASSWORD_MIN_LENGTH must be at least 6")
		}
		if c.Auth.MaxLoginAttempts < 1 {
			return fmt.Errorf("AUTH_MAX_LOGIN_ATTEMPTS must be at least 1")
		}
		if c.Auth.MaxActiveSessions < 1 {
			return fmt.Errorf("AUTH_MAX_ACTIVE_SESSIONS must be at least 1")
		}
	}

	// Validate OAuth configuration
	if err := c.validateOAuth(); err != nil {
		return err
	}

	return nil
}

// validateOAuth validates OAuth configuration.
func (c *Config) validateOAuth() error {
	if !c.OAuth.Enabled {
		return nil
	}

	// If any provider is enabled, we need state secret for CSRF protection
	if c.OAuth.HasAnyProvider() {
		if c.OAuth.StateSecret == "" {
			// Generate a warning but don't fail in development
			if c.App.Env == EnvProduction {
				return fmt.Errorf("OAUTH_STATE_SECRET is required when OAuth providers are enabled")
			}
		}
		if c.OAuth.FrontendCallbackURL == "" {
			return fmt.Errorf("OAUTH_FRONTEND_CALLBACK_URL is required when OAuth providers are enabled")
		}
	}

	return nil
}

// validateProduction validates production-specific configuration.
func (c *Config) validateProduction() error {
	// Only validate Keycloak if OIDC is supported
	if c.Auth.Provider.SupportsOIDC() {
		if err := c.validateProductionKeycloak(); err != nil {
			return err
		}
	}
	if err := c.validateProductionSecurity(); err != nil {
		return err
	}
	if err := c.validateProductionRedis(); err != nil {
		return err
	}
	if err := c.validateProductionAuth(); err != nil {
		return err
	}
	return nil
}

// validateProductionAuth validates auth configuration for production.
func (c *Config) validateProductionAuth() error {
	if c.Auth.Provider.SupportsLocal() {
		// Ensure strong JWT secret in production
		if len(c.Auth.JWTSecret) < 64 {
			return fmt.Errorf("AUTH_JWT_SECRET must be at least 64 characters in production")
		}
		// Ensure reasonable password policy
		if c.Auth.PasswordMinLength < 8 {
			return fmt.Errorf("AUTH_PASSWORD_MIN_LENGTH must be at least 8 in production")
		}
		// Ensure email verification is required
		if !c.Auth.RequireEmailVerification {
			return fmt.Errorf("AUTH_REQUIRE_EMAIL_VERIFICATION must be true in production")
		}
		// Ensure secure cookie settings in production
		if !c.Auth.CookieSecure {
			return fmt.Errorf("AUTH_COOKIE_SECURE must be true in production (HTTPS required)")
		}
		// Validate SameSite policy
		switch c.Auth.CookieSameSite {
		case "strict", "lax":
			// Valid for same-site deployments
		case "none":
			// Valid for cross-site but requires Secure flag
			if !c.Auth.CookieSecure {
				return fmt.Errorf("AUTH_COOKIE_SECURE must be true when SameSite=None")
			}
		default:
			return fmt.Errorf("AUTH_COOKIE_SAMESITE must be 'strict', 'lax', or 'none'")
		}
	}
	return nil
}

// validateProductionKeycloak validates Keycloak configuration for production.
func (c *Config) validateProductionKeycloak() error {
	if c.Keycloak.BaseURL == "" || c.Keycloak.BaseURL == "http://localhost:8080" {
		return fmt.Errorf("KEYCLOAK_BASE_URL must be set in production")
	}
	if c.Keycloak.Realm == "" || c.Keycloak.Realm == "openctem" {
		return fmt.Errorf("KEYCLOAK_REALM must be set in production")
	}
	// Ensure HTTPS in production
	if !strings.HasPrefix(c.Keycloak.BaseURL, "https://") {
		return fmt.Errorf("KEYCLOAK_BASE_URL must use HTTPS in production")
	}
	return nil
}

// validateProductionSecurity validates security settings for production.
func (c *Config) validateProductionSecurity() error {
	if slices.Contains(c.CORS.AllowedOrigins, "*") {
		return fmt.Errorf("CORS wildcard origin not allowed in production")
	}
	if c.Database.SSLMode == "disable" {
		return fmt.Errorf("database SSL must be enabled in production (use 'require' or 'verify-full')")
	}
	if !c.RateLimit.Enabled {
		return fmt.Errorf("rate limiting must be enabled in production")
	}
	if c.App.Debug {
		return fmt.Errorf("debug mode must be disabled in production")
	}
	if c.Log.Level == "debug" {
		return fmt.Errorf("log level should not be 'debug' in production")
	}
	return nil
}

// validateProductionRedis validates Redis configuration for production.
func (c *Config) validateProductionRedis() error {
	if c.Redis.Password == "" {
		return fmt.Errorf("redis password must be set in production")
	}
	if len(c.Redis.Password) < 32 {
		return fmt.Errorf("redis password must be at least 32 characters in production")
	}
	if !c.Redis.TLSEnabled {
		return fmt.Errorf("redis TLS must be enabled in production")
	}
	if c.Redis.TLSSkipVerify {
		return fmt.Errorf("redis TLS skip verify must be false in production")
	}
	if c.Redis.PoolSize < 10 || c.Redis.PoolSize > 500 {
		return fmt.Errorf("redis pool size must be between 10 and 500 in production, got %d", c.Redis.PoolSize)
	}
	if c.Redis.DialTimeout < time.Second {
		return fmt.Errorf("redis dial timeout too short: %v (min 1s)", c.Redis.DialTimeout)
	}
	if c.Redis.ReadTimeout < time.Second {
		return fmt.Errorf("redis read timeout too short: %v (min 1s)", c.Redis.ReadTimeout)
	}
	if c.Redis.WriteTimeout < time.Second {
		return fmt.Errorf("redis write timeout too short: %v (min 1s)", c.Redis.WriteTimeout)
	}
	if c.Redis.MaxRetries < 1 || c.Redis.MaxRetries > 10 {
		return fmt.Errorf("redis max retries must be between 1 and 10, got %d", c.Redis.MaxRetries)
	}
	return nil
}

// DSN returns the database connection string.
func (c *DatabaseConfig) DSN() string {
	return fmt.Sprintf(
		"host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
		c.Host, c.Port, c.User, c.Password, c.Name, c.SSLMode,
	)
}

// Addr returns the Redis address.
func (c *RedisConfig) Addr() string {
	return fmt.Sprintf("%s:%d", c.Host, c.Port)
}

// Addr returns the HTTP server address.
func (c *ServerConfig) Addr() string {
	return fmt.Sprintf("%s:%d", c.Host, c.Port)
}

// IsDevelopment returns true if the application is in development mode.
func (c *Config) IsDevelopment() bool {
	return c.App.Env == "development"
}

// IsProduction returns true if the application is in production mode.
func (c *Config) IsProduction() bool {
	return c.App.Env == EnvProduction
}

// Helper functions

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getEnvInt(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		if intVal, err := strconv.Atoi(value); err == nil {
			return intVal
		}
	}
	return defaultValue
}

func getEnvInt64(key string, defaultValue int64) int64 {
	if value := os.Getenv(key); value != "" {
		if intVal, err := strconv.ParseInt(value, 10, 64); err == nil {
			return intVal
		}
	}
	return defaultValue
}

func getEnvBool(key string, defaultValue bool) bool {
	if value := os.Getenv(key); value != "" {
		if boolVal, err := strconv.ParseBool(value); err == nil {
			return boolVal
		}
	}
	return defaultValue
}

func getEnvDuration(key string, defaultValue time.Duration) time.Duration {
	if value := os.Getenv(key); value != "" {
		if duration, err := time.ParseDuration(value); err == nil {
			return duration
		}
	}
	return defaultValue
}

func getEnvFloat(key string, defaultValue float64) float64 {
	if value := os.Getenv(key); value != "" {
		if floatVal, err := strconv.ParseFloat(value, 64); err == nil {
			return floatVal
		}
	}
	return defaultValue
}

func getEnvSlice(key string, defaultValue []string) []string {
	if value := os.Getenv(key); value != "" {
		var result []string
		for _, v := range splitAndTrim(value, ",") {
			if v != "" {
				result = append(result, v)
			}
		}
		if len(result) > 0 {
			return result
		}
	}
	return defaultValue
}

func splitAndTrim(s, sep string) []string {
	parts := make([]string, 0)
	for _, p := range strings.Split(s, sep) {
		trimmed := strings.TrimSpace(p)
		if trimmed != "" {
			parts = append(parts, trimmed)
		}
	}
	return parts
}
