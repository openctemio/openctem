// Package config loads and validates application configuration from environment variables.
package config

import (
	"fmt"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/openctemio/openctem/api/pkg/crypto"
	sensordom "github.com/openctemio/openctem/api/pkg/domain/sensor"
)

// Environment constants
const (
	EnvProduction = "production"
)

// Config holds all application configuration.
type Config struct {
	App          AppConfig
	Server       ServerConfig
	GRPC         GRPCConfig
	Database     DatabaseConfig
	Redis        RedisConfig
	Log          LogConfig
	Auth         AuthConfig
	OAuth        OAuthConfig
	Keycloak     KeycloakConfig
	CORS         CORSConfig
	RateLimit    RateLimitConfig
	SMTP         SMTPConfig
	Worker       SensorConfig
	Encryption   EncryptionConfig
	AITriage     AITriageConfig
	SensorConfig SensorConfigConfig
	Storage      StorageConfig
	Webhooks     WebhooksConfig
	Ingest       IngestConfig
	Metrics      MetricsConfig

	// AdminAuditRetention controls pruning of the platform-level
	// admin_audit_logs table.
	AdminAuditRetention AdminAuditRetentionConfig

	// AuditRetention controls the tenant audit log retention (hash-chain
	// prefix archive and prune).
	AuditRetention AuditRetentionConfig

	// Scope is the platform's scope guardrails (RFC-054 §8): operator-level,
	// never tenant-overridable.
	Scope ScopeConfig
}

// Active-probe proof modes, SCOPE_ACTIVE_PROOF (RFC-054 §8.1).
const (
	// ScopeProofOff: no proof needed (self-hosted default: the operator is
	// the tenant). Intrusive probes still need a verified domain.
	ScopeProofOff = "off"
	// ScopeProofPlatformSensors: a job on shared platform sensors needs every
	// target at or under a verified domain of the tenant (SaaS default).
	ScopeProofPlatformSensors = "platform_sensors"
	// ScopeProofAll: every active probe needs a verified domain.
	ScopeProofAll = "all"
)

// ScopeConfig is the operator's scope guardrails.
type ScopeConfig struct {
	// ActiveProof is off, platform_sensors or all. Unset: platform_sensors
	// when organizations are self-service (SaaS), otherwise off.
	ActiveProof string
	// MaxPublicCIDRv4 / v6 cap a public scope range (SCOPE_MAX_PUBLIC_CIDR_V4,
	// default 16; SCOPE_MAX_PUBLIC_CIDR_V6, default 32).
	MaxPublicCIDRv4 int
	MaxPublicCIDRv6 int
	// DenyExtra are the operator's own names and ranges no tenant may
	// target (SCOPE_DENY_EXTRA, comma-separated domains and CIDRs).
	DenyExtra []string
}

// validate checks the proof mode.
func (s ScopeConfig) validate() error {
	switch s.ActiveProof {
	case ScopeProofOff, ScopeProofPlatformSensors, ScopeProofAll:
		return nil
	}
	return fmt.Errorf("SCOPE_ACTIVE_PROOF must be off, platform_sensors or all, got %q", s.ActiveProof)
}

// AuditRetentionConfig controls tenant audit-log retention. Entries older than
// Days are written to a gzip JSONL archive under ArchiveDir, the chain head
// they leave is recorded as an anchor, then they are deleted. Without an
// ArchiveDir nothing is deleted. Days below 365 are raised to 365.
type AuditRetentionConfig struct {
	Days       int    // AUDIT_RETENTION_DAYS, default 365, minimum 365
	ArchiveDir string // AUDIT_ARCHIVE_DIR, default "" (retention off)
}

// AdminAuditRetentionConfig controls the admin-audit-log retention controller.
//
// admin_audit_logs is append-only and every platform-admin action writes a
// row, so without pruning the table grows forever. Deletion is irreversible
// and compliance-relevant (SOC 2 / PCI DSS want >= 1 year), so the controller
// ships in dry-run mode: it reports what it WOULD delete and deletes nothing
// until an operator sets ADMIN_AUDIT_RETENTION_DRY_RUN=false. That keeps an
// upgrade from silently destroying audit history, while making the retention
// policy an actual switch instead of a compiled-in constant.
type AdminAuditRetentionConfig struct {
	// Enabled registers the controller at all. Default true — in dry-run
	// mode it only reports, which is what makes the growth visible.
	// ADMIN_AUDIT_RETENTION_ENABLED
	Enabled bool

	// DryRun reports the row count instead of deleting. Default TRUE.
	// ADMIN_AUDIT_RETENTION_DRY_RUN
	DryRun bool

	// RetentionDays is the age threshold. Default 365.
	// ADMIN_AUDIT_RETENTION_DAYS
	RetentionDays int

	// Interval is how often the sweep runs. Default 24h.
	// ADMIN_AUDIT_RETENTION_INTERVAL
	Interval time.Duration

	// BatchSize bounds one delete transaction. Default 10000.
	// ADMIN_AUDIT_RETENTION_BATCH_SIZE
	BatchSize int
}

// MetricsConfig controls exposure of the Prometheus /metrics endpoint.
//
// SECURITY: /metrics leaks internal cardinality (route names, error rates,
// build info) and is a reconnaissance aid, so it is NOT public by default.
// When Public is false (the default) the endpoint requires a bearer token
// (Token) supplied via the Authorization header, e.g.
//
//	Authorization: Bearer <METRICS_TOKEN>
//
// Configure the scraper (Prometheus `authorization`/`bearer_token`) with the
// same value. If Public is false and Token is empty the endpoint fails closed
// (404) — metrics are effectively disabled until a token is set or Public is
// explicitly enabled. Set METRICS_PUBLIC=true to restore the legacy open
// endpoint (e.g. when it is already firewalled to an internal scrape network).
type MetricsConfig struct {
	// Public leaves /metrics unauthenticated when true (legacy behavior).
	// Default false.
	Public bool
	// Token is the bearer token required to scrape /metrics when Public is
	// false. Empty + non-public = endpoint disabled (fail closed).
	Token string
}

// IngestConfig controls asynchronous ingest (RFC-005).
type IngestConfig struct {
	// Mode is "sync" (default — process in the request) or "async" (enqueue +
	// 202, processed by the ingest worker). Async is opt-in per deployment.
	Mode string
	// MaxPendingPerTenant bounds a tenant's queue depth; further submissions get
	// 429 + Retry-After. 0 disables the check.
	MaxPendingPerTenant int

	// V2Results mounts sensor protocol v2 results (RFC-026) at
	// /api/v2/sensor, processes its jobs and advertises it to v1 sensors that
	// ask. SENSOR_PROTOCOL_V2_RESULTS (default true; false unmounts it).
	V2Results bool
	// V2BlindingRatio and V2BlindingMinFindings are the blinding guard of a
	// v2 commit: an auto-resolve that would close more than MinFindings and
	// more than Ratio of the open findings of that tool on the report's
	// assets is held for review. SENSOR_V2_BLINDING_RATIO (0.5),
	// SENSOR_V2_BLINDING_MIN_FINDINGS (100).
	V2BlindingRatio       float64
	V2BlindingMinFindings int

	// CoverageAutoResolve is the mode of coverage-scoped auto-resolve for
	// non-repository findings: "off", "dry_run" (default: log, metric and a
	// "would resolve" audit entry, no state change) or "enforce".
	// INGEST_COVERAGE_AUTO_RESOLVE.
	CoverageAutoResolve string

	// SourceResolve is the mode of source-asserted resolve: a connector
	// source (Tenable.sc) reporting a finding as mitigated resolves the
	// matching open finding (RFC-047 §7.6): "off", "dry_run" (default: count
	// and log, no state change) or "enforce". INGEST_SOURCE_RESOLVE.
	SourceResolve string

	// VEX is how a VEX not_affected statement in a report acts on the
	// matching open finding (CTIS 1.4): "off", "dry_run" (default: count,
	// log and audit, no state change) or "enforce" (the finding becomes
	// false_positive with the justification). INGEST_VEX.
	VEX string
}

// AsyncEnabled reports whether async ingest mode is on.
func (c IngestConfig) AsyncEnabled() bool { return c.Mode == "async" }

// WebhooksConfig holds shared secrets for incoming webhook HMAC verification (F-1).
// These are platform-wide fallbacks; per-integration secrets can be layered on
// top via the integration repository when that abstraction is added.
type WebhooksConfig struct {
	// JiraSecret is the HMAC-SHA256 secret used to verify inbound Jira webhooks
	// at POST /api/v1/webhooks/incoming/jira. REQUIRED — if empty, the endpoint
	// rejects all requests (fail closed).
	JiraSecret string
}

// StorageConfig holds file attachment storage settings.
// Default: local filesystem at ./data/attachments.
// Future: S3, MinIO, GCS via provider selection per-tenant.
type StorageConfig struct {
	// Provider selects the storage backend: "local" (default), "s3", "minio"
	Provider string
	// LocalPath is the filesystem path for the "local" provider.
	// Default: ./data/attachments
	// In Docker: mount a volume to persist across container rebuilds.
	LocalPath string
	// S3/MinIO settings (STORAGE_PROVIDER=s3 or minio): the server-wide bucket.
	// Endpoint empty = AWS S3; set it for MinIO or another S3-compatible store.
	Bucket    string
	Region    string
	Endpoint  string
	AccessKey string
	SecretKey string
}

// AppConfig holds application-level configuration.
type AppConfig struct {
	Name  string
	Env   string
	Debug bool
	URL   string // Public app URL (used as fallback for sensor config base URL)
}

// SensorConfigConfig holds the sensor config template service settings.
type SensorConfigConfig struct {
	// TransportV3 is sensor protocol v3 (RFC-059,
	// docs/rfcs/RFC-059-sensor-transport-v3.md).
	TransportV3 SensorTransportV3Config
	// TemplatesDir is the filesystem path containing sensor config templates
	// (yaml.tmpl, env.tmpl, docker.tmpl, cli.tmpl). Operators can edit these
	// without rebuilding the API or UI.
	// Default: configs/sensor-templates
	TemplatesDir string
	// PublicAPIURL is the URL sensors will connect to (embedded in templates).
	// If empty, falls back to App.URL.
	PublicAPIURL string
	// KeyTTL is how long a self-renewed sensor API key stays valid before it
	// must be renewed again (RFC-014 Phase 1b, RFC-032 Phase 0):
	// SENSOR_KEY_TTL, default DefaultSensorKeyTTL (90 days). "0" disables
	// expiry: renewed keys never expire. Only renewal applies it: a key an
	// administrator creates or regenerates never expires, and a sensor that
	// does not renew keeps its key.
	KeyTTL time.Duration
	// KeyRenewGrace is how long the key a sensor renewed with keeps
	// authenticating after the renewal, for requests already in flight;
	// every other key the sensor held is cut to the same moment, so a
	// renewal leaves one long-lived key and a copied key cannot renew a
	// parallel line of its own. SENSOR_KEY_RENEW_GRACE, default
	// DefaultSensorKeyRenewGrace (15 minutes); "0" retires it at once.
	KeyRenewGrace time.Duration
	// KeyPepper is the secret the sensor API-key hash (HMAC-SHA256) is keyed
	// with: SENSOR_KEY_PEPPER. Empty (the default) derives it from
	// APP_ENCRYPTION_KEY with HKDF, so the MAC key is never the encryption
	// key itself (RFC-032 Phase 0, G9). Keys stored under the old pepper (the
	// encryption key) keep verifying.
	KeyPepper string
	// KeyPepperPrevious lists earlier explicit peppers (comma-separated
	// SENSOR_KEY_PEPPER_PREVIOUS) whose hashes keep verifying while keys
	// rotate onto a new SENSOR_KEY_PEPPER.
	KeyPepperPrevious []string
	// KeyRenewBefore is how long before the presented key expires the
	// heartbeat starts ringing rotate_key. Zero (the default) means half of
	// KeyTTL, or 24h when no TTL is set. SENSOR_KEY_RENEW_BEFORE.
	KeyRenewBefore time.Duration
	// SlimHeartbeat lets a sensor whose manifest is acknowledged leave its
	// tool inventory out of heartbeats (RFC-033 §6.12, owner decision O3):
	// SENSOR_SLIM_HEARTBEAT, default true. false is the kill switch: manifest
	// answers say omit_inventory false and a slim heartbeat is asked for the
	// manifest again, so the sensor goes back to full heartbeats.
	SlimHeartbeat bool

	// Heartbeat doorbell (RFC-023 §9.2a): the intervals the heartbeat
	// response advises in next_heartbeat_seconds. Every value is clamped to
	// [HeartbeatMinInterval, HeartbeatMaxInterval], and the maximum to half
	// of WORKER_HEARTBEAT_TIMEOUT so a sensor that follows the advice is
	// never marked offline.
	HeartbeatInterval       time.Duration // SENSOR_HEARTBEAT_INTERVAL, idle (default 30s)
	HeartbeatBusyInterval   time.Duration // SENSOR_HEARTBEAT_BUSY_INTERVAL, work waiting (default 5s)
	HeartbeatLoadedInterval time.Duration // SENSOR_HEARTBEAT_LOADED_INTERVAL, platform under load (default 2m)
	HeartbeatMinInterval    time.Duration // SENSOR_HEARTBEAT_MIN_INTERVAL (default 5s)
	HeartbeatMaxInterval    time.Duration // SENSOR_HEARTBEAT_MAX_INTERVAL (default 5m)
	// HeartbeatSlowQuery is the doorbell query latency that counts as "under
	// load" and advises HeartbeatLoadedInterval. SENSOR_HEARTBEAT_SLOW_QUERY
	// (default 250ms).
	HeartbeatSlowQuery time.Duration

	// CommandLease is how long a sensor holds a claimed command without
	// renewing its lease (every heartbeat that lists the command renews
	// it). A command whose lease runs out goes back to the queue, and the
	// sensor that held it can no longer complete it (RFC-035 D6).
	// SENSOR_COMMAND_LEASE, default 3m, clamped to 1m-30m.
	CommandLease time.Duration

	// Platform-health guard of the sensor health controller (RFC-035 D3):
	// no sensor is convicted offline while the platform itself is slow.
	// HealthSlowHeartbeat is the heartbeat handling p95 that counts as slow
	// (SENSOR_HEALTH_SLOW_HEARTBEAT, default 2s); HealthStartupGrace is how
	// long after the API starts no sensor is convicted
	// (SENSOR_HEALTH_STARTUP_GRACE, default 0 = the offline distance of a
	// sensor on the SDK's 60s default interval, 4m).
	HealthSlowHeartbeat time.Duration
	HealthStartupGrace  time.Duration

	// LatestVersion is the newest sensor release (SENSOR_LATEST_VERSION,
	// default DefaultSensorLatestVersion). The Sensors page compares each
	// sensor's version with it ("update available"), and the install
	// snippets pin the image to it. Empty turns the comparison off.
	LatestVersion string
	// MinVersion is the oldest sensor release still supported
	// (SENSOR_MIN_VERSION, default DefaultSensorMinVersion; empty = no
	// minimum). A heartbeating sensor below it shows as degraded with
	// "version unsupported".
	MinVersion string
	// SDKMinVersion is the oldest SDK release still supported
	// (SENSOR_SDK_MIN_VERSION, default DefaultSensorSDKMinVersion; empty = no
	// minimum). A heartbeating sensor built with an older SDK shows as
	// degraded with "sdk_unsupported".
	SDKMinVersion string
	// SDKLatestVersion is the newest SDK release (SENSOR_SDK_LATEST_VERSION,
	// default DefaultSensorSDKLatestVersion). A sensor built with an older SDK
	// has sdk_status "outdated"; empty turns that comparison off.
	SDKLatestVersion string

	// Image is the sensor image repository the install snippets run
	// (SENSOR_IMAGE, default ghcr.io/openctemio/sensor). The tag is
	// LatestVersion (DefaultSensorLatestVersion when that is off), never
	// "latest", so a snippet installs the release the page compares against.
	Image string
	// CACertFile is the platform's private CA certificate (PEM) the install
	// snippets install on the sensor host (SENSOR_CA_CERT_FILE). Set it when
	// the platform uses the built-in gateway in TLS mode internal: mount the
	// gateway's CA export directory into the API read-only and point this at
	// openctem-root-ca.crt. Empty: the certificate is publicly trusted.
	CACertFile string
}

// DefaultSensorKeyTTL is how long a renewed sensor API key stays valid when
// SENSOR_KEY_TTL is not set: 90 days, renewed at half-life (45 days before
// expiry, SENSOR_KEY_RENEW_BEFORE). The install snippets and the Helm chart
// keep the renewed key on a persistent volume, and the sensor renews on its
// own only when that volume persists (RFC-032 Phase 0).
const DefaultSensorKeyTTL = 90 * 24 * time.Hour

// DefaultSensorKeyRenewGrace is how long a renewed-away sensor key keeps
// working when SENSOR_KEY_RENEW_GRACE is not set.
const DefaultSensorKeyRenewGrace = 15 * time.Minute

// Sensor and SDK release defaults. They are copied from versions.yaml at the
// repository root by .github/scripts/release/sync-versions.sh, and CI fails
// when they drift (RFC-037): change versions.yaml, never these lines.
//
// DefaultSensorLatestVersion is the newest sensor release when this API was
// built. Override with SENSOR_LATEST_VERSION when a newer sensor ships before
// the platform is upgraded; set it to "none" to turn the comparison off.
const DefaultSensorLatestVersion = "v0.6.4"

// DefaultSensorMinVersion is the oldest supported sensor release
// (SENSOR_MIN_VERSION); empty means no minimum.
const DefaultSensorMinVersion = ""

// DefaultSensorSDKLatestVersion is the newest SDK release
// (SENSOR_SDK_LATEST_VERSION); empty turns the "outdated" comparison off.
const DefaultSensorSDKLatestVersion = "v0.14.0"

// DefaultSensorSDKMinVersion is the oldest supported SDK release
// (SENSOR_SDK_MIN_VERSION); empty means no minimum.
const DefaultSensorSDKMinVersion = ""

// DefaultSensorImageRepository is the published sensor image.
const DefaultSensorImageRepository = "ghcr.io/openctemio/sensor"

// ServerConfig holds HTTP server configuration.
type ServerConfig struct {
	Host                  string
	Port                  int
	ReadTimeout           time.Duration
	WriteTimeout          time.Duration
	RequestTimeout        time.Duration // Per-request handler timeout
	ShutdownTimeout       time.Duration
	MaxBodySize           int64
	SessionTimeoutMinutes int // Session timeout in minutes (0 = disabled, default: 30)
	MaxConcurrentRequests int // Maximum concurrent requests (default: 1000)
	// TrustedProxies is the list of CIDR ranges (or bare IPs) whose
	// X-Real-IP / X-Forwarded-For headers will be honored. Requests from
	// peers outside this list have their forwarding headers ignored —
	// preventing IP spoofing of rate-limit and audit-log keys (S-4).
	// Empty list = treat the API as directly Internet-facing. X-Forwarded-For
	// is read right to left (list every proxy hop); X-Real-IP is used only when
	// X-Forwarded-For is absent (see httpsec.ClientIP).
	// Configure via SERVER_TRUSTED_PROXIES (comma-separated CIDRs).
	TrustedProxies []string
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
	// JITEnabled controls PostgreSQL's JIT compiler for the API's sessions
	// (env DB_JIT_ENABLED, default false). JIT pays off for long analytical
	// queries, but for this API's request-path queries the compile step is
	// pure overhead that kicks in as soon as row estimates cross
	// jit_above_cost: measured 351ms of JIT in a 533ms dashboard trend query
	// on a 200k-finding tenant. Disabled by default, per session, via the
	// connection startup parameter; the server-wide setting is untouched.
	JITEnabled bool
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
	TLSCertFile   string // Path to TLS certificate file (optional, for mTLS)
	TLSKeyFile    string // Path to TLS key file (optional, for mTLS)
	TLSCAFile     string // Path to CA certificate file (optional, for custom CA)
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

// Organization (tenant) creation modes, TENANT_CREATION_MODE (RFC-022 D8).
const (
	// TenantCreationSelfService lets any signed-in user create an organization
	// (SaaS / trial installs). An explicit opt-in.
	TenantCreationSelfService = "self_service"
	// TenantCreationAdminOnly reserves organization creation for the platform
	// administrator: the admin console, or bootstrap-admin -org-name at first
	// install (on-prem / enterprise, Tenable Security Center style). The
	// default.
	TenantCreationAdminOnly = "admin_only"
)

// SelfServiceTenantCreation reports whether signed-in users may create
// organizations themselves. It fails closed: only an explicit
// TENANT_CREATION_MODE=self_service opens it.
func (c AuthConfig) SelfServiceTenantCreation() bool {
	return c.TenantCreationMode == TenantCreationSelfService
}

// AuthConfig holds authentication configuration.
type AuthConfig struct {
	// TenantCreationMode is TenantCreationSelfService or TenantCreationAdminOnly.
	// The platform administrator can create organizations in either mode.
	// Anything but TenantCreationSelfService (including empty) is admin-only:
	// use SelfServiceTenantCreation to test it.
	TenantCreationMode string

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
	PasswordMinLength      int  // Minimum password length (default: 12)
	PasswordRequireUpper   bool // Require uppercase letter
	PasswordRequireLower   bool // Require lowercase letter
	PasswordRequireNumber  bool // Require number
	PasswordRequireSpecial bool // Require special character

	// Security settings
	MaxLoginAttempts  int           // Max failed attempts before lockout (default: 5)
	LockoutDuration   time.Duration // Account lockout duration (default: 15m)
	MaxActiveSessions int           // Max concurrent sessions per user (default: 10)

	// Registration settings
	// AllowRegistration lets anyone create an account on /auth/register
	// (AUTH_ALLOW_REGISTRATION, default false). Off by default: accounts come
	// from an administrator, an invitation, or the organization SSO.
	// An invited person can still register with their invitation token.
	AllowRegistration        bool
	RequireEmailVerification bool // Require email verification (default: true)

	// Email verification/reset token settings
	EmailVerificationDuration time.Duration // Email verification token lifetime (default: 24h)
	PasswordResetDuration     time.Duration // Password reset token lifetime (default: 1h)

	// Cookie settings for tokens (security best practice)
	CookieSecure           bool   // Secure flag (HTTPS only); defaults true unless APP_ENV=development, required in production
	CookieDomain           string // Cookie domain (empty = current host)
	CookieSameSite         string // SameSite policy: "strict", "lax", or "none"
	AccessTokenCookieName  string // Cookie name for access token (default: "auth_token")
	RefreshTokenCookieName string // Cookie name for refresh token (default: "refresh_token")
	TenantCookieName       string // Cookie name for tenant (default: "app_tenant")

	// EntraSSO is the platform-wide Microsoft Entra ID SSO fallback. When a
	// tenant has NOT configured its own entra_id identity provider, the SSO
	// flow falls back to this shared config (if Enabled). A tenant's own
	// provider always takes precedence.
	EntraSSO EntraSSOConfig

	// AllowedRedirectURIs is the exact-match allow-list for the caller-supplied
	// redirect_uri of the per-tenant SSO OIDC flow (SSO_ALLOWED_REDIRECT_URIS,
	// csv). It is the OAuth 2.1 / RFC 9700 open-redirect guard: the frontend
	// callback the SSO flow returns to must match one of these entries exactly.
	// Each entry is a trusted frontend origin (scheme+host[:port], authorizing
	// any path on that exact origin) or an origin+path prefix (ending in "/",
	// restricting to that path). No wildcards, no suffix matching. When left
	// empty at load time it is derived from the configured frontend origins
	// (CORS allowed origins + OAuth frontend callback) so the shipped UI keeps
	// working; an empty list at request time fails closed (rejects every URI).
	AllowedRedirectURIs []string
}

// EntraSSOConfig holds the platform-wide (env-based) Microsoft Entra ID SSO
// fallback used when a tenant has no entra_id provider of its own.
type EntraSSOConfig struct {
	Enabled        bool     // SSO_ENTRA_ENABLED
	ClientID       string   // SSO_ENTRA_CLIENT_ID
	ClientSecret   string   // SSO_ENTRA_CLIENT_SECRET (plaintext — env is the trust boundary)
	TenantID       string   // SSO_ENTRA_TENANT_ID (Entra directory id; default "common")
	AllowedDomains []string // SSO_ENTRA_ALLOWED_DOMAINS (csv; empty = any)
	DefaultRole    string   // SSO_ENTRA_DEFAULT_ROLE (default "viewer", least privilege)
	AutoProvision  bool     // SSO_ENTRA_AUTO_PROVISION (default true)
	DisplayName    string   // SSO_ENTRA_DISPLAY_NAME (default "Microsoft Entra ID")

	// AllowedTenants is the opt-in allow-list of tenant SLUGS (SSO_ENTRA_ALLOWED_TENANTS,
	// csv) that may use this platform-wide env fallback. It is fail-closed: a tenant
	// whose slug is NOT listed gets NO env SSO button and NO env-fallback login, so a
	// shared multi-tenant (`/common`) app registration cannot let any Microsoft account
	// self-join every organization. Empty ⇒ the env fallback is disabled for all tenants.
	AllowedTenants []string // SSO_ENTRA_ALLOWED_TENANTS (csv of tenant slugs; empty = none)
}

// IsConfigured reports whether the platform-wide Entra SSO fallback is usable:
// enabled and carrying the minimum credentials to drive an OAuth code flow.
func (c EntraSSOConfig) IsConfigured() bool {
	return c.Enabled && c.ClientID != "" && c.ClientSecret != ""
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

	// AllowedRedirectURLs is a whitelist of allowed OAuth redirect URLs.
	// If empty, only the FrontendCallbackURL origin is allowed.
	AllowedRedirectURLs []string

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

// SMTPFromEnv reads the system SMTP settings (SMTP_*) on their own, for tools
// such as bootstrap-admin that send email without loading (and validating) the
// whole server configuration.
func SMTPFromEnv() SMTPConfig {
	return SMTPConfig{
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
	}
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
	// ReadRequestsPerMin is the per-user budget for authenticated GET
	// requests (the read-endpoint limiter). It is also the burst, so a
	// page that fires many parallel reads on load does not trip it.
	// Env: RATE_LIMIT_READ_PER_MIN. Default 120. Values <= 0 fall back
	// to the default; they never disable the limiter.
	ReadRequestsPerMin int
}

// SensorTransportV3Config configures sensor protocol v3 (RFC-059).
type SensorTransportV3Config struct {
	// Enabled mounts v3: the HTTPS binding under /api/v3/sensor (and, with a
	// sensor CA, the gRPC binding). SENSOR_TRANSPORT_V3_ENABLED, default
	// false: nothing changes for sensors until an operator turns it on.
	Enabled bool
	// PublicHost is host[:port] sensors dial for the gRPC binding
	// (SENSOR_PUBLIC_HOST, e.g. sensors.example.com:443). Empty: the
	// platform serves only the HTTPS binding (no mTLS listener).
	PublicHost string
	// MTLSListenAddr is the gRPC binding's TLS 1.3 listener
	// (SENSOR_MTLS_LISTEN_ADDR, default :8443). The gateway passes the
	// PublicHost name through to it at layer 4.
	MTLSListenAddr string
	// CACertFile and CAKeyFile are the sensor CA (SENSOR_MTLS_CA_CERT_FILE,
	// SENSOR_MTLS_CA_KEY_FILE, PEM). Its key is not the job signer's.
	CACertFile string
	CAKeyFile  string
	// CADir is where the sensor CA is created once when the two files are
	// not set (SENSOR_MTLS_CA_DIR, default data/sensor-ca).
	CADir string
	// CertTTL is the client certificate lifetime (SENSOR_MTLS_CERT_TTL,
	// default 168h, clamped to 1h..720h).
	CertTTL time.Duration
}

// SensorConfig holds sensor management configuration.
type SensorConfig struct {
	// HeartbeatTimeout is the duration after which a sensor is marked as inactive
	// if no heartbeat is received. Default: 5 minutes.
	HeartbeatTimeout time.Duration

	// HealthCheckInterval is how often to check for stale sensors.
	// Default: 1 minute.
	HealthCheckInterval time.Duration

	// Enabled turns on the legacy sensor health checker (jobs.SensorHealthChecker,
	// WORKER_HEALTH_CHECK_ENABLED). Default: false. The sensor health controller
	// (internal/infra/controller/sensor_health.go, RFC-035 §5.6) owns liveness:
	// it applies the late/stale/offline ladder and holds convictions during its
	// startup grace and while the platform itself is slow. The legacy checker
	// knows none of that and sweeps the moment the API starts, so with it on an
	// API restart convicted every sensor that could not heartbeat while the API
	// was down. Keep it off unless the health controller is not running.
	Enabled bool

	// SCMSyncInterval is how often the scheduled SCM repository/branch sync runs.
	// 0 (default) disables it — repositories are then only imported on demand via
	// POST /integrations/{id}/import-repositories. Set SCM_SYNC_INTERVAL (e.g. 6h)
	// to enable periodic auto-import + branch sync + expired-token detection.
	SCMSyncInterval time.Duration

	// CTEMIDFeedURL is the CTEM-ID catalog feed the daily ctem-id-refresh
	// controller mirrors into local reference storage. Behind the same
	// feed-refresh machinery as the EPSS/KEV threat-intel refresh. Set
	// CTEM_ID_FEED_URL to override; defaults to https://ctem.org/source.json.
	CTEMIDFeedURL string

	// CertMonitorEnabled toggles the Certificate-Transparency discovery sweep
	// (the cert-monitor controller). Default true — it is a passive, public-data,
	// no-credentials external-exposure source. Set CERT_MONITOR_ENABLED=false to
	// disable outbound crt.sh polling entirely.
	CertMonitorEnabled bool

	// CertMonitorFeedBaseURL is the CT-log aggregator the cert-monitor controller
	// queries per tenant domain. Set CERT_MONITOR_FEED_URL to override; defaults
	// to https://crt.sh. Queried via the SSRF-guarded SafeHTTPClient.
	CertMonitorFeedBaseURL string

	// CertMonitorInterval is how often the CT sweep runs across all tenants.
	// Defaults to 24h (daily), matching the threat-intel / CTEM-ID refreshes.
	CertMonitorInterval time.Duration

	// EASMDNSChecksEnabled toggles the daily DNS-only EASM checks (dangling
	// CNAME/NS, email posture; RFC-036 P1). Passive: the platform's resolver
	// is asked about the tenant's own names. EASM_DNS_CHECKS_ENABLED, default
	// true (research/22 owner decision E3): cheap T0 checks for every tenant
	// with the attack-surface module; each tenant's run holds a controller
	// lease, and the per-run name cap and QPS bound the work. Set false to
	// turn them off platform-wide.
	EASMDNSChecksEnabled bool
	// EASMDNSResolver is the recursive resolver (host[:port]) the checks ask.
	// Empty: the first nameserver of /etc/resolv.conf. EASM_DNS_RESOLVER.
	EASMDNSResolver string
	// EASMDNSQPS bounds the checks' DNS queries per second across all
	// tenants. EASM_DNS_QPS, default 20.
	EASMDNSQPS float64
	// EASMDNSInterval is how often the checks run. EASM_DNS_CHECK_INTERVAL,
	// default 24h (RFC-036 O9: daily light checks).
	EASMDNSInterval time.Duration
	// EASMDNSMaxNamesPerRun caps names checked per tenant per run; the rest
	// rotate in, longest-unchecked first. EASM_DNS_MAX_NAMES_PER_RUN, 500.
	EASMDNSMaxNamesPerRun int

	// CertMonitorMaxDomainsPerRun caps how many domains of one tenant a sweep
	// queries; the rest rotate in on later runs, oldest-queried first.
	// CERT_MONITOR_MAX_DOMAINS_PER_RUN, default 50.
	CertMonitorMaxDomainsPerRun int

	// CertMonitorCertSpotterURL is the Cert Spotter API used, unauthenticated
	// (free tier), when crt.sh still fails after its retries. Set
	// CERT_MONITOR_CERTSPOTTER_URL=off to disable the fallback.
	CertMonitorCertSpotterURL string

	// LoadBalancing holds configuration for sensor load balancing weights.
	LoadBalancing LoadBalancingConfig
}

// LoadBalancingConfig holds weights for sensor load balancing score computation.
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

// Weights converts the operator-facing SENSOR_LB_* settings into the domain
// weight set consumed by Sensor.ComputeLoadScoreWithWeights and the sensor
// selector. This is the seam that makes those environment variables
// observable in scheduling behavior.
func (c LoadBalancingConfig) Weights() sensordom.LoadBalancingWeights {
	return sensordom.LoadBalancingWeights{
		JobLoad:                  c.JobWeight,
		CPU:                      c.CPUWeight,
		Memory:                   c.MemoryWeight,
		DiskIO:                   c.DiskIOWeight,
		Network:                  c.NetworkWeight,
		MaxDiskThroughputMBPS:    c.MaxDiskThroughputMBPS,
		MaxNetworkThroughputMBPS: c.MaxNetworkThroughputMBPS,
	}
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

	// AllowPlaintext, when true, lets non-production deployments fall
	// back to plaintext credential storage if Key is empty. Required
	// to make the security trade-off intentional and visible — without
	// this opt-in, a missing APP_ENCRYPTION_KEY refuses to boot even
	// in dev. Production NEVER allows plaintext (initEncryptor enforces).
	// Env var: APP_ALLOW_PLAINTEXT_CREDENTIALS
	AllowPlaintext bool

	// PreviousKeys are earlier encryption keys, kept only while a key
	// rotation is in progress: values encrypted under them stay readable,
	// and token hashes peppered with them keep verifying, while new values
	// use Key. Each is auto-detected like Key (raw 32, hex 64, base64 44).
	// Remove them once cmd/rekey has re-encrypted the stored values and the
	// tokens issued under the old key have been rotated.
	// Env var: APP_ENCRYPTION_KEY_PREVIOUS (comma-separated)
	PreviousKeys []string

	// TemplateSigningKey is the 32-byte master secret each tenant's custom
	// template signing key is derived from (Ed25519; sensors pin the
	// tenant's public key). Same formats as Key. Empty: derived from Key,
	// so rotating Key also rotates every tenant's template key and sensors
	// must pin the new one; set it to rotate them independently.
	// Env var: APP_TEMPLATE_SIGNING_KEY
	TemplateSigningKey string
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

	// Per-tenant LLM token budget (RFC-008 Phase 1).
	// BudgetEnabled defaults to false — the budget service is wired
	// but Check() returns nil so no tenant is blocked. Flip to true
	// per RFC-008 Phase 2 rollout after backfill + dashboards ship.
	BudgetEnabled bool
	// BudgetStrict controls the fail-mode when the budget repo is
	// unreachable. In production (strict=true) a repo outage blocks
	// triage — we refuse to run without a running counter. In dev/
	// staging (strict=false) we log and proceed. Defaults to false
	// to match "flag off = zero behaviour change" on first deploy.
	BudgetStrict bool
	// BudgetDefaultTokensPerMonth is the fallback ceiling applied when
	// a tenant has no row in ai_triage_budgets for the current month
	// AND no per-plan override. 0 = unlimited (back-compat). A paying
	// SaaS deployment typically sets this at plan-onboarding time,
	// not here.
	BudgetDefaultTokensPerMonth int64
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
// envDevelopment is the APP_ENV value of a developer machine.
const envDevelopment = "development"

// defaultLogLevel is LOG_LEVEL when it is not set.
func defaultLogLevel(appEnv string) string {
	if appEnv == envDevelopment {
		return "debug"
	}
	return "info"
}

// defaultLogFormat is LOG_FORMAT when it is not set.
func defaultLogFormat(appEnv string) string {
	if appEnv == envDevelopment {
		return "text"
	}
	return "json"
}

func Load() (*Config, error) {
	if err := rejectRetiredEnv(os.LookupEnv); err != nil {
		return nil, err
	}

	cfg := &Config{
		App: AppConfig{
			Name:  getEnv("APP_NAME", "openctem"),
			Env:   getEnv("APP_ENV", "development"),
			Debug: getEnvBool("APP_DEBUG", false), // Default false for safety
			URL:   getEnv("APP_URL", ""),
		},
		SensorConfig: SensorConfigConfig{
			TransportV3: SensorTransportV3Config{
				Enabled:        getEnvBool("SENSOR_TRANSPORT_V3_ENABLED", false),
				PublicHost:     getEnv("SENSOR_PUBLIC_HOST", ""),
				MTLSListenAddr: getEnv("SENSOR_MTLS_LISTEN_ADDR", ":8443"),
				CACertFile:     getEnv("SENSOR_MTLS_CA_CERT_FILE", ""),
				CAKeyFile:      getEnv("SENSOR_MTLS_CA_KEY_FILE", ""),
				CADir:          getEnv("SENSOR_MTLS_CA_DIR", "data/sensor-ca"),
				CertTTL:        getEnvDuration("SENSOR_MTLS_CERT_TTL", 7*24*time.Hour),
			},
			TemplatesDir:      getEnv("SENSOR_CONFIG_TEMPLATES_DIR", DefaultSensorConfigTemplatesDir),
			PublicAPIURL:      getEnv("SENSOR_PUBLIC_API_URL", ""),
			KeyTTL:            getEnvDuration("SENSOR_KEY_TTL", DefaultSensorKeyTTL),
			KeyRenewGrace:     getEnvDuration("SENSOR_KEY_RENEW_GRACE", DefaultSensorKeyRenewGrace),
			KeyPepper:         getEnv("SENSOR_KEY_PEPPER", ""),
			KeyPepperPrevious: getEnvSlice("SENSOR_KEY_PEPPER_PREVIOUS", nil),

			KeyRenewBefore:          getEnvDuration("SENSOR_KEY_RENEW_BEFORE", 0),
			SlimHeartbeat:           getEnvBool("SENSOR_SLIM_HEARTBEAT", true),
			HeartbeatInterval:       getEnvDuration("SENSOR_HEARTBEAT_INTERVAL", 30*time.Second),
			HeartbeatBusyInterval:   getEnvDuration("SENSOR_HEARTBEAT_BUSY_INTERVAL", 5*time.Second),
			HeartbeatLoadedInterval: getEnvDuration("SENSOR_HEARTBEAT_LOADED_INTERVAL", 2*time.Minute),
			HeartbeatMinInterval:    getEnvDuration("SENSOR_HEARTBEAT_MIN_INTERVAL", 5*time.Second),
			HeartbeatMaxInterval:    getEnvDuration("SENSOR_HEARTBEAT_MAX_INTERVAL", 5*time.Minute),
			HeartbeatSlowQuery:      getEnvDuration("SENSOR_HEARTBEAT_SLOW_QUERY", 250*time.Millisecond),
			CommandLease:            getEnvDuration("SENSOR_COMMAND_LEASE", 3*time.Minute),
			HealthSlowHeartbeat:     getEnvDuration("SENSOR_HEALTH_SLOW_HEARTBEAT", 2*time.Second),
			HealthStartupGrace:      getEnvDuration("SENSOR_HEALTH_STARTUP_GRACE", 0),
			LatestVersion:           sensorVersionSetting(getEnv("SENSOR_LATEST_VERSION", DefaultSensorLatestVersion)),
			MinVersion:              sensorVersionSetting(getEnv("SENSOR_MIN_VERSION", DefaultSensorMinVersion)),
			SDKMinVersion:           sensorVersionSetting(getEnv("SENSOR_SDK_MIN_VERSION", DefaultSensorSDKMinVersion)),
			SDKLatestVersion:        sensorVersionSetting(getEnv("SENSOR_SDK_LATEST_VERSION", DefaultSensorSDKLatestVersion)),
			Image:                   getEnv("SENSOR_IMAGE", DefaultSensorImageRepository),
			CACertFile:              getEnv("SENSOR_CA_CERT_FILE", ""),
		},
		Storage: StorageConfig{
			Provider:  getEnv("STORAGE_PROVIDER", "local"),
			LocalPath: getEnv("STORAGE_LOCAL_PATH", "./data/attachments"),
			Bucket:    getEnv("STORAGE_BUCKET", ""),
			Region:    getEnv("STORAGE_REGION", ""),
			Endpoint:  getEnv("STORAGE_ENDPOINT", ""),
			AccessKey: getEnv("STORAGE_ACCESS_KEY", ""),
			SecretKey: getEnv("STORAGE_SECRET_KEY", ""),
		},
		Server: ServerConfig{
			Host:                  getEnv("SERVER_HOST", "0.0.0.0"),
			Port:                  getEnvInt("SERVER_PORT", 8080),
			ReadTimeout:           getEnvDuration("SERVER_READ_TIMEOUT", 15*time.Second),
			WriteTimeout:          getEnvDuration("SERVER_WRITE_TIMEOUT", 15*time.Second),
			RequestTimeout:        getEnvDuration("SERVER_REQUEST_TIMEOUT", 30*time.Second), // Per-request timeout
			ShutdownTimeout:       getEnvDuration("SERVER_SHUTDOWN_TIMEOUT", 30*time.Second),
			MaxBodySize:           getEnvInt64("SERVER_MAX_BODY_SIZE", 10<<20), // 10MB default
			SessionTimeoutMinutes: getEnvInt("SESSION_TIMEOUT_MINUTES", 30),    // 30 minutes default
			MaxConcurrentRequests: getEnvInt("MAX_CONCURRENT_REQUESTS", 1000),  // 1000 concurrent requests default
			TrustedProxies:        getEnvSlice("SERVER_TRUSTED_PROXIES", nil),
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
			JITEnabled:      getEnvBool("DB_JIT_ENABLED", false),
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
			TLSCertFile:   getEnv("REDIS_TLS_CERT_FILE", ""),
			TLSKeyFile:    getEnv("REDIS_TLS_KEY_FILE", ""),
			TLSCAFile:     getEnv("REDIS_TLS_CA_FILE", ""),
			MaxRetries:    getEnvInt("REDIS_MAX_RETRIES", 3),
			MinRetryDelay: getEnvDuration("REDIS_MIN_RETRY_DELAY", 100*time.Millisecond),
			MaxRetryDelay: getEnvDuration("REDIS_MAX_RETRY_DELAY", 3*time.Second),
		},
		Log: LogConfig{
			// Unset: debug/text for APP_ENV=development (readable while
			// developing), info/json everywhere else. Set, they apply in every
			// environment.
			Level:              getEnv("LOG_LEVEL", defaultLogLevel(getEnv("APP_ENV", envDevelopment))),
			Format:             getEnv("LOG_FORMAT", defaultLogFormat(getEnv("APP_ENV", envDevelopment))),
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
			PasswordMinLength:         getEnvInt("AUTH_PASSWORD_MIN_LENGTH", 12),
			PasswordRequireUpper:      getEnvBool("AUTH_PASSWORD_REQUIRE_UPPERCASE", true),
			PasswordRequireLower:      getEnvBool("AUTH_PASSWORD_REQUIRE_LOWERCASE", true),
			PasswordRequireNumber:     getEnvBool("AUTH_PASSWORD_REQUIRE_NUMBER", true),
			PasswordRequireSpecial:    getEnvBool("AUTH_PASSWORD_REQUIRE_SPECIAL", false),
			MaxLoginAttempts:          getEnvInt("AUTH_MAX_LOGIN_ATTEMPTS", 5),
			LockoutDuration:           getEnvDuration("AUTH_LOCKOUT_DURATION", 15*time.Minute),
			MaxActiveSessions:         getEnvInt("AUTH_MAX_ACTIVE_SESSIONS", 10),
			AllowRegistration:         getEnvBool("AUTH_ALLOW_REGISTRATION", false),
			RequireEmailVerification:  getEnvBool("AUTH_REQUIRE_EMAIL_VERIFICATION", true),
			EmailVerificationDuration: getEnvDuration("AUTH_EMAIL_VERIFICATION_DURATION", 24*time.Hour),
			PasswordResetDuration:     getEnvDuration("AUTH_PASSWORD_RESET_DURATION", 1*time.Hour),
			CookieSecure:              getEnvBool("AUTH_COOKIE_SECURE", defaultCookieSecure(getEnv("APP_ENV", "development"))),
			CookieDomain:              getEnv("AUTH_COOKIE_DOMAIN", ""),                          // Empty = current host
			CookieSameSite:            getEnv("AUTH_COOKIE_SAMESITE", "lax"),                     // "strict", "lax", or "none"
			AccessTokenCookieName:     getEnv("AUTH_ACCESS_TOKEN_COOKIE_NAME", "auth_token"),     // Cookie name for access token
			RefreshTokenCookieName:    getEnv("AUTH_REFRESH_TOKEN_COOKIE_NAME", "refresh_token"), // Cookie name for refresh token
			TenantCookieName:          getEnv("AUTH_TENANT_COOKIE_NAME", "app_tenant"),           // Cookie name for tenant
			EntraSSO: EntraSSOConfig{
				Enabled:        getEnvBool("SSO_ENTRA_ENABLED", false),
				ClientID:       getEnv("SSO_ENTRA_CLIENT_ID", ""),
				ClientSecret:   getEnv("SSO_ENTRA_CLIENT_SECRET", ""),
				TenantID:       getEnv("SSO_ENTRA_TENANT_ID", "common"),
				AllowedDomains: getEnvSlice("SSO_ENTRA_ALLOWED_DOMAINS", nil),
				DefaultRole:    getEnv("SSO_ENTRA_DEFAULT_ROLE", "viewer"),
				AutoProvision:  getEnvBool("SSO_ENTRA_AUTO_PROVISION", true),
				DisplayName:    getEnv("SSO_ENTRA_DISPLAY_NAME", "Microsoft Entra ID"),
				AllowedTenants: getEnvSlice("SSO_ENTRA_ALLOWED_TENANTS", nil),
			},
			AllowedRedirectURIs: getEnvSlice("SSO_ALLOWED_REDIRECT_URIS", nil),
			TenantCreationMode:  getEnv("TENANT_CREATION_MODE", TenantCreationAdminOnly),
		},
		Keycloak: KeycloakConfig{
			BaseURL:             getEnv("KEYCLOAK_BASE_URL", "http://localhost:8080"),
			Realm:               getEnv("KEYCLOAK_REALM", "openctem"),
			ClientID:            getEnv("KEYCLOAK_CLIENT_ID", ""),
			JWKSRefreshInterval: getEnvDuration("KEYCLOAK_JWKS_REFRESH_INTERVAL", 1*time.Hour),
			HTTPTimeout:         getEnvDuration("KEYCLOAK_HTTP_TIMEOUT", 10*time.Second),
		},
		CORS: CORSConfig{
			// F-12: Default to localhost dev origin instead of wildcard. Production
			// validation in middleware/middleware.go rejects "*" regardless.
			AllowedOrigins: getEnvSlice("CORS_ALLOWED_ORIGINS", []string{"http://localhost:3000"}),
			AllowedMethods: getEnvSlice("CORS_ALLOWED_METHODS", []string{"GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"}),
			AllowedHeaders: getEnvSlice("CORS_ALLOWED_HEADERS", []string{"Accept", "Authorization", "Content-Type", "X-Request-ID"}),
			MaxAge:         getEnvInt("CORS_MAX_AGE", 86400),
		},
		RateLimit: RateLimitConfig{
			Enabled:         getEnvBool("RATE_LIMIT_ENABLED", true),
			RequestsPerSec:  getEnvFloat("RATE_LIMIT_RPS", 100),
			Burst:           getEnvInt("RATE_LIMIT_BURST", 200),
			CleanupInterval: getEnvDuration("RATE_LIMIT_CLEANUP", 1*time.Minute),
			// Per-user GET budget. 120/min matches the historical
			// hard-coded default (DefaultReadEndpointRateLimitConfig).
			ReadRequestsPerMin: getEnvInt("RATE_LIMIT_READ_PER_MIN", 120),
		},
		SMTP: SMTPFromEnv(),
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
		Worker: SensorConfig{
			Enabled:                     getEnvBool("WORKER_HEALTH_CHECK_ENABLED", false),
			HeartbeatTimeout:            getEnvDuration("WORKER_HEARTBEAT_TIMEOUT", 5*time.Minute),
			HealthCheckInterval:         getEnvDuration("WORKER_HEALTH_CHECK_INTERVAL", 1*time.Minute),
			SCMSyncInterval:             getEnvDuration("SCM_SYNC_INTERVAL", 0),
			CTEMIDFeedURL:               getEnv("CTEM_ID_FEED_URL", "https://ctem.org/source.json"),
			CertMonitorEnabled:          getEnvBool("CERT_MONITOR_ENABLED", true),
			CertMonitorFeedBaseURL:      getEnv("CERT_MONITOR_FEED_URL", "https://crt.sh"),
			CertMonitorInterval:         getEnvDuration("CERT_MONITOR_INTERVAL", 24*time.Hour),
			CertMonitorMaxDomainsPerRun: getEnvInt("CERT_MONITOR_MAX_DOMAINS_PER_RUN", 50),
			EASMDNSChecksEnabled:        getEnvBool("EASM_DNS_CHECKS_ENABLED", true),
			EASMDNSResolver:             getEnv("EASM_DNS_RESOLVER", ""),
			EASMDNSQPS:                  getEnvFloat("EASM_DNS_QPS", 20),
			EASMDNSInterval:             getEnvDuration("EASM_DNS_CHECK_INTERVAL", 24*time.Hour),
			EASMDNSMaxNamesPerRun:       getEnvInt("EASM_DNS_MAX_NAMES_PER_RUN", 500),
			CertMonitorCertSpotterURL:   getEnv("CERT_MONITOR_CERTSPOTTER_URL", "https://api.certspotter.com"),
			LoadBalancing: LoadBalancingConfig{
				JobWeight:                getEnvFloat("SENSOR_LB_JOB_WEIGHT", sensordom.DefaultJobLoadWeight),
				CPUWeight:                getEnvFloat("SENSOR_LB_CPU_WEIGHT", sensordom.DefaultCPUWeight),
				MemoryWeight:             getEnvFloat("SENSOR_LB_MEMORY_WEIGHT", sensordom.DefaultMemoryWeight),
				DiskIOWeight:             getEnvFloat("SENSOR_LB_DISK_IO_WEIGHT", sensordom.DefaultDiskIOWeight),
				NetworkWeight:            getEnvFloat("SENSOR_LB_NETWORK_WEIGHT", sensordom.DefaultNetworkWeight),
				MaxDiskThroughputMBPS:    getEnvFloat("SENSOR_LB_MAX_DISK_THROUGHPUT_MBPS", sensordom.DefaultMaxDiskThroughputMBPS),
				MaxNetworkThroughputMBPS: getEnvFloat("SENSOR_LB_MAX_NETWORK_THROUGHPUT_MBPS", sensordom.DefaultMaxNetworkThroughputMBPS),
			},
		},
		Encryption: EncryptionConfig{
			Key:            getEnv("APP_ENCRYPTION_KEY", ""),
			KeyFormat:      getEnv("APP_ENCRYPTION_KEY_FORMAT", ""),
			AllowPlaintext: getEnvBool("APP_ALLOW_PLAINTEXT_CREDENTIALS", false),
			PreviousKeys:   getEnvSlice("APP_ENCRYPTION_KEY_PREVIOUS", nil),
			// Read as is: a leading or trailing space is a malformed key.
			TemplateSigningKey: getEnv("APP_TEMPLATE_SIGNING_KEY", ""),
		},
		Webhooks: WebhooksConfig{
			// F-1: HMAC secret for incoming Jira webhooks. REQUIRED — the
			// middleware fails closed if empty.
			JiraSecret: getEnv("JIRA_WEBHOOK_SECRET", ""),
		},
		Ingest: IngestConfig{
			Mode:                  getEnv("INGEST_MODE", "sync"),
			MaxPendingPerTenant:   getEnvInt("INGEST_MAX_PENDING_PER_TENANT", 100),
			V2Results:             getEnvBool("SENSOR_PROTOCOL_V2_RESULTS", true),
			V2BlindingRatio:       getEnvFloat("SENSOR_V2_BLINDING_RATIO", 0.5),
			V2BlindingMinFindings: getEnvInt("SENSOR_V2_BLINDING_MIN_FINDINGS", 100),
			CoverageAutoResolve:   getEnv("INGEST_COVERAGE_AUTO_RESOLVE", "dry_run"),
			SourceResolve:         getEnv("INGEST_SOURCE_RESOLVE", "dry_run"),
			VEX:                   getEnv("INGEST_VEX", "dry_run"),
		},
		Metrics: MetricsConfig{
			// SECURITY: default NON-public. See MetricsConfig docs.
			Public: getEnvBool("METRICS_PUBLIC", false),
			Token:  getEnv("METRICS_TOKEN", ""),
		},
		AuditRetention: AuditRetentionConfig{
			Days:       getEnvInt("AUDIT_RETENTION_DAYS", 365),
			ArchiveDir: getEnv("AUDIT_ARCHIVE_DIR", ""),
		},
		Scope: ScopeConfig{
			ActiveProof:     getEnv("SCOPE_ACTIVE_PROOF", ""),
			MaxPublicCIDRv4: getEnvInt("SCOPE_MAX_PUBLIC_CIDR_V4", 16),
			MaxPublicCIDRv6: getEnvInt("SCOPE_MAX_PUBLIC_CIDR_V6", 32),
			DenyExtra:       getEnvSlice("SCOPE_DENY_EXTRA", nil),
		},
		AdminAuditRetention: AdminAuditRetentionConfig{
			Enabled: getEnvBool("ADMIN_AUDIT_RETENTION_ENABLED", true),
			// Default TRUE: never start deleting audit history on upgrade.
			DryRun:        getEnvBool("ADMIN_AUDIT_RETENTION_DRY_RUN", true),
			RetentionDays: getEnvInt("ADMIN_AUDIT_RETENTION_DAYS", 365),
			Interval:      getEnvDuration("ADMIN_AUDIT_RETENTION_INTERVAL", 24*time.Hour),
			BatchSize:     getEnvInt("ADMIN_AUDIT_RETENTION_BATCH_SIZE", 10000),
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
			// RFC-008 Phase 1: budget service wired but OFF by default.
			BudgetEnabled:               getEnvBool("AI_TRIAGE_BUDGET_ENABLED", false),
			BudgetStrict:                getEnvBool("AI_TRIAGE_BUDGET_STRICT", false),
			BudgetDefaultTokensPerMonth: int64(getEnvInt("AI_TRIAGE_BUDGET_DEFAULT_TOKENS", 0)),
		},
	}

	// SSO redirect-URI allow-list (OAuth 2.1 / RFC 9700): pin the caller-supplied
	// redirect_uri to trusted frontend origins. An explicit SSO_ALLOWED_REDIRECT_URIS
	// wins; otherwise derive the origins already trusted elsewhere in config so the
	// shipped UI callback keeps working out of the box.
	if len(cfg.Auth.AllowedRedirectURIs) == 0 {
		cfg.Auth.AllowedRedirectURIs = deriveSSORedirectAllowList(cfg)
	}

	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	return cfg, nil
}

// deriveSSORedirectAllowList builds the default SSO redirect_uri allow-list from
// the frontend origins already configured elsewhere (CORS allowed origins, the
// OAuth frontend callback, and the email base URL). Each is reduced to its exact
// origin (scheme://host[:port]); a request-time redirect_uri on that exact origin
// is then permitted. Operators can override/tighten via SSO_ALLOWED_REDIRECT_URIS.
func deriveSSORedirectAllowList(cfg *Config) []string {
	seen := make(map[string]struct{})
	out := make([]string, 0, len(cfg.CORS.AllowedOrigins)+2)
	add := func(raw string) {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			return
		}
		u, err := url.Parse(raw)
		if err != nil || u.Scheme == "" || u.Host == "" {
			return
		}
		origin := u.Scheme + "://" + u.Host
		if _, ok := seen[origin]; ok {
			return
		}
		seen[origin] = struct{}{}
		out = append(out, origin)
	}
	for _, o := range cfg.CORS.AllowedOrigins {
		add(o)
	}
	add(cfg.OAuth.FrontendCallbackURL)
	add(cfg.SMTP.BaseURL)
	return out
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

// validateStorage checks the server-wide attachment storage settings, so a
// typo fails at start-up instead of the API quietly keeping files on the
// container disk.
func (c *Config) validateStorage() error {
	switch c.Storage.Provider {
	case "", "local":
		return nil
	case "s3", "minio":
		if c.Storage.Bucket == "" {
			return fmt.Errorf("STORAGE_BUCKET is required when STORAGE_PROVIDER=%s", c.Storage.Provider)
		}
		if c.Storage.AccessKey == "" || c.Storage.SecretKey == "" {
			return fmt.Errorf("STORAGE_ACCESS_KEY and STORAGE_SECRET_KEY are required when STORAGE_PROVIDER=%s", c.Storage.Provider)
		}
		return nil
	default:
		return fmt.Errorf("invalid STORAGE_PROVIDER: %q (must be local, s3 or minio)", c.Storage.Provider)
	}
}

// validateBasic validates basic configuration regardless of environment.
func (c *Config) validateBasic() error {
	if c.Scope.ActiveProof == "" {
		c.Scope.ActiveProof = ScopeProofOff
		if c.Auth.SelfServiceTenantCreation() {
			c.Scope.ActiveProof = ScopeProofPlatformSensors
		}
	}
	if err := c.Scope.validate(); err != nil {
		return err
	}
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
	if err := c.validateAdminAuditRetention(); err != nil {
		return err
	}
	if err := c.validateStorage(); err != nil {
		return err
	}
	return nil
}

// minAdminAuditRetentionDays is the floor for admin-audit retention. SOC 2 and
// PCI DSS both expect at least one year of audit history; anything under 30
// days is far more likely to be a typo (or a units mistake) than a policy, and
// the delete is irreversible. Refusing to boot beats silently shredding the
// audit trail.
const minAdminAuditRetentionDays = 30

// validateAdminAuditRetention guards the destructive knobs. A zero or negative
// retention window would push the cutoff to now-or-later and delete every row.
func (c *Config) validateAdminAuditRetention() error {
	r := c.AdminAuditRetention
	if !r.Enabled || r.DryRun {
		return nil
	}
	if r.RetentionDays < minAdminAuditRetentionDays {
		return fmt.Errorf(
			"ADMIN_AUDIT_RETENTION_DAYS must be >= %d when deletion is enabled (got %d); "+
				"a smaller window deletes audit history that compliance frameworks require",
			minAdminAuditRetentionDays, r.RetentionDays)
	}
	if r.Interval <= 0 {
		return fmt.Errorf("ADMIN_AUDIT_RETENTION_INTERVAL must be positive, got %s", r.Interval)
	}
	if r.BatchSize < 1 {
		return fmt.Errorf("ADMIN_AUDIT_RETENTION_BATCH_SIZE must be >= 1, got %d", r.BatchSize)
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
	if k := c.Encryption.TemplateSigningKey; k != "" {
		if _, err := crypto.ParseKey(k, ""); err != nil {
			// Never echo the key itself.
			return fmt.Errorf("APP_TEMPLATE_SIGNING_KEY is not a valid key (expected 32 raw, 64 hex or 44 base64 characters); generate one with `openssl rand -hex 32`")
		}
		if k == c.Encryption.Key {
			return fmt.Errorf("APP_TEMPLATE_SIGNING_KEY must differ from APP_ENCRYPTION_KEY (leave it unset to derive it)")
		}
	}

	// Encryption key is optional only in development. Any other APP_ENV
	// (production, staging, preview, etc.) stores real tenant credentials
	// and MUST have a key — otherwise integration tokens sit in plaintext.
	if c.Encryption.Key == "" {
		if !c.IsDevelopment() {
			return fmt.Errorf("APP_ENCRYPTION_KEY is required when APP_ENV=%q (only APP_ENV=development may omit it); generate one with `openssl rand -hex 32`", c.App.Env)
		}
		return nil
	}

	// Validate key format and length
	keyLen := len(c.Encryption.Key)
	format := c.Encryption.KeyFormat

	// Auto-detect format if not specified
	if format == "" {
		switch keyLen {
		case 32:
			format = "raw"
		case 64:
			format = "hex"
		case 44:
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

	for i, prev := range c.Encryption.PreviousKeys {
		if _, err := crypto.ParseKey(prev, ""); err != nil {
			// Never echo the key itself.
			return fmt.Errorf("APP_ENCRYPTION_KEY_PREVIOUS entry %d is not a valid key (expected 32 raw, 64 hex or 44 base64 characters)", i+1)
		}
		if prev == c.Encryption.Key {
			return fmt.Errorf("APP_ENCRYPTION_KEY_PREVIOUS entry %d equals APP_ENCRYPTION_KEY", i+1)
		}
	}

	return nil
}

// validateAuth validates authentication configuration.
func (c *Config) validateAuth() error {
	switch c.Auth.TenantCreationMode {
	case "":
		// Unset (e.g. a Config built in code): the default.
		c.Auth.TenantCreationMode = TenantCreationAdminOnly
	case TenantCreationSelfService, TenantCreationAdminOnly:
	default:
		return fmt.Errorf("invalid TENANT_CREATION_MODE: %s (must be '%s' or '%s')",
			c.Auth.TenantCreationMode, TenantCreationSelfService, TenantCreationAdminOnly)
	}
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
		// Refuse to start in non-development environments when the JWT
		// secret matches one of the docker-compose.yml / .env.example
		// dev defaults. The dev defaults are deliberately preserved
		// in development to keep `docker compose up` ergonomic, but
		// shipping them to production / staging means every attacker
		// with repo access can forge tokens.
		if !c.IsDevelopment() && isDevDefaultJWTSecret(c.Auth.JWTSecret) {
			return fmt.Errorf("AUTH_JWT_SECRET is a known development default and APP_ENV=%q is not 'development'; generate one with `openssl rand -hex 32`", c.App.Env)
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

	// Same sentinel for the credential-at-rest key: only refuse outside
	// development. Dev keeps the predictable `0123…cdef` value so
	// `docker compose up` works without further config; non-dev MUST
	// override it because the value is publicly known.
	if !c.IsDevelopment() && c.Encryption.Key != "" && isDevDefaultEncryptionKey(c.Encryption.Key) {
		return fmt.Errorf("APP_ENCRYPTION_KEY is the docker-compose default and APP_ENV=%q is not 'development'; generate one with `openssl rand -hex 32`", c.App.Env)
	}

	// A dedicated sensor-key pepper must be a real secret: at least 32
	// characters (openssl rand -hex 32 gives 64).
	if p := c.SensorConfig.KeyPepper; p != "" && len(p) < 32 {
		return fmt.Errorf("SENSOR_KEY_PEPPER must be at least 32 characters, got %d; generate one with `openssl rand -hex 32`", len(p))
	}

	// Validate OAuth configuration
	if err := c.validateOAuth(); err != nil {
		return err
	}

	return nil
}

// devDefaultJWTSecrets is the closed set of "dev-quickstart" JWT secret
// literals that ship in docker-compose.yml and .env.*.example files
// across this repo. Refusing them at startup prevents the "copied the
// compose file to prod" failure mode. Update this list whenever a new
// docs/config example is introduced.
var devDefaultJWTSecrets = []string{
	"this-is-a-development-secret-key-at-least-64-characters-long-for-security",
	"this-is-a-development-secret-key-at-least-32-characters",
}

func isDevDefaultJWTSecret(s string) bool {
	return slices.Contains(devDefaultJWTSecrets, s)
}

// isDevDefaultEncryptionKey flags the repeating-hex-digit AES-256 key
// that ships as the docker-compose fallback. Matching the literal (not
// a pattern) avoids false positives on legitimate high-entropy keys
// that happen to start with common bytes.
func isDevDefaultEncryptionKey(s string) bool {
	const dockerComposeDefault = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	return s == dockerComposeDefault
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
	// Every auth provider sets session cookies (local login, SSO/SAML
	// callbacks, the admin console, the CSRF double-submit cookie), so the
	// Secure flag is required in production regardless of provider.
	if !c.Auth.CookieSecure {
		return fmt.Errorf("AUTH_COOKIE_SECURE must be true in production (HTTPS required)")
	}
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
	// Values are quoted: unquoted, an empty password swallowed the next
	// key ("password= dbname=x" sets the password to "dbname=x"), and a
	// space or backslash in a value broke or changed it.
	dsn := fmt.Sprintf(
		"host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
		dsnQuote(c.Host), c.Port, dsnQuote(c.User), dsnQuote(c.Password), dsnQuote(c.Name), dsnQuote(c.SSLMode),
	)
	if !c.JITEnabled {
		// lib/pq forwards unknown keys as session startup parameters.
		dsn += " jit=off"
	}
	return dsn
}

// dsnQuote quotes a libpq key/value connection-string value: single quotes
// around it, with backslash and single quote escaped by a backslash.
func dsnQuote(v string) string {
	return "'" + strings.NewReplacer(`\`, `\\`, `'`, `\'`).Replace(v) + "'"
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

// defaultCookieSecure is the AUTH_COOKIE_SECURE default: cookies carry the
// Secure flag everywhere except APP_ENV=development, where the stack is
// usually served over plain http://localhost. Any other environment
// (production, staging, ...) is assumed to sit behind HTTPS; an operator
// who really serves it over http must opt out with AUTH_COOKIE_SECURE=false
// (and production refuses to start with that, see validateProductionAuth).
func defaultCookieSecure(appEnv string) bool {
	return appEnv != "development"
}

// DefaultSensorConfigTemplatesDir is SENSOR_CONFIG_TEMPLATES_DIR when unset.
const DefaultSensorConfigTemplatesDir = "configs/sensor-templates"

// retiredEnv lists the pre-sensor environment variable names. They are no
// longer read. Startup refuses to run while one is set: silently ignoring,
// say, AGENT_KEY_TTL would turn short-lived sensor keys back into
// non-expiring ones without the operator noticing.
var retiredEnv = []struct{ Old, New string }{
	{"AGENT_CONFIG_TEMPLATES_DIR", "SENSOR_CONFIG_TEMPLATES_DIR"},
	{"AGENT_PUBLIC_API_URL", "SENSOR_PUBLIC_API_URL"},
	{"AGENT_KEY_TTL", "SENSOR_KEY_TTL"},
	{"AGENT_LB_JOB_WEIGHT", "SENSOR_LB_JOB_WEIGHT"},
	{"AGENT_LB_CPU_WEIGHT", "SENSOR_LB_CPU_WEIGHT"},
	{"AGENT_LB_MEMORY_WEIGHT", "SENSOR_LB_MEMORY_WEIGHT"},
	{"AGENT_LB_DISK_IO_WEIGHT", "SENSOR_LB_DISK_IO_WEIGHT"},
	{"AGENT_LB_NETWORK_WEIGHT", "SENSOR_LB_NETWORK_WEIGHT"},
	{"AGENT_LB_MAX_DISK_THROUGHPUT_MBPS", "SENSOR_LB_MAX_DISK_THROUGHPUT_MBPS"},
	{"AGENT_LB_MAX_NETWORK_THROUGHPUT_MBPS", "SENSOR_LB_MAX_NETWORK_THROUGHPUT_MBPS"},
}

// rejectRetiredEnv fails when any retired name is set, naming its replacement.
func rejectRetiredEnv(lookup func(string) (string, bool)) error {
	var bad []string
	for _, r := range retiredEnv {
		if _, ok := lookup(r.Old); ok {
			bad = append(bad, fmt.Sprintf("%s (rename it to %s)", r.Old, r.New))
		}
	}
	if len(bad) > 0 {
		return fmt.Errorf("retired environment variables are set and no longer read: %s", strings.Join(bad, ", "))
	}
	return nil
}

// sensorVersionSetting reads a SENSOR_*_VERSION value: "none" or "off" means
// not set (so the compiled-in default can be turned off).
func sensorVersionSetting(v string) string {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "none", "off":
		return ""
	}
	return strings.TrimSpace(v)
}

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
	for p := range strings.SplitSeq(s, sep) {
		trimmed := strings.TrimSpace(p)
		if trimmed != "" {
			parts = append(parts, trimmed)
		}
	}
	return parts
}
