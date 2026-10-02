package sensor

import (
	"context"
	"net"
	"time"

	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/pagination"
)

// Filter represents filter options for listing sensors.
type Filter struct {
	TenantID *shared.ID
	// ExcludePlatform leaves out shared platform sensors (is_platform_sensor):
	// a tenant's sensor list shows the tenant's own sensors only.
	ExcludePlatform bool
	Type            *SensorType
	Status          *SensorStatus // Admin-controlled: active, disabled, revoked
	Health          *SensorHealth // Automatic: unknown, online, offline, error
	ExecutionMode   *ExecutionMode
	Capabilities    []string
	Tools           []string
	Labels          map[string]string
	Search          string
	HasCapacity     *bool // Filter by sensors that have job capacity
}

// HeartbeatUpdate is the set of columns a heartbeat is allowed to write.
// Empty Version/Hostname/Region leave the stored value unchanged.
type HeartbeatUpdate struct {
	// TenantID scopes the write; nil for platform sensors (tenant_id IS NULL).
	TenantID *shared.ID
	Version  string
	Hostname string
	// IPAddress is the client address of the heartbeat request; nil keeps the
	// stored value.
	IPAddress     net.IP
	Region        string
	CPUPercent    float64
	MemoryPercent float64
	DiskReadMBPS  float64
	DiskWriteMBPS float64
	NetworkRxMBPS float64
	NetworkTxMBPS float64
	LoadScore     float64

	// Outbox is the outbox snapshot carried by the heartbeat, already
	// clamped. nil leaves the stored snapshot untouched: SDKs without an
	// outbox never send one, and a sensor downgraded to such an SDK keeps its
	// last snapshot, whose reported-at time shows how old it is.
	Outbox *OutboxStats

	// Protocol is the sensor protocol the heartbeat arrived on; 0 leaves the
	// stored protocol telemetry untouched. UserAgent is already sanitized.
	Protocol  int
	UserAgent string

	// UptimeSeconds is how long the sensor process has been running, as the
	// heartbeat reported it (already clamped). 0 leaves the stored start time
	// untouched: SDKs that do not report it send nothing.
	UptimeSeconds int64
}

// MaxReportedUptime caps the uptime a heartbeat may report (ten years); a
// larger value is an error or a hostile sensor, and is ignored.
const MaxReportedUptime = 10 * 365 * 24 * 60 * 60

// ClampUptime returns the reported uptime when it is plausible, else 0.
func ClampUptime(seconds int64) int64 {
	if seconds <= 0 || seconds > MaxReportedUptime {
		return 0
	}
	return seconds
}

// Repository defines the interface for sensor persistence.
type Repository interface {
	// Create creates a new sensor.
	Create(ctx context.Context, sensor *Sensor) error

	// CountByTenant counts the number of sensors for a tenant.
	// Used for enforcing sensor limits per plan.
	CountByTenant(ctx context.Context, tenantID shared.ID) (int, error)

	// GetByID retrieves a sensor by ID without tenant scoping.
	//
	// F-5: UNSAFE for user-facing handlers. Platform (shared) sensors are
	// tenant-agnostic so this lookup is legitimate for platform orchestration
	// paths, but any handler that authorizes on the caller's JWT MUST use
	// GetByTenantAndID instead to prevent IDOR across tenants.
	GetByID(ctx context.Context, id shared.ID) (*Sensor, error)

	// GetByTenantAndID retrieves a sensor by tenant and ID.
	// Prefer this in handlers exposed to user input.
	GetByTenantAndID(ctx context.Context, tenantID, id shared.ID) (*Sensor, error)

	// GetByAPIKeyHash retrieves a sensor by API key hash.
	//
	// F-5: By design this lookup is not tenant-scoped — the hash IS the
	// authentication material that establishes the tenant binding. Callers
	// MUST NOT expose the returned object directly to another user; it is
	// used only by the platform-auth middleware to identify the calling
	// sensor before downstream tenant filters take over.
	GetByAPIKeyHash(ctx context.Context, hash string) (*Sensor, error)

	// List lists sensors with filters and pagination.
	List(ctx context.Context, filter Filter, page pagination.Pagination) (pagination.Result[*Sensor], error)

	// Update updates a sensor.
	Update(ctx context.Context, sensor *Sensor) error

	// UpdateKeyExpiry sets only the inline API-key expiry, guarded by
	// status = 'active' so it cannot revive a concurrently-revoked sensor.
	// A nil expiresAt clears the expiry (never expires).
	UpdateKeyExpiry(ctx context.Context, id shared.ID, expiresAt *time.Time) error

	// UpdateHeartbeat persists ONLY the liveness/metric columns a sensor
	// heartbeat owns (version, hostname, metrics, load score, last_seen_at,
	// health). It never touches admin-controlled columns (status, API key,
	// name, capabilities...). The write is guarded by id + tenant +
	// status = 'active', so a heartbeat racing an admin revoke/disable can
	// neither revive the sensor nor overwrite its rotated key. Returns false
	// (no error) when no active row matched.
	UpdateHeartbeat(ctx context.Context, id shared.ID, hb HeartbeatUpdate) (bool, error)

	// UpdateAPIKey writes ONLY the inline API-key columns (hash, prefix,
	// expiry). With requireActive the write is additionally guarded by
	// status = 'active' (sensor self-renewal), so it cannot race an admin
	// revoke. Returns false (no error) when no row matched.
	UpdateAPIKey(ctx context.Context, id shared.ID, hash, prefix string, expiresAt *time.Time, requireActive bool) (bool, error)

	// Delete deletes a sensor.
	Delete(ctx context.Context, id shared.ID) error

	// UpdateLastSeen updates the last seen timestamp for a sensor.
	UpdateLastSeen(ctx context.Context, id shared.ID) error

	// IncrementStats increments sensor statistics.
	IncrementStats(ctx context.Context, id shared.ID, findings, scans, errors int64) error

	// FindByCapabilities finds sensors with the given capabilities.
	FindByCapabilities(ctx context.Context, tenantID shared.ID, capabilities []string, tool string) ([]*Sensor, error)

	// FindAvailable finds available sensors for a step.
	FindAvailable(ctx context.Context, tenantID shared.ID, capabilities []string, tool string) ([]*Sensor, error)

	// FindAvailableWithTool finds the best available sensor for a tool.
	// Returns the least-loaded sensor that has the required tool.
	FindAvailableWithTool(ctx context.Context, tenantID shared.ID, tool string) (*Sensor, error)

	// MarkStaleAsOffline marks sensors as offline (health) if they haven't sent heartbeat within the timeout.
	// Note: This updates Health (automatic), not Status (admin-controlled).
	// Sensors can still authenticate if their Status is 'active', regardless of Health.
	// Returns the number of sensors marked as offline.
	MarkStaleAsOffline(ctx context.Context, timeout time.Duration) (int64, error)

	// FindAvailableWithCapacity finds sensors that have capacity for new jobs.
	FindAvailableWithCapacity(ctx context.Context, tenantID shared.ID, capabilities []string, tool string) ([]*Sensor, error)

	// ClaimJob atomically claims a job slot for a sensor.
	ClaimJob(ctx context.Context, sensorID shared.ID) error

	// ReleaseJob releases a job slot for a sensor.
	ReleaseJob(ctx context.Context, sensorID shared.ID) error

	// ==========================================================================
	// Online/Offline Tracking Methods (Heartbeat Optimization)
	// ==========================================================================

	// UpdateOfflineTimestamp marks a sensor as offline with the current timestamp.
	// Called when a health monitor detects heartbeat timeout.
	UpdateOfflineTimestamp(ctx context.Context, id shared.ID) error

	// MarkStaleSensorsOffline finds sensors that haven't sent heartbeat within timeout and marks them offline.
	// Returns the list of sensor IDs that were marked offline (for audit logging).
	MarkStaleSensorsOffline(ctx context.Context, timeout time.Duration) ([]shared.ID, error)

	// GetSensorsOfflineSince returns sensors that went offline after the given timestamp.
	// Used for historical queries like "which sensors went offline in the last hour?"
	GetSensorsOfflineSince(ctx context.Context, since time.Time) ([]*Sensor, error)

	// ==========================================================================
	// Tool Availability Methods
	// ==========================================================================

	// GetAvailableToolsForTenant returns all unique tool names that have at least one available sensor.
	// Used to determine which tools can actually be executed.
	GetAvailableToolsForTenant(ctx context.Context, tenantID shared.ID) ([]string, error)

	// HasSensorForTool checks if there's at least one sensor that supports the given tool.
	HasSensorForTool(ctx context.Context, tenantID shared.ID, tool string) (bool, error)

	// GetAvailableCapabilitiesForTenant returns all unique capability names from all sensors accessible to the tenant.
	// Used to determine what capabilities a tenant can use based on their available sensors.
	GetAvailableCapabilitiesForTenant(ctx context.Context, tenantID shared.ID) ([]string, error)

	// HasSensorForCapability checks if there's at least one sensor that supports the given capability.
	HasSensorForCapability(ctx context.Context, tenantID shared.ID, capability string) (bool, error)

	// ==========================================================================
	// Platform Sensor Statistics
	// ==========================================================================

	// GetPlatformSensorStats returns aggregate statistics for platform sensors.
	GetPlatformSensorStats(ctx context.Context, tenantID shared.ID) (*PlatformSensorStatsResult, error)

	// GetTenantSensorStats returns aggregate statistics for the tenant's sensors,
	// grouped by status, health, type, and execution mode. Computed via SQL
	// aggregation in a single round-trip. Excludes platform-shared sensors.
	GetTenantSensorStats(ctx context.Context, tenantID shared.ID) (*TenantSensorStats, error)
}

// APIKeyFilter represents filter options for listing API keys.
type APIKeyFilter struct {
	SensorID *shared.ID
	IsActive *bool
}

// APIKeyRepository defines the interface for API key persistence.
type APIKeyRepository interface {
	// Create creates a new API key.
	Create(ctx context.Context, key *APIKey) error

	// GetByID retrieves an API key by ID.
	GetByID(ctx context.Context, id shared.ID) (*APIKey, error)

	// GetByHash retrieves an API key by hash.
	GetByHash(ctx context.Context, hash string) (*APIKey, error)

	// GetBySensorID retrieves all API keys for a sensor.
	GetBySensorID(ctx context.Context, sensorID shared.ID) ([]*APIKey, error)

	// List lists API keys with filters.
	List(ctx context.Context, filter APIKeyFilter) ([]*APIKey, error)

	// Update updates an API key.
	Update(ctx context.Context, key *APIKey) error

	// Delete deletes an API key.
	Delete(ctx context.Context, id shared.ID) error

	// RecordUsage records API key usage.
	RecordUsage(ctx context.Context, id shared.ID, ip string) error

	// Revoke revokes an API key.
	Revoke(ctx context.Context, id shared.ID, reason string) error

	// CountActiveBySensorID counts active keys for a sensor.
	CountActiveBySensorID(ctx context.Context, sensorID shared.ID) (int, error)
}

// RegistrationTokenFilter represents filter options for listing tokens.
type RegistrationTokenFilter struct {
	TenantID *shared.ID
	IsActive *bool
}

// RegistrationTokenRepository defines the interface for registration token persistence.
type RegistrationTokenRepository interface {
	// Create creates a new registration token.
	Create(ctx context.Context, token *RegistrationToken) error

	// GetByID retrieves a token by ID.
	GetByID(ctx context.Context, id shared.ID) (*RegistrationToken, error)

	// GetByTenantAndID retrieves a token by tenant and ID.
	GetByTenantAndID(ctx context.Context, tenantID, id shared.ID) (*RegistrationToken, error)

	// GetByHash retrieves a token by hash.
	GetByHash(ctx context.Context, hash string) (*RegistrationToken, error)

	// List lists tokens with filters and pagination.
	List(ctx context.Context, filter RegistrationTokenFilter, page pagination.Pagination) (pagination.Result[*RegistrationToken], error)

	// Update updates a token.
	Update(ctx context.Context, token *RegistrationToken) error

	// Delete deletes a token.
	Delete(ctx context.Context, id shared.ID) error

	// IncrementUsage increments the usage counter.
	IncrementUsage(ctx context.Context, id shared.ID) error

	// Deactivate deactivates a token.
	Deactivate(ctx context.Context, id shared.ID) error
}
