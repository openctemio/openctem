package datasource

import (
	"net"
	"time"

	"github.com/openctemio/api/pkg/domain/shared"
)

// DataSource represents a data source that can push or pull assets and findings.
// It can be an integration (pull), collector (push), scanner (push), or manual.
type DataSource struct {
	// Identity
	id       shared.ID
	tenantID shared.ID
	name     string
	typ      SourceType

	// Description
	description string

	// Deployment info (for collectors/scanners)
	version   string
	hostname  string
	ipAddress net.IP

	// Authentication (for push sources)
	apiKeyHash   string // Hashed API key
	apiKeyPrefix string // First 12 chars for identification (e.g., "rs_live_xxxx")

	// Status tracking
	status           SourceStatus
	lastSeenAt       *time.Time
	lastError        string
	errorCount       int
	apiKeyLastUsedAt *time.Time

	// Capabilities
	capabilities Capabilities

	// Configuration
	config   map[string]any
	metadata map[string]any

	// Statistics
	assetsCollected    int64
	findingsReported   int64
	lastSyncAt         *time.Time
	lastSyncDurationMs int
	lastSyncAssets     int
	lastSyncFindings   int

	// Timestamps
	createdAt time.Time
	updatedAt time.Time
}

// NewDataSource creates a new data source.
func NewDataSource(
	tenantID shared.ID,
	name string,
	typ SourceType,
) (*DataSource, error) {
	if tenantID.IsZero() {
		return nil, ErrTenantIDRequired
	}
	if name == "" {
		return nil, ErrNameRequired
	}
	if !typ.IsValid() {
		return nil, ErrInvalidSourceType
	}

	now := time.Now()
	return &DataSource{
		id:           shared.NewID(),
		tenantID:     tenantID,
		name:         name,
		typ:          typ,
		status:       SourceStatusPending,
		capabilities: make(Capabilities, 0),
		config:       make(map[string]any),
		metadata:     make(map[string]any),
		createdAt:    now,
		updatedAt:    now,
	}, nil
}

// Reconstruct creates a DataSource from stored data (used by repository).
func Reconstruct(
	id shared.ID,
	tenantID shared.ID,
	name string,
	typ SourceType,
	description string,
	version string,
	hostname string,
	ipAddress net.IP,
	apiKeyHash string,
	apiKeyPrefix string,
	status SourceStatus,
	lastSeenAt *time.Time,
	lastError string,
	errorCount int,
	apiKeyLastUsedAt *time.Time,
	capabilities Capabilities,
	config map[string]any,
	metadata map[string]any,
	assetsCollected int64,
	findingsReported int64,
	lastSyncAt *time.Time,
	lastSyncDurationMs int,
	lastSyncAssets int,
	lastSyncFindings int,
	createdAt time.Time,
	updatedAt time.Time,
) *DataSource {
	if capabilities == nil {
		capabilities = make(Capabilities, 0)
	}
	if config == nil {
		config = make(map[string]any)
	}
	if metadata == nil {
		metadata = make(map[string]any)
	}

	return &DataSource{
		id:                 id,
		tenantID:           tenantID,
		name:               name,
		typ:                typ,
		description:        description,
		version:            version,
		hostname:           hostname,
		ipAddress:          ipAddress,
		apiKeyHash:         apiKeyHash,
		apiKeyPrefix:       apiKeyPrefix,
		status:             status,
		lastSeenAt:         lastSeenAt,
		lastError:          lastError,
		errorCount:         errorCount,
		apiKeyLastUsedAt:   apiKeyLastUsedAt,
		capabilities:       capabilities,
		config:             config,
		metadata:           metadata,
		assetsCollected:    assetsCollected,
		findingsReported:   findingsReported,
		lastSyncAt:         lastSyncAt,
		lastSyncDurationMs: lastSyncDurationMs,
		lastSyncAssets:     lastSyncAssets,
		lastSyncFindings:   lastSyncFindings,
		createdAt:          createdAt,
		updatedAt:          updatedAt,
	}
}

// =============================================================================
// Getters
// =============================================================================

func (d *DataSource) ID() shared.ID                { return d.id }
func (d *DataSource) TenantID() shared.ID          { return d.tenantID }
func (d *DataSource) Name() string                 { return d.name }
func (d *DataSource) Type() SourceType             { return d.typ }
func (d *DataSource) Description() string          { return d.description }
func (d *DataSource) Version() string              { return d.version }
func (d *DataSource) Hostname() string             { return d.hostname }
func (d *DataSource) IPAddress() net.IP            { return d.ipAddress }
func (d *DataSource) APIKeyHash() string           { return d.apiKeyHash }
func (d *DataSource) APIKeyPrefix() string         { return d.apiKeyPrefix }
func (d *DataSource) Status() SourceStatus         { return d.status }
func (d *DataSource) LastSeenAt() *time.Time       { return d.lastSeenAt }
func (d *DataSource) LastError() string            { return d.lastError }
func (d *DataSource) ErrorCount() int              { return d.errorCount }
func (d *DataSource) APIKeyLastUsedAt() *time.Time { return d.apiKeyLastUsedAt }
func (d *DataSource) Capabilities() Capabilities   { return d.capabilities }
func (d *DataSource) Config() map[string]any       { return d.config }
func (d *DataSource) Metadata() map[string]any     { return d.metadata }
func (d *DataSource) AssetsCollected() int64       { return d.assetsCollected }
func (d *DataSource) FindingsReported() int64      { return d.findingsReported }
func (d *DataSource) LastSyncAt() *time.Time       { return d.lastSyncAt }
func (d *DataSource) LastSyncDurationMs() int      { return d.lastSyncDurationMs }
func (d *DataSource) LastSyncAssets() int          { return d.lastSyncAssets }
func (d *DataSource) LastSyncFindings() int        { return d.lastSyncFindings }
func (d *DataSource) CreatedAt() time.Time         { return d.createdAt }
func (d *DataSource) UpdatedAt() time.Time         { return d.updatedAt }

// =============================================================================
// Setters / Mutations
// =============================================================================

// SetDescription sets the description.
func (d *DataSource) SetDescription(description string) {
	d.description = description
	d.updatedAt = time.Now()
}

// SetVersion sets the version.
func (d *DataSource) SetVersion(version string) {
	d.version = version
	d.updatedAt = time.Now()
}

// SetHostname sets the hostname.
func (d *DataSource) SetHostname(hostname string) {
	d.hostname = hostname
	d.updatedAt = time.Now()
}

// SetIPAddress sets the IP address.
func (d *DataSource) SetIPAddress(ip net.IP) {
	d.ipAddress = ip
	d.updatedAt = time.Now()
}

// SetAPIKey sets the API key hash and prefix.
func (d *DataSource) SetAPIKey(hash, prefix string) {
	d.apiKeyHash = hash
	d.apiKeyPrefix = prefix
	d.updatedAt = time.Now()
}

// SetCapabilities sets the capabilities.
func (d *DataSource) SetCapabilities(caps Capabilities) {
	d.capabilities = caps
	d.updatedAt = time.Now()
}

// SetConfig sets the configuration.
func (d *DataSource) SetConfig(config map[string]any) {
	if config == nil {
		config = make(map[string]any)
	}
	d.config = config
	d.updatedAt = time.Now()
}

// SetMetadata sets the metadata.
func (d *DataSource) SetMetadata(metadata map[string]any) {
	if metadata == nil {
		metadata = make(map[string]any)
	}
	d.metadata = metadata
	d.updatedAt = time.Now()
}

// =============================================================================
// Status Management
// =============================================================================

// MarkActive marks the source as active.
func (d *DataSource) MarkActive() {
	now := time.Now()
	d.status = SourceStatusActive
	d.lastSeenAt = &now
	d.lastError = ""
	d.errorCount = 0
	d.updatedAt = now
}

// MarkInactive marks the source as inactive.
func (d *DataSource) MarkInactive() {
	d.status = SourceStatusInactive
	d.updatedAt = time.Now()
}

// MarkError marks the source as having an error.
func (d *DataSource) MarkError(errMsg string) {
	d.status = SourceStatusError
	d.lastError = errMsg
	d.errorCount++
	d.updatedAt = time.Now()
}

// MarkDisabled marks the source as disabled.
func (d *DataSource) MarkDisabled() {
	d.status = SourceStatusDisabled
	d.updatedAt = time.Now()
}

// Enable enables a disabled source (sets to pending).
func (d *DataSource) Enable() {
	if d.status == SourceStatusDisabled {
		d.status = SourceStatusPending
		d.updatedAt = time.Now()
	}
}

// RecordHeartbeat records a heartbeat from the source.
func (d *DataSource) RecordHeartbeat(version, hostname string, ip net.IP) {
	now := time.Now()
	d.status = SourceStatusActive
	d.lastSeenAt = &now
	d.lastError = ""
	d.errorCount = 0
	if version != "" {
		d.version = version
	}
	if hostname != "" {
		d.hostname = hostname
	}
	if ip != nil {
		d.ipAddress = ip
	}
	d.updatedAt = now
}

// RecordAPIKeyUsage records API key usage.
func (d *DataSource) RecordAPIKeyUsage() {
	now := time.Now()
	d.apiKeyLastUsedAt = &now
	d.updatedAt = now
}

// =============================================================================
// Statistics
// =============================================================================

// RecordSync records a sync operation.
func (d *DataSource) RecordSync(durationMs, assetsCount, findingsCount int) {
	now := time.Now()
	d.lastSyncAt = &now
	d.lastSyncDurationMs = durationMs
	d.lastSyncAssets = assetsCount
	d.lastSyncFindings = findingsCount
	d.assetsCollected += int64(assetsCount)
	d.findingsReported += int64(findingsCount)
	d.updatedAt = now
}

// IncrementAssets increments the assets collected count.
func (d *DataSource) IncrementAssets(count int) {
	d.assetsCollected += int64(count)
	d.updatedAt = time.Now()
}

// IncrementFindings increments the findings reported count.
func (d *DataSource) IncrementFindings(count int) {
	d.findingsReported += int64(count)
	d.updatedAt = time.Now()
}

// =============================================================================
// Business Logic
// =============================================================================

// CanAcceptData returns true if the source can accept data pushes.
func (d *DataSource) CanAcceptData() bool {
	if !d.typ.IsPush() {
		return false
	}
	return d.status.CanReceiveData()
}

// IsStale returns true if the source hasn't been seen recently.
func (d *DataSource) IsStale(threshold time.Duration) bool {
	if d.lastSeenAt == nil {
		return true
	}
	return time.Since(*d.lastSeenAt) > threshold
}

// HasCapability returns true if the source has the given capability.
func (d *DataSource) HasCapability(cap Capability) bool {
	return d.capabilities.Contains(cap)
}
