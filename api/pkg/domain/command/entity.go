// Package command defines the Command domain entity for server-controlled sensors.
package command

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

const (
	// AuthTokenLength is the length of generated auth tokens (32 bytes = 64 hex chars)
	AuthTokenLength = 32

	// AuthTokenPrefix is the prefix for auth tokens
	AuthTokenPrefix = "oc-cmd-"

	// DefaultAuthTokenTTL is the default time-to-live for auth tokens (24 hours)
	DefaultAuthTokenTTL = 24 * time.Hour

	// DefaultCommandTTL is the expiry every command gets unless the caller asks
	// for a different one. It is a BACKSTOP, not a scheduling knob: it exists so
	// a command that nothing ever answers eventually reaches
	// ExpirationChecker -> scanrun.OnStepFailed("COMMAND_EXPIRED") instead of
	// leaving the owning run waiting forever.
	//
	// Every command used to be created with expires_at NULL, and both consumers
	// of the column require `expires_at IS NOT NULL` — so FindExpired matched
	// zero rows in every deployment and the checker had never expired anything.
	//
	// 48h is deliberately chosen to sit BEYOND every other timeout in the
	// command path, so those fire first and this one only catches what they miss:
	//
	//   10m  JobRecoveryController.TenantStuckThresholdMinutes
	//   30m  JobRecoveryController.StuckThresholdMinutes (platform jobs)
	//   60m  ExpirationChecker.MaxQueueMinutes (platform job stuck in queue)
	//    1h  scan.DefaultScanTimeoutSeconds -> ScanTimeoutController
	//   24h  scan.MaxScanTimeoutSeconds (the longest a scan may legitimately run)
	//   24h  DefaultAuthTokenTTL (past this a platform job cannot authenticate,
	//        so it can no longer be executed even if a sensor picked it up)
	//
	// A shorter TTL would start expiring healthy in-flight work, which is worse
	// than the inertness this replaces. Note also that FindExpired only matches
	// status IN ('pending','acknowledged') — a command that is actually
	// 'running' is never expired by this path however long it runs.
	DefaultCommandTTL = 48 * time.Hour
)

// CommandType represents the type of command.
type CommandType string

const (
	CommandTypeScan         CommandType = "scan"
	CommandTypeCollect      CommandType = "collect"
	CommandTypeHealthCheck  CommandType = "health_check"
	CommandTypeConfigUpdate CommandType = "config_update"
	CommandTypeCancel       CommandType = "cancel"
	// CommandTypeValidate is a CTEM Stage-4 validation job: a sensor re-checks a
	// finding (safe-check / nuclei / adversary emulation) and reports an outcome
	// that is mapped back into validation evidence on completion.
	CommandTypeValidate CommandType = "validate"
	// CommandTypeRefreshContent asks one sensor to refresh its scanner
	// content (trivy DB, nuclei templates, semgrep rules) under the tenant's
	// content policy (RFC-031). Always pinned to the sensor.
	CommandTypeRefreshContent CommandType = "refresh_content"
	// CommandTypeConnectorSync asks the sensor named by a connector
	// integration to pull data from the product it connects to (Tenable.sc:
	// hosts, vulnerabilities, plugins) and push it as CTIS reports bound to
	// the command (docs/rfcs/RFC-047-tenable-sc-sensor-connector.md). Always
	// pinned to the sensor; the payload names the tool in "scanner".
	CommandTypeConnectorSync CommandType = "connector_sync"
	// CommandTypeConnectorScan asks a connector sensor to launch one scan in
	// the product it connects to on probe-gated targets (RFC-047).
	CommandTypeConnectorScan CommandType = "connector_scan"
	// CommandTypeRetest asks a sensor to re-check known findings with the
	// retest handler of the tool that produced them (RFC-039, tool retest).
	// The payload names the tool, the targets (each finding's own asset
	// address, active-probe gated) and the items; the result carries one
	// verdict per item: still_present, fixed or unverifiable.
	CommandTypeRetest CommandType = "retest"
)

// CommandStatus represents the status of a command.
type CommandStatus string

const (
	CommandStatusPending      CommandStatus = "pending"
	CommandStatusAcknowledged CommandStatus = "acknowledged"
	CommandStatusRunning      CommandStatus = "running"
	CommandStatusCompleted    CommandStatus = "completed"
	CommandStatusFailed       CommandStatus = "failed"
	CommandStatusCanceled     CommandStatus = "canceled"
	CommandStatusExpired      CommandStatus = "expired"
)

// CommandPriority represents the priority of a command.
type CommandPriority string

const (
	CommandPriorityLow      CommandPriority = "low"
	CommandPriorityNormal   CommandPriority = "normal"
	CommandPriorityHigh     CommandPriority = "high"
	CommandPriorityCritical CommandPriority = "critical"
)

// Command represents a command to be executed by a sensor.
type Command struct {
	ID       shared.ID
	TenantID shared.ID
	SensorID *shared.ID // Target sensor (nil = any sensor can pick up)

	Type     CommandType
	Priority CommandPriority
	Payload  json.RawMessage

	Status       CommandStatus
	ErrorMessage string

	// Timing
	CreatedAt      time.Time
	ExpiresAt      *time.Time
	AcknowledgedAt *time.Time
	StartedAt      *time.Time
	CompletedAt    *time.Time

	// Result
	Result json.RawMessage

	// Scheduling
	ScheduledAt *time.Time
	ScheduleID  *shared.ID

	// Scan workflow tracking
	StepRunID *shared.ID // Reference to workflow step run (for progression tracking)

	// ScanZoneID is the scan zone the command was routed to (RFC-023). When
	// set, only a sensor assigned to that zone may poll or claim it, even after
	// the reaper unpins it. Never sent on the protocol-v1 wire.
	ScanZoneID *shared.ID

	// FreezeOverride lets the command through an active scan freeze window.
	// Only the server sets it, on the commands of a run a member with
	// scans:freeze:override started during a window (audited); it is
	// written on create and never read back from a request.
	FreezeOverride bool

	// HostKeys are the hosts an active workflow chunk sends traffic to.
	// While the command is acknowledged or running, no other command of
	// the tenant with one of these keys is claimed (platform-side per-host
	// politeness, research/49 §3.12.3). Nil: no per-host limit. Written on
	// create only; never sent to a sensor.
	HostKeys []string

	// DispatchGate is what the dispatch gate checked the targets with; the
	// claim re-checks them with it (dispatch_gate.go). Nil: not recorded.
	// Written on create only; never sent to a sensor.
	DispatchGate *DispatchGate

	// ==========================================================================
	// Platform Job Fields (v3.2)
	// ==========================================================================

	// IsPlatformJob indicates this job runs on a platform sensor (not tenant's own sensor)
	IsPlatformJob bool

	// PlatformSensorID is the platform sensor assigned to execute this job (auto-selected)
	PlatformSensorID *shared.ID

	// ==========================================================================
	// Authentication Token Fields (for platform sensors)
	// Platform sensors use these tokens to verify they're authorized to execute
	// this specific command. Provides defense-in-depth with API key.
	// ==========================================================================

	// AuthTokenHash is the SHA256 hash of the auth token (for verification)
	AuthTokenHash string

	// AuthTokenPrefix is the first 8 characters of the token (for logging/debugging)
	AuthTokenPrefix string

	// AuthTokenExpiresAt is when the auth token expires (typically 24h after creation)
	AuthTokenExpiresAt *time.Time

	// ==========================================================================
	// Queue Management Fields (v3.1)
	// For fair scheduling of platform jobs across tenants
	// ==========================================================================

	// QueuePriority is the calculated priority score (plan_base + age_bonus)
	// Higher value = processed first
	QueuePriority int

	// QueuedAt is when the job was added to the platform queue
	QueuedAt *time.Time

	// DispatchAttempts tracks how many times dispatch was attempted
	DispatchAttempts int

	// LastDispatchAt is the last time dispatch was attempted
	LastDispatchAt *time.Time

	// LeaseEpoch counts the claims of the command: every claim starts a new
	// lease epoch. A sensor-side state change is applied only under the
	// epoch it read (no completion after a re-queue). LeaseExpiresAt is when
	// the holder's lease runs out unless renewed; nil when nobody holds it.
	LeaseEpoch     int
	LeaseExpiresAt *time.Time
}

// NewCommand creates a new Command entity.
//
// The expiry default is applied here rather than at the call sites because this
// constructor is the single seam every command creation goes through
// (scan/trigger, scan/coverage dispatch, scan workflow/run, validation/dispatcher and
// the command service). Setting it per-site is what left expires_at NULL
// everywhere. Callers that need a different deadline override it afterwards with
// SetExpiration.
func NewCommand(tenantID shared.ID, cmdType CommandType, priority CommandPriority, payload json.RawMessage) (*Command, error) {
	if cmdType == "" {
		return nil, shared.NewDomainError("VALIDATION", "command type is required", shared.ErrValidation)
	}

	if priority == "" {
		priority = CommandPriorityNormal
	}

	now := time.Now()
	expiresAt := now.Add(DefaultCommandTTL)

	return &Command{
		ID:        shared.NewID(),
		TenantID:  tenantID,
		Type:      cmdType,
		Priority:  priority,
		Payload:   payload,
		Status:    CommandStatusPending,
		CreatedAt: now,
		ExpiresAt: &expiresAt,
	}, nil
}

// SetSensorID sets the target sensor ID.
func (c *Command) SetSensorID(sensorID shared.ID) {
	c.SensorID = &sensorID
}

// SetScanZone stamps the scan zone the command was routed to.
func (c *Command) SetScanZone(zoneID shared.ID) {
	c.ScanZoneID = &zoneID
}

// SetStepRunID sets the workflow step run ID for tracking.
func (c *Command) SetStepRunID(stepRunID shared.ID) {
	c.StepRunID = &stepRunID
}

// SetExpiration sets the expiration time.
func (c *Command) SetExpiration(expiresAt time.Time) {
	c.ExpiresAt = &expiresAt
}

// Acknowledge marks the command as acknowledged.
func (c *Command) Acknowledge() {
	now := time.Now()
	c.Status = CommandStatusAcknowledged
	c.AcknowledgedAt = &now
}

// Start marks the command as running.
func (c *Command) Start() {
	now := time.Now()
	c.Status = CommandStatusRunning
	c.StartedAt = &now
}

// Complete marks the command as completed.
func (c *Command) Complete(result json.RawMessage) {
	now := time.Now()
	c.Status = CommandStatusCompleted
	c.CompletedAt = &now
	c.Result = result
}

// Fail marks the command as failed.
func (c *Command) Fail(errorMessage string) {
	now := time.Now()
	c.Status = CommandStatusFailed
	c.CompletedAt = &now
	c.ErrorMessage = errorMessage
}

// Cancel marks the command as canceled.
func (c *Command) Cancel() {
	now := time.Now()
	c.Status = CommandStatusCanceled
	c.CompletedAt = &now
}

// Expire marks the command as expired.
func (c *Command) Expire() {
	c.Status = CommandStatusExpired
}

// IsExpired checks if the command has expired.
func (c *Command) IsExpired() bool {
	if c.ExpiresAt == nil {
		return false
	}
	return time.Now().After(*c.ExpiresAt)
}

// IsPending checks if the command is pending.
func (c *Command) IsPending() bool {
	return c.Status == CommandStatusPending
}

// CanBeAcknowledged checks if the command can be acknowledged.
func (c *Command) CanBeAcknowledged() bool {
	return c.Status == CommandStatusPending && !c.IsExpired()
}

// =============================================================================
// Platform Job Methods
// =============================================================================

// SetPlatformJob marks this command as a platform job and enqueues it.
func (c *Command) SetPlatformJob(queuePriority int) {
	c.IsPlatformJob = true
	c.QueuePriority = queuePriority
	now := time.Now()
	c.QueuedAt = &now
}

// AssignToPlatformSensor assigns this job to a specific platform sensor.
func (c *Command) AssignToPlatformSensor(sensorID shared.ID) {
	c.PlatformSensorID = &sensorID
	c.DispatchAttempts++
	now := time.Now()
	c.LastDispatchAt = &now
}

// ReturnToQueue returns the job to the queue (e.g., if sensor went offline).
func (c *Command) ReturnToQueue() {
	c.PlatformSensorID = nil
	c.Status = CommandStatusPending
	c.AcknowledgedAt = nil
}

// UpdateQueuePriority updates the queue priority (called by scheduler).
func (c *Command) UpdateQueuePriority(newPriority int) {
	c.QueuePriority = newPriority
}

// IsQueued checks if this job is in the queue waiting for dispatch.
func (c *Command) IsQueued() bool {
	return c.IsPlatformJob && c.Status == CommandStatusPending && c.PlatformSensorID == nil
}

// IsDispatchedToPlatformSensor checks if this job has been dispatched to a platform sensor.
func (c *Command) IsDispatchedToPlatformSensor() bool {
	return c.IsPlatformJob && c.PlatformSensorID != nil
}

// CanRetry checks if this job can be retried after failure.
func (c *Command) CanRetry(maxRetries int) bool {
	return c.DispatchAttempts < maxRetries
}

// =============================================================================
// Auth Token Methods (for platform sensor authentication)
// =============================================================================

// GenerateAuthToken generates a new auth token for this command.
// Returns the raw token (to be sent to sensor) and sets the hash on the command.
// The raw token should only be transmitted once and never stored.
func (c *Command) GenerateAuthToken(ttl time.Duration) (string, error) {
	// Generate random bytes
	tokenBytes := make([]byte, AuthTokenLength)
	if _, err := rand.Read(tokenBytes); err != nil {
		return "", err
	}

	// Create the full token with prefix
	rawToken := AuthTokenPrefix + hex.EncodeToString(tokenBytes)

	// Hash the token for storage
	hash := sha256.Sum256([]byte(rawToken))
	c.AuthTokenHash = hex.EncodeToString(hash[:])

	// Store prefix for logging
	c.AuthTokenPrefix = rawToken[:len(AuthTokenPrefix)+8]

	// Set expiration
	if ttl == 0 {
		ttl = DefaultAuthTokenTTL
	}
	expiresAt := time.Now().Add(ttl)
	c.AuthTokenExpiresAt = &expiresAt

	return rawToken, nil
}

// VerifyAuthToken verifies if the provided token matches this command's token.
// Uses constant-time comparison to prevent timing attacks.
func (c *Command) VerifyAuthToken(token string) bool {
	if c.AuthTokenHash == "" {
		return false
	}

	// Hash the provided token
	hash := sha256.Sum256([]byte(token))
	providedHash := hex.EncodeToString(hash[:])

	// Constant-time comparison
	if len(providedHash) != len(c.AuthTokenHash) {
		return false
	}

	var result byte
	for i := 0; i < len(providedHash); i++ {
		result |= providedHash[i] ^ c.AuthTokenHash[i]
	}
	return result == 0
}

// IsAuthTokenValid checks if the auth token is still valid (not expired).
func (c *Command) IsAuthTokenValid() bool {
	if c.AuthTokenExpiresAt == nil {
		return false
	}
	return time.Now().Before(*c.AuthTokenExpiresAt)
}

// CanAcceptIngest checks if this command can accept ingest data from a platform sensor.
// The command must be running, have a valid token, and match the sensor.
func (c *Command) CanAcceptIngest(sensorID shared.ID, token string) bool {
	// Must be a platform job
	if !c.IsPlatformJob {
		return false
	}

	// Must be running
	if c.Status != CommandStatusRunning && c.Status != CommandStatusAcknowledged {
		return false
	}

	// Sensor must match
	if c.PlatformSensorID == nil || *c.PlatformSensorID != sensorID {
		return false
	}

	// Token must be valid
	if !c.IsAuthTokenValid() || !c.VerifyAuthToken(token) {
		return false
	}

	return true
}

// ClearAuthToken clears the auth token (call after command completes).
func (c *Command) ClearAuthToken() {
	c.AuthTokenHash = ""
	c.AuthTokenPrefix = ""
	c.AuthTokenExpiresAt = nil
}

// =============================================================================
// Queue Position Estimation
// =============================================================================

// QueuePosition represents a position in the platform job queue.
type QueuePosition struct {
	Position      int           `json:"position"`       // Position in queue (1-based)
	TotalQueued   int           `json:"total_queued"`   // Total jobs in queue
	Priority      int           `json:"priority"`       // Current priority score
	EstimatedWait time.Duration `json:"estimated_wait"` // Estimated wait time
}

// EstimateWaitTime estimates the wait time based on position and historical data.
func (q *QueuePosition) EstimateWaitTime(avgJobDuration time.Duration, availableSensors int) time.Duration {
	if availableSensors <= 0 {
		availableSensors = 1
	}
	// Rough estimate: (position / sensors) * avg_duration
	waves := (q.Position + availableSensors - 1) / availableSensors
	return time.Duration(waves) * avgJobDuration
}
