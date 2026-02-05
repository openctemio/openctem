// Package command defines the Command domain entity for server-controlled agents.
package command

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"time"

	"github.com/openctemio/api/pkg/domain/shared"
)

const (
	// AuthTokenLength is the length of generated auth tokens (32 bytes = 64 hex chars)
	AuthTokenLength = 32

	// AuthTokenPrefix is the prefix for auth tokens
	AuthTokenPrefix = "exp-ct-"

	// DefaultAuthTokenTTL is the default time-to-live for auth tokens (24 hours)
	DefaultAuthTokenTTL = 24 * time.Hour
)

// CommandType represents the type of command.
type CommandType string

const (
	CommandTypeScan         CommandType = "scan"
	CommandTypeCollect      CommandType = "collect"
	CommandTypeHealthCheck  CommandType = "health_check"
	CommandTypeConfigUpdate CommandType = "config_update"
	CommandTypeCancel       CommandType = "cancel"
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

// Command represents a command to be executed by an agent.
type Command struct {
	ID       shared.ID
	TenantID shared.ID
	AgentID  *shared.ID // Target agent (nil = any agent can pick up)

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

	// Pipeline tracking
	StepRunID *shared.ID // Reference to pipeline step run (for progression tracking)

	// ==========================================================================
	// Platform Job Fields (v3.2)
	// ==========================================================================

	// IsPlatformJob indicates this job runs on a platform agent (not tenant's own agent)
	IsPlatformJob bool

	// PlatformAgentID is the platform agent assigned to execute this job (auto-selected)
	PlatformAgentID *shared.ID

	// ==========================================================================
	// Authentication Token Fields (for platform agents)
	// Platform agents use these tokens to verify they're authorized to execute
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
}

// NewCommand creates a new Command entity.
func NewCommand(tenantID shared.ID, cmdType CommandType, priority CommandPriority, payload json.RawMessage) (*Command, error) {
	if cmdType == "" {
		return nil, shared.NewDomainError("VALIDATION", "command type is required", shared.ErrValidation)
	}

	if priority == "" {
		priority = CommandPriorityNormal
	}

	return &Command{
		ID:        shared.NewID(),
		TenantID:  tenantID,
		Type:      cmdType,
		Priority:  priority,
		Payload:   payload,
		Status:    CommandStatusPending,
		CreatedAt: time.Now(),
	}, nil
}

// SetAgentID sets the target agent ID.
func (c *Command) SetAgentID(agentID shared.ID) {
	c.AgentID = &agentID
}

// SetStepRunID sets the pipeline step run ID for tracking.
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

// AssignToPlatformAgent assigns this job to a specific platform agent.
func (c *Command) AssignToPlatformAgent(agentID shared.ID) {
	c.PlatformAgentID = &agentID
	c.DispatchAttempts++
	now := time.Now()
	c.LastDispatchAt = &now
}

// ReturnToQueue returns the job to the queue (e.g., if agent went offline).
func (c *Command) ReturnToQueue() {
	c.PlatformAgentID = nil
	c.Status = CommandStatusPending
	c.AcknowledgedAt = nil
}

// UpdateQueuePriority updates the queue priority (called by scheduler).
func (c *Command) UpdateQueuePriority(newPriority int) {
	c.QueuePriority = newPriority
}

// IsQueued checks if this job is in the queue waiting for dispatch.
func (c *Command) IsQueued() bool {
	return c.IsPlatformJob && c.Status == CommandStatusPending && c.PlatformAgentID == nil
}

// IsDispatchedToPlatformAgent checks if this job has been dispatched to a platform agent.
func (c *Command) IsDispatchedToPlatformAgent() bool {
	return c.IsPlatformJob && c.PlatformAgentID != nil
}

// CanRetry checks if this job can be retried after failure.
func (c *Command) CanRetry(maxRetries int) bool {
	return c.DispatchAttempts < maxRetries
}

// =============================================================================
// Auth Token Methods (for platform agent authentication)
// =============================================================================

// GenerateAuthToken generates a new auth token for this command.
// Returns the raw token (to be sent to agent) and sets the hash on the command.
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

// CanAcceptIngest checks if this command can accept ingest data from a platform agent.
// The command must be running, have a valid token, and match the agent.
func (c *Command) CanAcceptIngest(agentID shared.ID, token string) bool {
	// Must be a platform job
	if !c.IsPlatformJob {
		return false
	}

	// Must be running
	if c.Status != CommandStatusRunning && c.Status != CommandStatusAcknowledged {
		return false
	}

	// Agent must match
	if c.PlatformAgentID == nil || *c.PlatformAgentID != agentID {
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
func (q *QueuePosition) EstimateWaitTime(avgJobDuration time.Duration, availableAgents int) time.Duration {
	if availableAgents <= 0 {
		availableAgents = 1
	}
	// Rough estimate: (position / agents) * avg_duration
	waves := (q.Position + availableAgents - 1) / availableAgents
	return time.Duration(waves) * avgJobDuration
}
