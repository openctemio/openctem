package agent

import (
	"time"

	"github.com/openctemio/api/pkg/domain/shared"
)

// APIKeyScope represents a permission scope for API keys.
type APIKeyScope string

const (
	ScopeIngestWrite    APIKeyScope = "ingest:write"     // Push findings and assets
	ScopeIngestRead     APIKeyScope = "ingest:read"      // Read ingested data
	ScopeCommandsRead   APIKeyScope = "commands:read"    // Poll for pending commands
	ScopeCommandsExec   APIKeyScope = "commands:execute" // Execute commands and report results
	ScopeCommandsWrite  APIKeyScope = "commands:write"   // Create commands (admin only)
	ScopeAgentHeartbeat APIKeyScope = "agent:heartbeat"  // Send heartbeat/status updates
	ScopeAgentRead      APIKeyScope = "agent:read"       // Read own agent config
	ScopeAgentWrite     APIKeyScope = "agent:write"      // Update own agent config
	ScopeAdminAgents    APIKeyScope = "admin:agents"     // Manage other agents
	ScopeAdminKeys      APIKeyScope = "admin:keys"       // Manage API keys
	ScopeAdminTokens    APIKeyScope = "admin:tokens"     // Manage registration tokens
)

// DefaultAgentScopes returns default scopes for an agent.
func DefaultAgentScopes() []string {
	return []string{
		string(ScopeIngestWrite),
		string(ScopeCommandsRead),
		string(ScopeAgentHeartbeat),
	}
}

// RunnerScopes returns scopes for a runner (CI/CD).
func RunnerScopes() []string {
	return []string{
		string(ScopeIngestWrite),
		string(ScopeAgentHeartbeat),
	}
}

// CollectorScopes returns scopes for a collector.
func CollectorScopes() []string {
	return []string{
		string(ScopeIngestWrite),
		string(ScopeAgentHeartbeat),
		string(ScopeAgentRead),
	}
}

// WorkerScopes returns scopes for a worker (daemon).
func WorkerScopes() []string {
	return []string{
		string(ScopeIngestWrite),
		string(ScopeCommandsRead),
		string(ScopeCommandsExec),
		string(ScopeAgentHeartbeat),
		string(ScopeAgentRead),
	}
}

// SensorScopes returns scopes for a sensor (EASM).
func SensorScopes() []string {
	return []string{
		string(ScopeIngestWrite),
		string(ScopeAgentHeartbeat),
		string(ScopeAgentRead),
	}
}

// APIKey represents an API key for an agent.
type APIKey struct {
	ID        shared.ID
	AgentID   shared.ID
	Name      string
	KeyHash   string
	KeyPrefix string
	Scopes    []string

	// Lifecycle
	ExpiresAt  *time.Time
	LastUsedAt *time.Time
	LastUsedIP string
	UseCount   int64

	// Status
	IsActive      bool
	RevokedAt     *time.Time
	RevokedReason string

	// Timestamps
	CreatedAt time.Time
}

// NewAPIKey creates a new API key entity.
func NewAPIKey(agentID shared.ID, name string, scopes []string) (*APIKey, error) {
	if name == "" {
		name = "default"
	}

	if len(scopes) == 0 {
		scopes = DefaultAgentScopes()
	}

	return &APIKey{
		ID:        shared.NewID(),
		AgentID:   agentID,
		Name:      name,
		Scopes:    scopes,
		IsActive:  true,
		CreatedAt: time.Now(),
	}, nil
}

// SetKeyHash sets the key hash and prefix.
func (k *APIKey) SetKeyHash(hash, prefix string) {
	k.KeyHash = hash
	k.KeyPrefix = prefix
}

// SetExpiration sets the expiration time.
func (k *APIKey) SetExpiration(expiresAt time.Time) {
	k.ExpiresAt = &expiresAt
}

// RecordUsage records a usage of the API key.
func (k *APIKey) RecordUsage(ip string) {
	now := time.Now()
	k.LastUsedAt = &now
	k.LastUsedIP = ip
	k.UseCount++
}

// Revoke revokes the API key.
func (k *APIKey) Revoke(reason string) {
	now := time.Now()
	k.IsActive = false
	k.RevokedAt = &now
	k.RevokedReason = reason
}

// IsExpired checks if the key is expired.
func (k *APIKey) IsExpired() bool {
	if k.ExpiresAt == nil {
		return false
	}
	return time.Now().After(*k.ExpiresAt)
}

// IsValid checks if the key is valid (active and not expired).
func (k *APIKey) IsValid() bool {
	return k.IsActive && !k.IsExpired()
}

// HasScope checks if the key has a specific scope.
func (k *APIKey) HasScope(scope APIKeyScope) bool {
	for _, s := range k.Scopes {
		if s == string(scope) {
			return true
		}
	}
	return false
}

// HasAnyScope checks if the key has any of the specified scopes.
func (k *APIKey) HasAnyScope(scopes ...APIKeyScope) bool {
	for _, scope := range scopes {
		if k.HasScope(scope) {
			return true
		}
	}
	return false
}
