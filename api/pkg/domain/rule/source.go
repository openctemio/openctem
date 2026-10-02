// Package rule provides domain entities for rule management.
// Rules are security scanning rules/templates from various sources
// (platform defaults, Git repos, HTTP URLs) that can be customized per tenant.
package rule

import (
	"encoding/json"
	"time"

	"github.com/openctemio/api/pkg/domain/shared"
)

// SourceType represents the type of rule source.
type SourceType string

const (
	SourceTypeGit   SourceType = "git"
	SourceTypeHTTP  SourceType = "http"
	SourceTypeLocal SourceType = "local"
)

// IsValid checks if the source type is valid.
func (t SourceType) IsValid() bool {
	switch t {
	case SourceTypeGit, SourceTypeHTTP, SourceTypeLocal:
		return true
	}
	return false
}

// SyncStatus represents the synchronization status.
type SyncStatus string

const (
	SyncStatusPending SyncStatus = "pending"
	SyncStatusSyncing SyncStatus = "syncing"
	SyncStatusSuccess SyncStatus = "success"
	SyncStatusFailed  SyncStatus = "failed"
)

// GitConfig represents configuration for Git-based rule sources.
type GitConfig struct {
	URL           string `json:"url"`
	Branch        string `json:"branch"`
	Path          string `json:"path"`           // Subdirectory containing rules
	AuthType      string `json:"auth_type"`      // none, ssh, token
	CredentialsID string `json:"credentials_id"` // Reference to stored credentials
}

// HTTPConfig represents configuration for HTTP-based rule sources.
type HTTPConfig struct {
	URL           string `json:"url"`
	AuthType      string `json:"auth_type"`      // none, basic, bearer
	CredentialsID string `json:"credentials_id"` // Reference to stored credentials
}

// LocalConfig represents configuration for local file-based rule sources.
type LocalConfig struct {
	Path string `json:"path"`
}

// Source represents a rule source where rules are fetched from.
type Source struct {
	ID          shared.ID
	TenantID    shared.ID
	ToolID      *shared.ID // Optional: if nil, applies to all tools
	Name        string
	Description string

	// Source configuration
	SourceType SourceType
	Config     json.RawMessage // GitConfig, HTTPConfig, or LocalConfig

	// Credentials reference (not stored directly)
	CredentialsID *shared.ID

	// Sync configuration
	SyncEnabled         bool
	SyncIntervalMinutes int

	// Sync status
	LastSyncAt       *time.Time
	LastSyncStatus   SyncStatus
	LastSyncError    string
	LastSyncDuration time.Duration
	ContentHash      string // SHA256 of synced content

	// Statistics
	RuleCount int

	// Priority for merge order (higher = applied later)
	Priority int

	// Platform default (managed by system)
	IsPlatformDefault bool

	Enabled   bool
	CreatedAt time.Time
	UpdatedAt time.Time
}

// NewSource creates a new rule source.
func NewSource(
	tenantID shared.ID,
	toolID *shared.ID,
	name string,
	sourceType SourceType,
	config json.RawMessage,
) (*Source, error) {
	if name == "" {
		return nil, shared.NewDomainError("VALIDATION", "name is required", shared.ErrValidation)
	}

	if !sourceType.IsValid() {
		return nil, shared.NewDomainError("VALIDATION", "invalid source type", shared.ErrValidation)
	}

	now := time.Now()
	return &Source{
		ID:                  shared.NewID(),
		TenantID:            tenantID,
		ToolID:              toolID,
		Name:                name,
		SourceType:          sourceType,
		Config:              config,
		SyncEnabled:         true,
		SyncIntervalMinutes: 60,
		LastSyncStatus:      SyncStatusPending,
		Priority:            100,
		IsPlatformDefault:   false,
		Enabled:             true,
		CreatedAt:           now,
		UpdatedAt:           now,
	}, nil
}

// GetGitConfig parses and returns the Git configuration.
func (s *Source) GetGitConfig() (*GitConfig, error) {
	if s.SourceType != SourceTypeGit {
		return nil, shared.NewDomainError("VALIDATION", "source is not a Git source", shared.ErrValidation)
	}
	var cfg GitConfig
	if err := json.Unmarshal(s.Config, &cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// GetHTTPConfig parses and returns the HTTP configuration.
func (s *Source) GetHTTPConfig() (*HTTPConfig, error) {
	if s.SourceType != SourceTypeHTTP {
		return nil, shared.NewDomainError("VALIDATION", "source is not an HTTP source", shared.ErrValidation)
	}
	var cfg HTTPConfig
	if err := json.Unmarshal(s.Config, &cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// GetLocalConfig parses and returns the local configuration.
func (s *Source) GetLocalConfig() (*LocalConfig, error) {
	if s.SourceType != SourceTypeLocal {
		return nil, shared.NewDomainError("VALIDATION", "source is not a local source", shared.ErrValidation)
	}
	var cfg LocalConfig
	if err := json.Unmarshal(s.Config, &cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// MarkSyncStarted marks the source as currently syncing.
func (s *Source) MarkSyncStarted() {
	s.LastSyncStatus = SyncStatusSyncing
	s.UpdatedAt = time.Now()
}

// MarkSyncSuccess marks the source as successfully synced.
func (s *Source) MarkSyncSuccess(hash string, ruleCount int, duration time.Duration) {
	now := time.Now()
	s.LastSyncAt = &now
	s.LastSyncStatus = SyncStatusSuccess
	s.LastSyncError = ""
	s.LastSyncDuration = duration
	s.ContentHash = hash
	s.RuleCount = ruleCount
	s.UpdatedAt = now
}

// MarkSyncFailed marks the source sync as failed.
func (s *Source) MarkSyncFailed(errMsg string, duration time.Duration) {
	now := time.Now()
	s.LastSyncAt = &now
	s.LastSyncStatus = SyncStatusFailed
	s.LastSyncError = errMsg
	s.LastSyncDuration = duration
	s.UpdatedAt = now
}

// NeedsSync checks if the source needs to be synced based on interval.
func (s *Source) NeedsSync() bool {
	if !s.Enabled || !s.SyncEnabled {
		return false
	}
	if s.LastSyncAt == nil {
		return true
	}
	nextSync := s.LastSyncAt.Add(time.Duration(s.SyncIntervalMinutes) * time.Minute)
	return time.Now().After(nextSync)
}

// SetEnabled enables or disables the source.
func (s *Source) SetEnabled(enabled bool) {
	s.Enabled = enabled
	s.UpdatedAt = time.Now()
}

// SetPriority sets the merge priority.
func (s *Source) SetPriority(priority int) {
	s.Priority = priority
	s.UpdatedAt = time.Now()
}
