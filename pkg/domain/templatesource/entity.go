// Package template_source defines the TemplateSource domain entity for managing external template sources.
package templatesource

import (
	"time"

	"github.com/openctemio/api/pkg/domain/scannertemplate"
	"github.com/openctemio/api/pkg/domain/shared"
)

// SourceType represents the type of template source.
type SourceType string

const (
	// SourceTypeGit represents a Git repository source.
	SourceTypeGit SourceType = "git"
	// SourceTypeS3 represents an S3/MinIO bucket source.
	SourceTypeS3 SourceType = "s3"
	// SourceTypeHTTP represents an HTTP URL source.
	SourceTypeHTTP SourceType = "http"
)

// IsValid checks if the source type is valid.
func (s SourceType) IsValid() bool {
	switch s {
	case SourceTypeGit, SourceTypeS3, SourceTypeHTTP:
		return true
	}
	return false
}

// SyncStatus represents the status of the last sync operation.
type SyncStatus string

const (
	// SyncStatusPending means sync has not been attempted yet.
	SyncStatusPending SyncStatus = "pending"
	// SyncStatusInProgress means sync is currently running.
	SyncStatusInProgress SyncStatus = "in_progress"
	// SyncStatusSuccess means the last sync was successful.
	SyncStatusSuccess SyncStatus = "success"
	// SyncStatusFailed means the last sync failed.
	SyncStatusFailed SyncStatus = "failed"
)

// IsValid checks if the sync status is valid.
func (s SyncStatus) IsValid() bool {
	switch s {
	case SyncStatusPending, SyncStatusInProgress, SyncStatusSuccess, SyncStatusFailed:
		return true
	}
	return false
}

// GitSourceConfig holds configuration for Git repository sources.
type GitSourceConfig struct {
	URL      string `json:"url"`                 // https://github.com/org/repo
	Branch   string `json:"branch"`              // main, develop
	Path     string `json:"path,omitempty"`      // templates/nuclei/
	AuthType string `json:"auth_type,omitempty"` // none, ssh, token, oauth
}

// Validate validates the Git source configuration.
func (c *GitSourceConfig) Validate() error {
	if c.URL == "" {
		return shared.NewDomainError("VALIDATION", "git url is required", shared.ErrValidation)
	}
	if c.Branch == "" {
		return shared.NewDomainError("VALIDATION", "git branch is required", shared.ErrValidation)
	}
	return nil
}

// S3SourceConfig holds configuration for S3/MinIO bucket sources.
type S3SourceConfig struct {
	Bucket     string `json:"bucket"`
	Region     string `json:"region"`
	Prefix     string `json:"prefix,omitempty"`      // scanner-templates/nuclei/
	Endpoint   string `json:"endpoint,omitempty"`    // For MinIO
	AuthType   string `json:"auth_type,omitempty"`   // keys, sts_role
	RoleArn    string `json:"role_arn,omitempty"`    // For cross-account
	ExternalID string `json:"external_id,omitempty"` // For STS
}

// Validate validates the S3 source configuration.
func (c *S3SourceConfig) Validate() error {
	if c.Bucket == "" {
		return shared.NewDomainError("VALIDATION", "s3 bucket is required", shared.ErrValidation)
	}
	if c.Region == "" {
		return shared.NewDomainError("VALIDATION", "s3 region is required", shared.ErrValidation)
	}
	return nil
}

// HTTPSourceConfig holds configuration for HTTP URL sources.
type HTTPSourceConfig struct {
	URL      string            `json:"url"`
	AuthType string            `json:"auth_type,omitempty"` // none, bearer, basic, api_key
	Headers  map[string]string `json:"headers,omitempty"`
	Timeout  int               `json:"timeout,omitempty"` // Seconds
}

// Validate validates the HTTP source configuration.
func (c *HTTPSourceConfig) Validate() error {
	if c.URL == "" {
		return shared.NewDomainError("VALIDATION", "http url is required", shared.ErrValidation)
	}
	return nil
}

// TemplateSource represents an external source for scanner templates.
type TemplateSource struct {
	ID           shared.ID
	TenantID     shared.ID
	Name         string
	SourceType   SourceType
	TemplateType scannertemplate.TemplateType
	Description  string
	Enabled      bool

	// Source-specific configuration (polymorphic)
	GitConfig  *GitSourceConfig  `json:"git_config,omitempty"`
	S3Config   *S3SourceConfig   `json:"s3_config,omitempty"`
	HTTPConfig *HTTPSourceConfig `json:"http_config,omitempty"`

	// Lazy sync settings (NO background polling - sync on scan trigger)
	AutoSyncOnScan  bool // Check for updates when scan triggers
	CacheTTLMinutes int  // Minutes to cache before re-check (default: 60)

	// Last sync info
	LastSyncAt     *time.Time
	LastSyncHash   string // ETag/commit hash for change detection
	LastSyncStatus SyncStatus
	LastSyncError  *string

	// Sync statistics
	TotalTemplates int
	LastSyncCount  int // Templates synced in last sync

	// Credential reference
	CredentialID *shared.ID

	// Audit
	CreatedBy *shared.ID
	CreatedAt time.Time
	UpdatedAt time.Time
}

// NewTemplateSource creates a new template source.
func NewTemplateSource(
	tenantID shared.ID,
	name string,
	sourceType SourceType,
	templateType scannertemplate.TemplateType,
	createdBy *shared.ID,
) (*TemplateSource, error) {
	if name == "" {
		return nil, shared.NewDomainError("VALIDATION", "name is required", shared.ErrValidation)
	}
	if len(name) > 255 {
		return nil, shared.NewDomainError("VALIDATION", "name must be less than 255 characters", shared.ErrValidation)
	}
	if !sourceType.IsValid() {
		return nil, shared.NewDomainError("VALIDATION", "invalid source type", shared.ErrValidation)
	}
	if !templateType.IsValid() {
		return nil, shared.NewDomainError("VALIDATION", "invalid template type", shared.ErrValidation)
	}

	now := time.Now()
	return &TemplateSource{
		ID:              shared.NewID(),
		TenantID:        tenantID,
		Name:            name,
		SourceType:      sourceType,
		TemplateType:    templateType,
		Enabled:         true,
		AutoSyncOnScan:  true,
		CacheTTLMinutes: 60,
		LastSyncStatus:  SyncStatusPending,
		CreatedBy:       createdBy,
		CreatedAt:       now,
		UpdatedAt:       now,
	}, nil
}

// SetGitConfig sets the Git source configuration.
func (s *TemplateSource) SetGitConfig(config *GitSourceConfig) error {
	if s.SourceType != SourceTypeGit {
		return shared.NewDomainError("VALIDATION", "cannot set git config for non-git source", shared.ErrValidation)
	}
	if config == nil {
		return shared.NewDomainError("VALIDATION", "git config is required", shared.ErrValidation)
	}
	if err := config.Validate(); err != nil {
		return err
	}
	s.GitConfig = config
	s.UpdatedAt = time.Now()
	return nil
}

// SetS3Config sets the S3 source configuration.
func (s *TemplateSource) SetS3Config(config *S3SourceConfig) error {
	if s.SourceType != SourceTypeS3 {
		return shared.NewDomainError("VALIDATION", "cannot set s3 config for non-s3 source", shared.ErrValidation)
	}
	if config == nil {
		return shared.NewDomainError("VALIDATION", "s3 config is required", shared.ErrValidation)
	}
	if err := config.Validate(); err != nil {
		return err
	}
	s.S3Config = config
	s.UpdatedAt = time.Now()
	return nil
}

// SetHTTPConfig sets the HTTP source configuration.
func (s *TemplateSource) SetHTTPConfig(config *HTTPSourceConfig) error {
	if s.SourceType != SourceTypeHTTP {
		return shared.NewDomainError("VALIDATION", "cannot set http config for non-http source", shared.ErrValidation)
	}
	if config == nil {
		return shared.NewDomainError("VALIDATION", "http config is required", shared.ErrValidation)
	}
	if err := config.Validate(); err != nil {
		return err
	}
	s.HTTPConfig = config
	s.UpdatedAt = time.Now()
	return nil
}

// Update updates the template source.
func (s *TemplateSource) Update(name, description string, autoSyncOnScan bool, cacheTTLMinutes int) error {
	if name != "" {
		if len(name) > 255 {
			return shared.NewDomainError("VALIDATION", "name must be less than 255 characters", shared.ErrValidation)
		}
		s.Name = name
	}
	s.Description = description
	s.AutoSyncOnScan = autoSyncOnScan

	if cacheTTLMinutes > 0 {
		s.CacheTTLMinutes = cacheTTLMinutes
	}

	s.UpdatedAt = time.Now()
	return nil
}

// SetCredential sets the credential reference.
func (s *TemplateSource) SetCredential(credentialID shared.ID) {
	s.CredentialID = &credentialID
	s.UpdatedAt = time.Now()
}

// ClearCredential clears the credential reference.
func (s *TemplateSource) ClearCredential() {
	s.CredentialID = nil
	s.UpdatedAt = time.Now()
}

// Enable enables the source.
func (s *TemplateSource) Enable() {
	s.Enabled = true
	s.UpdatedAt = time.Now()
}

// Disable disables the source.
func (s *TemplateSource) Disable() {
	s.Enabled = false
	s.UpdatedAt = time.Now()
}

// NeedsSync checks if the source needs to be synced based on cache TTL.
func (s *TemplateSource) NeedsSync() bool {
	if !s.Enabled || !s.AutoSyncOnScan {
		return false
	}
	if s.LastSyncAt == nil {
		return true
	}
	cacheDuration := time.Duration(s.CacheTTLMinutes) * time.Minute
	return time.Since(*s.LastSyncAt) > cacheDuration
}

// StartSync marks the sync as in progress.
func (s *TemplateSource) StartSync() {
	s.LastSyncStatus = SyncStatusInProgress
	s.LastSyncError = nil
	s.UpdatedAt = time.Now()
}

// CompleteSyncSuccess marks the sync as successful.
func (s *TemplateSource) CompleteSyncSuccess(hash string, templateCount int) {
	now := time.Now()
	s.LastSyncAt = &now
	s.LastSyncHash = hash
	s.LastSyncStatus = SyncStatusSuccess
	s.LastSyncError = nil
	s.LastSyncCount = templateCount
	s.TotalTemplates = templateCount
	s.UpdatedAt = now
}

// CompleteSyncFailure marks the sync as failed.
func (s *TemplateSource) CompleteSyncFailure(err string) {
	now := time.Now()
	s.LastSyncAt = &now
	s.LastSyncStatus = SyncStatusFailed
	s.LastSyncError = &err
	s.UpdatedAt = now
}

// CanManage checks if the given tenant can manage this source.
func (s *TemplateSource) CanManage(tenantID shared.ID) error {
	if !s.TenantID.Equals(tenantID) {
		return shared.NewDomainError("FORBIDDEN", "source belongs to another tenant", shared.ErrForbidden)
	}
	return nil
}

// BelongsToTenant checks if this source belongs to the specified tenant.
func (s *TemplateSource) BelongsToTenant(tenantID shared.ID) bool {
	return s.TenantID.Equals(tenantID)
}

// GetSourceConfig returns the active source configuration based on source type.
func (s *TemplateSource) GetSourceConfig() any {
	switch s.SourceType {
	case SourceTypeGit:
		return s.GitConfig
	case SourceTypeS3:
		return s.S3Config
	case SourceTypeHTTP:
		return s.HTTPConfig
	default:
		return nil
	}
}

// Validate validates the source configuration.
func (s *TemplateSource) Validate() error {
	switch s.SourceType {
	case SourceTypeGit:
		if s.GitConfig == nil {
			return shared.NewDomainError("VALIDATION", "git config is required for git source", shared.ErrValidation)
		}
		return s.GitConfig.Validate()
	case SourceTypeS3:
		if s.S3Config == nil {
			return shared.NewDomainError("VALIDATION", "s3 config is required for s3 source", shared.ErrValidation)
		}
		return s.S3Config.Validate()
	case SourceTypeHTTP:
		if s.HTTPConfig == nil {
			return shared.NewDomainError("VALIDATION", "http config is required for http source", shared.ErrValidation)
		}
		return s.HTTPConfig.Validate()
	default:
		return shared.NewDomainError("VALIDATION", "invalid source type", shared.ErrValidation)
	}
}
