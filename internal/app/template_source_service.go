package app

import (
	"context"
	"fmt"
	"sync"

	"github.com/openctemio/api/pkg/domain/scannertemplate"
	"github.com/openctemio/api/pkg/domain/shared"
	ts "github.com/openctemio/api/pkg/domain/templatesource"
	"github.com/openctemio/api/pkg/logger"
)

// MaxSourcesPerTenant is the maximum number of template sources a tenant can have.
const MaxSourcesPerTenant = 50

// TemplateSourceService handles template source business operations.
type TemplateSourceService struct {
	repo           ts.Repository
	templateSyncer *TemplateSyncer
	syncingMap     sync.Map // Tracks currently syncing sources
	logger         *logger.Logger
}

// NewTemplateSourceService creates a new TemplateSourceService.
func NewTemplateSourceService(repo ts.Repository, log *logger.Logger) *TemplateSourceService {
	return &TemplateSourceService{
		repo:   repo,
		logger: log.With("service", "template_source"),
	}
}

// SetTemplateSyncer sets the template syncer for force sync operations.
func (s *TemplateSourceService) SetTemplateSyncer(syncer *TemplateSyncer) {
	s.templateSyncer = syncer
}

// CreateTemplateSourceInput represents the input for creating a template source.
type CreateTemplateSourceInput struct {
	TenantID        string               `json:"tenant_id" validate:"required,uuid"`
	UserID          string               `json:"user_id" validate:"omitempty,uuid"`
	Name            string               `json:"name" validate:"required,min=1,max=255"`
	SourceType      string               `json:"source_type" validate:"required,oneof=git s3 http"`
	TemplateType    string               `json:"template_type" validate:"required,oneof=nuclei semgrep gitleaks"`
	Description     string               `json:"description" validate:"max=1000"`
	Enabled         bool                 `json:"enabled"`
	AutoSyncOnScan  bool                 `json:"auto_sync_on_scan"`
	CacheTTLMinutes int                  `json:"cache_ttl_minutes" validate:"min=0,max=10080"` // Max 1 week
	GitConfig       *ts.GitSourceConfig  `json:"git_config,omitempty"`
	S3Config        *ts.S3SourceConfig   `json:"s3_config,omitempty"`
	HTTPConfig      *ts.HTTPSourceConfig `json:"http_config,omitempty"`
	CredentialID    string               `json:"credential_id" validate:"omitempty,uuid"`
}

// CreateSource creates a new template source.
func (s *TemplateSourceService) CreateSource(ctx context.Context, input CreateTemplateSourceInput) (*ts.TemplateSource, error) {
	s.logger.Info("creating template source", "name", input.Name, "source_type", input.SourceType, "template_type", input.TemplateType)

	tenantID, err := shared.IDFromString(input.TenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}

	var createdBy *shared.ID
	if input.UserID != "" {
		uid, err := shared.IDFromString(input.UserID)
		if err != nil {
			return nil, fmt.Errorf("%w: invalid user id", shared.ErrValidation)
		}
		createdBy = &uid
	}

	sourceType := ts.SourceType(input.SourceType)
	if !sourceType.IsValid() {
		return nil, fmt.Errorf("%w: invalid source type", shared.ErrValidation)
	}

	templateType := scannertemplate.TemplateType(input.TemplateType)
	if !templateType.IsValid() {
		return nil, fmt.Errorf("%w: invalid template type", shared.ErrValidation)
	}

	// Check source limit per tenant
	count, err := s.repo.CountByTenant(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to count sources: %w", err)
	}
	if count >= MaxSourcesPerTenant {
		return nil, shared.NewDomainError("LIMIT_EXCEEDED", fmt.Sprintf("maximum of %d template sources per tenant", MaxSourcesPerTenant), shared.ErrForbidden)
	}

	// Check if name already exists
	existing, err := s.repo.GetByTenantAndName(ctx, tenantID, input.Name)
	if err == nil && existing != nil {
		return nil, shared.NewDomainError("ALREADY_EXISTS", "template source with this name already exists", shared.ErrAlreadyExists)
	}

	// Create source
	source, err := ts.NewTemplateSource(tenantID, input.Name, sourceType, templateType, createdBy)
	if err != nil {
		return nil, err
	}

	// Set additional fields
	source.Description = input.Description
	source.Enabled = input.Enabled
	source.AutoSyncOnScan = input.AutoSyncOnScan
	if input.CacheTTLMinutes > 0 {
		source.CacheTTLMinutes = input.CacheTTLMinutes
	}

	// Set source-specific config
	switch sourceType {
	case ts.SourceTypeGit:
		if input.GitConfig == nil {
			return nil, shared.NewDomainError("VALIDATION", "git config is required for git source", shared.ErrValidation)
		}
		if err := source.SetGitConfig(input.GitConfig); err != nil {
			return nil, err
		}
	case ts.SourceTypeS3:
		if input.S3Config == nil {
			return nil, shared.NewDomainError("VALIDATION", "s3 config is required for s3 source", shared.ErrValidation)
		}
		if err := source.SetS3Config(input.S3Config); err != nil {
			return nil, err
		}
	case ts.SourceTypeHTTP:
		if input.HTTPConfig == nil {
			return nil, shared.NewDomainError("VALIDATION", "http config is required for http source", shared.ErrValidation)
		}
		if err := source.SetHTTPConfig(input.HTTPConfig); err != nil {
			return nil, err
		}
	}

	// Set credential if provided
	if input.CredentialID != "" {
		credID, err := shared.IDFromString(input.CredentialID)
		if err != nil {
			return nil, fmt.Errorf("%w: invalid credential id", shared.ErrValidation)
		}
		source.SetCredential(credID)
	}

	// Persist
	if err := s.repo.Create(ctx, source); err != nil {
		return nil, err
	}

	s.logger.Info("created template source", "id", source.ID.String(), "name", source.Name)
	return source, nil
}

// GetSource retrieves a template source by ID.
func (s *TemplateSourceService) GetSource(ctx context.Context, tenantID, sourceID string) (*ts.TemplateSource, error) {
	tid, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}

	sid, err := shared.IDFromString(sourceID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid source id", shared.ErrValidation)
	}

	source, err := s.repo.GetByID(ctx, sid)
	if err != nil {
		return nil, err
	}

	// Validate ownership
	if !source.BelongsToTenant(tid) {
		return nil, shared.NewDomainError("FORBIDDEN", "source belongs to another tenant", shared.ErrForbidden)
	}

	return source, nil
}

// ListTemplateSourcesInput represents the input for listing template sources.
type ListTemplateSourcesInput struct {
	TenantID     string  `json:"tenant_id" validate:"required,uuid"`
	SourceType   *string `json:"source_type" validate:"omitempty,oneof=git s3 http"`
	TemplateType *string `json:"template_type" validate:"omitempty,oneof=nuclei semgrep gitleaks"`
	Enabled      *bool   `json:"enabled"`
	Page         int     `json:"page"`
	PageSize     int     `json:"page_size"`
	SortBy       string  `json:"sort_by"`
	SortOrder    string  `json:"sort_order"`
}

// ListSources lists template sources with filters.
func (s *TemplateSourceService) ListSources(ctx context.Context, input ListTemplateSourcesInput) (*ts.ListOutput, error) {
	tenantID, err := shared.IDFromString(input.TenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}

	listInput := ts.ListInput{
		TenantID:  tenantID,
		Enabled:   input.Enabled,
		Page:      input.Page,
		PageSize:  input.PageSize,
		SortBy:    input.SortBy,
		SortOrder: input.SortOrder,
	}

	if input.SourceType != nil {
		st := ts.SourceType(*input.SourceType)
		listInput.SourceType = &st
	}

	if input.TemplateType != nil {
		tt := scannertemplate.TemplateType(*input.TemplateType)
		listInput.TemplateType = &tt
	}

	return s.repo.List(ctx, listInput)
}

// UpdateTemplateSourceInput represents the input for updating a template source.
type UpdateTemplateSourceInput struct {
	TenantID        string               `json:"tenant_id" validate:"required,uuid"`
	SourceID        string               `json:"source_id" validate:"required,uuid"`
	Name            string               `json:"name" validate:"omitempty,min=1,max=255"`
	Description     string               `json:"description" validate:"max=1000"`
	Enabled         *bool                `json:"enabled"`
	AutoSyncOnScan  *bool                `json:"auto_sync_on_scan"`
	CacheTTLMinutes *int                 `json:"cache_ttl_minutes" validate:"omitempty,min=0,max=10080"`
	GitConfig       *ts.GitSourceConfig  `json:"git_config,omitempty"`
	S3Config        *ts.S3SourceConfig   `json:"s3_config,omitempty"`
	HTTPConfig      *ts.HTTPSourceConfig `json:"http_config,omitempty"`
	CredentialID    *string              `json:"credential_id" validate:"omitempty,uuid"`
}

// UpdateSource updates an existing template source.
func (s *TemplateSourceService) UpdateSource(ctx context.Context, input UpdateTemplateSourceInput) (*ts.TemplateSource, error) {
	s.logger.Info("updating template source", "source_id", input.SourceID)

	tenantID, err := shared.IDFromString(input.TenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}

	source, err := s.GetSource(ctx, input.TenantID, input.SourceID)
	if err != nil {
		return nil, err
	}

	// Validate ownership
	if err := source.CanManage(tenantID); err != nil {
		return nil, err
	}

	// Update basic fields
	autoSync := source.AutoSyncOnScan
	if input.AutoSyncOnScan != nil {
		autoSync = *input.AutoSyncOnScan
	}
	cacheTTL := source.CacheTTLMinutes
	if input.CacheTTLMinutes != nil {
		cacheTTL = *input.CacheTTLMinutes
	}
	if err := source.Update(input.Name, input.Description, autoSync, cacheTTL); err != nil {
		return nil, err
	}

	// Update enabled status
	if input.Enabled != nil {
		if *input.Enabled {
			source.Enable()
		} else {
			source.Disable()
		}
	}

	// Update source-specific config
	switch source.SourceType {
	case ts.SourceTypeGit:
		if input.GitConfig != nil {
			if err := source.SetGitConfig(input.GitConfig); err != nil {
				return nil, err
			}
		}
	case ts.SourceTypeS3:
		if input.S3Config != nil {
			if err := source.SetS3Config(input.S3Config); err != nil {
				return nil, err
			}
		}
	case ts.SourceTypeHTTP:
		if input.HTTPConfig != nil {
			if err := source.SetHTTPConfig(input.HTTPConfig); err != nil {
				return nil, err
			}
		}
	}

	// Update credential
	if input.CredentialID != nil {
		if *input.CredentialID == "" {
			source.ClearCredential()
		} else {
			credID, err := shared.IDFromString(*input.CredentialID)
			if err != nil {
				return nil, fmt.Errorf("%w: invalid credential id", shared.ErrValidation)
			}
			source.SetCredential(credID)
		}
	}

	if err := s.repo.Update(ctx, source); err != nil {
		return nil, err
	}

	return source, nil
}

// DeleteSource deletes a template source.
func (s *TemplateSourceService) DeleteSource(ctx context.Context, tenantID, sourceID string) error {
	s.logger.Info("deleting template source", "source_id", sourceID)

	tid, err := shared.IDFromString(tenantID)
	if err != nil {
		return fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}

	source, err := s.GetSource(ctx, tenantID, sourceID)
	if err != nil {
		return err
	}

	// Validate ownership
	if err := source.CanManage(tid); err != nil {
		return err
	}

	return s.repo.Delete(ctx, source.ID)
}

// EnableSource enables a template source.
func (s *TemplateSourceService) EnableSource(ctx context.Context, tenantID, sourceID string) (*ts.TemplateSource, error) {
	source, err := s.GetSource(ctx, tenantID, sourceID)
	if err != nil {
		return nil, err
	}

	tid, _ := shared.IDFromString(tenantID)
	if err := source.CanManage(tid); err != nil {
		return nil, err
	}

	source.Enable()

	if err := s.repo.Update(ctx, source); err != nil {
		return nil, err
	}

	return source, nil
}

// DisableSource disables a template source.
func (s *TemplateSourceService) DisableSource(ctx context.Context, tenantID, sourceID string) (*ts.TemplateSource, error) {
	source, err := s.GetSource(ctx, tenantID, sourceID)
	if err != nil {
		return nil, err
	}

	tid, _ := shared.IDFromString(tenantID)
	if err := source.CanManage(tid); err != nil {
		return nil, err
	}

	source.Disable()

	if err := s.repo.Update(ctx, source); err != nil {
		return nil, err
	}

	return source, nil
}

// GetSourcesForScan retrieves enabled template sources linked to a scan profile.
func (s *TemplateSourceService) GetSourcesForScan(ctx context.Context, tenantID string, templateTypes []scannertemplate.TemplateType) ([]*ts.TemplateSource, error) {
	tid, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}

	var allSources []*ts.TemplateSource
	for _, tt := range templateTypes {
		sources, err := s.repo.ListByTenantAndTemplateType(ctx, tid, tt)
		if err != nil {
			return nil, err
		}
		allSources = append(allSources, sources...)
	}

	return allSources, nil
}

// GetSourcesNeedingSync returns sources that need to be synced (cache expired).
func (s *TemplateSourceService) GetSourcesNeedingSync(ctx context.Context, tenantID string) ([]*ts.TemplateSource, error) {
	tid, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}

	sources, err := s.repo.ListEnabledForSync(ctx, tid)
	if err != nil {
		return nil, err
	}

	// Filter to only those that need sync
	var needsSync []*ts.TemplateSource
	for _, src := range sources {
		if src.NeedsSync() {
			needsSync = append(needsSync, src)
		}
	}

	return needsSync, nil
}

// UpdateSyncStatus updates the sync status of a template source.
func (s *TemplateSourceService) UpdateSyncStatus(ctx context.Context, source *ts.TemplateSource) error {
	return s.repo.UpdateSyncStatus(ctx, source)
}

// ForceSync triggers an immediate sync for a specific source.
// This is used for manual "force sync" requests from the API.
func (s *TemplateSourceService) ForceSync(ctx context.Context, tenantID, sourceID string) (*TemplateSyncResult, error) {
	if s.templateSyncer == nil {
		return nil, shared.NewDomainError("SYNCER_NOT_CONFIGURED", "template syncer is not configured", nil)
	}

	tid, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}

	sid, err := shared.IDFromString(sourceID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid source id", shared.ErrValidation)
	}

	// Get the source
	source, err := s.repo.GetByTenantAndID(ctx, tid, sid)
	if err != nil {
		return nil, err
	}

	// Check if already syncing
	if _, syncing := s.syncingMap.Load(sid); syncing {
		return nil, shared.NewDomainError("SYNC_IN_PROGRESS", "source is already being synced", nil)
	}

	// Mark as syncing
	s.syncingMap.Store(sid, true)
	defer s.syncingMap.Delete(sid)

	s.logger.Info("force syncing template source",
		"source_id", sourceID,
		"source_name", source.Name,
		"source_type", string(source.SourceType))

	// Perform sync
	result, err := s.templateSyncer.SyncSource(ctx, source)
	if err != nil {
		return nil, fmt.Errorf("sync failed: %w", err)
	}

	// Record metrics
	TemplateSyncsTotal.WithLabelValues(tenantID, string(source.SourceType)).Inc()
	if result.Success {
		TemplateSyncsSuccessTotal.WithLabelValues(tenantID).Inc()
	} else {
		TemplateSyncsFailedTotal.WithLabelValues(tenantID).Inc()
	}

	s.logger.Info("force sync completed",
		"source_id", sourceID,
		"success", result.Success,
		"templates_found", result.TemplatesFound,
		"templates_added", result.TemplatesAdded,
		"duration", result.Duration)

	return result, nil
}
