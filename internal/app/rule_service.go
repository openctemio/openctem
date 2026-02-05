package app

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/openctemio/api/pkg/domain/rule"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/logger"
	"github.com/openctemio/api/pkg/pagination"
)

// RuleService handles rule management business operations.
type RuleService struct {
	sourceRepo      rule.SourceRepository
	ruleRepo        rule.RuleRepository
	bundleRepo      rule.BundleRepository
	overrideRepo    rule.OverrideRepository
	syncHistoryRepo rule.SyncHistoryRepository
	logger          *logger.Logger
	auditService    *AuditService
}

// NewRuleService creates a new RuleService.
func NewRuleService(
	sourceRepo rule.SourceRepository,
	ruleRepo rule.RuleRepository,
	bundleRepo rule.BundleRepository,
	overrideRepo rule.OverrideRepository,
	syncHistoryRepo rule.SyncHistoryRepository,
	auditService *AuditService,
	log *logger.Logger,
) *RuleService {
	return &RuleService{
		sourceRepo:      sourceRepo,
		ruleRepo:        ruleRepo,
		bundleRepo:      bundleRepo,
		overrideRepo:    overrideRepo,
		syncHistoryRepo: syncHistoryRepo,
		auditService:    auditService,
		logger:          log.With("service", "rule"),
	}
}

// =============================================================================
// Rule Source Operations
// =============================================================================

// CreateSourceInput represents the input for creating a rule source.
type CreateSourceInput struct {
	TenantID            string `json:"tenant_id" validate:"required,uuid"`
	ToolID              string `json:"tool_id" validate:"omitempty,uuid"`
	Name                string `json:"name" validate:"required,min=1,max=255"`
	Description         string `json:"description" validate:"max=1000"`
	SourceType          string `json:"source_type" validate:"required,oneof=git http local"`
	Config              []byte `json:"config" validate:"required"`
	CredentialsID       string `json:"credentials_id" validate:"omitempty,uuid"`
	SyncEnabled         bool   `json:"sync_enabled"`
	SyncIntervalMinutes int    `json:"sync_interval_minutes" validate:"min=5,max=10080"`
	Priority            int    `json:"priority" validate:"min=0,max=1000"`
}

// CreateSource creates a new rule source.
func (s *RuleService) CreateSource(ctx context.Context, input CreateSourceInput) (*rule.Source, error) {
	s.logger.Info("creating rule source", "tenant_id", input.TenantID, "name", input.Name, "type", input.SourceType)

	tenantID, err := shared.IDFromString(input.TenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}

	var toolID *shared.ID
	if input.ToolID != "" {
		tid, err := shared.IDFromString(input.ToolID)
		if err != nil {
			return nil, fmt.Errorf("%w: invalid tool id", shared.ErrValidation)
		}
		toolID = &tid
	}

	var credID *shared.ID
	if input.CredentialsID != "" {
		cid, err := shared.IDFromString(input.CredentialsID)
		if err != nil {
			return nil, fmt.Errorf("%w: invalid credentials id", shared.ErrValidation)
		}
		credID = &cid
	}

	sourceType := rule.SourceType(input.SourceType)
	if !sourceType.IsValid() {
		return nil, fmt.Errorf("%w: invalid source type", shared.ErrValidation)
	}

	source, err := rule.NewSource(tenantID, toolID, input.Name, sourceType, input.Config)
	if err != nil {
		return nil, err
	}

	source.Description = input.Description
	source.CredentialsID = credID
	source.SyncEnabled = input.SyncEnabled
	source.Priority = input.Priority

	if input.SyncIntervalMinutes > 0 {
		source.SyncIntervalMinutes = input.SyncIntervalMinutes
	}

	if err := s.sourceRepo.Create(ctx, source); err != nil {
		return nil, err
	}

	// Audit creation
	actx := AuditContext{
		TenantID: tenantID.String(),
		// ActorID from context/input if available
	}
	_ = s.auditService.LogRuleSourceCreated(ctx, actx, source.ID.String(), source.Name, string(source.SourceType))

	return source, nil
}

// GetSource retrieves a rule source by ID.
func (s *RuleService) GetSource(ctx context.Context, sourceID string) (*rule.Source, error) {
	id, err := shared.IDFromString(sourceID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid source id", shared.ErrValidation)
	}

	return s.sourceRepo.GetByID(ctx, id)
}

// GetSourceByTenantAndID retrieves a rule source by tenant and ID.
func (s *RuleService) GetSourceByTenantAndID(ctx context.Context, tenantID, sourceID string) (*rule.Source, error) {
	tid, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}

	sid, err := shared.IDFromString(sourceID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid source id", shared.ErrValidation)
	}

	return s.sourceRepo.GetByTenantAndID(ctx, tid, sid)
}

// ListSourcesInput represents the input for listing rule sources.
type ListSourcesInput struct {
	TenantID          string `json:"tenant_id" validate:"omitempty,uuid"`
	ToolID            string `json:"tool_id" validate:"omitempty,uuid"`
	SourceType        string `json:"source_type" validate:"omitempty,oneof=git http local"`
	Enabled           *bool  `json:"enabled"`
	IsPlatformDefault *bool  `json:"is_platform_default"`
	SyncStatus        string `json:"sync_status" validate:"omitempty,oneof=pending syncing success failed"`
	Search            string `json:"search" validate:"max=255"`
	Page              int    `json:"page"`
	PerPage           int    `json:"per_page"`
}

// ListSources lists rule sources with filters.
func (s *RuleService) ListSources(ctx context.Context, input ListSourcesInput) (pagination.Result[*rule.Source], error) {
	filter := rule.SourceFilter{
		Enabled:           input.Enabled,
		IsPlatformDefault: input.IsPlatformDefault,
		Search:            input.Search,
	}

	if input.TenantID != "" {
		tenantID, err := shared.IDFromString(input.TenantID)
		if err != nil {
			return pagination.Result[*rule.Source]{}, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
		}
		filter.TenantID = &tenantID
	}

	if input.ToolID != "" {
		toolID, err := shared.IDFromString(input.ToolID)
		if err != nil {
			return pagination.Result[*rule.Source]{}, fmt.Errorf("%w: invalid tool id", shared.ErrValidation)
		}
		filter.ToolID = &toolID
	}

	if input.SourceType != "" {
		st := rule.SourceType(input.SourceType)
		filter.SourceType = &st
	}

	if input.SyncStatus != "" {
		ss := rule.SyncStatus(input.SyncStatus)
		filter.SyncStatus = &ss
	}

	page := pagination.New(input.Page, input.PerPage)
	return s.sourceRepo.List(ctx, filter, page)
}

// UpdateSourceInput represents the input for updating a rule source.
type UpdateSourceInput struct {
	TenantID            string `json:"tenant_id" validate:"required,uuid"`
	SourceID            string `json:"source_id" validate:"required,uuid"`
	Name                string `json:"name" validate:"min=1,max=255"`
	Description         string `json:"description" validate:"max=1000"`
	Config              []byte `json:"config"`
	CredentialsID       string `json:"credentials_id" validate:"omitempty,uuid"`
	SyncEnabled         *bool  `json:"sync_enabled"`
	SyncIntervalMinutes int    `json:"sync_interval_minutes" validate:"omitempty,min=5,max=10080"`
	Priority            int    `json:"priority" validate:"omitempty,min=0,max=1000"`
	Enabled             *bool  `json:"enabled"`
}

// UpdateSource updates a rule source.
func (s *RuleService) UpdateSource(ctx context.Context, input UpdateSourceInput) (*rule.Source, error) {
	s.logger.Info("updating rule source", "tenant_id", input.TenantID, "source_id", input.SourceID)

	source, err := s.GetSourceByTenantAndID(ctx, input.TenantID, input.SourceID)
	if err != nil {
		return nil, err
	}

	if input.Name != "" {
		source.Name = input.Name
	}
	if input.Description != "" {
		source.Description = input.Description
	}
	if len(input.Config) > 0 {
		source.Config = input.Config
	}
	if input.CredentialsID != "" {
		credID, err := shared.IDFromString(input.CredentialsID)
		if err != nil {
			return nil, fmt.Errorf("%w: invalid credentials id", shared.ErrValidation)
		}
		source.CredentialsID = &credID
	}
	if input.SyncEnabled != nil {
		source.SyncEnabled = *input.SyncEnabled
	}
	if input.SyncIntervalMinutes > 0 {
		source.SyncIntervalMinutes = input.SyncIntervalMinutes
	}
	if input.Priority > 0 {
		source.Priority = input.Priority
	}
	if input.Enabled != nil {
		source.Enabled = *input.Enabled
	}

	source.UpdatedAt = time.Now()

	if err := s.sourceRepo.Update(ctx, source); err != nil {
		return nil, err
	}

	// Audit update
	actx := AuditContext{
		TenantID: input.TenantID,
	}
	_ = s.auditService.LogRuleSourceUpdated(ctx, actx, source.ID.String(), source.Name)

	return source, nil
}

// DeleteSource deletes a rule source and its associated rules.
func (s *RuleService) DeleteSource(ctx context.Context, tenantID, sourceID string) error {
	s.logger.Info("deleting rule source", "tenant_id", tenantID, "source_id", sourceID)

	source, err := s.GetSourceByTenantAndID(ctx, tenantID, sourceID)
	if err != nil {
		return err
	}

	// Delete associated rules first
	if err := s.ruleRepo.DeleteBySource(ctx, source.ID); err != nil {
		return fmt.Errorf("failed to delete source rules: %w", err)
	}

	if err := s.sourceRepo.Delete(ctx, source.ID); err != nil {
		return err
	}

	// Audit deletion
	actx := AuditContext{
		TenantID: tenantID,
	}
	_ = s.auditService.LogRuleSourceDeleted(ctx, actx, sourceID, source.Name)

	return nil
}

// EnableSource enables a rule source.
func (s *RuleService) EnableSource(ctx context.Context, tenantID, sourceID string) (*rule.Source, error) {
	s.logger.Info("enabling rule source", "tenant_id", tenantID, "source_id", sourceID)

	source, err := s.GetSourceByTenantAndID(ctx, tenantID, sourceID)
	if err != nil {
		return nil, err
	}

	source.SetEnabled(true)

	if err := s.sourceRepo.Update(ctx, source); err != nil {
		return nil, err
	}

	return source, nil
}

// DisableSource disables a rule source.
func (s *RuleService) DisableSource(ctx context.Context, tenantID, sourceID string) (*rule.Source, error) {
	s.logger.Info("disabling rule source", "tenant_id", tenantID, "source_id", sourceID)

	source, err := s.GetSourceByTenantAndID(ctx, tenantID, sourceID)
	if err != nil {
		return nil, err
	}

	source.SetEnabled(false)

	if err := s.sourceRepo.Update(ctx, source); err != nil {
		return nil, err
	}

	return source, nil
}

// =============================================================================
// Rule Operations
// =============================================================================

// ListRulesInput represents the input for listing rules.
type ListRulesInput struct {
	TenantID string   `json:"tenant_id" validate:"omitempty,uuid"`
	ToolID   string   `json:"tool_id" validate:"omitempty,uuid"`
	SourceID string   `json:"source_id" validate:"omitempty,uuid"`
	Severity string   `json:"severity" validate:"omitempty,oneof=critical high medium low info unknown"`
	Category string   `json:"category" validate:"max=100"`
	Tags     []string `json:"tags"`
	RuleIDs  []string `json:"rule_ids"`
	Search   string   `json:"search" validate:"max=255"`
	Page     int      `json:"page"`
	PerPage  int      `json:"per_page"`
}

// ListRules lists rules with filters.
func (s *RuleService) ListRules(ctx context.Context, input ListRulesInput) (pagination.Result[*rule.Rule], error) {
	filter := rule.RuleFilter{
		Category: input.Category,
		Tags:     input.Tags,
		RuleIDs:  input.RuleIDs,
		Search:   input.Search,
	}

	if input.TenantID != "" {
		tenantID, err := shared.IDFromString(input.TenantID)
		if err != nil {
			return pagination.Result[*rule.Rule]{}, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
		}
		filter.TenantID = &tenantID
	}

	if input.ToolID != "" {
		toolID, err := shared.IDFromString(input.ToolID)
		if err != nil {
			return pagination.Result[*rule.Rule]{}, fmt.Errorf("%w: invalid tool id", shared.ErrValidation)
		}
		filter.ToolID = &toolID
	}

	if input.SourceID != "" {
		sourceID, err := shared.IDFromString(input.SourceID)
		if err != nil {
			return pagination.Result[*rule.Rule]{}, fmt.Errorf("%w: invalid source id", shared.ErrValidation)
		}
		filter.SourceID = &sourceID
	}

	if input.Severity != "" {
		sev := rule.Severity(input.Severity)
		filter.Severity = &sev
	}

	page := pagination.New(input.Page, input.PerPage)
	return s.ruleRepo.List(ctx, filter, page)
}

// GetRule retrieves a rule by ID.
func (s *RuleService) GetRule(ctx context.Context, ruleID string) (*rule.Rule, error) {
	id, err := shared.IDFromString(ruleID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid rule id", shared.ErrValidation)
	}

	return s.ruleRepo.GetByID(ctx, id)
}

// ListRulesBySource lists all rules for a source.
func (s *RuleService) ListRulesBySource(ctx context.Context, sourceID string) ([]*rule.Rule, error) {
	id, err := shared.IDFromString(sourceID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid source id", shared.ErrValidation)
	}

	return s.ruleRepo.ListBySource(ctx, id)
}

// CountRulesBySource counts rules for a source.
func (s *RuleService) CountRulesBySource(ctx context.Context, sourceID string) (int, error) {
	id, err := shared.IDFromString(sourceID)
	if err != nil {
		return 0, fmt.Errorf("%w: invalid source id", shared.ErrValidation)
	}

	return s.ruleRepo.CountBySource(ctx, id)
}

// =============================================================================
// Rule Override Operations
// =============================================================================

// CreateOverrideInput represents the input for creating a rule override.
type CreateOverrideInput struct {
	TenantID         string  `json:"tenant_id" validate:"required,uuid"`
	ToolID           string  `json:"tool_id" validate:"omitempty,uuid"`
	RulePattern      string  `json:"rule_pattern" validate:"required,min=1,max=500"`
	IsPattern        bool    `json:"is_pattern"`
	Enabled          bool    `json:"enabled"`
	SeverityOverride string  `json:"severity_override" validate:"omitempty,oneof=critical high medium low info"`
	AssetGroupID     string  `json:"asset_group_id" validate:"omitempty,uuid"`
	ScanProfileID    string  `json:"scan_profile_id" validate:"omitempty,uuid"`
	Reason           string  `json:"reason" validate:"max=1000"`
	CreatedBy        string  `json:"created_by" validate:"omitempty,uuid"`
	ExpiresAt        *string `json:"expires_at"` // RFC3339 format
}

// CreateOverride creates a new rule override.
func (s *RuleService) CreateOverride(ctx context.Context, input CreateOverrideInput) (*rule.Override, error) {
	s.logger.Info("creating rule override", "tenant_id", input.TenantID, "pattern", input.RulePattern)

	tenantID, err := shared.IDFromString(input.TenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}

	var toolID *shared.ID
	if input.ToolID != "" {
		tid, err := shared.IDFromString(input.ToolID)
		if err != nil {
			return nil, fmt.Errorf("%w: invalid tool id", shared.ErrValidation)
		}
		toolID = &tid
	}

	var createdBy *shared.ID
	if input.CreatedBy != "" {
		cid, err := shared.IDFromString(input.CreatedBy)
		if err != nil {
			return nil, fmt.Errorf("%w: invalid created_by id", shared.ErrValidation)
		}
		createdBy = &cid
	}

	override := rule.NewOverride(
		tenantID,
		toolID,
		input.RulePattern,
		input.IsPattern,
		input.Enabled,
		input.Reason,
		createdBy,
	)

	if input.SeverityOverride != "" {
		override.SetSeverityOverride(rule.Severity(input.SeverityOverride))
	}

	if input.AssetGroupID != "" || input.ScanProfileID != "" {
		var assetGroupID, scanProfileID *shared.ID
		if input.AssetGroupID != "" {
			agid, err := shared.IDFromString(input.AssetGroupID)
			if err != nil {
				return nil, fmt.Errorf("%w: invalid asset_group_id", shared.ErrValidation)
			}
			assetGroupID = &agid
		}
		if input.ScanProfileID != "" {
			spid, err := shared.IDFromString(input.ScanProfileID)
			if err != nil {
				return nil, fmt.Errorf("%w: invalid scan_profile_id", shared.ErrValidation)
			}
			scanProfileID = &spid
		}
		override.SetScope(assetGroupID, scanProfileID)
	}

	if input.ExpiresAt != nil {
		expiresAt, err := time.Parse(time.RFC3339, *input.ExpiresAt)
		if err != nil {
			return nil, fmt.Errorf("%w: invalid expires_at format", shared.ErrValidation)
		}
		override.SetExpiration(&expiresAt)
	}

	if err := s.overrideRepo.Create(ctx, override); err != nil {
		return nil, err
	}

	// Audit creation
	actx := AuditContext{
		TenantID: tenantID.String(),
		ActorID:  input.CreatedBy,
	}
	_ = s.auditService.LogRuleOverrideCreated(ctx, actx, override.ID.String(), override.RulePattern)

	return override, nil
}

// GetOverride retrieves an override by ID.
func (s *RuleService) GetOverride(ctx context.Context, overrideID string) (*rule.Override, error) {
	id, err := shared.IDFromString(overrideID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid override id", shared.ErrValidation)
	}

	return s.overrideRepo.GetByID(ctx, id)
}

// GetOverrideByTenantAndID retrieves an override by tenant and ID.
func (s *RuleService) GetOverrideByTenantAndID(ctx context.Context, tenantID, overrideID string) (*rule.Override, error) {
	tid, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}

	oid, err := shared.IDFromString(overrideID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid override id", shared.ErrValidation)
	}

	return s.overrideRepo.GetByTenantAndID(ctx, tid, oid)
}

// ListOverridesInput represents the input for listing rule overrides.
type ListOverridesInput struct {
	TenantID      string `json:"tenant_id" validate:"omitempty,uuid"`
	ToolID        string `json:"tool_id" validate:"omitempty,uuid"`
	AssetGroupID  string `json:"asset_group_id" validate:"omitempty,uuid"`
	ScanProfileID string `json:"scan_profile_id" validate:"omitempty,uuid"`
	Enabled       *bool  `json:"enabled"`
	Page          int    `json:"page"`
	PerPage       int    `json:"per_page"`
}

// ListOverrides lists rule overrides with filters.
func (s *RuleService) ListOverrides(ctx context.Context, input ListOverridesInput) (pagination.Result[*rule.Override], error) {
	filter := rule.OverrideFilter{
		Enabled: input.Enabled,
	}

	if input.TenantID != "" {
		tenantID, err := shared.IDFromString(input.TenantID)
		if err != nil {
			return pagination.Result[*rule.Override]{}, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
		}
		filter.TenantID = &tenantID
	}

	if input.ToolID != "" {
		toolID, err := shared.IDFromString(input.ToolID)
		if err != nil {
			return pagination.Result[*rule.Override]{}, fmt.Errorf("%w: invalid tool id", shared.ErrValidation)
		}
		filter.ToolID = &toolID
	}

	if input.AssetGroupID != "" {
		agID, err := shared.IDFromString(input.AssetGroupID)
		if err != nil {
			return pagination.Result[*rule.Override]{}, fmt.Errorf("%w: invalid asset_group id", shared.ErrValidation)
		}
		filter.AssetGroupID = &agID
	}

	if input.ScanProfileID != "" {
		spID, err := shared.IDFromString(input.ScanProfileID)
		if err != nil {
			return pagination.Result[*rule.Override]{}, fmt.Errorf("%w: invalid scan_profile id", shared.ErrValidation)
		}
		filter.ScanProfileID = &spID
	}

	page := pagination.New(input.Page, input.PerPage)
	return s.overrideRepo.List(ctx, filter, page)
}

// UpdateOverrideInput represents the input for updating a rule override.
type UpdateOverrideInput struct {
	TenantID         string  `json:"tenant_id" validate:"required,uuid"`
	OverrideID       string  `json:"override_id" validate:"required,uuid"`
	RulePattern      string  `json:"rule_pattern" validate:"omitempty,min=1,max=500"`
	IsPattern        *bool   `json:"is_pattern"`
	Enabled          *bool   `json:"enabled"`
	SeverityOverride string  `json:"severity_override" validate:"omitempty,oneof=critical high medium low info"`
	AssetGroupID     string  `json:"asset_group_id" validate:"omitempty,uuid"`
	ScanProfileID    string  `json:"scan_profile_id" validate:"omitempty,uuid"`
	Reason           string  `json:"reason" validate:"max=1000"`
	ExpiresAt        *string `json:"expires_at"` // RFC3339 format, null to remove
}

// UpdateOverride updates a rule override.
func (s *RuleService) UpdateOverride(ctx context.Context, input UpdateOverrideInput) (*rule.Override, error) {
	s.logger.Info("updating rule override", "tenant_id", input.TenantID, "override_id", input.OverrideID)

	override, err := s.GetOverrideByTenantAndID(ctx, input.TenantID, input.OverrideID)
	if err != nil {
		return nil, err
	}

	if input.RulePattern != "" {
		override.RulePattern = input.RulePattern
	}
	if input.IsPattern != nil {
		override.IsPattern = *input.IsPattern
	}
	if input.Enabled != nil {
		override.Enabled = *input.Enabled
	}
	if input.SeverityOverride != "" {
		override.SetSeverityOverride(rule.Severity(input.SeverityOverride))
	}
	if input.Reason != "" {
		override.Reason = input.Reason
	}

	if input.AssetGroupID != "" || input.ScanProfileID != "" {
		var assetGroupID, scanProfileID *shared.ID
		if input.AssetGroupID != "" {
			agid, err := shared.IDFromString(input.AssetGroupID)
			if err != nil {
				return nil, fmt.Errorf("%w: invalid asset_group_id", shared.ErrValidation)
			}
			assetGroupID = &agid
		}
		if input.ScanProfileID != "" {
			spid, err := shared.IDFromString(input.ScanProfileID)
			if err != nil {
				return nil, fmt.Errorf("%w: invalid scan_profile_id", shared.ErrValidation)
			}
			scanProfileID = &spid
		}
		override.SetScope(assetGroupID, scanProfileID)
	}

	if input.ExpiresAt != nil {
		if *input.ExpiresAt == "" {
			override.SetExpiration(nil)
		} else {
			expiresAt, err := time.Parse(time.RFC3339, *input.ExpiresAt)
			if err != nil {
				return nil, fmt.Errorf("%w: invalid expires_at format", shared.ErrValidation)
			}
			override.SetExpiration(&expiresAt)
		}
	}

	override.UpdatedAt = time.Now()

	if err := s.overrideRepo.Update(ctx, override); err != nil {
		return nil, err
	}

	// Audit update
	actx := AuditContext{
		TenantID: input.TenantID,
	}
	_ = s.auditService.LogRuleOverrideUpdated(ctx, actx, override.ID.String(), override.RulePattern)

	return override, nil
}

// DeleteOverride deletes a rule override.
func (s *RuleService) DeleteOverride(ctx context.Context, tenantID, overrideID string) error {
	s.logger.Info("deleting rule override", "tenant_id", tenantID, "override_id", overrideID)

	override, err := s.GetOverrideByTenantAndID(ctx, tenantID, overrideID)
	if err != nil {
		return err
	}

	if err := s.overrideRepo.Delete(ctx, override.ID); err != nil {
		return err
	}

	// Audit deletion
	actx := AuditContext{
		TenantID: tenantID,
	}
	_ = s.auditService.LogRuleOverrideDeleted(ctx, actx, overrideID, override.RulePattern)

	return nil
}

// ListActiveOverridesForTool lists all active (non-expired) overrides for a tenant and tool.
func (s *RuleService) ListActiveOverridesForTool(ctx context.Context, tenantID string, toolID *string) ([]*rule.Override, error) {
	tid, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}

	var toid *shared.ID
	if toolID != nil && *toolID != "" {
		id, err := shared.IDFromString(*toolID)
		if err != nil {
			return nil, fmt.Errorf("%w: invalid tool id", shared.ErrValidation)
		}
		toid = &id
	}

	return s.overrideRepo.ListByTenantAndTool(ctx, tid, toid)
}

// =============================================================================
// Bundle Operations
// =============================================================================

// GetLatestBundle retrieves the latest ready bundle for a tenant and tool.
func (s *RuleService) GetLatestBundle(ctx context.Context, tenantID, toolID string) (*rule.Bundle, error) {
	tid, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}

	toid, err := shared.IDFromString(toolID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tool id", shared.ErrValidation)
	}

	return s.bundleRepo.GetLatest(ctx, tid, toid)
}

// GetBundleByID retrieves a bundle by ID.
func (s *RuleService) GetBundleByID(ctx context.Context, bundleID string) (*rule.Bundle, error) {
	id, err := shared.IDFromString(bundleID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid bundle id", shared.ErrValidation)
	}

	return s.bundleRepo.GetByID(ctx, id)
}

// ListBundlesInput represents the input for listing bundles.
type ListBundlesInput struct {
	TenantID string `json:"tenant_id" validate:"omitempty,uuid"`
	ToolID   string `json:"tool_id" validate:"omitempty,uuid"`
	Status   string `json:"status" validate:"omitempty,oneof=building ready failed expired"`
}

// ListBundles lists bundles with filters.
func (s *RuleService) ListBundles(ctx context.Context, input ListBundlesInput) ([]*rule.Bundle, error) {
	filter := rule.BundleFilter{}

	if input.TenantID != "" {
		tenantID, err := shared.IDFromString(input.TenantID)
		if err != nil {
			return nil, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
		}
		filter.TenantID = &tenantID
	}

	if input.ToolID != "" {
		toolID, err := shared.IDFromString(input.ToolID)
		if err != nil {
			return nil, fmt.Errorf("%w: invalid tool id", shared.ErrValidation)
		}
		filter.ToolID = &toolID
	}

	if input.Status != "" {
		status := rule.BundleStatus(input.Status)
		filter.Status = &status
	}

	return s.bundleRepo.List(ctx, filter)
}

// CreateBundleInput represents the input for creating a rule bundle.
type CreateBundleInput struct {
	TenantID    string   `json:"tenant_id" validate:"required,uuid"`
	ToolID      string   `json:"tool_id" validate:"required,uuid"`
	SourceIDs   []string `json:"source_ids" validate:"required,min=1,dive,uuid"`
	StoragePath string   `json:"storage_path" validate:"required,max=500"`
}

// CreateBundle creates a new rule bundle (starts building).
func (s *RuleService) CreateBundle(ctx context.Context, input CreateBundleInput) (*rule.Bundle, error) {
	s.logger.Info("creating rule bundle", "tenant_id", input.TenantID, "tool_id", input.ToolID)

	tenantID, err := shared.IDFromString(input.TenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}

	toolID, err := shared.IDFromString(input.ToolID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tool id", shared.ErrValidation)
	}

	sourceIDs := make([]shared.ID, 0, len(input.SourceIDs))
	for _, sid := range input.SourceIDs {
		id, err := shared.IDFromString(sid)
		if err != nil {
			return nil, fmt.Errorf("%w: invalid source id %s", shared.ErrValidation, sid)
		}
		sourceIDs = append(sourceIDs, id)
	}

	bundle := rule.NewBundle(tenantID, toolID)
	bundle.SourceIDs = sourceIDs
	bundle.StoragePath = input.StoragePath

	if err := s.bundleRepo.Create(ctx, bundle); err != nil {
		return nil, err
	}

	return bundle, nil
}

// CompleteBundleInput represents the input for completing a bundle build.
type CompleteBundleInput struct {
	BundleID     string            `json:"bundle_id" validate:"required,uuid"`
	Version      string            `json:"version" validate:"required,max=50"`
	ContentHash  string            `json:"content_hash" validate:"required,max=64"`
	RuleCount    int               `json:"rule_count" validate:"min=0"`
	SourceCount  int               `json:"source_count" validate:"min=0"`
	SizeBytes    int64             `json:"size_bytes" validate:"min=0"`
	SourceHashes map[string]string `json:"source_hashes"`
	ExpiresAt    *string           `json:"expires_at"` // RFC3339 format
}

// CompleteBundle marks a bundle build as completed successfully.
func (s *RuleService) CompleteBundle(ctx context.Context, input CompleteBundleInput) (*rule.Bundle, error) {
	s.logger.Info("completing bundle build", "bundle_id", input.BundleID)

	bundleID, err := shared.IDFromString(input.BundleID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid bundle id", shared.ErrValidation)
	}

	bundle, err := s.bundleRepo.GetByID(ctx, bundleID)
	if err != nil {
		return nil, err
	}

	sourceHashes := input.SourceHashes
	if sourceHashes == nil {
		sourceHashes = make(map[string]string)
	}

	// Use MarkBuildSuccess to complete the bundle
	bundle.MarkBuildSuccess(
		input.Version,
		input.ContentHash,
		bundle.StoragePath,
		input.RuleCount,
		input.SizeBytes,
		bundle.SourceIDs,
		sourceHashes,
	)

	// Override expiration if custom one is provided
	if input.ExpiresAt != nil {
		expiresAt, err := time.Parse(time.RFC3339, *input.ExpiresAt)
		if err != nil {
			return nil, fmt.Errorf("%w: invalid expires_at format", shared.ErrValidation)
		}
		bundle.ExpiresAt = &expiresAt
	}

	if err := s.bundleRepo.Update(ctx, bundle); err != nil {
		return nil, err
	}

	return bundle, nil
}

// FailBundle marks a bundle build as failed.
func (s *RuleService) FailBundle(ctx context.Context, bundleID, errorMessage string) (*rule.Bundle, error) {
	s.logger.Info("failing bundle build", "bundle_id", bundleID)

	bid, err := shared.IDFromString(bundleID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid bundle id", shared.ErrValidation)
	}

	bundle, err := s.bundleRepo.GetByID(ctx, bid)
	if err != nil {
		return nil, err
	}

	bundle.MarkBuildFailed(errorMessage)

	if err := s.bundleRepo.Update(ctx, bundle); err != nil {
		return nil, err
	}

	return bundle, nil
}

// DeleteBundle deletes a bundle.
func (s *RuleService) DeleteBundle(ctx context.Context, bundleID string) error {
	s.logger.Info("deleting bundle", "bundle_id", bundleID)

	bid, err := shared.IDFromString(bundleID)
	if err != nil {
		return fmt.Errorf("%w: invalid bundle id", shared.ErrValidation)
	}

	return s.bundleRepo.Delete(ctx, bid)
}

// CleanupExpiredBundles deletes all expired bundles.
func (s *RuleService) CleanupExpiredBundles(ctx context.Context) (int64, error) {
	s.logger.Info("cleaning up expired bundles")
	return s.bundleRepo.DeleteExpired(ctx)
}

// =============================================================================
// Sync Operations
// =============================================================================

// SyncSourceInput represents the input for syncing a rule source.
type SyncSourceInput struct {
	TenantID string `json:"tenant_id" validate:"required,uuid"`
	SourceID string `json:"source_id" validate:"required,uuid"`
}

// RecordSyncResult records the result of a source sync operation.
func (s *RuleService) RecordSyncResult(ctx context.Context, sourceID string, result *SyncResult) error {
	s.logger.Info("recording sync result", "source_id", sourceID, "status", result.Status)

	sid, err := shared.IDFromString(sourceID)
	if err != nil {
		return fmt.Errorf("%w: invalid source id", shared.ErrValidation)
	}

	// Update source sync status
	source, err := s.sourceRepo.GetByID(ctx, sid)
	if err != nil {
		return err
	}

	now := time.Now()
	source.LastSyncAt = &now
	source.LastSyncStatus = result.Status
	source.LastSyncError = result.ErrorMessage
	source.LastSyncDuration = result.Duration

	if result.NewContentHash != "" {
		source.ContentHash = result.NewContentHash
	}
	if result.RulesAdded+result.RulesUpdated > 0 || result.Status == rule.SyncStatusSuccess {
		count, _ := s.ruleRepo.CountBySource(ctx, sid)
		source.RuleCount = count
	}

	if err := s.sourceRepo.Update(ctx, source); err != nil {
		return fmt.Errorf("failed to update source: %w", err)
	}

	// Record sync history
	history := &rule.SyncHistory{
		ID:           shared.NewID(),
		SourceID:     sid,
		Status:       result.Status,
		RulesAdded:   result.RulesAdded,
		RulesUpdated: result.RulesUpdated,
		RulesRemoved: result.RulesRemoved,
		Duration:     result.Duration,
		ErrorMessage: result.ErrorMessage,
		ErrorDetails: result.ErrorDetails,
		PreviousHash: result.PreviousHash,
		NewHash:      result.NewContentHash,
		CreatedAt:    now,
	}

	return s.syncHistoryRepo.Create(ctx, history)
}

// SyncResult represents the result of a sync operation.
type SyncResult struct {
	Status         rule.SyncStatus
	RulesAdded     int
	RulesUpdated   int
	RulesRemoved   int
	Duration       time.Duration
	ErrorMessage   string
	ErrorDetails   map[string]any
	PreviousHash   string
	NewContentHash string
}

// ListSourcesNeedingSync lists sources that need synchronization.
func (s *RuleService) ListSourcesNeedingSync(ctx context.Context, limit int) ([]*rule.Source, error) {
	if limit <= 0 {
		limit = 10
	}
	return s.sourceRepo.ListNeedingSync(ctx, limit)
}

// GetSyncHistory lists sync history for a source.
func (s *RuleService) GetSyncHistory(ctx context.Context, sourceID string, limit int) ([]*rule.SyncHistory, error) {
	sid, err := shared.IDFromString(sourceID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid source id", shared.ErrValidation)
	}

	if limit <= 0 {
		limit = 20
	}

	return s.syncHistoryRepo.ListBySource(ctx, sid, limit)
}

// UpsertRulesFromSync upserts rules from a sync operation.
func (s *RuleService) UpsertRulesFromSync(ctx context.Context, rules []*rule.Rule) error {
	if len(rules) == 0 {
		return nil
	}
	return s.ruleRepo.UpsertBatch(ctx, rules)
}

// =============================================================================
// Utility Functions
// =============================================================================

// ComputeContentHash computes a SHA256 hash of the given content.
func ComputeContentHash(content []byte) string {
	hash := sha256.Sum256(content)
	return hex.EncodeToString(hash[:])
}

// GenerateBundleVersion generates a version string for a bundle.
func GenerateBundleVersion(timestamp time.Time, contentHash string) string {
	dateStr := timestamp.Format("20060102")
	shortHash := contentHash
	if len(shortHash) > 8 {
		shortHash = shortHash[:8]
	}
	return fmt.Sprintf("%s-%s", dateStr, shortHash)
}
