package app

import (
	"context"
	"fmt"

	"github.com/openctemio/api/pkg/domain/scanprofile"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/logger"
	"github.com/openctemio/api/pkg/pagination"
)

// ScanProfileService handles scan profile business operations.
type ScanProfileService struct {
	repo   scanprofile.Repository
	logger *logger.Logger
}

// NewScanProfileService creates a new ScanProfileService.
func NewScanProfileService(repo scanprofile.Repository, log *logger.Logger) *ScanProfileService {
	return &ScanProfileService{
		repo:   repo,
		logger: log.With("service", "scan_profile"),
	}
}

// CreateScanProfileInput represents the input for creating a scan profile.
type CreateScanProfileInput struct {
	TenantID           string                            `json:"tenant_id" validate:"required,uuid"`
	UserID             string                            `json:"user_id" validate:"omitempty,uuid"`
	Name               string                            `json:"name" validate:"required,min=1,max=100"`
	Description        string                            `json:"description" validate:"max=500"`
	ToolsConfig        map[string]scanprofile.ToolConfig `json:"tools_config"`
	Intensity          string                            `json:"intensity" validate:"omitempty,oneof=low medium high"`
	MaxConcurrentScans int                               `json:"max_concurrent_scans" validate:"omitempty,min=1,max=100"`
	TimeoutSeconds     int                               `json:"timeout_seconds" validate:"omitempty,min=60,max=86400"`
	Tags               []string                          `json:"tags" validate:"max=20,dive,max=50"`
	IsDefault          bool                              `json:"is_default"`
	QualityGate        *scanprofile.QualityGate          `json:"quality_gate"`
}

// CreateScanProfile creates a new scan profile.
func (s *ScanProfileService) CreateScanProfile(ctx context.Context, input CreateScanProfileInput) (*scanprofile.ScanProfile, error) {
	s.logger.Info("creating scan profile", "name", input.Name, "tenant_id", input.TenantID)

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

	intensity := scanprofile.Intensity(input.Intensity)
	if !intensity.IsValid() {
		intensity = scanprofile.IntensityMedium
	}

	profile, err := scanprofile.NewScanProfile(
		tenantID,
		input.Name,
		input.Description,
		input.ToolsConfig,
		intensity,
		createdBy,
	)
	if err != nil {
		return nil, err
	}

	// Apply optional settings
	if input.MaxConcurrentScans > 0 {
		profile.MaxConcurrentScans = input.MaxConcurrentScans
	}
	if input.TimeoutSeconds > 0 {
		profile.TimeoutSeconds = input.TimeoutSeconds
	}
	if input.Tags != nil {
		profile.Tags = input.Tags
	}
	if input.QualityGate != nil {
		profile.QualityGate = *input.QualityGate
	}

	// Handle default flag
	if input.IsDefault {
		// Clear any existing default for this tenant
		if err := s.repo.ClearDefaultForTenant(ctx, tenantID); err != nil {
			return nil, fmt.Errorf("failed to clear existing default: %w", err)
		}
		profile.SetAsDefault()
	}

	if err := s.repo.Create(ctx, profile); err != nil {
		return nil, err
	}

	return profile, nil
}

// GetScanProfile retrieves a scan profile by ID.
func (s *ScanProfileService) GetScanProfile(ctx context.Context, tenantID, profileID string) (*scanprofile.ScanProfile, error) {
	tid, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}

	pid, err := shared.IDFromString(profileID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid profile id", shared.ErrValidation)
	}

	return s.repo.GetByTenantAndID(ctx, tid, pid)
}

// GetDefaultScanProfile retrieves the default scan profile for a tenant.
func (s *ScanProfileService) GetDefaultScanProfile(ctx context.Context, tenantID string) (*scanprofile.ScanProfile, error) {
	tid, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}

	return s.repo.GetDefaultByTenant(ctx, tid)
}

// GetScanProfileForUse retrieves a scan profile by ID for use in scans.
// This method allows tenants to use both their own profiles and system profiles.
func (s *ScanProfileService) GetScanProfileForUse(ctx context.Context, tenantID, profileID string) (*scanprofile.ScanProfile, error) {
	tid, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}

	pid, err := shared.IDFromString(profileID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid profile id", shared.ErrValidation)
	}

	return s.repo.GetByIDWithSystemFallback(ctx, tid, pid)
}

// ListScanProfilesInput represents the input for listing scan profiles.
type ListScanProfilesInput struct {
	TenantID      string   `json:"tenant_id" validate:"required,uuid"`
	IsDefault     *bool    `json:"is_default"`
	IsSystem      *bool    `json:"is_system"`
	Tags          []string `json:"tags"`
	Search        string   `json:"search" validate:"max=255"`
	Page          int      `json:"page"`
	PerPage       int      `json:"per_page"`
	IncludeSystem bool     `json:"include_system"` // Include system profiles in results
}

// ListScanProfiles lists scan profiles with filters.
// If IncludeSystem is true, system profiles will be included alongside tenant profiles.
func (s *ScanProfileService) ListScanProfiles(ctx context.Context, input ListScanProfilesInput) (pagination.Result[*scanprofile.ScanProfile], error) {
	tenantID, err := shared.IDFromString(input.TenantID)
	if err != nil {
		return pagination.Result[*scanprofile.ScanProfile]{}, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}

	filter := scanprofile.Filter{
		TenantID:  &tenantID,
		IsDefault: input.IsDefault,
		IsSystem:  input.IsSystem,
		Tags:      input.Tags,
		Search:    input.Search,
	}

	page := pagination.New(input.Page, input.PerPage)

	// If include_system is true, use the method that includes system profiles
	if input.IncludeSystem {
		return s.repo.ListWithSystemProfiles(ctx, tenantID, filter, page)
	}

	return s.repo.List(ctx, filter, page)
}

// UpdateScanProfileInput represents the input for updating a scan profile.
type UpdateScanProfileInput struct {
	TenantID           string                            `json:"tenant_id" validate:"required,uuid"`
	ProfileID          string                            `json:"profile_id" validate:"required,uuid"`
	Name               string                            `json:"name" validate:"omitempty,min=1,max=100"`
	Description        string                            `json:"description" validate:"max=500"`
	ToolsConfig        map[string]scanprofile.ToolConfig `json:"tools_config"`
	Intensity          string                            `json:"intensity" validate:"omitempty,oneof=low medium high"`
	MaxConcurrentScans int                               `json:"max_concurrent_scans" validate:"omitempty,min=1,max=100"`
	TimeoutSeconds     int                               `json:"timeout_seconds" validate:"omitempty,min=60,max=86400"`
	Tags               []string                          `json:"tags" validate:"max=20,dive,max=50"`
	QualityGate        *scanprofile.QualityGate          `json:"quality_gate"`
}

// UpdateScanProfile updates an existing scan profile.
func (s *ScanProfileService) UpdateScanProfile(ctx context.Context, input UpdateScanProfileInput) (*scanprofile.ScanProfile, error) {
	s.logger.Info("updating scan profile", "profile_id", input.ProfileID)

	tenantID, err := shared.IDFromString(input.TenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}

	profile, err := s.GetScanProfile(ctx, input.TenantID, input.ProfileID)
	if err != nil {
		return nil, err
	}

	// Validate ownership - tenants can only edit their own profiles, not system profiles
	if err := profile.CanManage(tenantID); err != nil {
		return nil, err
	}

	err = profile.Update(
		input.Name,
		input.Description,
		input.ToolsConfig,
		scanprofile.Intensity(input.Intensity),
		input.MaxConcurrentScans,
		input.TimeoutSeconds,
		input.Tags,
	)
	if err != nil {
		return nil, err
	}

	// Update quality gate if provided
	if input.QualityGate != nil {
		if err := profile.UpdateQualityGate(*input.QualityGate); err != nil {
			return nil, err
		}
	}

	if err := s.repo.Update(ctx, profile); err != nil {
		return nil, err
	}

	return profile, nil
}

// DeleteScanProfile deletes a scan profile.
func (s *ScanProfileService) DeleteScanProfile(ctx context.Context, tenantID, profileID string) error {
	s.logger.Info("deleting scan profile", "profile_id", profileID)

	tid, err := shared.IDFromString(tenantID)
	if err != nil {
		return fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}

	profile, err := s.GetScanProfile(ctx, tenantID, profileID)
	if err != nil {
		return err
	}

	// Validate ownership - tenants can only delete their own profiles, not system profiles
	if err := profile.CanManage(tid); err != nil {
		return err
	}

	return s.repo.Delete(ctx, profile.ID)
}

// SetDefaultScanProfile sets a scan profile as the default for a tenant.
func (s *ScanProfileService) SetDefaultScanProfile(ctx context.Context, tenantID, profileID string) (*scanprofile.ScanProfile, error) {
	s.logger.Info("setting default scan profile", "profile_id", profileID)

	tid, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}

	profile, err := s.GetScanProfile(ctx, tenantID, profileID)
	if err != nil {
		return nil, err
	}

	// Clear existing default
	if err := s.repo.ClearDefaultForTenant(ctx, tid); err != nil {
		return nil, fmt.Errorf("failed to clear existing default: %w", err)
	}

	// Set new default
	profile.SetAsDefault()
	if err := s.repo.Update(ctx, profile); err != nil {
		return nil, err
	}

	return profile, nil
}

// CloneScanProfileInput represents the input for cloning a scan profile.
type CloneScanProfileInput struct {
	TenantID  string `json:"tenant_id" validate:"required,uuid"`
	ProfileID string `json:"profile_id" validate:"required,uuid"`
	NewName   string `json:"new_name" validate:"required,min=1,max=100"`
	UserID    string `json:"user_id" validate:"omitempty,uuid"`
}

// CloneScanProfile creates a copy of an existing scan profile.
func (s *ScanProfileService) CloneScanProfile(ctx context.Context, input CloneScanProfileInput) (*scanprofile.ScanProfile, error) {
	s.logger.Info("cloning scan profile", "profile_id", input.ProfileID, "new_name", input.NewName)

	profile, err := s.GetScanProfile(ctx, input.TenantID, input.ProfileID)
	if err != nil {
		return nil, err
	}

	var createdBy *shared.ID
	if input.UserID != "" {
		uid, err := shared.IDFromString(input.UserID)
		if err != nil {
			return nil, fmt.Errorf("%w: invalid user id", shared.ErrValidation)
		}
		createdBy = &uid
	}

	clone, err := profile.Clone(input.NewName, createdBy)
	if err != nil {
		return nil, err
	}

	if err := s.repo.Create(ctx, clone); err != nil {
		return nil, err
	}

	return clone, nil
}

// UpdateQualityGateInput represents the input for updating a quality gate.
type UpdateQualityGateInput struct {
	TenantID    string                  `json:"tenant_id" validate:"required,uuid"`
	ProfileID   string                  `json:"profile_id" validate:"required,uuid"`
	QualityGate scanprofile.QualityGate `json:"quality_gate" validate:"required"`
}

// UpdateQualityGate updates the quality gate configuration for a scan profile.
func (s *ScanProfileService) UpdateQualityGate(ctx context.Context, input UpdateQualityGateInput) (*scanprofile.ScanProfile, error) {
	s.logger.Info("updating quality gate", "profile_id", input.ProfileID)

	tenantID, err := shared.IDFromString(input.TenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}

	profile, err := s.GetScanProfile(ctx, input.TenantID, input.ProfileID)
	if err != nil {
		return nil, err
	}

	// Validate ownership - tenants can only edit their own profiles, not system profiles
	if err := profile.CanManage(tenantID); err != nil {
		return nil, err
	}

	if err := profile.UpdateQualityGate(input.QualityGate); err != nil {
		return nil, err
	}

	if err := s.repo.Update(ctx, profile); err != nil {
		return nil, err
	}

	return profile, nil
}

// EvaluateQualityGateInput represents the input for evaluating quality gate.
type EvaluateQualityGateInput struct {
	TenantID  string                    `json:"tenant_id" validate:"required,uuid"`
	ProfileID string                    `json:"profile_id" validate:"required,uuid"`
	Counts    scanprofile.FindingCounts `json:"counts" validate:"required"`
}

// EvaluateQualityGate evaluates finding counts against a scan profile's quality gate.
// Returns the quality gate result indicating pass/fail and any breaches.
func (s *ScanProfileService) EvaluateQualityGate(ctx context.Context, input EvaluateQualityGateInput) (*scanprofile.QualityGateResult, error) {
	s.logger.Info("evaluating quality gate", "profile_id", input.ProfileID)

	profile, err := s.GetScanProfile(ctx, input.TenantID, input.ProfileID)
	if err != nil {
		return nil, err
	}

	result := profile.QualityGate.Evaluate(input.Counts)
	return result, nil
}

// EvaluateQualityGateByProfile evaluates finding counts against a given quality gate.
// This can be used when the profile is already loaded.
func (s *ScanProfileService) EvaluateQualityGateByProfile(profile *scanprofile.ScanProfile, counts scanprofile.FindingCounts) *scanprofile.QualityGateResult {
	return profile.QualityGate.Evaluate(counts)
}
