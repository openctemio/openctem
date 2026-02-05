package app

import (
	"context"
	"fmt"
	"time"

	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/domain/sla"
	"github.com/openctemio/api/pkg/domain/vulnerability"
	"github.com/openctemio/api/pkg/logger"
)

// SLAService handles SLA policy-related business operations.
type SLAService struct {
	repo   sla.Repository
	logger *logger.Logger
}

// NewSLAService creates a new SLAService.
func NewSLAService(repo sla.Repository, log *logger.Logger) *SLAService {
	return &SLAService{
		repo:   repo,
		logger: log.With("service", "sla"),
	}
}

// CreateSLAPolicyInput represents the input for creating an SLA policy.
type CreateSLAPolicyInput struct {
	TenantID            string `validate:"required,uuid"`
	AssetID             string `validate:"omitempty,uuid"` // Optional, nil for tenant default
	Name                string `validate:"required,min=1,max=100"`
	Description         string `validate:"max=500"`
	IsDefault           bool
	CriticalDays        int `validate:"required,min=1,max=365"`
	HighDays            int `validate:"required,min=1,max=365"`
	MediumDays          int `validate:"required,min=1,max=365"`
	LowDays             int `validate:"required,min=1,max=365"`
	InfoDays            int `validate:"required,min=1,max=365"`
	WarningThresholdPct int `validate:"min=0,max=100"`
	EscalationEnabled   bool
	EscalationConfig    map[string]any
}

// CreateSLAPolicy creates a new SLA policy.
func (s *SLAService) CreateSLAPolicy(ctx context.Context, input CreateSLAPolicyInput) (*sla.Policy, error) {
	s.logger.Info("creating SLA policy", "name", input.Name, "tenant_id", input.TenantID)

	tenantID, err := shared.IDFromString(input.TenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id format", shared.ErrValidation)
	}

	// Validate days order: critical < high < medium < low < info
	if input.CriticalDays > input.HighDays ||
		input.HighDays > input.MediumDays ||
		input.MediumDays > input.LowDays ||
		input.LowDays > input.InfoDays {
		return nil, fmt.Errorf("%w: SLA days must be in order: critical <= high <= medium <= low <= info", shared.ErrValidation)
	}

	policy, err := sla.NewPolicy(tenantID, input.Name)
	if err != nil {
		return nil, err
	}

	if input.AssetID != "" {
		assetID, err := shared.IDFromString(input.AssetID)
		if err != nil {
			return nil, fmt.Errorf("%w: invalid asset id format", shared.ErrValidation)
		}
		policy.SetAssetID(assetID)
	}

	if input.Description != "" {
		policy.UpdateDescription(input.Description)
	}

	if input.IsDefault {
		policy.SetDefault(true)
	}

	if err := policy.UpdateSLADays(input.CriticalDays, input.HighDays, input.MediumDays, input.LowDays, input.InfoDays); err != nil {
		return nil, err
	}

	if input.WarningThresholdPct > 0 {
		if err := policy.SetWarningThreshold(input.WarningThresholdPct); err != nil {
			return nil, err
		}
	}

	if input.EscalationEnabled {
		policy.EnableEscalation(input.EscalationConfig)
	}

	if err := s.repo.Create(ctx, policy); err != nil {
		return nil, fmt.Errorf("failed to create SLA policy: %w", err)
	}

	s.logger.Info("SLA policy created", "id", policy.ID().String(), "name", policy.Name())
	return policy, nil
}

// GetSLAPolicy retrieves an SLA policy by ID.
func (s *SLAService) GetSLAPolicy(ctx context.Context, policyID string) (*sla.Policy, error) {
	parsedID, err := shared.IDFromString(policyID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid id format", shared.ErrValidation)
	}

	return s.repo.GetByID(ctx, parsedID)
}

// GetAssetSLAPolicy retrieves the effective SLA policy for an asset.
// Returns asset-specific policy if exists, otherwise tenant default.
func (s *SLAService) GetAssetSLAPolicy(ctx context.Context, tenantID, assetID string) (*sla.Policy, error) {
	parsedTenantID, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id format", shared.ErrValidation)
	}

	parsedAssetID, err := shared.IDFromString(assetID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid asset id format", shared.ErrValidation)
	}

	return s.repo.GetByAsset(ctx, parsedTenantID, parsedAssetID)
}

// GetTenantDefaultPolicy retrieves the default SLA policy for a tenant.
func (s *SLAService) GetTenantDefaultPolicy(ctx context.Context, tenantID string) (*sla.Policy, error) {
	parsedID, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id format", shared.ErrValidation)
	}

	return s.repo.GetTenantDefault(ctx, parsedID)
}

// UpdateSLAPolicyInput represents the input for updating an SLA policy.
type UpdateSLAPolicyInput struct {
	Name                *string `validate:"omitempty,min=1,max=100"`
	Description         *string `validate:"omitempty,max=500"`
	IsDefault           *bool
	CriticalDays        *int `validate:"omitempty,min=1,max=365"`
	HighDays            *int `validate:"omitempty,min=1,max=365"`
	MediumDays          *int `validate:"omitempty,min=1,max=365"`
	LowDays             *int `validate:"omitempty,min=1,max=365"`
	InfoDays            *int `validate:"omitempty,min=1,max=365"`
	WarningThresholdPct *int `validate:"omitempty,min=0,max=100"`
	EscalationEnabled   *bool
	EscalationConfig    map[string]any
	IsActive            *bool
}

// updateSLADaysIfNeeded updates SLA days if any are provided in the input.
func (s *SLAService) updateSLADaysIfNeeded(policy *sla.Policy, input UpdateSLAPolicyInput) error {
	if input.CriticalDays == nil && input.HighDays == nil &&
		input.MediumDays == nil && input.LowDays == nil && input.InfoDays == nil {
		return nil // No days to update
	}

	critical := policy.CriticalDays()
	high := policy.HighDays()
	medium := policy.MediumDays()
	low := policy.LowDays()
	info := policy.InfoDays()

	if input.CriticalDays != nil {
		critical = *input.CriticalDays
	}
	if input.HighDays != nil {
		high = *input.HighDays
	}
	if input.MediumDays != nil {
		medium = *input.MediumDays
	}
	if input.LowDays != nil {
		low = *input.LowDays
	}
	if input.InfoDays != nil {
		info = *input.InfoDays
	}

	// Validate order
	if critical > high || high > medium || medium > low || low > info {
		return fmt.Errorf("%w: SLA days must be in order: critical <= high <= medium <= low <= info", shared.ErrValidation)
	}

	return policy.UpdateSLADays(critical, high, medium, low, info)
}

// UpdateSLAPolicy updates an existing SLA policy.
func (s *SLAService) UpdateSLAPolicy(ctx context.Context, policyID, tenantID string, input UpdateSLAPolicyInput) (*sla.Policy, error) {
	parsedID, err := shared.IDFromString(policyID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid id format", shared.ErrValidation)
	}

	policy, err := s.repo.GetByID(ctx, parsedID)
	if err != nil {
		return nil, err
	}

	// IDOR prevention: verify policy belongs to the tenant
	if tenantID != "" && policy.TenantID().String() != tenantID {
		return nil, shared.ErrNotFound
	}

	if input.Name != nil {
		if err := policy.UpdateName(*input.Name); err != nil {
			return nil, err
		}
	}

	if input.Description != nil {
		policy.UpdateDescription(*input.Description)
	}

	if input.IsDefault != nil && *input.IsDefault {
		policy.SetDefault(true)
	}

	// Update SLA days if any provided
	if err := s.updateSLADaysIfNeeded(policy, input); err != nil {
		return nil, err
	}

	if input.WarningThresholdPct != nil {
		if err := policy.SetWarningThreshold(*input.WarningThresholdPct); err != nil {
			return nil, err
		}
	}

	if input.EscalationEnabled != nil {
		if *input.EscalationEnabled {
			policy.EnableEscalation(input.EscalationConfig)
		} else {
			policy.DisableEscalation()
		}
	}

	if input.IsActive != nil {
		if *input.IsActive {
			policy.Activate()
		} else {
			policy.Deactivate()
		}
	}

	if err := s.repo.Update(ctx, policy); err != nil {
		return nil, fmt.Errorf("failed to update SLA policy: %w", err)
	}

	s.logger.Info("SLA policy updated", "id", policy.ID().String())
	return policy, nil
}

// DeleteSLAPolicy deletes an SLA policy by ID.
func (s *SLAService) DeleteSLAPolicy(ctx context.Context, policyID, tenantID string) error {
	parsedID, err := shared.IDFromString(policyID)
	if err != nil {
		return fmt.Errorf("%w: invalid id format", shared.ErrValidation)
	}

	// IDOR prevention: verify policy belongs to the tenant before deletion
	if tenantID != "" {
		policy, err := s.repo.GetByID(ctx, parsedID)
		if err != nil {
			return err
		}
		if policy.TenantID().String() != tenantID {
			return shared.ErrNotFound
		}
		// Prevent deletion of default policy
		if policy.IsDefault() {
			return fmt.Errorf("%w: cannot delete default SLA policy", shared.ErrValidation)
		}
	}

	if err := s.repo.Delete(ctx, parsedID); err != nil {
		return err
	}

	s.logger.Info("SLA policy deleted", "id", policyID)
	return nil
}

// ListTenantPolicies retrieves all SLA policies for a tenant.
func (s *SLAService) ListTenantPolicies(ctx context.Context, tenantID string) ([]*sla.Policy, error) {
	parsedID, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id format", shared.ErrValidation)
	}

	return s.repo.ListByTenant(ctx, parsedID)
}

// CalculateSLADeadline calculates the SLA deadline for a finding based on its severity.
func (s *SLAService) CalculateSLADeadline(ctx context.Context, tenantID, assetID string, severity vulnerability.Severity, detectedAt time.Time) (time.Time, error) {
	var policy *sla.Policy
	var err error

	if assetID != "" {
		policy, err = s.GetAssetSLAPolicy(ctx, tenantID, assetID)
	} else {
		policy, err = s.GetTenantDefaultPolicy(ctx, tenantID)
	}

	if err != nil {
		// Fall back to default values if no policy found
		s.logger.Warn("no SLA policy found, using defaults", "tenant_id", tenantID, "asset_id", assetID, "error", err)
		defaultDays, ok := sla.DefaultSLADays[severity.String()]
		if !ok {
			return time.Time{}, fmt.Errorf("%w: invalid severity", shared.ErrValidation)
		}
		return detectedAt.Add(time.Duration(defaultDays) * 24 * time.Hour), nil
	}

	return policy.CalculateDeadline(severity.String(), detectedAt), nil
}

// CheckSLACompliance checks if a finding is within SLA compliance.
type SLAComplianceResult struct {
	IsCompliant      bool
	Status           string // on_track, warning, overdue, exceeded
	DeadlineAt       time.Time
	DaysRemaining    int
	PercentElapsed   float64
	EscalationNeeded bool
}

// CheckSLACompliance checks the SLA status of a finding.
func (s *SLAService) CheckSLACompliance(
	ctx context.Context,
	tenantID, assetID string,
	severity vulnerability.Severity,
	detectedAt time.Time,
	resolvedAt *time.Time,
) (*SLAComplianceResult, error) {
	var policy *sla.Policy
	var err error

	if assetID != "" {
		policy, err = s.GetAssetSLAPolicy(ctx, tenantID, assetID)
	} else {
		policy, err = s.GetTenantDefaultPolicy(ctx, tenantID)
	}

	// Use default days if no policy found
	var deadline time.Time
	var warningThreshold int
	var escalationEnabled bool

	if err != nil || policy == nil {
		days := sla.DefaultSLADays[severity.String()]
		deadline = detectedAt.Add(time.Duration(days) * 24 * time.Hour)
		warningThreshold = 80
		escalationEnabled = false
	} else {
		deadline = policy.CalculateDeadline(severity.String(), detectedAt)
		warningThreshold = policy.WarningThresholdPct()
		escalationEnabled = policy.EscalationEnabled()
	}

	now := time.Now()

	// If already resolved
	if resolvedAt != nil {
		if resolvedAt.Before(deadline) {
			return &SLAComplianceResult{
				IsCompliant:    true,
				Status:         "on_track",
				DeadlineAt:     deadline,
				DaysRemaining:  0,
				PercentElapsed: 100,
			}, nil
		}
		return &SLAComplianceResult{
			IsCompliant:    false,
			Status:         "exceeded",
			DeadlineAt:     deadline,
			DaysRemaining:  0,
			PercentElapsed: 100,
		}, nil
	}

	// Calculate time elapsed
	totalDuration := deadline.Sub(detectedAt)
	elapsed := now.Sub(detectedAt)
	percentElapsed := float64(elapsed) / float64(totalDuration) * 100
	if percentElapsed > 100 {
		percentElapsed = 100
	}

	daysRemaining := int(deadline.Sub(now).Hours() / 24)
	if daysRemaining < 0 {
		daysRemaining = 0
	}

	result := &SLAComplianceResult{
		DeadlineAt:     deadline,
		DaysRemaining:  daysRemaining,
		PercentElapsed: percentElapsed,
	}

	// Determine status
	switch {
	case now.After(deadline):
		result.IsCompliant = false
		result.Status = "overdue"
		result.EscalationNeeded = escalationEnabled
	case percentElapsed >= float64(warningThreshold):
		result.IsCompliant = true
		result.Status = "warning"
	default:
		result.IsCompliant = true
		result.Status = "on_track"
	}

	return result, nil
}

// CreateDefaultTenantPolicy creates a default SLA policy for a new tenant.
func (s *SLAService) CreateDefaultTenantPolicy(ctx context.Context, tenantID string) (*sla.Policy, error) {
	return s.CreateSLAPolicy(ctx, CreateSLAPolicyInput{
		TenantID:            tenantID,
		Name:                "Default SLA Policy",
		Description:         "Default remediation timeline policy",
		IsDefault:           true,
		CriticalDays:        sla.DefaultSLADays["critical"],
		HighDays:            sla.DefaultSLADays["high"],
		MediumDays:          sla.DefaultSLADays["medium"],
		LowDays:             sla.DefaultSLADays["low"],
		InfoDays:            sla.DefaultSLADays["info"],
		WarningThresholdPct: 80,
		EscalationEnabled:   false,
	})
}
