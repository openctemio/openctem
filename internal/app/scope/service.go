package scope

import (
	"context"
	"fmt"
	"math"
	"time"

	"github.com/openctemio/api/pkg/domain/asset"
	scopedom "github.com/openctemio/api/pkg/domain/scope"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/logger"
	"github.com/openctemio/api/pkg/pagination"
)

// Service handles scope configuration business operations.
type Service struct {
	targetRepo    scopedom.TargetRepository
	exclusionRepo scopedom.ExclusionRepository
	scheduleRepo  scopedom.ScheduleRepository
	assetRepo     asset.Repository
	logger        *logger.Logger
}

// NewService creates a new Service.
func NewService(
	targetRepo scopedom.TargetRepository,
	exclusionRepo scopedom.ExclusionRepository,
	scheduleRepo scopedom.ScheduleRepository,
	assetRepo asset.Repository,
	log *logger.Logger,
) *Service {
	return &Service{
		targetRepo:    targetRepo,
		exclusionRepo: exclusionRepo,
		scheduleRepo:  scheduleRepo,
		assetRepo:     assetRepo,
		logger:        log.With("service", "scope"),
	}
}

// =============================================================================
// Target Operations
// =============================================================================

// CreateTargetInput represents the input for creating a scope target.
type CreateTargetInput struct {
	TenantID    string   `validate:"required,uuid"`
	TargetType  string   `validate:"required"`
	Pattern     string   `validate:"required,max=500"`
	Description string   `validate:"max=1000"`
	Priority    int      `validate:"min=0,max=100"`
	Tags        []string `validate:"max=20,dive,max=50"`
	CreatedBy   string   `validate:"max=200"`
}

// CreateTarget creates a new scope target.
func (s *Service) CreateTarget(ctx context.Context, input CreateTargetInput) (*scopedom.Target, error) {
	s.logger.Info("creating scope target", "type", input.TargetType, "pattern", input.Pattern)

	tenantID, err := shared.IDFromString(input.TenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}

	targetType, err := scopedom.ParseTargetType(input.TargetType)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", shared.ErrValidation, err)
	}

	// Check if pattern already exists
	exists, err := s.targetRepo.ExistsByPattern(ctx, tenantID, targetType, input.Pattern)
	if err != nil {
		return nil, fmt.Errorf("failed to check target existence: %w", err)
	}
	if exists {
		return nil, scopedom.ErrTargetAlreadyExists
	}

	target, err := scopedom.NewTarget(tenantID, targetType, input.Pattern, input.Description, input.CreatedBy)
	if err != nil {
		return nil, err
	}

	// Apply optional settings
	if input.Priority > 0 {
		if err := target.UpdatePriority(input.Priority); err != nil {
			return nil, err
		}
	}
	if len(input.Tags) > 0 {
		target.UpdateTags(input.Tags)
	}

	if err := s.targetRepo.Create(ctx, target); err != nil {
		return nil, fmt.Errorf("failed to create scope target: %w", err)
	}

	s.logger.Info("scope target created", "id", target.ID().String(), "pattern", input.Pattern)
	return target, nil
}

// GetTarget retrieves a scope target by tenant ID and ID.
func (s *Service) GetTarget(ctx context.Context, tenantID string, targetID string) (*scopedom.Target, error) {
	parsedTenantID, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}
	parsedID, err := shared.IDFromString(targetID)
	if err != nil {
		return nil, shared.ErrNotFound
	}
	return s.targetRepo.GetByID(ctx, parsedTenantID, parsedID)
}

// UpdateTargetInput represents the input for updating a scope target.
type UpdateTargetInput struct {
	Description *string  `validate:"omitempty,max=1000"`
	Priority    *int     `validate:"omitempty,min=0,max=100"`
	Tags        []string `validate:"omitempty,max=20,dive,max=50"`
}

// UpdateTarget updates an existing scope target.
func (s *Service) UpdateTarget(ctx context.Context, targetID string, tenantID string, input UpdateTargetInput) (*scopedom.Target, error) {
	parsedTenantID, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}
	parsedID, err := shared.IDFromString(targetID)
	if err != nil {
		return nil, shared.ErrNotFound
	}

	target, err := s.targetRepo.GetByID(ctx, parsedTenantID, parsedID)
	if err != nil {
		return nil, err
	}

	if input.Description != nil {
		target.UpdateDescription(*input.Description)
	}
	if input.Priority != nil {
		if err := target.UpdatePriority(*input.Priority); err != nil {
			return nil, err
		}
	}
	if input.Tags != nil {
		target.UpdateTags(input.Tags)
	}

	if err := s.targetRepo.Update(ctx, target); err != nil {
		return nil, fmt.Errorf("failed to update scope target: %w", err)
	}

	s.logger.Info("scope target updated", "id", targetID)
	return target, nil
}

// DeleteTarget deletes a scope target by ID with atomic tenant verification.
func (s *Service) DeleteTarget(ctx context.Context, targetID string, tenantID string) error {
	parsedID, err := shared.IDFromString(targetID)
	if err != nil {
		return shared.ErrNotFound
	}

	parsedTenantID, err := shared.IDFromString(tenantID)
	if err != nil {
		return fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}

	if err := s.targetRepo.Delete(ctx, parsedTenantID, parsedID); err != nil {
		return err
	}

	s.logger.Info("scope target deleted", "id", targetID)
	return nil
}

// ListTargetsInput represents the input for listing scope targets.
type ListTargetsInput struct {
	TenantID    string   `validate:"omitempty,uuid"`
	TargetTypes []string `validate:"max=20"`
	Statuses    []string `validate:"max=3"`
	Tags        []string `validate:"max=20,dive,max=50"`
	Search      string   `validate:"max=255"`
	Page        int      `validate:"min=0"`
	PerPage     int      `validate:"min=0,max=100"`
}

// ListTargets retrieves scope targets with filtering and pagination.
func (s *Service) ListTargets(ctx context.Context, input ListTargetsInput) (pagination.Result[*scopedom.Target], error) {
	filter := scopedom.TargetFilter{}

	if input.TenantID != "" {
		filter.TenantID = &input.TenantID
	}

	if len(input.TargetTypes) > 0 {
		types := make([]scopedom.TargetType, 0, len(input.TargetTypes))
		for _, t := range input.TargetTypes {
			if parsed, err := scopedom.ParseTargetType(t); err == nil {
				types = append(types, parsed)
			}
		}
		filter.TargetTypes = types
	}

	if len(input.Statuses) > 0 {
		statuses := make([]scopedom.Status, 0, len(input.Statuses))
		for _, st := range input.Statuses {
			statuses = append(statuses, scopedom.Status(st))
		}
		filter.Statuses = statuses
	}

	if len(input.Tags) > 0 {
		filter.Tags = input.Tags
	}

	if input.Search != "" {
		filter.Search = &input.Search
	}

	page := pagination.New(input.Page, input.PerPage)
	return s.targetRepo.List(ctx, filter, page)
}

// ListActiveTargets retrieves all active scope targets for a tenant.
func (s *Service) ListActiveTargets(ctx context.Context, tenantID string) ([]*scopedom.Target, error) {
	parsedID, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}
	return s.targetRepo.ListActive(ctx, parsedID)
}

// ActivateTarget activates a scope target.
func (s *Service) ActivateTarget(ctx context.Context, targetID string, tenantID string) (*scopedom.Target, error) {
	parsedTenantID, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}
	parsedID, err := shared.IDFromString(targetID)
	if err != nil {
		return nil, shared.ErrNotFound
	}

	target, err := s.targetRepo.GetByID(ctx, parsedTenantID, parsedID)
	if err != nil {
		return nil, err
	}

	target.Activate()

	if err := s.targetRepo.Update(ctx, target); err != nil {
		return nil, fmt.Errorf("failed to activate scope target: %w", err)
	}

	s.logger.Info("scope target activated", "id", targetID)
	return target, nil
}

// DeactivateTarget deactivates a scope target.
func (s *Service) DeactivateTarget(ctx context.Context, targetID string, tenantID string) (*scopedom.Target, error) {
	parsedTenantID, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}
	parsedID, err := shared.IDFromString(targetID)
	if err != nil {
		return nil, shared.ErrNotFound
	}

	target, err := s.targetRepo.GetByID(ctx, parsedTenantID, parsedID)
	if err != nil {
		return nil, err
	}

	target.Deactivate()

	if err := s.targetRepo.Update(ctx, target); err != nil {
		return nil, fmt.Errorf("failed to deactivate scope target: %w", err)
	}

	s.logger.Info("scope target deactivated", "id", targetID)
	return target, nil
}

// =============================================================================
// Exclusion Operations
// =============================================================================

// CreateExclusionInput represents the input for creating a scope exclusion.
type CreateExclusionInput struct {
	TenantID      string     `validate:"required,uuid"`
	ExclusionType string     `validate:"required"`
	Pattern       string     `validate:"required,max=500"`
	Reason        string     `validate:"required,max=1000"`
	ExpiresAt     *time.Time `validate:"omitempty"`
	CreatedBy     string     `validate:"max=200"`
}

// CreateExclusion creates a new scope exclusion.
func (s *Service) CreateExclusion(ctx context.Context, input CreateExclusionInput) (*scopedom.Exclusion, error) {
	s.logger.Info("creating scope exclusion", "type", input.ExclusionType, "pattern", input.Pattern)

	tenantID, err := shared.IDFromString(input.TenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}

	exclusionType, err := scopedom.ParseExclusionType(input.ExclusionType)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", shared.ErrValidation, err)
	}

	exclusion, err := scopedom.NewExclusion(tenantID, exclusionType, input.Pattern, input.Reason, input.ExpiresAt, input.CreatedBy)
	if err != nil {
		return nil, err
	}

	if err := s.exclusionRepo.Create(ctx, exclusion); err != nil {
		return nil, fmt.Errorf("failed to create scope exclusion: %w", err)
	}

	s.logger.Info("scope exclusion created", "id", exclusion.ID().String(), "pattern", input.Pattern)
	return exclusion, nil
}

// GetExclusion retrieves a scope exclusion by tenant ID and ID.
func (s *Service) GetExclusion(ctx context.Context, tenantID string, exclusionID string) (*scopedom.Exclusion, error) {
	parsedTenantID, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}
	parsedID, err := shared.IDFromString(exclusionID)
	if err != nil {
		return nil, shared.ErrNotFound
	}
	return s.exclusionRepo.GetByID(ctx, parsedTenantID, parsedID)
}

// UpdateExclusionInput represents the input for updating a scope exclusion.
type UpdateExclusionInput struct {
	Reason    *string    `validate:"omitempty,max=1000"`
	ExpiresAt *time.Time `validate:"omitempty"`
}

// UpdateExclusion updates an existing scope exclusion.
func (s *Service) UpdateExclusion(ctx context.Context, exclusionID string, tenantID string, input UpdateExclusionInput) (*scopedom.Exclusion, error) {
	parsedTenantID, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}
	parsedID, err := shared.IDFromString(exclusionID)
	if err != nil {
		return nil, shared.ErrNotFound
	}

	exclusion, err := s.exclusionRepo.GetByID(ctx, parsedTenantID, parsedID)
	if err != nil {
		return nil, err
	}

	if input.Reason != nil {
		exclusion.UpdateReason(*input.Reason)
	}
	if input.ExpiresAt != nil {
		exclusion.UpdateExpiresAt(input.ExpiresAt)
	}

	if err := s.exclusionRepo.Update(ctx, exclusion); err != nil {
		return nil, fmt.Errorf("failed to update scope exclusion: %w", err)
	}

	s.logger.Info("scope exclusion updated", "id", exclusionID)
	return exclusion, nil
}

// DeleteExclusion deletes a scope exclusion by ID with atomic tenant verification.
func (s *Service) DeleteExclusion(ctx context.Context, exclusionID string, tenantID string) error {
	parsedID, err := shared.IDFromString(exclusionID)
	if err != nil {
		return shared.ErrNotFound
	}

	parsedTenantID, err := shared.IDFromString(tenantID)
	if err != nil {
		return fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}

	if err := s.exclusionRepo.Delete(ctx, parsedTenantID, parsedID); err != nil {
		return err
	}

	s.logger.Info("scope exclusion deleted", "id", exclusionID)
	return nil
}

// ListExclusionsInput represents the input for listing scope exclusions.
type ListExclusionsInput struct {
	TenantID       string   `validate:"omitempty,uuid"`
	ExclusionTypes []string `validate:"max=20"`
	Statuses       []string `validate:"max=3"`
	IsApproved     *bool
	Search         string `validate:"max=255"`
	Page           int    `validate:"min=0"`
	PerPage        int    `validate:"min=0,max=100"`
}

// ListExclusions retrieves scope exclusions with filtering and pagination.
func (s *Service) ListExclusions(ctx context.Context, input ListExclusionsInput) (pagination.Result[*scopedom.Exclusion], error) {
	filter := scopedom.ExclusionFilter{}

	if input.TenantID != "" {
		filter.TenantID = &input.TenantID
	}

	if len(input.ExclusionTypes) > 0 {
		types := make([]scopedom.ExclusionType, 0, len(input.ExclusionTypes))
		for _, t := range input.ExclusionTypes {
			if parsed, err := scopedom.ParseExclusionType(t); err == nil {
				types = append(types, parsed)
			}
		}
		filter.ExclusionTypes = types
	}

	if len(input.Statuses) > 0 {
		statuses := make([]scopedom.Status, 0, len(input.Statuses))
		for _, st := range input.Statuses {
			statuses = append(statuses, scopedom.Status(st))
		}
		filter.Statuses = statuses
	}

	if input.IsApproved != nil {
		filter.IsApproved = input.IsApproved
	}

	if input.Search != "" {
		filter.Search = &input.Search
	}

	page := pagination.New(input.Page, input.PerPage)
	return s.exclusionRepo.List(ctx, filter, page)
}

// ListActiveExclusions retrieves all active scope exclusions for a tenant.
func (s *Service) ListActiveExclusions(ctx context.Context, tenantID string) ([]*scopedom.Exclusion, error) {
	parsedID, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}
	return s.exclusionRepo.ListActive(ctx, parsedID)
}

// ApproveExclusion approves a scope exclusion.
func (s *Service) ApproveExclusion(ctx context.Context, exclusionID string, tenantID string, approvedBy string) (*scopedom.Exclusion, error) {
	parsedTenantID, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}
	parsedID, err := shared.IDFromString(exclusionID)
	if err != nil {
		return nil, shared.ErrNotFound
	}

	exclusion, err := s.exclusionRepo.GetByID(ctx, parsedTenantID, parsedID)
	if err != nil {
		return nil, err
	}

	exclusion.Approve(approvedBy)

	if err := s.exclusionRepo.Update(ctx, exclusion); err != nil {
		return nil, fmt.Errorf("failed to approve scope exclusion: %w", err)
	}

	s.logger.Info("scope exclusion approved", "id", exclusionID, "approvedBy", approvedBy)
	return exclusion, nil
}

// ActivateExclusion activates a scope exclusion.
func (s *Service) ActivateExclusion(ctx context.Context, exclusionID string, tenantID string) (*scopedom.Exclusion, error) {
	parsedTenantID, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}
	parsedID, err := shared.IDFromString(exclusionID)
	if err != nil {
		return nil, shared.ErrNotFound
	}

	exclusion, err := s.exclusionRepo.GetByID(ctx, parsedTenantID, parsedID)
	if err != nil {
		return nil, err
	}

	exclusion.Activate()

	if err := s.exclusionRepo.Update(ctx, exclusion); err != nil {
		return nil, fmt.Errorf("failed to activate scope exclusion: %w", err)
	}

	s.logger.Info("scope exclusion activated", "id", exclusionID)
	return exclusion, nil
}

// DeactivateExclusion deactivates a scope exclusion.
func (s *Service) DeactivateExclusion(ctx context.Context, exclusionID string, tenantID string) (*scopedom.Exclusion, error) {
	parsedTenantID, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}
	parsedID, err := shared.IDFromString(exclusionID)
	if err != nil {
		return nil, shared.ErrNotFound
	}

	exclusion, err := s.exclusionRepo.GetByID(ctx, parsedTenantID, parsedID)
	if err != nil {
		return nil, err
	}

	exclusion.Deactivate()

	if err := s.exclusionRepo.Update(ctx, exclusion); err != nil {
		return nil, fmt.Errorf("failed to deactivate scope exclusion: %w", err)
	}

	s.logger.Info("scope exclusion deactivated", "id", exclusionID)
	return exclusion, nil
}

// ExpireOldExclusions marks expired exclusions as expired.
func (s *Service) ExpireOldExclusions(ctx context.Context) error {
	if err := s.exclusionRepo.ExpireOld(ctx); err != nil {
		return fmt.Errorf("failed to expire old exclusions: %w", err)
	}
	s.logger.Info("expired old exclusions")
	return nil
}

// =============================================================================
// Schedule Operations
// =============================================================================

// CreateScheduleInput represents the input for creating a scan schedule.
type CreateScheduleInput struct {
	TenantID             string                 `validate:"required,uuid"`
	Name                 string                 `validate:"required,min=1,max=200"`
	Description          string                 `validate:"max=1000"`
	ScanType             string                 `validate:"required"`
	TargetScope          string                 `validate:"omitempty"`
	TargetIDs            []string               `validate:"max=100"`
	TargetTags           []string               `validate:"max=20,dive,max=50"`
	ScannerConfigs       map[string]interface{} `validate:"omitempty"`
	ScheduleType         string                 `validate:"required"`
	CronExpression       string                 `validate:"max=100"`
	IntervalHours        int                    `validate:"min=0,max=8760"`
	NotifyOnCompletion   bool
	NotifyOnFindings     bool
	NotificationChannels []string `validate:"max=10,dive,max=50"`
	CreatedBy            string   `validate:"max=200"`
}

// CreateSchedule creates a new scan schedule.
func (s *Service) CreateSchedule(ctx context.Context, input CreateScheduleInput) (*scopedom.Schedule, error) {
	s.logger.Info("creating scan schedule", "name", input.Name, "type", input.ScheduleType)

	tenantID, err := shared.IDFromString(input.TenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}

	scanType, err := scopedom.ParseScanType(input.ScanType)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", shared.ErrValidation, err)
	}

	scheduleType := scopedom.ScheduleType(input.ScheduleType)
	if !scheduleType.IsValid() {
		return nil, fmt.Errorf("%w: invalid schedule type", shared.ErrValidation)
	}

	schedule, err := scopedom.NewSchedule(tenantID, input.Name, scanType, scheduleType, input.CreatedBy)
	if err != nil {
		return nil, err
	}

	// Apply optional settings
	if input.Description != "" {
		schedule.UpdateDescription(input.Description)
	}

	// Set schedule timing
	if input.ScheduleType == string(scopedom.ScheduleTypeCron) && input.CronExpression != "" {
		if err := schedule.SetCronSchedule(input.CronExpression); err != nil {
			return nil, err
		}
	} else if input.ScheduleType == string(scopedom.ScheduleTypeInterval) && input.IntervalHours > 0 {
		if err := schedule.SetIntervalSchedule(input.IntervalHours); err != nil {
			return nil, err
		}
	}

	// Set target scope
	if input.TargetScope != "" {
		targetIDs := make([]shared.ID, 0, len(input.TargetIDs))
		for _, idStr := range input.TargetIDs {
			if id, err := shared.IDFromString(idStr); err == nil {
				targetIDs = append(targetIDs, id)
			}
		}
		schedule.SetTargetScope(scopedom.TargetScope(input.TargetScope), targetIDs, input.TargetTags)
	}

	// Set scanner configs
	if input.ScannerConfigs != nil {
		schedule.UpdateScannerConfigs(input.ScannerConfigs)
	}

	// Set notifications
	schedule.UpdateNotifications(input.NotifyOnCompletion, input.NotifyOnFindings, input.NotificationChannels)

	if err := s.scheduleRepo.Create(ctx, schedule); err != nil {
		return nil, fmt.Errorf("failed to create scan schedule: %w", err)
	}

	s.logger.Info("scan schedule created", "id", schedule.ID().String(), "name", input.Name)
	return schedule, nil
}

// GetSchedule retrieves a scan schedule by tenant ID and ID.
func (s *Service) GetSchedule(ctx context.Context, tenantID string, scheduleID string) (*scopedom.Schedule, error) {
	parsedTenantID, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}
	parsedID, err := shared.IDFromString(scheduleID)
	if err != nil {
		return nil, shared.ErrNotFound
	}
	return s.scheduleRepo.GetByID(ctx, parsedTenantID, parsedID)
}

// UpdateScheduleInput represents the input for updating a scan schedule.
type UpdateScheduleInput struct {
	Name                 *string                `validate:"omitempty,min=1,max=200"`
	Description          *string                `validate:"omitempty,max=1000"`
	TargetScope          *string                `validate:"omitempty"`
	TargetIDs            []string               `validate:"omitempty,max=100"`
	TargetTags           []string               `validate:"omitempty,max=20,dive,max=50"`
	ScannerConfigs       map[string]interface{} `validate:"omitempty"`
	ScheduleType         *string                `validate:"omitempty"`
	CronExpression       *string                `validate:"omitempty,max=100"`
	IntervalHours        *int                   `validate:"omitempty,min=0,max=8760"`
	NotifyOnCompletion   *bool
	NotifyOnFindings     *bool
	NotificationChannels []string `validate:"omitempty,max=10,dive,max=50"`
}

// UpdateSchedule updates an existing scan schedule.
func (s *Service) UpdateSchedule(ctx context.Context, scheduleID string, tenantID string, input UpdateScheduleInput) (*scopedom.Schedule, error) {
	parsedTenantID, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}
	parsedID, err := shared.IDFromString(scheduleID)
	if err != nil {
		return nil, shared.ErrNotFound
	}

	schedule, err := s.scheduleRepo.GetByID(ctx, parsedTenantID, parsedID)
	if err != nil {
		return nil, err
	}

	if input.Name != nil {
		schedule.UpdateName(*input.Name)
	}
	if input.Description != nil {
		schedule.UpdateDescription(*input.Description)
	}

	// Update schedule timing
	if input.ScheduleType != nil {
		if *input.ScheduleType == string(scopedom.ScheduleTypeCron) && input.CronExpression != nil {
			if err := schedule.SetCronSchedule(*input.CronExpression); err != nil {
				return nil, err
			}
		} else if *input.ScheduleType == string(scopedom.ScheduleTypeInterval) && input.IntervalHours != nil {
			if err := schedule.SetIntervalSchedule(*input.IntervalHours); err != nil {
				return nil, err
			}
		}
	}

	// Update target scope
	if input.TargetScope != nil {
		targetIDs := make([]shared.ID, 0, len(input.TargetIDs))
		for _, idStr := range input.TargetIDs {
			if id, err := shared.IDFromString(idStr); err == nil {
				targetIDs = append(targetIDs, id)
			}
		}
		schedule.SetTargetScope(scopedom.TargetScope(*input.TargetScope), targetIDs, input.TargetTags)
	}

	// Update scanner configs
	if input.ScannerConfigs != nil {
		schedule.UpdateScannerConfigs(input.ScannerConfigs)
	}

	// Update notifications
	if input.NotifyOnCompletion != nil || input.NotifyOnFindings != nil || input.NotificationChannels != nil {
		onCompletion := schedule.NotifyOnCompletion()
		onFindings := schedule.NotifyOnFindings()
		channels := schedule.NotificationChannels()

		if input.NotifyOnCompletion != nil {
			onCompletion = *input.NotifyOnCompletion
		}
		if input.NotifyOnFindings != nil {
			onFindings = *input.NotifyOnFindings
		}
		if input.NotificationChannels != nil {
			channels = input.NotificationChannels
		}
		schedule.UpdateNotifications(onCompletion, onFindings, channels)
	}

	if err := s.scheduleRepo.Update(ctx, schedule); err != nil {
		return nil, fmt.Errorf("failed to update scan schedule: %w", err)
	}

	s.logger.Info("scan schedule updated", "id", scheduleID)
	return schedule, nil
}

// DeleteSchedule deletes a scan schedule by ID with atomic tenant verification.
func (s *Service) DeleteSchedule(ctx context.Context, scheduleID string, tenantID string) error {
	parsedID, err := shared.IDFromString(scheduleID)
	if err != nil {
		return shared.ErrNotFound
	}

	parsedTenantID, err := shared.IDFromString(tenantID)
	if err != nil {
		return fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}

	if err := s.scheduleRepo.Delete(ctx, parsedTenantID, parsedID); err != nil {
		return err
	}

	s.logger.Info("scan schedule deleted", "id", scheduleID)
	return nil
}

// ListSchedulesInput represents the input for listing scan schedules.
type ListSchedulesInput struct {
	TenantID      string   `validate:"omitempty,uuid"`
	ScanTypes     []string `validate:"max=20"`
	ScheduleTypes []string `validate:"max=3"`
	Enabled       *bool
	Search        string `validate:"max=255"`
	Page          int    `validate:"min=0"`
	PerPage       int    `validate:"min=0,max=100"`
}

// ListSchedules retrieves scan schedules with filtering and pagination.
func (s *Service) ListSchedules(ctx context.Context, input ListSchedulesInput) (pagination.Result[*scopedom.Schedule], error) {
	filter := scopedom.ScheduleFilter{}

	if input.TenantID != "" {
		filter.TenantID = &input.TenantID
	}

	if len(input.ScanTypes) > 0 {
		types := make([]scopedom.ScanType, 0, len(input.ScanTypes))
		for _, t := range input.ScanTypes {
			if parsed, err := scopedom.ParseScanType(t); err == nil {
				types = append(types, parsed)
			}
		}
		filter.ScanTypes = types
	}

	if len(input.ScheduleTypes) > 0 {
		types := make([]scopedom.ScheduleType, 0, len(input.ScheduleTypes))
		for _, t := range input.ScheduleTypes {
			types = append(types, scopedom.ScheduleType(t))
		}
		filter.ScheduleTypes = types
	}

	if input.Enabled != nil {
		filter.Enabled = input.Enabled
	}

	if input.Search != "" {
		filter.Search = &input.Search
	}

	page := pagination.New(input.Page, input.PerPage)
	return s.scheduleRepo.List(ctx, filter, page)
}

// ListDueSchedules retrieves all enabled schedules that are due to run.
func (s *Service) ListDueSchedules(ctx context.Context) ([]*scopedom.Schedule, error) {
	return s.scheduleRepo.ListDue(ctx)
}

// EnableSchedule enables a scan schedule.
func (s *Service) EnableSchedule(ctx context.Context, scheduleID string, tenantID string) (*scopedom.Schedule, error) {
	parsedTenantID, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}
	parsedID, err := shared.IDFromString(scheduleID)
	if err != nil {
		return nil, shared.ErrNotFound
	}

	schedule, err := s.scheduleRepo.GetByID(ctx, parsedTenantID, parsedID)
	if err != nil {
		return nil, err
	}

	schedule.Enable()

	if err := s.scheduleRepo.Update(ctx, schedule); err != nil {
		return nil, fmt.Errorf("failed to enable scan schedule: %w", err)
	}

	s.logger.Info("scan schedule enabled", "id", scheduleID)
	return schedule, nil
}

// DisableSchedule disables a scan schedule.
func (s *Service) DisableSchedule(ctx context.Context, scheduleID string, tenantID string) (*scopedom.Schedule, error) {
	parsedTenantID, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}
	parsedID, err := shared.IDFromString(scheduleID)
	if err != nil {
		return nil, shared.ErrNotFound
	}

	schedule, err := s.scheduleRepo.GetByID(ctx, parsedTenantID, parsedID)
	if err != nil {
		return nil, err
	}

	schedule.Disable()

	if err := s.scheduleRepo.Update(ctx, schedule); err != nil {
		return nil, fmt.Errorf("failed to disable scan schedule: %w", err)
	}

	s.logger.Info("scan schedule disabled", "id", scheduleID)
	return schedule, nil
}

// RunScheduleNow triggers an immediate run of a scan schedule.
func (s *Service) RunScheduleNow(ctx context.Context, scheduleID string, tenantID string) (*scopedom.Schedule, error) {
	parsedTenantID, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}
	parsedID, err := shared.IDFromString(scheduleID)
	if err != nil {
		return nil, shared.ErrNotFound
	}

	schedule, err := s.scheduleRepo.GetByID(ctx, parsedTenantID, parsedID)
	if err != nil {
		return nil, err
	}

	// Record a run with "running" status
	schedule.RecordRun("running", nil)

	if err := s.scheduleRepo.Update(ctx, schedule); err != nil {
		return nil, fmt.Errorf("failed to run schedule now: %w", err)
	}

	s.logger.Info("scan schedule triggered manually", "id", scheduleID)
	return schedule, nil
}

// RecordScheduleRun records a scan run for a schedule.
func (s *Service) RecordScheduleRun(ctx context.Context, tenantID string, scheduleID string, status string, nextRunAt *time.Time) (*scopedom.Schedule, error) {
	parsedTenantID, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}
	parsedID, err := shared.IDFromString(scheduleID)
	if err != nil {
		return nil, shared.ErrNotFound
	}

	schedule, err := s.scheduleRepo.GetByID(ctx, parsedTenantID, parsedID)
	if err != nil {
		return nil, err
	}

	schedule.RecordRun(status, nextRunAt)

	if err := s.scheduleRepo.Update(ctx, schedule); err != nil {
		return nil, fmt.Errorf("failed to record schedule run: %w", err)
	}

	s.logger.Info("scan schedule run recorded", "id", scheduleID, "status", status)
	return schedule, nil
}

// =============================================================================
// Stats & Coverage Operations
// =============================================================================

// GetStats retrieves scope configuration statistics for a tenant.
func (s *Service) GetStats(ctx context.Context, tenantID string) (*scopedom.Stats, error) {
	targetFilter := scopedom.TargetFilter{TenantID: &tenantID}
	exclusionFilter := scopedom.ExclusionFilter{TenantID: &tenantID}
	scheduleFilter := scopedom.ScheduleFilter{TenantID: &tenantID}

	totalTargets, err := s.targetRepo.Count(ctx, targetFilter)
	if err != nil {
		return nil, fmt.Errorf("failed to count targets: %w", err)
	}

	activeTargetFilter := scopedom.TargetFilter{
		TenantID: &tenantID,
		Statuses: []scopedom.Status{scopedom.StatusActive},
	}
	activeTargets, err := s.targetRepo.Count(ctx, activeTargetFilter)
	if err != nil {
		return nil, fmt.Errorf("failed to count active targets: %w", err)
	}

	totalExclusions, err := s.exclusionRepo.Count(ctx, exclusionFilter)
	if err != nil {
		return nil, fmt.Errorf("failed to count exclusions: %w", err)
	}

	activeExclusionFilter := scopedom.ExclusionFilter{
		TenantID: &tenantID,
		Statuses: []scopedom.Status{scopedom.StatusActive},
	}
	activeExclusions, err := s.exclusionRepo.Count(ctx, activeExclusionFilter)
	if err != nil {
		return nil, fmt.Errorf("failed to count active exclusions: %w", err)
	}

	totalSchedules, err := s.scheduleRepo.Count(ctx, scheduleFilter)
	if err != nil {
		return nil, fmt.Errorf("failed to count schedules: %w", err)
	}

	enabled := true
	enabledScheduleFilter := scopedom.ScheduleFilter{
		TenantID: &tenantID,
		Enabled:  &enabled,
	}
	enabledSchedules, err := s.scheduleRepo.Count(ctx, enabledScheduleFilter)
	if err != nil {
		return nil, fmt.Errorf("failed to count enabled schedules: %w", err)
	}

	// Calculate real coverage: (assets in scope / total assets) * 100
	coverage, err := s.calculateCoverage(ctx, tenantID)
	if err != nil {
		s.logger.Warn("failed to calculate coverage, using 0", "error", err)
		coverage = 0
	}

	return &scopedom.Stats{
		TotalTargets:     totalTargets,
		ActiveTargets:    activeTargets,
		TotalExclusions:  totalExclusions,
		ActiveExclusions: activeExclusions,
		TotalSchedules:   totalSchedules,
		EnabledSchedules: enabledSchedules,
		Coverage:         coverage,
	}, nil
}

// calculateCoverage calculates the percentage of discovered assets that are covered by scope targets.
// Formula: (assets matching active scope targets / total active assets) * 100
func (s *Service) calculateCoverage(ctx context.Context, tenantID string) (float64, error) {
	parsedTenantID, err := shared.IDFromString(tenantID)
	if err != nil {
		return 0, fmt.Errorf("invalid tenant id: %w", err)
	}

	// Get total count of active assets for this tenant
	assetFilter := asset.Filter{
		TenantID: &tenantID,
		Statuses: []asset.Status{asset.StatusActive},
	}
	totalAssets, err := s.assetRepo.Count(ctx, assetFilter)
	if err != nil {
		return 0, fmt.Errorf("failed to count assets: %w", err)
	}

	// If no assets, coverage is 0%
	if totalAssets == 0 {
		return 0, nil
	}

	// Get all active scope targets for this tenant
	targets, err := s.targetRepo.ListActive(ctx, parsedTenantID)
	if err != nil {
		return 0, fmt.Errorf("failed to list active targets: %w", err)
	}

	// If no active targets, coverage is 0%
	if len(targets) == 0 {
		return 0, nil
	}

	// Get active exclusions for this tenant
	exclusions, err := s.exclusionRepo.ListActive(ctx, parsedTenantID)
	if err != nil {
		return 0, fmt.Errorf("failed to list active exclusions: %w", err)
	}

	// Count assets in scope using pagination
	assetsInScope, err := s.countAssetsInScope(ctx, assetFilter, targets, exclusions)
	if err != nil {
		return 0, err
	}

	// Calculate coverage percentage (rounded to 2 decimal places)
	coverage := (float64(assetsInScope) / float64(totalAssets)) * 100
	coverage = math.Round(coverage*100) / 100
	return coverage, nil
}

// countAssetsInScope counts assets that are in scope and not excluded.
func (s *Service) countAssetsInScope(
	ctx context.Context,
	assetFilter asset.Filter,
	targets []*scopedom.Target,
	exclusions []*scopedom.Exclusion,
) (int64, error) {
	var assetsInScope int64
	pageSize := 100
	page := 1

	for {
		pager := pagination.New(page, pageSize)
		result, err := s.assetRepo.List(ctx, assetFilter, asset.NewListOptions(), pager)
		if err != nil {
			return 0, fmt.Errorf("failed to list assets: %w", err)
		}

		for _, a := range result.Data {
			if s.checkAssetCoverage(a, targets, exclusions) {
				assetsInScope++
			}
		}

		// Check if we've processed all assets
		if int64(page*pageSize) >= result.Total {
			break
		}
		page++
	}

	return assetsInScope, nil
}

// checkAssetCoverage checks if an asset is in scope and not excluded.
func (s *Service) checkAssetCoverage(
	a *asset.Asset,
	targets []*scopedom.Target,
	exclusions []*scopedom.Exclusion,
) bool {
	assetValues := s.getAssetValues(a)

	if !s.isAssetInScope(assetValues, targets) {
		return false
	}

	return !s.isAssetExcluded(assetValues, exclusions)
}

// getAssetValues returns all values to check for an asset (name, URLs, etc).
func (s *Service) getAssetValues(a *asset.Asset) []string {
	values := []string{a.Name()}

	// Add additional values based on asset type
	if a.Type() != asset.AssetTypeRepository {
		return values
	}

	props := a.Properties()
	if props == nil {
		return values
	}

	// Add repository-specific properties
	for _, key := range []string{"full_name", "web_url", "clone_url"} {
		if val, ok := props[key].(string); ok && val != "" {
			values = append(values, val)
		}
	}

	return values
}

// isAssetInScope checks if any asset value matches any scope target.
func (s *Service) isAssetInScope(assetValues []string, targets []*scopedom.Target) bool {
	for _, assetValue := range assetValues {
		for _, target := range targets {
			if scopedom.MatchesPattern(target.TargetType(), target.Pattern(), assetValue) {
				return true
			}
		}
	}
	return false
}

// isAssetExcluded checks if any asset value matches any exclusion.
func (s *Service) isAssetExcluded(assetValues []string, exclusions []*scopedom.Exclusion) bool {
	for _, av := range assetValues {
		for _, exclusion := range exclusions {
			if scopedom.MatchesExclusionPattern(exclusion.ExclusionType(), exclusion.Pattern(), av) {
				return true
			}
		}
	}
	return false
}

// CheckScope checks if an asset value is in scope.
func (s *Service) CheckScope(ctx context.Context, tenantID string, assetType string, value string) (*scopedom.MatchResult, error) {
	parsedTenantID, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}

	// Get active targets
	targets, err := s.targetRepo.ListActive(ctx, parsedTenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to list active targets: %w", err)
	}

	// Get active exclusions
	exclusions, err := s.exclusionRepo.ListActive(ctx, parsedTenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to list active exclusions: %w", err)
	}

	result := &scopedom.MatchResult{
		InScope:             false,
		Excluded:            false,
		MatchedTargetIDs:    []shared.ID{},
		MatchedExclusionIDs: []shared.ID{},
	}

	// Check targets
	for _, target := range targets {
		if target.Matches(value) {
			result.InScope = true
			result.MatchedTargetIDs = append(result.MatchedTargetIDs, target.ID())
		}
	}

	// Check exclusions only if in scope
	if result.InScope {
		for _, exclusion := range exclusions {
			if exclusion.Matches(value) {
				result.Excluded = true
				result.MatchedExclusionIDs = append(result.MatchedExclusionIDs, exclusion.ID())
			}
		}
	}

	return result, nil
}

// =============================================================================
// Pattern Conflict Detection
// =============================================================================

// CheckPatternOverlaps checks if a new target pattern overlaps with existing patterns.
// Returns a list of warning messages describing the overlaps (non-blocking).
func (s *Service) CheckPatternOverlaps(ctx context.Context, tenantID string, targetType string, pattern string) ([]string, error) {
	parsedTenantID, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}

	parsedTargetType, err := scopedom.ParseTargetType(targetType)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", shared.ErrValidation, err)
	}

	// Get all active targets for this tenant
	activeTargets, err := s.targetRepo.ListActive(ctx, parsedTenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to list active targets: %w", err)
	}

	warnings := make([]string, 0)

	for _, existing := range activeTargets {
		if existing.TargetType() != parsedTargetType {
			continue
		}

		if existing.Pattern() == pattern {
			continue // Exact duplicate handled by ExistsByPattern check
		}

		// Check bidirectional: does the new pattern match the existing one, or vice versa?
		newMatchesExisting := scopedom.MatchesPattern(parsedTargetType, pattern, existing.Pattern())
		existingMatchesNew := scopedom.MatchesPattern(parsedTargetType, existing.Pattern(), pattern)

		switch {
		case newMatchesExisting && existingMatchesNew:
			warnings = append(warnings, fmt.Sprintf("Pattern %q is equivalent to existing pattern %q", pattern, existing.Pattern()))
		case newMatchesExisting:
			warnings = append(warnings, fmt.Sprintf("Pattern %q is a superset of existing pattern %q", pattern, existing.Pattern()))
		case existingMatchesNew:
			warnings = append(warnings, fmt.Sprintf("Pattern %q is a subset of existing pattern %q", pattern, existing.Pattern()))
		}
	}

	return warnings, nil
}
