package app

import (
	"context"
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/openctemio/api/pkg/domain/asset"
	"github.com/openctemio/api/pkg/domain/scope"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/logger"
	"github.com/openctemio/api/pkg/pagination"
)

// ScopeService handles scope configuration business operations.
type ScopeService struct {
	targetRepo    scope.TargetRepository
	exclusionRepo scope.ExclusionRepository
	scheduleRepo  scope.ScheduleRepository
	assetRepo     asset.Repository
	logger        *logger.Logger
}

// NewScopeService creates a new ScopeService.
func NewScopeService(
	targetRepo scope.TargetRepository,
	exclusionRepo scope.ExclusionRepository,
	scheduleRepo scope.ScheduleRepository,
	assetRepo asset.Repository,
	log *logger.Logger,
) *ScopeService {
	return &ScopeService{
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
func (s *ScopeService) CreateTarget(ctx context.Context, input CreateTargetInput) (*scope.Target, error) {
	s.logger.Info("creating scope target", "type", input.TargetType, "pattern", input.Pattern)

	tenantID, err := shared.IDFromString(input.TenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}

	targetType, err := scope.ParseTargetType(input.TargetType)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", shared.ErrValidation, err)
	}

	// Check if pattern already exists
	exists, err := s.targetRepo.ExistsByPattern(ctx, tenantID, targetType, input.Pattern)
	if err != nil {
		return nil, fmt.Errorf("failed to check target existence: %w", err)
	}
	if exists {
		return nil, scope.ErrTargetAlreadyExists
	}

	target, err := scope.NewTarget(tenantID, targetType, input.Pattern, input.Description, input.CreatedBy)
	if err != nil {
		return nil, err
	}

	// Apply optional settings
	if input.Priority > 0 {
		target.UpdatePriority(input.Priority)
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

// GetTarget retrieves a scope target by ID.
func (s *ScopeService) GetTarget(ctx context.Context, targetID string) (*scope.Target, error) {
	parsedID, err := shared.IDFromString(targetID)
	if err != nil {
		return nil, shared.ErrNotFound
	}
	return s.targetRepo.GetByID(ctx, parsedID)
}

// UpdateTargetInput represents the input for updating a scope target.
type UpdateTargetInput struct {
	Description *string  `validate:"omitempty,max=1000"`
	Priority    *int     `validate:"omitempty,min=0,max=100"`
	Tags        []string `validate:"omitempty,max=20,dive,max=50"`
}

// UpdateTarget updates an existing scope target.
func (s *ScopeService) UpdateTarget(ctx context.Context, targetID string, tenantID string, input UpdateTargetInput) (*scope.Target, error) {
	parsedID, err := shared.IDFromString(targetID)
	if err != nil {
		return nil, shared.ErrNotFound
	}

	target, err := s.targetRepo.GetByID(ctx, parsedID)
	if err != nil {
		return nil, err
	}

	// Verify tenant ownership
	if tenantID != "" {
		parsedTenantID, err := shared.IDFromString(tenantID)
		if err != nil {
			return nil, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
		}
		if target.TenantID() != parsedTenantID {
			return nil, shared.ErrNotFound
		}
	}

	if input.Description != nil {
		target.UpdateDescription(*input.Description)
	}
	if input.Priority != nil {
		target.UpdatePriority(*input.Priority)
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

// DeleteTarget deletes a scope target by ID.
func (s *ScopeService) DeleteTarget(ctx context.Context, targetID string, tenantID string) error {
	parsedID, err := shared.IDFromString(targetID)
	if err != nil {
		return shared.ErrNotFound
	}

	// Verify tenant ownership
	if tenantID != "" {
		target, err := s.targetRepo.GetByID(ctx, parsedID)
		if err != nil {
			return err
		}
		parsedTenantID, err := shared.IDFromString(tenantID)
		if err != nil {
			return fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
		}
		if target.TenantID() != parsedTenantID {
			return shared.ErrNotFound
		}
	}

	if err := s.targetRepo.Delete(ctx, parsedID); err != nil {
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
func (s *ScopeService) ListTargets(ctx context.Context, input ListTargetsInput) (pagination.Result[*scope.Target], error) {
	filter := scope.TargetFilter{}

	if input.TenantID != "" {
		filter.TenantID = &input.TenantID
	}

	if len(input.TargetTypes) > 0 {
		types := make([]scope.TargetType, 0, len(input.TargetTypes))
		for _, t := range input.TargetTypes {
			if parsed, err := scope.ParseTargetType(t); err == nil {
				types = append(types, parsed)
			}
		}
		filter.TargetTypes = types
	}

	if len(input.Statuses) > 0 {
		statuses := make([]scope.Status, 0, len(input.Statuses))
		for _, st := range input.Statuses {
			statuses = append(statuses, scope.Status(st))
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
func (s *ScopeService) ListActiveTargets(ctx context.Context, tenantID string) ([]*scope.Target, error) {
	parsedID, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}
	return s.targetRepo.ListActive(ctx, parsedID)
}

// ActivateTarget activates a scope target.
func (s *ScopeService) ActivateTarget(ctx context.Context, targetID string) (*scope.Target, error) {
	parsedID, err := shared.IDFromString(targetID)
	if err != nil {
		return nil, shared.ErrNotFound
	}

	target, err := s.targetRepo.GetByID(ctx, parsedID)
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
func (s *ScopeService) DeactivateTarget(ctx context.Context, targetID string) (*scope.Target, error) {
	parsedID, err := shared.IDFromString(targetID)
	if err != nil {
		return nil, shared.ErrNotFound
	}

	target, err := s.targetRepo.GetByID(ctx, parsedID)
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
func (s *ScopeService) CreateExclusion(ctx context.Context, input CreateExclusionInput) (*scope.Exclusion, error) {
	s.logger.Info("creating scope exclusion", "type", input.ExclusionType, "pattern", input.Pattern)

	tenantID, err := shared.IDFromString(input.TenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}

	exclusionType, err := scope.ParseExclusionType(input.ExclusionType)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", shared.ErrValidation, err)
	}

	exclusion, err := scope.NewExclusion(tenantID, exclusionType, input.Pattern, input.Reason, input.ExpiresAt, input.CreatedBy)
	if err != nil {
		return nil, err
	}

	if err := s.exclusionRepo.Create(ctx, exclusion); err != nil {
		return nil, fmt.Errorf("failed to create scope exclusion: %w", err)
	}

	s.logger.Info("scope exclusion created", "id", exclusion.ID().String(), "pattern", input.Pattern)
	return exclusion, nil
}

// GetExclusion retrieves a scope exclusion by ID.
func (s *ScopeService) GetExclusion(ctx context.Context, exclusionID string) (*scope.Exclusion, error) {
	parsedID, err := shared.IDFromString(exclusionID)
	if err != nil {
		return nil, shared.ErrNotFound
	}
	return s.exclusionRepo.GetByID(ctx, parsedID)
}

// UpdateExclusionInput represents the input for updating a scope exclusion.
type UpdateExclusionInput struct {
	Reason    *string    `validate:"omitempty,max=1000"`
	ExpiresAt *time.Time `validate:"omitempty"`
}

// UpdateExclusion updates an existing scope exclusion.
func (s *ScopeService) UpdateExclusion(ctx context.Context, exclusionID string, tenantID string, input UpdateExclusionInput) (*scope.Exclusion, error) {
	parsedID, err := shared.IDFromString(exclusionID)
	if err != nil {
		return nil, shared.ErrNotFound
	}

	exclusion, err := s.exclusionRepo.GetByID(ctx, parsedID)
	if err != nil {
		return nil, err
	}

	// Verify tenant ownership
	if tenantID != "" {
		parsedTenantID, err := shared.IDFromString(tenantID)
		if err != nil {
			return nil, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
		}
		if exclusion.TenantID() != parsedTenantID {
			return nil, shared.ErrNotFound
		}
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

// DeleteExclusion deletes a scope exclusion by ID.
func (s *ScopeService) DeleteExclusion(ctx context.Context, exclusionID string, tenantID string) error {
	parsedID, err := shared.IDFromString(exclusionID)
	if err != nil {
		return shared.ErrNotFound
	}

	// Verify tenant ownership
	if tenantID != "" {
		exclusion, err := s.exclusionRepo.GetByID(ctx, parsedID)
		if err != nil {
			return err
		}
		parsedTenantID, err := shared.IDFromString(tenantID)
		if err != nil {
			return fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
		}
		if exclusion.TenantID() != parsedTenantID {
			return shared.ErrNotFound
		}
	}

	if err := s.exclusionRepo.Delete(ctx, parsedID); err != nil {
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
func (s *ScopeService) ListExclusions(ctx context.Context, input ListExclusionsInput) (pagination.Result[*scope.Exclusion], error) {
	filter := scope.ExclusionFilter{}

	if input.TenantID != "" {
		filter.TenantID = &input.TenantID
	}

	if len(input.ExclusionTypes) > 0 {
		types := make([]scope.ExclusionType, 0, len(input.ExclusionTypes))
		for _, t := range input.ExclusionTypes {
			if parsed, err := scope.ParseExclusionType(t); err == nil {
				types = append(types, parsed)
			}
		}
		filter.ExclusionTypes = types
	}

	if len(input.Statuses) > 0 {
		statuses := make([]scope.Status, 0, len(input.Statuses))
		for _, st := range input.Statuses {
			statuses = append(statuses, scope.Status(st))
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
func (s *ScopeService) ListActiveExclusions(ctx context.Context, tenantID string) ([]*scope.Exclusion, error) {
	parsedID, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}
	return s.exclusionRepo.ListActive(ctx, parsedID)
}

// ApproveExclusion approves a scope exclusion.
func (s *ScopeService) ApproveExclusion(ctx context.Context, exclusionID string, approvedBy string) (*scope.Exclusion, error) {
	parsedID, err := shared.IDFromString(exclusionID)
	if err != nil {
		return nil, shared.ErrNotFound
	}

	exclusion, err := s.exclusionRepo.GetByID(ctx, parsedID)
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
func (s *ScopeService) ActivateExclusion(ctx context.Context, exclusionID string) (*scope.Exclusion, error) {
	parsedID, err := shared.IDFromString(exclusionID)
	if err != nil {
		return nil, shared.ErrNotFound
	}

	exclusion, err := s.exclusionRepo.GetByID(ctx, parsedID)
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
func (s *ScopeService) DeactivateExclusion(ctx context.Context, exclusionID string) (*scope.Exclusion, error) {
	parsedID, err := shared.IDFromString(exclusionID)
	if err != nil {
		return nil, shared.ErrNotFound
	}

	exclusion, err := s.exclusionRepo.GetByID(ctx, parsedID)
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
func (s *ScopeService) ExpireOldExclusions(ctx context.Context) error {
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
func (s *ScopeService) CreateSchedule(ctx context.Context, input CreateScheduleInput) (*scope.Schedule, error) {
	s.logger.Info("creating scan schedule", "name", input.Name, "type", input.ScheduleType)

	tenantID, err := shared.IDFromString(input.TenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}

	scanType, err := scope.ParseScanType(input.ScanType)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", shared.ErrValidation, err)
	}

	scheduleType := scope.ScheduleType(input.ScheduleType)
	if !scheduleType.IsValid() {
		return nil, fmt.Errorf("%w: invalid schedule type", shared.ErrValidation)
	}

	schedule, err := scope.NewSchedule(tenantID, input.Name, scanType, scheduleType, input.CreatedBy)
	if err != nil {
		return nil, err
	}

	// Apply optional settings
	if input.Description != "" {
		schedule.UpdateDescription(input.Description)
	}

	// Set schedule timing
	if input.ScheduleType == string(scope.ScheduleTypeCron) && input.CronExpression != "" {
		schedule.SetCronSchedule(input.CronExpression)
	} else if input.ScheduleType == string(scope.ScheduleTypeInterval) && input.IntervalHours > 0 {
		schedule.SetIntervalSchedule(input.IntervalHours)
	}

	// Set target scope
	if input.TargetScope != "" {
		targetIDs := make([]shared.ID, 0, len(input.TargetIDs))
		for _, idStr := range input.TargetIDs {
			if id, err := shared.IDFromString(idStr); err == nil {
				targetIDs = append(targetIDs, id)
			}
		}
		schedule.SetTargetScope(scope.TargetScope(input.TargetScope), targetIDs, input.TargetTags)
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

// GetSchedule retrieves a scan schedule by ID.
func (s *ScopeService) GetSchedule(ctx context.Context, scheduleID string) (*scope.Schedule, error) {
	parsedID, err := shared.IDFromString(scheduleID)
	if err != nil {
		return nil, shared.ErrNotFound
	}
	return s.scheduleRepo.GetByID(ctx, parsedID)
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
func (s *ScopeService) UpdateSchedule(ctx context.Context, scheduleID string, tenantID string, input UpdateScheduleInput) (*scope.Schedule, error) {
	parsedID, err := shared.IDFromString(scheduleID)
	if err != nil {
		return nil, shared.ErrNotFound
	}

	schedule, err := s.scheduleRepo.GetByID(ctx, parsedID)
	if err != nil {
		return nil, err
	}

	// Verify tenant ownership
	if tenantID != "" {
		parsedTenantID, err := shared.IDFromString(tenantID)
		if err != nil {
			return nil, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
		}
		if schedule.TenantID() != parsedTenantID {
			return nil, shared.ErrNotFound
		}
	}

	if input.Name != nil {
		schedule.UpdateName(*input.Name)
	}
	if input.Description != nil {
		schedule.UpdateDescription(*input.Description)
	}

	// Update schedule timing
	if input.ScheduleType != nil {
		if *input.ScheduleType == string(scope.ScheduleTypeCron) && input.CronExpression != nil {
			schedule.SetCronSchedule(*input.CronExpression)
		} else if *input.ScheduleType == string(scope.ScheduleTypeInterval) && input.IntervalHours != nil {
			schedule.SetIntervalSchedule(*input.IntervalHours)
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
		schedule.SetTargetScope(scope.TargetScope(*input.TargetScope), targetIDs, input.TargetTags)
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

// DeleteSchedule deletes a scan schedule by ID.
func (s *ScopeService) DeleteSchedule(ctx context.Context, scheduleID string, tenantID string) error {
	parsedID, err := shared.IDFromString(scheduleID)
	if err != nil {
		return shared.ErrNotFound
	}

	// Verify tenant ownership
	if tenantID != "" {
		schedule, err := s.scheduleRepo.GetByID(ctx, parsedID)
		if err != nil {
			return err
		}
		parsedTenantID, err := shared.IDFromString(tenantID)
		if err != nil {
			return fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
		}
		if schedule.TenantID() != parsedTenantID {
			return shared.ErrNotFound
		}
	}

	if err := s.scheduleRepo.Delete(ctx, parsedID); err != nil {
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
func (s *ScopeService) ListSchedules(ctx context.Context, input ListSchedulesInput) (pagination.Result[*scope.Schedule], error) {
	filter := scope.ScheduleFilter{}

	if input.TenantID != "" {
		filter.TenantID = &input.TenantID
	}

	if len(input.ScanTypes) > 0 {
		types := make([]scope.ScanType, 0, len(input.ScanTypes))
		for _, t := range input.ScanTypes {
			if parsed, err := scope.ParseScanType(t); err == nil {
				types = append(types, parsed)
			}
		}
		filter.ScanTypes = types
	}

	if len(input.ScheduleTypes) > 0 {
		types := make([]scope.ScheduleType, 0, len(input.ScheduleTypes))
		for _, t := range input.ScheduleTypes {
			types = append(types, scope.ScheduleType(t))
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
func (s *ScopeService) ListDueSchedules(ctx context.Context) ([]*scope.Schedule, error) {
	return s.scheduleRepo.ListDue(ctx)
}

// EnableSchedule enables a scan schedule.
func (s *ScopeService) EnableSchedule(ctx context.Context, scheduleID string) (*scope.Schedule, error) {
	parsedID, err := shared.IDFromString(scheduleID)
	if err != nil {
		return nil, shared.ErrNotFound
	}

	schedule, err := s.scheduleRepo.GetByID(ctx, parsedID)
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
func (s *ScopeService) DisableSchedule(ctx context.Context, scheduleID string) (*scope.Schedule, error) {
	parsedID, err := shared.IDFromString(scheduleID)
	if err != nil {
		return nil, shared.ErrNotFound
	}

	schedule, err := s.scheduleRepo.GetByID(ctx, parsedID)
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

// RecordScheduleRun records a scan run for a schedule.
func (s *ScopeService) RecordScheduleRun(ctx context.Context, scheduleID string, status string, nextRunAt *time.Time) (*scope.Schedule, error) {
	parsedID, err := shared.IDFromString(scheduleID)
	if err != nil {
		return nil, shared.ErrNotFound
	}

	schedule, err := s.scheduleRepo.GetByID(ctx, parsedID)
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
func (s *ScopeService) GetStats(ctx context.Context, tenantID string) (*scope.Stats, error) {
	targetFilter := scope.TargetFilter{TenantID: &tenantID}
	exclusionFilter := scope.ExclusionFilter{TenantID: &tenantID}
	scheduleFilter := scope.ScheduleFilter{TenantID: &tenantID}

	totalTargets, err := s.targetRepo.Count(ctx, targetFilter)
	if err != nil {
		return nil, fmt.Errorf("failed to count targets: %w", err)
	}

	activeTargetFilter := scope.TargetFilter{
		TenantID: &tenantID,
		Statuses: []scope.Status{scope.StatusActive},
	}
	activeTargets, err := s.targetRepo.Count(ctx, activeTargetFilter)
	if err != nil {
		return nil, fmt.Errorf("failed to count active targets: %w", err)
	}

	totalExclusions, err := s.exclusionRepo.Count(ctx, exclusionFilter)
	if err != nil {
		return nil, fmt.Errorf("failed to count exclusions: %w", err)
	}

	activeExclusionFilter := scope.ExclusionFilter{
		TenantID: &tenantID,
		Statuses: []scope.Status{scope.StatusActive},
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
	enabledScheduleFilter := scope.ScheduleFilter{
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

	return &scope.Stats{
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
func (s *ScopeService) calculateCoverage(ctx context.Context, tenantID string) (float64, error) {
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
func (s *ScopeService) countAssetsInScope(
	ctx context.Context,
	assetFilter asset.Filter,
	targets []*scope.Target,
	exclusions []*scope.Exclusion,
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
func (s *ScopeService) checkAssetCoverage(
	a *asset.Asset,
	targets []*scope.Target,
	exclusions []*scope.Exclusion,
) bool {
	assetValues := s.getAssetValues(a)

	if !s.isAssetInScope(assetValues, targets) {
		return false
	}

	return !s.isAssetExcluded(assetValues, exclusions)
}

// getAssetValues returns all values to check for an asset (name, URLs, etc).
func (s *ScopeService) getAssetValues(a *asset.Asset) []string {
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
func (s *ScopeService) isAssetInScope(assetValues []string, targets []*scope.Target) bool {
	for _, assetValue := range assetValues {
		for _, target := range targets {
			if s.matchesPattern(assetValue, target.Pattern(), target.TargetType()) {
				return true
			}
		}
	}
	return false
}

// isAssetExcluded checks if any asset value matches any exclusion.
func (s *ScopeService) isAssetExcluded(assetValues []string, exclusions []*scope.Exclusion) bool {
	for _, av := range assetValues {
		for _, exclusion := range exclusions {
			if s.matchesPattern(av, exclusion.Pattern(), scope.TargetType(exclusion.ExclusionType())) {
				return true
			}
		}
	}
	return false
}

// matchesPattern checks if an asset value matches a scope pattern.
// Supports wildcard patterns (*.example.com) and CIDR notation.
func (s *ScopeService) matchesPattern(value, pattern string, targetType scope.TargetType) bool {
	value = strings.ToLower(value)
	pattern = strings.ToLower(pattern)

	// Handle different target types
	switch targetType {
	case scope.TargetTypeDomain, scope.TargetTypeSubdomain:
		return s.matchDomainPattern(value, pattern)
	case scope.TargetTypeIPAddress, scope.TargetTypeIPRange:
		return s.matchIPPattern(value, pattern)
	case scope.TargetTypeRepository:
		return s.matchRepositoryPattern(value, pattern)
	default:
		// For other types, use simple wildcard matching
		return s.matchWildcard(value, pattern)
	}
}

// matchRepositoryPattern matches repository patterns
// Pattern formats: github.com/owner/repo, owner/repo, repo
// Asset name formats: repo, owner/repo
func (s *ScopeService) matchRepositoryPattern(value, pattern string) bool {
	// Exact match
	if value == pattern {
		return true
	}

	// Extract repo parts from pattern and value
	ownerRepo, repoName := s.parseRepoParts(pattern)
	valueOwnerRepo, valueRepoName := s.parseRepoParts(value)

	// Match owner/repo format
	if ownerRepo != "" && valueOwnerRepo != "" && ownerRepo == valueOwnerRepo {
		return true
	}

	// Match just repo name
	if repoName == valueRepoName {
		return true
	}

	// Check if pattern contains value (for partial matches)
	if strings.Contains(pattern, value) || strings.Contains(value, ownerRepo) {
		return true
	}

	return false
}

// parseRepoParts extracts owner/repo and repo name from a path.
// Handles formats: github.com/owner/repo, owner/repo, repo
func (s *ScopeService) parseRepoParts(path string) (ownerRepo, repoName string) {
	parts := strings.Split(path, "/")

	switch {
	case len(parts) >= 3:
		// Format: github.com/owner/repo or host/owner/repo
		ownerRepo = strings.Join(parts[1:], "/")
		repoName = parts[len(parts)-1]
	case len(parts) == 2:
		// Format: owner/repo
		ownerRepo = path
		repoName = parts[1]
	default:
		// Format: just repo name
		repoName = path
	}

	return ownerRepo, repoName
}

// matchDomainPattern matches domain patterns like *.example.com
func (s *ScopeService) matchDomainPattern(value, pattern string) bool {
	// Exact match
	if value == pattern {
		return true
	}

	// Wildcard match: *.example.com matches sub.example.com, a.b.example.com, etc.
	if strings.HasPrefix(pattern, "*.") {
		suffix := pattern[1:] // Remove the asterisk, keep the dot
		return strings.HasSuffix(value, suffix)
	}

	// Check if value is a subdomain of pattern
	if strings.HasSuffix(value, "."+pattern) {
		return true
	}

	return false
}

// matchIPPattern matches IP addresses and CIDR ranges
func (s *ScopeService) matchIPPattern(value, pattern string) bool {
	// Exact match
	if value == pattern {
		return true
	}

	// CIDR matching would require parsing IP addresses
	// For simplicity, we just check prefix for now
	// TODO: Implement proper CIDR matching with net.ParseCIDR
	if strings.Contains(pattern, "/") {
		// Extract network prefix (simplified)
		parts := strings.Split(pattern, "/")
		if len(parts) == 2 {
			networkPrefix := parts[0]
			// Check if value starts with same octets
			if strings.HasPrefix(value, strings.TrimSuffix(networkPrefix, ".0")) {
				return true
			}
		}
	}

	return false
}

// matchWildcard performs simple wildcard matching
func (s *ScopeService) matchWildcard(value, pattern string) bool {
	// Exact match
	if value == pattern {
		return true
	}

	// Simple wildcard: * at start or end
	if strings.HasPrefix(pattern, "*") {
		return strings.HasSuffix(value, pattern[1:])
	}
	if strings.HasSuffix(pattern, "*") {
		return strings.HasPrefix(value, pattern[:len(pattern)-1])
	}

	return false
}

// CheckScope checks if an asset value is in scope.
func (s *ScopeService) CheckScope(ctx context.Context, tenantID string, assetType string, value string) (*scope.MatchResult, error) {
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

	result := &scope.MatchResult{
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
