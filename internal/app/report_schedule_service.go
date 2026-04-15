package app

import (
	"context"
	"fmt"
	"time"

	"github.com/openctemio/api/pkg/domain/reportschedule"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/logger"
	"github.com/openctemio/api/pkg/pagination"
)

// ReportScheduleService handles report schedule business logic.
type ReportScheduleService struct {
	repo   reportschedule.Repository
	logger *logger.Logger
}

// NewReportScheduleService creates a new ReportScheduleService.
func NewReportScheduleService(repo reportschedule.Repository, log *logger.Logger) *ReportScheduleService {
	return &ReportScheduleService{
		repo:   repo,
		logger: log.With("service", "report-schedule"),
	}
}

// CreateReportScheduleInput holds input for creating a schedule.
type CreateReportScheduleInput struct {
	TenantID       string
	Name           string
	ReportType     string
	Format         string
	CronExpression string
	Timezone       string
	Recipients     []reportschedule.Recipient
	Options        map[string]any
	ActorID        string
}

// CreateSchedule creates a new report schedule.
func (s *ReportScheduleService) CreateSchedule(ctx context.Context, input CreateReportScheduleInput) (*reportschedule.ReportSchedule, error) {
	tenantID, err := shared.IDFromString(input.TenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant ID", shared.ErrValidation)
	}

	if input.Timezone != "" {
		if _, err := time.LoadLocation(input.Timezone); err != nil {
			return nil, fmt.Errorf("%w: invalid timezone: %s", shared.ErrValidation, input.Timezone)
		}
	}

	if err := reportschedule.ValidateRecipients(input.Recipients); err != nil {
		return nil, err
	}

	if len(input.Options) > 100 {
		return nil, fmt.Errorf("%w: max 100 options fields", shared.ErrValidation)
	}

	schedule, err := reportschedule.NewReportSchedule(tenantID, input.Name, input.ReportType, input.Format, input.CronExpression)
	if err != nil {
		return nil, err
	}

	if input.Timezone != "" {
		schedule.Update(input.Name, input.ReportType, input.Format, input.CronExpression, input.Timezone)
	}
	if len(input.Recipients) > 0 {
		schedule.SetRecipients(input.Recipients)
	}
	if len(input.Options) > 0 {
		schedule.SetOptions(input.Options)
	}
	if input.ActorID != "" {
		actorID, _ := shared.IDFromString(input.ActorID)
		schedule.SetCreatedBy(actorID)
	}

	if err := s.repo.Create(ctx, schedule); err != nil {
		return nil, fmt.Errorf("create schedule: %w", err)
	}

	s.logger.Info("report schedule created", "id", schedule.ID().String(), "name", input.Name)
	return schedule, nil
}

// ListSchedules returns schedules for a tenant.
func (s *ReportScheduleService) ListSchedules(ctx context.Context, tenantID string, page pagination.Pagination) (pagination.Result[*reportschedule.ReportSchedule], error) {
	tid, err := shared.IDFromString(tenantID)
	if err != nil {
		return pagination.Result[*reportschedule.ReportSchedule]{}, fmt.Errorf("%w: invalid tenant ID", shared.ErrValidation)
	}
	return s.repo.List(ctx, reportschedule.ScheduleFilter{TenantID: &tid}, page)
}

// GetSchedule retrieves a single schedule.
func (s *ReportScheduleService) GetSchedule(ctx context.Context, tenantID, scheduleID string) (*reportschedule.ReportSchedule, error) {
	tid, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant ID", shared.ErrValidation)
	}
	sid, err := shared.IDFromString(scheduleID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid schedule ID", shared.ErrValidation)
	}
	return s.repo.GetByID(ctx, tid, sid)
}

// DeleteSchedule removes a schedule.
func (s *ReportScheduleService) DeleteSchedule(ctx context.Context, tenantID, scheduleID string) error {
	tid, err := shared.IDFromString(tenantID)
	if err != nil {
		return fmt.Errorf("%w: invalid tenant ID", shared.ErrValidation)
	}
	sid, err := shared.IDFromString(scheduleID)
	if err != nil {
		return fmt.Errorf("%w: invalid schedule ID", shared.ErrValidation)
	}
	return s.repo.Delete(ctx, tid, sid)
}

// ToggleSchedule activates or deactivates a schedule.
func (s *ReportScheduleService) ToggleSchedule(ctx context.Context, tenantID, scheduleID string, active bool) error {
	tid, err := shared.IDFromString(tenantID)
	if err != nil {
		return fmt.Errorf("%w: invalid tenant ID", shared.ErrValidation)
	}
	sid, err := shared.IDFromString(scheduleID)
	if err != nil {
		return fmt.Errorf("%w: invalid schedule ID", shared.ErrValidation)
	}

	schedule, err := s.repo.GetByID(ctx, tid, sid)
	if err != nil {
		return err
	}

	if active {
		schedule.Activate()
	} else {
		schedule.Deactivate()
	}

	return s.repo.Update(ctx, schedule)
}
