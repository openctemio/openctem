// Package reportschedule provides domain models for recurring report generation.
package reportschedule

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/robfig/cron/v3"

	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/pagination"
)

// validReportTypes are the report types the scheduler can actually generate
// (mirrors ReportScheduler.supportsType). Anything else would persist and then
// be silently skipped at run time, so reject it at creation.
var validReportTypes = map[string]bool{
	"executive_summary": true,
	"summary":           true,
	"findings":          true,
}

// cronParser matches the parser the scheduler uses (5-field standard cron:
// minute hour dom month dow) so a schedule that validates here also parses at
// run time.
var cronParser = cron.NewParser(cron.Minute | cron.Hour | cron.Dom | cron.Month | cron.Dow)

// maxNameLen bounds the schedule display name to keep it a label, not a blob.
const maxNameLen = 200

// minCronInterval is the shortest firing interval a report schedule may have.
// The scan path runs cron through securityValidator.ValidateCronExpression, but
// that only checks format/injection — it does NOT bound the interval. Reports
// fan out to up to 50 recipients, so a sub-hourly cron (`* * * * *`) is an
// email-amplification vector; require at least one hour between fires.
const minCronInterval = time.Hour

// validateName enforces the shared name rules for create and update.
func validateName(name string) error {
	if name == "" {
		return fmt.Errorf("%w: name is required", shared.ErrValidation)
	}
	if len(name) > maxNameLen {
		return fmt.Errorf("%w: name exceeds %d characters", shared.ErrValidation, maxNameLen)
	}
	return nil
}

// validateCron parses the cron expression and rejects schedules that fire more
// often than minCronInterval. Sampling several consecutive fire times (rather
// than just the first gap) catches split schedules like `0 0,0/30 * * *`
// regardless of the current time.
func validateCron(expr string) error {
	if expr == "" {
		return fmt.Errorf("%w: cron expression is required", shared.ErrValidation)
	}
	if len(expr) > 200 {
		return fmt.Errorf("%w: cron expression too long", shared.ErrValidation)
	}
	sched, err := cronParser.Parse(expr)
	if err != nil {
		return fmt.Errorf("%w: invalid cron expression", shared.ErrValidation)
	}
	prev := sched.Next(time.Now())
	for i := 0; i < 4; i++ {
		next := sched.Next(prev)
		if next.Sub(prev) < minCronInterval {
			return fmt.Errorf("%w: schedule must not fire more than once per hour", shared.ErrValidation)
		}
		prev = next
	}
	return nil
}

// ReportSchedule represents a recurring report delivery configuration.
type ReportSchedule struct {
	id              shared.ID
	tenantID        shared.ID
	name            string
	reportType      string
	format          string
	options         map[string]any
	recipients      []Recipient
	deliveryChannel string
	integrationID   *shared.ID
	cronExpression  string
	timezone        string
	isActive        bool
	lastRunAt       *time.Time
	lastStatus      string
	nextRunAt       *time.Time
	runCount        int
	createdBy       *shared.ID
	createdAt       time.Time
	updatedAt       time.Time
}

// Recipient represents a report delivery target.
type Recipient struct {
	Email string `json:"email"`
	Name  string `json:"name"`
}

// NewReportSchedule creates a new schedule.
func NewReportSchedule(tenantID shared.ID, name, reportType, format, cron string) (*ReportSchedule, error) {
	if err := validateName(name); err != nil {
		return nil, err
	}
	if err := validateCron(cron); err != nil {
		return nil, err
	}
	if reportType == "" {
		return nil, fmt.Errorf("%w: report type is required", shared.ErrValidation)
	}
	if !validReportTypes[strings.ToLower(strings.TrimSpace(reportType))] {
		return nil, fmt.Errorf("%w: unsupported report type %q", shared.ErrValidation, reportType)
	}
	if format == "" {
		return nil, fmt.Errorf("%w: format is required", shared.ErrValidation)
	}
	now := time.Now()
	return &ReportSchedule{
		id:              shared.NewID(),
		tenantID:        tenantID,
		name:            name,
		reportType:      reportType,
		format:          format,
		options:         map[string]any{},
		recipients:      []Recipient{},
		deliveryChannel: "email",
		cronExpression:  cron,
		timezone:        "UTC",
		isActive:        true,
		createdAt:       now,
		updatedAt:       now,
	}, nil
}

// ReconstituteReportSchedule creates from persisted data.
func ReconstituteReportSchedule(
	id, tenantID shared.ID,
	name, reportType, format string,
	options map[string]any,
	recipients []Recipient,
	deliveryChannel string,
	integrationID *shared.ID,
	cronExpression, timezone string,
	isActive bool,
	lastRunAt, nextRunAt *time.Time,
	lastStatus string,
	runCount int,
	createdBy *shared.ID,
	createdAt, updatedAt time.Time,
) *ReportSchedule {
	return &ReportSchedule{
		id: id, tenantID: tenantID,
		name: name, reportType: reportType, format: format,
		options: options, recipients: recipients,
		deliveryChannel: deliveryChannel, integrationID: integrationID,
		cronExpression: cronExpression, timezone: timezone,
		isActive:  isActive,
		lastRunAt: lastRunAt, nextRunAt: nextRunAt,
		lastStatus: lastStatus, runCount: runCount,
		createdBy: createdBy,
		createdAt: createdAt, updatedAt: updatedAt,
	}
}

// Getters
func (s *ReportSchedule) ID() shared.ID             { return s.id }
func (s *ReportSchedule) TenantID() shared.ID       { return s.tenantID }
func (s *ReportSchedule) Name() string              { return s.name }
func (s *ReportSchedule) ReportType() string        { return s.reportType }
func (s *ReportSchedule) Format() string            { return s.format }
func (s *ReportSchedule) Options() map[string]any   { return s.options }
func (s *ReportSchedule) Recipients() []Recipient   { return s.recipients }
func (s *ReportSchedule) DeliveryChannel() string   { return s.deliveryChannel }
func (s *ReportSchedule) IntegrationID() *shared.ID { return s.integrationID }
func (s *ReportSchedule) CronExpression() string    { return s.cronExpression }
func (s *ReportSchedule) Timezone() string          { return s.timezone }
func (s *ReportSchedule) IsActive() bool            { return s.isActive }
func (s *ReportSchedule) LastRunAt() *time.Time     { return s.lastRunAt }
func (s *ReportSchedule) LastStatus() string        { return s.lastStatus }
func (s *ReportSchedule) NextRunAt() *time.Time     { return s.nextRunAt }
func (s *ReportSchedule) RunCount() int             { return s.runCount }
func (s *ReportSchedule) CreatedBy() *shared.ID     { return s.createdBy }
func (s *ReportSchedule) CreatedAt() time.Time      { return s.createdAt }
func (s *ReportSchedule) UpdatedAt() time.Time      { return s.updatedAt }

// Update sets mutable fields. Name (when provided) and cron are re-validated so
// the update path enforces the same bounds as create.
func (s *ReportSchedule) Update(name, reportType, format, cron, timezone string) error {
	if name != "" {
		if err := validateName(name); err != nil {
			return err
		}
		s.name = name
	}
	if err := validateCron(cron); err != nil {
		return err
	}
	s.reportType = reportType
	s.format = format
	s.cronExpression = cron
	if timezone != "" {
		s.timezone = timezone
	}
	s.updatedAt = time.Now()
	return nil
}

// SetOptions sets report generation options.
func (s *ReportSchedule) SetOptions(options map[string]any) {
	s.options = options
	s.updatedAt = time.Now()
}

// SetRecipients sets delivery recipients.
func (s *ReportSchedule) SetRecipients(recipients []Recipient) {
	s.recipients = recipients
	s.updatedAt = time.Now()
}

// SetDelivery sets delivery configuration.
func (s *ReportSchedule) SetDelivery(channel string, integrationID *shared.ID) {
	s.deliveryChannel = channel
	s.integrationID = integrationID
	s.updatedAt = time.Now()
}

// RecordRun updates after a scheduled run.
func (s *ReportSchedule) RecordRun(status string, nextRunAt *time.Time) {
	now := time.Now()
	s.lastRunAt = &now
	s.lastStatus = status
	s.nextRunAt = nextRunAt
	s.runCount++
	s.updatedAt = now
}

// Activate enables the schedule.
func (s *ReportSchedule) Activate() { s.isActive = true; s.updatedAt = time.Now() }

// Deactivate disables the schedule.
func (s *ReportSchedule) Deactivate() { s.isActive = false; s.updatedAt = time.Now() }

// ValidateRecipients validates a list of recipients.
func ValidateRecipients(recipients []Recipient) error {
	if len(recipients) > 50 {
		return fmt.Errorf("%w: max 50 recipients allowed", shared.ErrValidation)
	}
	for _, r := range recipients {
		if r.Email == "" {
			return fmt.Errorf("%w: recipient email is required", shared.ErrValidation)
		}
		if len(r.Email) > 254 {
			return fmt.Errorf("%w: recipient email too long", shared.ErrValidation)
		}
		// Basic email format check
		if !strings.Contains(r.Email, "@") || strings.ContainsAny(r.Email, " \n\r\t") {
			return fmt.Errorf("%w: invalid recipient email format", shared.ErrValidation)
		}
	}
	return nil
}

// SetCreatedBy sets the creator.
func (s *ReportSchedule) SetCreatedBy(userID shared.ID) { s.createdBy = &userID }

// ScheduleFilter defines criteria for listing schedules.
type ScheduleFilter struct {
	TenantID *shared.ID
	IsActive *bool
}

// Repository defines persistence for report schedules.
type Repository interface {
	Create(ctx context.Context, schedule *ReportSchedule) error
	GetByID(ctx context.Context, tenantID, id shared.ID) (*ReportSchedule, error)
	Update(ctx context.Context, schedule *ReportSchedule) error
	Delete(ctx context.Context, tenantID, id shared.ID) error
	List(ctx context.Context, filter ScheduleFilter, page pagination.Pagination) (pagination.Result[*ReportSchedule], error)
	ListDue(ctx context.Context, now time.Time) ([]*ReportSchedule, error)
}
