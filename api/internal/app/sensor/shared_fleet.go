package sensor

// The console's view of the shared sensor fleet
// (docs/rfcs/RFC-100-shared-sensors.md §12): the instance sensors with their
// state, queue aggregates per tool lane, per-organization usage counts and
// job metadata, plus the remote actions an administrator takes on one shared
// sensor (pause, resume, retire).
//
// Threat model: the console is the instance operator's plane, and shared
// sensors run every organization's jobs. Administrators see aggregates and
// job metadata freely (which organization, which tool, which state, when),
// never a job's payload, result, error text or findings. A job's targets and
// logs are tenant data: they are shown only through JobDetails, which needs
// a reason and writes a high admin audit row before anything is returned
// (no row, no data). Remote actions change what runs on shared
// infrastructure, so the routes need a super admin, a fresh authenticator
// code and a reason, and each writes a critical admin audit row. Every
// write is guarded in SQL by scope = 'instance', so an organization's sensor
// can never be paused, resumed or retired from here.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/openctemio/openctem/api/internal/app/commandlog"
	"github.com/openctemio/openctem/api/pkg/domain/admin"
	"github.com/openctemio/openctem/api/pkg/domain/command"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/pagination"
)

// Admin audit actions of the shared sensor fleet.
const (
	ActionSharedSensorPaused    = "shared_sensor.paused"
	ActionSharedSensorResumed   = "shared_sensor.resumed"
	ActionSharedSensorRetired   = "shared_sensor.retired"
	ActionSharedSensorJobViewed = "shared_sensor.job_viewed"
)

var sharedJobStatuses = map[command.CommandStatus]bool{
	command.CommandStatusPending: true, command.CommandStatusAcknowledged: true, command.CommandStatusRunning: true,
	command.CommandStatusCompleted: true, command.CommandStatusFailed: true, command.CommandStatusCanceled: true,
	command.CommandStatusExpired: true,
}

// SharedJobLogLines caps the log lines the audited job view returns.
const SharedJobLogLines = 500

// ErrSharedSensorRetired refuses an action on a retired shared sensor.
var ErrSharedSensorRetired = fmt.Errorf("%w: the shared sensor is retired", shared.ErrConflict)

// SharedFleetSensor is one instance sensor as the console lists it.
type SharedFleetSensor struct {
	ID          shared.ID
	Name        string
	Region      string
	Status      string
	Health      string
	Version     string
	Tools       []string
	CurrentJobs int
	MaxJobs     int
	LastSeenAt  *time.Time
	CreatedAt   time.Time
}

// SharedLane is the queue of one tool lane.
type SharedLane struct {
	Tool    string
	Queued  int
	Running int
}

// SharedOrgUsage counts one organization's shared jobs.
type SharedOrgUsage struct {
	TenantID   shared.ID
	TenantName string
	Queued     int
	Running    int
	Completed  int // in the last 24 hours
	Failed     int // in the last 24 hours
}

// SharedQueue is the queue aggregates of the fleet.
type SharedQueue struct {
	Lanes         []SharedLane
	Organizations []SharedOrgUsage
}

// SharedJobFilter narrows the job metadata list.
type SharedJobFilter struct {
	SensorID *shared.ID
	TenantID *shared.ID
	Status   string
}

// SharedJob is the metadata of one shared job: never its payload, targets,
// result or error text.
type SharedJob struct {
	ID          shared.ID
	TenantID    shared.ID
	TenantName  string
	Type        string
	Tool        string
	Status      string
	SensorID    *shared.ID
	SensorName  string
	CreatedAt   time.Time
	StartedAt   *time.Time
	CompletedAt *time.Time
}

// SharedJobDetail is what the audited view shows: the job, its targets and
// its logs. Never its result or findings.
type SharedJobDetail struct {
	Job          SharedJob
	Targets      []string
	Logs         []commandlog.Line
	LogsTruncate bool
}

// SharedFleetStore reads and changes the fleet (the postgres repository).
type SharedFleetStore interface {
	ListSharedSensors(ctx context.Context) ([]SharedFleetSensor, error)
	SharedQueue(ctx context.Context) (SharedQueue, error)
	ListSharedJobs(ctx context.Context, f SharedJobFilter, page pagination.Pagination) (pagination.Result[SharedJob], error)
	// GetSharedJob returns the job's metadata and payload;
	// shared.ErrNotFound unless it is a shared job.
	GetSharedJob(ctx context.Context, id shared.ID) (SharedJob, json.RawMessage, error)
	// SetSharedSensorStatus sets an instance sensor's status unless it is
	// retired; shared.ErrNotFound for anything that is not an instance
	// sensor, ErrSharedSensorRetired for a retired one. It returns the name.
	SetSharedSensorStatus(ctx context.Context, id shared.ID, status, message string) (string, error)
}

// SharedJobLogs reads a job's logs within its own organization.
type SharedJobLogs interface {
	ListForCommand(ctx context.Context, tenantID, commandID shared.ID, maxLines int) (commandlog.Page, error)
}

// SharedFleetAudit writes admin audit rows.
type SharedFleetAudit interface {
	Create(ctx context.Context, l *admin.AuditLog) error
}

// SharedFleetService is the console's shared sensor fleet.
type SharedFleetService struct {
	store SharedFleetStore
	logs  SharedJobLogs
	audit SharedFleetAudit
	log   *logger.Logger
}

// NewSharedFleetService builds the service. Without an audit repository the
// audited job view and the remote actions are refused (fail closed).
func NewSharedFleetService(store SharedFleetStore, logs SharedJobLogs, audit SharedFleetAudit, log *logger.Logger) *SharedFleetService {
	return &SharedFleetService{store: store, logs: logs, audit: audit, log: log.With("service", "shared_fleet")}
}

// AdminChange is who acts and why.
type AdminChange struct {
	Actor     *admin.AdminUser
	Reason    string
	IP        string
	UserAgent string
}

func (c AdminChange) check() error {
	if c.Actor == nil {
		return fmt.Errorf("%w: an administrator acts on shared sensors", shared.ErrForbidden)
	}
	if r := strings.TrimSpace(c.Reason); r == "" || len(c.Reason) > 1000 {
		return fmt.Errorf("%w: a reason (at most 1000 characters) is required", shared.ErrValidation)
	}
	return nil
}

// List returns every instance sensor.
func (s *SharedFleetService) List(ctx context.Context) ([]SharedFleetSensor, error) {
	return s.store.ListSharedSensors(ctx)
}

// Queue returns the queue aggregates.
func (s *SharedFleetService) Queue(ctx context.Context) (SharedQueue, error) {
	return s.store.SharedQueue(ctx)
}

// Jobs returns job metadata.
func (s *SharedFleetService) Jobs(ctx context.Context, f SharedJobFilter, page pagination.Pagination) (pagination.Result[SharedJob], error) {
	if f.Status != "" && !sharedJobStatuses[command.CommandStatus(f.Status)] {
		return pagination.Result[SharedJob]{}, fmt.Errorf("%w: unknown status", shared.ErrValidation)
	}
	return s.store.ListSharedJobs(ctx, f, page)
}

// JobDetails returns a job's targets and logs after writing the audit row
// that names the administrator, the organization and the reason. The caller
// checked the role.
func (s *SharedFleetService) JobDetails(ctx context.Context, jobID shared.ID, c AdminChange) (*SharedJobDetail, error) {
	if err := c.check(); err != nil {
		return nil, err
	}
	job, payload, err := s.store.GetSharedJob(ctx, jobID)
	if err != nil {
		return nil, err
	}
	tid := job.TenantID
	if err := s.record(ctx, c, ActionSharedSensorJobViewed, "command", &jobID, job.Tool,
		map[string]any{"tenant_id": tid.String(), "reason": strings.TrimSpace(c.Reason)}, false); err != nil {
		return nil, err
	}
	out := &SharedJobDetail{Job: job, Targets: command.PayloadTargets(payload), Logs: []commandlog.Line{}}
	if out.Targets == nil {
		out.Targets = []string{}
	}
	if s.logs != nil {
		page, err := s.logs.ListForCommand(ctx, tid, jobID, SharedJobLogLines)
		if err != nil && !errors.Is(err, commandlog.ErrNotFound) {
			return nil, fmt.Errorf("read the job's logs: %w", err)
		}
		if page.Lines != nil {
			out.Logs = page.Lines
		}
		out.LogsTruncate = page.Truncated
	}
	return out, nil
}

// Pause stops a shared sensor from taking new jobs: its heartbeat answers
// pause; jobs it holds run to the end (drain). The caller checked the role
// and the step-up.
func (s *SharedFleetService) Pause(ctx context.Context, id shared.ID, c AdminChange) error {
	return s.setStatus(ctx, id, "disabled", "Paused by the instance administrator: "+strings.TrimSpace(c.Reason), ActionSharedSensorPaused, c)
}

// Resume lets a paused shared sensor take jobs again.
func (s *SharedFleetService) Resume(ctx context.Context, id shared.ID, c AdminChange) error {
	return s.setStatus(ctx, id, "active", "", ActionSharedSensorResumed, c)
}

// Retire revokes a shared sensor for good: its key no longer authenticates
// and it can never be resumed.
func (s *SharedFleetService) Retire(ctx context.Context, id shared.ID, c AdminChange) error {
	return s.setStatus(ctx, id, "revoked", "Retired by the instance administrator: "+strings.TrimSpace(c.Reason), ActionSharedSensorRetired, c)
}

func (s *SharedFleetService) setStatus(ctx context.Context, id shared.ID, status, message, action string, c AdminChange) error {
	if err := c.check(); err != nil {
		return err
	}
	if s.audit == nil {
		return errors.New("shared fleet: no admin audit log wired")
	}
	if len(message) > 500 {
		message = message[:500]
	}
	name, err := s.store.SetSharedSensorStatus(ctx, id, status, message)
	if err != nil {
		return err
	}
	s.log.Warn("shared sensor state changed", "alert", action, "admin_id", c.Actor.ID().String(), "sensor_id", id.String(), "status", status)
	if err := s.record(ctx, c, action, "sensor", &id, name, map[string]any{"status": status, "reason": strings.TrimSpace(c.Reason)}, true); err != nil {
		// The change is stored; the missing row is logged loudly.
		s.log.Error("write admin audit for a shared sensor action", "action", action, "error", err)
	}
	return nil
}

func (s *SharedFleetService) record(ctx context.Context, c AdminChange, action, resourceType string, id *shared.ID, name string, body map[string]any, critical bool) error {
	if s.audit == nil {
		return errors.New("shared fleet: no admin audit log wired")
	}
	b := admin.NewAuditLogBuilder(c.Actor, action).
		Resource(resourceType, id, name).
		Context(c.IP, c.UserAgent).
		Request("POST", "", body)
	if critical {
		b.Critical()
	} else {
		b.High()
	}
	actx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	if err := s.audit.Create(actx, b.Build()); err != nil {
		return fmt.Errorf("write admin audit: %w", err)
	}
	return nil
}
