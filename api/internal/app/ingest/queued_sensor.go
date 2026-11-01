package ingest

// The async ingest worker re-reads the submitting sensor before it processes
// a queued report (RFC-040 §5.2, gap S2e). Design:
// docs/rfcs/RFC-040-platform-sensor-mutual-distrust.md.

import (
	"context"
	"errors"
	"fmt"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// DroppedJob is stored as the result of a queued job whose sensor may no
// longer submit work.
type DroppedJob struct {
	ReportID string `json:"report_id"`
	Dropped  bool   `json:"dropped"`
	Reason   string `json:"reason"`
}

// queuedSensorChecker is the slice of *Service the job processors use to
// re-check the sensor of a queued job.
type queuedSensorChecker interface {
	QueuedWorkSensor(ctx context.Context, tenantID shared.ID, sensorID, commandID *shared.ID, leaseEpoch *int, reportID string) (*sensor.Sensor, *DroppedJob, error)
}

// QueuedWorkSensor re-reads the sensor that submitted a queued job. It
// returns the sensor when it is still active. When the sensor was revoked,
// disabled or deleted after the job was accepted (or the job names none), it
// returns a DroppedJob instead and records the drop in the tenant's audit
// log: the work of a sensor taken out of service is never processed. A
// lookup error is returned so the worker retries the job.
//
// A shared sensor (scope instance) is not one of the tenant's sensors: its
// work is processed only when the report is bound to a shared job of this
// tenant that the sensor still holds (sharedHolder); the tenant is the
// command's, set when the report was accepted.
//
// A report bound to a command (commandID) is processed only while the
// sensor still holds that command, and, when the report recorded it
// (leaseEpoch), under the lease epoch it was accepted under: a report of a
// run the platform took back and handed out again (to another sensor, or to
// this one as a new run) is dropped, so it never binds to the new run.
func (s *Service) QueuedWorkSensor(ctx context.Context, tenantID shared.ID, sensorID, commandID *shared.ID, leaseEpoch *int, reportID string) (*sensor.Sensor, *DroppedJob, error) {
	if s.sensorRepo == nil {
		return nil, nil, errors.New("ingest worker: no sensor repository to re-check the sensor")
	}
	var reason string
	var agt *sensor.Sensor
	if sensorID == nil || sensorID.IsZero() {
		reason = "the job names no sensor"
	} else {
		stored, err := s.sensorRepo.GetByTenantAndID(ctx, tenantID, *sensorID)
		if errors.Is(err, shared.ErrNotFound) {
			stored, reason, err = s.sharedHolder(ctx, tenantID, *sensorID, commandID, leaseEpoch)
		}
		switch {
		case reason != "":
		case errors.Is(err, shared.ErrNotFound):
			reason = "the sensor no longer exists"
		case err != nil:
			return nil, nil, fmt.Errorf("ingest worker: re-read sensor: %w", err)
		case stored == nil:
			reason = "the sensor no longer exists"
		case stored.Status == sensor.SensorStatusRevoked:
			reason = "the sensor was revoked"
		case !stored.Status.CanAuthenticate():
			reason = "the sensor is " + string(stored.Status)
		case !stored.IsShared():
			// An organization sensor's bound report: still its run?
			if reason, err = s.heldRun(ctx, tenantID, *sensorID, commandID, leaseEpoch); err != nil {
				return nil, nil, err
			}
			if reason == "" {
				agt = stored
			}
		default:
			agt = stored
		}
	}
	if agt != nil {
		return agt, nil, nil
	}

	s.logger.Warn("ingest worker: dropped queued report",
		"tenant_id", tenantID.String(), "sensor_id", idString(sensorID),
		"report_id", sanitizeIngestLogField(reportID), "reason", reason)
	s.auditDroppedJob(ctx, tenantID, sensorID, reportID, reason)
	return nil, &DroppedJob{ReportID: reportID, Dropped: true, Reason: reason}, nil
}

// reasonSharedNotHeld: a queued report of a shared sensor that does not
// hold the report's shared job (or names none).
const reasonSharedNotHeld = "a shared sensor reports only for a job it holds"

// Why a queued report of an organization sensor's run is dropped.
const (
	reasonCommandGone    = "the command no longer exists"
	reasonRunTakenBack   = "the command was taken back from the sensor and handed out again"
	reasonRunNotHeldNow  = "the sensor no longer holds the command"
	errQueuedCommandRead = "ingest worker: re-read command"
)

// heldRun re-checks the command a queued organization-sensor report is
// bound to: it still exists in the tenant, sensorID still holds it, and its
// lease epoch is the one the report was accepted under (when recorded).
// Returns the reason to drop the report, or "" to process it. A report with
// no command (unsolicited) or a worker without a command reader is not
// checked here.
func (s *Service) heldRun(ctx context.Context, tenantID, sensorID shared.ID, commandID *shared.ID, leaseEpoch *int) (string, error) {
	if commandID == nil || s.commands == nil {
		return "", nil
	}
	cmd, err := s.commands.GetByTenantAndID(ctx, tenantID, *commandID)
	switch {
	case errors.Is(err, shared.ErrNotFound) || (err == nil && cmd == nil):
		return reasonCommandGone, nil
	case err != nil:
		return "", fmt.Errorf("%s: %w", errQueuedCommandRead, err)
	case cmd.TenantID != tenantID || cmd.SensorID == nil || *cmd.SensorID != sensorID:
		return reasonRunNotHeldNow, nil
	case leaseEpoch != nil && cmd.LeaseEpoch != *leaseEpoch:
		return reasonRunTakenBack, nil
	}
	return "", nil
}

// sharedHolder re-reads a sensor that is not one of tenantID's own: it is
// returned only when it is a shared sensor (scope instance, no tenant) and
// the report is bound to a shared job (is_platform_job) of tenantID that it
// still holds. Otherwise reason says why the work is dropped. A shared
// sensor never has unsolicited work processed.
func (s *Service) sharedHolder(ctx context.Context, tenantID, sensorID shared.ID, commandID *shared.ID, leaseEpoch *int) (*sensor.Sensor, string, error) {
	stored, err := s.sensorRepo.GetByID(ctx, sensorID)
	switch {
	case errors.Is(err, shared.ErrNotFound) || (err == nil && stored == nil):
		return nil, "", shared.ErrNotFound
	case err != nil:
		return nil, "", err
	case !stored.IsShared() || stored.TenantID != nil:
		// Another tenant's sensor: not this tenant's, as before.
		return nil, "", shared.ErrNotFound
	case commandID == nil || s.commands == nil:
		return nil, reasonSharedNotHeld, nil
	}
	cmd, err := s.commands.GetByTenantAndID(ctx, tenantID, *commandID)
	switch {
	case errors.Is(err, shared.ErrNotFound):
		return nil, reasonSharedNotHeld, nil
	case err != nil:
		return nil, "", err
	case cmd == nil || !cmd.IsPlatformJob || cmd.TenantID != tenantID || cmd.SensorID == nil || *cmd.SensorID != sensorID:
		return nil, reasonSharedNotHeld, nil
	case leaseEpoch != nil && cmd.LeaseEpoch != *leaseEpoch:
		return nil, reasonRunTakenBack, nil
	}
	return stored, "", nil
}

func (s *Service) auditDroppedJob(ctx context.Context, tenantID shared.ID, sensorID *shared.ID, reportID, reason string) {
	if s.auditSvc == nil && s.auditRepo == nil {
		return
	}
	resourceID := reportID
	if resourceID == "" {
		resourceID = UnknownValue
	}
	event := auditapp.NewDeniedEvent(audit.ActionIngestFailed, audit.ResourceTypeIngest, resourceID, reason).
		WithMessage("Queued report dropped: "+reason).
		WithMetadata("sensor_id", idString(sensorID)).
		WithMetadata("report_id", reportID)
	actx := auditapp.AuditContext{TenantID: tenantID.String()}
	if err := s.writeIngestAuditLog(ctx, actx, event); err != nil {
		s.logger.Error("ingest worker: failed to audit a dropped report", "error", err)
	}
}

func idString(id *shared.ID) string {
	if id == nil {
		return ""
	}
	return id.String()
}
