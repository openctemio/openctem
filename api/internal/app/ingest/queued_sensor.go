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
	QueuedWorkSensor(ctx context.Context, tenantID shared.ID, sensorID *shared.ID, reportID string) (*sensor.Sensor, *DroppedJob, error)
}

// QueuedWorkSensor re-reads the sensor that submitted a queued job. It
// returns the sensor when it is still active. When the sensor was revoked,
// disabled or deleted after the job was accepted (or the job names none), it
// returns a DroppedJob instead and records the drop in the tenant's audit
// log: the work of a sensor taken out of service is never processed. A
// lookup error is returned so the worker retries the job.
func (s *Service) QueuedWorkSensor(ctx context.Context, tenantID shared.ID, sensorID *shared.ID, reportID string) (*sensor.Sensor, *DroppedJob, error) {
	if s.sensorRepo == nil {
		return nil, nil, errors.New("ingest worker: no sensor repository to re-check the sensor")
	}
	var reason string
	var agt *sensor.Sensor
	if sensorID == nil || sensorID.IsZero() {
		reason = "the job names no sensor"
	} else {
		stored, err := s.sensorRepo.GetByTenantAndID(ctx, tenantID, *sensorID)
		switch {
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
