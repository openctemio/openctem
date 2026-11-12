package sensor

// Grant refusals on the sensor's timeline and in the audit log
// (docs/rfcs/RFC-052-sensor-pairing-and-authorization.md §5.3, D-6): a claim
// by id of a job outside the grant, a job carrying credentials the sensor may
// not receive, results without a job from a sensor without push ingest.

import (
	"context"
	"fmt"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	auditdom "github.com/openctemio/openctem/api/pkg/domain/audit"
	sensordom "github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// ObserveGrantRefusal records a claim the sensor's grant refused: a
// timeline event, and (once per event-limit window) a high-severity audit
// row, sensor.credential_refused when the dimension was credentials.
func (s *SensorService) ObserveGrantRefusal(ctx context.Context, tenantID, sensorID shared.ID, commandID string, r *sensordom.GrantRefusal) {
	if r == nil {
		return
	}
	s.logger.Warn("sensor claim refused: outside its grant", "sensor_id", sensorID.String(),
		"command_id", logLine(commandID), "dimension", r.Dimension)
	ev := sensordom.NewEvent(tenantID, sensorID, sensordom.EventJobRefusedByGrant, s.now(),
		"Claim refused: the job is outside the sensor's grant ("+r.Dimension+")",
		map[string]any{"command_id": commandID, "dimension": r.Dimension, "detail": r.Detail})
	if !s.recordOnce(ctx, ev) {
		return
	}
	action := auditdom.ActionSensorClaimRefusedGrant
	if r.Dimension == sensordom.DimCredentials {
		action = auditdom.ActionSensorCredentialRefused
	}
	name := s.sensorName(ctx, tenantID, sensorID)
	s.logGrantAudit(ctx, tenantID, auditapp.NewSuccessEvent(action, auditdom.ResourceTypeSensor, sensorID.String()).
		WithResourceName(name).WithSeverity(auditdom.SeverityHigh).
		WithMessage(fmt.Sprintf("Sensor '%s' tried to claim a job outside its grant (%s)", name, r.Dimension)).
		WithMetadata("command_id", commandID).WithMetadata("dimension", r.Dimension).WithMetadata("detail", r.Detail))
}

// ObservePushRefusal records results without a job that the sensor's grant
// refused. reason is "grant" (push ingest is off in the grant) or "trust"
// (the grant allows it, but the sensor is not trusted).
func (s *SensorService) ObservePushRefusal(ctx context.Context, tenantID, sensorID shared.ID, route, reason string) {
	why := "the sensor's grant does not allow push ingest"
	if reason == "trust" {
		why = "the sensor's grant allows push ingest, but the sensor is not trusted"
	} else {
		reason = "grant"
	}
	s.logger.Warn("sensor results without a job refused", "sensor_id", sensorID.String(),
		"route", logLine(route), "missing", reason)
	ev := sensordom.NewEvent(tenantID, sensorID, sensordom.EventPushRefusedByGrant, s.now(),
		"Results without a job refused: "+why,
		map[string]any{"route": logLine(route), "missing": reason})
	if !s.recordOnce(ctx, ev) {
		return
	}
	name := s.sensorName(ctx, tenantID, sensorID)
	s.logGrantAudit(ctx, tenantID, auditapp.NewSuccessEvent(auditdom.ActionSensorPushRefusedGrant, auditdom.ResourceTypeSensor, sensorID.String()).
		WithResourceName(name).WithSeverity(auditdom.SeverityMedium).
		WithMessage(fmt.Sprintf("Sensor '%s' sent results without a job; %s", name, why)).
		WithMetadata("route", logLine(route)).WithMetadata("missing", reason))
}

// recordOnce writes ev and reports whether it was new (not suppressed by
// the per-sensor event limits); without an event store it is always new.
func (s *SensorService) recordOnce(ctx context.Context, ev sensordom.Event) bool {
	if s.events == nil {
		return true
	}
	res, err := s.events.Record(ctx, ev, s.eventLimits)
	if err != nil {
		s.logger.Warn("failed to record sensor event", "sensor_id", ev.SensorID.String(), "type", string(ev.Type), "error", err)
		return true
	}
	return res == sensordom.EventInserted
}

func (s *SensorService) sensorName(ctx context.Context, tenantID, sensorID shared.ID) string {
	if a, err := s.repo.GetByTenantAndID(ctx, tenantID, sensorID); err == nil && a != nil {
		return a.Name
	}
	return sensorID.String()
}

func (s *SensorService) logGrantAudit(ctx context.Context, tenantID shared.ID, ev auditapp.AuditEvent) {
	if s.auditService == nil {
		return
	}
	s.warnAudit(s.auditService.LogEvent(ctx, auditapp.AuditContext{TenantID: tenantID.String(), ActorEmail: sensorAuditSystemActor}, ev),
		"LogEvent", "")
}
