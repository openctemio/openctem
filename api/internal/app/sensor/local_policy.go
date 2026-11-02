package sensor

// The sensor-local policy report (RFC-040 §5.7, pkg/domain/sensor/
// local_policy.go): stored from heartbeats (service.go) and manifests, and
// the jobs a sensor refused under it (detection A11).

import (
	"context"
	"reflect"
	"strings"
	"time"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	sensordom "github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// localPolicyWriter is implemented by a sensor repository that can store a
// local policy report on its own (postgres.SensorRepository).
type localPolicyWriter interface {
	UpdateLocalPolicy(ctx context.Context, tenantID *shared.ID, id shared.ID, r *sensordom.LocalPolicyReport) (bool, error)
}

// RefusalForgetter lifts a sensor's exclusion from the pending commands it
// refused (postgres.CommandRepository.ForgetRefusalsOf).
type RefusalForgetter interface {
	ForgetRefusalsOf(ctx context.Context, tenantID, sensorID shared.ID) (int64, error)
}

// SetRefusalForgetter makes a change of a sensor's reported local policy
// lift its exclusion from the pending commands it refused: under the new
// policy it may accept them, and it is offered them again (bounded: every
// refusal still counts toward the command's refusal limit).
func (s *SensorService) SetRefusalForgetter(f RefusalForgetter) { s.refusalForgetter = f }

// localPolicyChanged is called with a sensor's stored row and its new
// report: when the policy changed (state, digest or kill switch), the
// sensor may claim again what it refused. Tenant sensors only. Best effort.
func (s *SensorService) localPolicyChanged(ctx context.Context, a *sensordom.Sensor, next *sensordom.LocalPolicyReport) {
	if s.refusalForgetter == nil || a == nil || a.TenantID == nil || next == nil {
		return
	}
	prev := a.LocalPolicy
	if prev != nil && prev.State == next.State && prev.Digest == next.Digest && prev.KillSwitch == next.KillSwitch {
		return
	}
	n, err := s.refusalForgetter.ForgetRefusalsOf(ctx, *a.TenantID, a.ID)
	if err != nil {
		s.logger.Warn("failed to offer refused commands again after a local policy change", "sensor_id", a.ID.String(), "error", err)
		return
	}
	if n > 0 {
		s.logger.Info("local policy changed; the sensor may claim the commands it refused again", "sensor_id", a.ID.String(), "commands", n)
	}
}

// storeManifestLocalPolicy stores the local policy report a manifest
// carried (RFC-040 §5.7) when it differs from the stored one: the manifest
// has the summary that slim heartbeats leave out. The live kill switch is
// the heartbeat's and is kept. Best effort: failures are logged.
func (s *SensorService) storeManifestLocalPolicy(ctx context.Context, a *sensordom.Sensor, lp *sensordom.LocalPolicyReport, now time.Time) {
	w, ok := s.repo.(localPolicyWriter)
	if !ok || lp == nil {
		return
	}
	next := *lp
	if a.LocalPolicy != nil {
		next.KillSwitch = a.LocalPolicy.KillSwitch
		if reflect.DeepEqual(*a.LocalPolicy, next) {
			return
		}
	}
	saved, err := w.UpdateLocalPolicy(ctx, a.TenantID, a.ID, &next)
	if err != nil {
		s.logger.Warn("failed to store sensor local policy", "sensor_id", a.ID.String(), "error", err)
		return
	}
	if saved {
		s.localPolicyChanged(ctx, a, &next)
	}
	if saved && s.events != nil {
		if e, ok := sensordom.LocalPolicyEvent(a, &next, now); ok {
			s.recordEvents(ctx, []sensordom.Event{e})
		}
	}
}

// ObserveLocalPolicyRefusal records a command the sensor failed because its
// local policy refused it (RFC-040 §5.7, detection A11): an entry on the
// sensor's activity timeline and, once per coalesced burst (same rule within
// the event window), an audit entry. errorMessage is the sensor's failure
// reason; anything that is not a local-policy refusal is ignored.
func (s *SensorService) ObserveLocalPolicyRefusal(ctx context.Context, tenantID, sensorID shared.ID, commandID, errorMessage string) {
	rule, ok := sensordom.LocalPolicyRefusal(errorMessage)
	if !ok {
		return
	}
	s.logger.Warn("sensor refused a job under its local policy", "sensor_id", sensorID.String(),
		"command_id", logLine(commandID), "rule", logLine(rule))
	inserted := true
	if s.events != nil {
		res, err := s.events.Record(ctx, sensordom.LocalPolicyRefusalEvent(tenantID, sensorID, commandID, rule, errorMessage, s.now()), s.eventLimits)
		if err != nil {
			s.logger.Warn("failed to record sensor event", "sensor_id", sensorID.String(),
				"type", string(sensordom.EventJobRefusedByLocalPolicy), "error", err)
		}
		inserted = err != nil || res == sensordom.EventInserted
	}
	if s.auditService == nil || !inserted {
		return
	}
	name := sensorID.String()
	if a, err := s.repo.GetByTenantAndID(ctx, tenantID, sensorID); err == nil && a != nil {
		name = a.Name
	}
	s.warnAudit(s.auditService.LogSensorJobRefusedByLocalPolicy(ctx, auditapp.AuditContext{
		TenantID: tenantID.String(), ActorEmail: sensorAuditSystemActor,
	}, sensorID.String(), name, commandID, rule), "LogSensorJobRefusedByLocalPolicy", sensorID.String())
}

// logLine strips line breaks from a value that came from the sensor before
// it is logged (no forged log lines).
func logLine(v string) string {
	return strings.ReplaceAll(strings.ReplaceAll(v, "\n", ""), "\r", "")
}
