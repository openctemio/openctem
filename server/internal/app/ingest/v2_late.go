package ingest

// Late reports (docs/architecture/sensor-results-v2.md, "Late reports"). A
// sensor whose command-bound report is refused as command-not-found sends it
// again without the command, naming the command and the lease epoch it was
// made for (protov2.HeaderLateCommand, HeaderLateLeaseEpoch). When the
// platform took that run back and handed the command out again, the
// replacing run's results are the record: the late report is refused with
// lease-superseded (final; the sensor dead-letters it) and counted, so it
// can no longer create or refresh findings after the run that replaced it.
// Any other late report goes on as an unsolicited report, as before.
//
// The headers never bind a report to a command: the command is looked up in
// the authenticated sensor's own tenant only, a shared job is never one of
// an organization sensor's commands, and an id that is not found there
// (another tenant's, unknown, malformed epoch) is treated exactly like an
// absent header. The only distinguishable answer, lease-superseded, is given
// for a command of the sensor's own tenant whose lease moved past the stated
// epoch.

import (
	"context"

	"github.com/openctemio/openctem/server/internal/metrics"
	"github.com/openctemio/openctem/server/pkg/domain/command"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
	protov2 "github.com/openctemio/openctem/server/pkg/sensorproto/v2"
)

// lateOutcome is what a late report's provenance decides.
type lateOutcome string

const (
	// lateUnknown: the stated command is not one of the sensor's tenant
	// (or the epoch is not one it was handed out under); the report goes
	// on as if it named none.
	lateUnknown lateOutcome = "unknown"
	// lateCurrent: the stated lease is still the command's last one, held
	// by this sensor; the report goes on unsolicited.
	lateCurrent lateOutcome = "accepted"
	// lateSuperseded: the command was handed out again after the stated
	// lease (a later epoch, or taken back from this sensor); refused.
	lateSuperseded lateOutcome = "superseded"
)

// decideLate is the outcome for a late report of sensorID in tenantID that
// states cmd (nil: not found) under epoch.
func decideLate(cmd *command.Command, tenantID, sensorID shared.ID, epoch *int) lateOutcome {
	if cmd == nil || cmd.TenantID != tenantID || cmd.IsPlatformJob || epoch == nil ||
		*epoch < 1 || *epoch > cmd.LeaseEpoch {
		return lateUnknown
	}
	if *epoch < cmd.LeaseEpoch || cmd.SensorID == nil || *cmd.SensorID != sensorID {
		return lateSuperseded
	}
	return lateCurrent
}

// checkLate refuses an unbound write whose late provenance names a
// superseded lease (ProblemLeaseSuperseded); nil otherwise. A bound write,
// or one without the header, is not looked at.
func (v *V2Receiver) checkLate(ctx context.Context, tenantID shared.ID, t V2Target) error {
	if t.CommandID != "" || t.LateCommand == "" || t.Sensor == nil {
		return nil
	}
	var cmd *command.Command
	if id, err := shared.IDFromString(t.LateCommand); err == nil && v.commands != nil {
		if c, err := v.commands.GetByTenantAndID(ctx, tenantID, id); err == nil {
			cmd = c
		}
	}
	out := decideLate(cmd, tenantID, t.Sensor.ID, t.LateLeaseEpoch)
	metrics.IngestLateReportsTotal.WithLabelValues(string(out)).Inc()
	switch out {
	case lateSuperseded:
		// No payload is logged: the ids and epochs say what was refused.
		v.logger.Warn("late sensor report refused: its lease was superseded",
			"tenant_id", tenantID.String(), "sensor_id", t.Sensor.ID.String(), "report_id", t.ReportID,
			"command_id", cmd.ID.String(), "stated_lease_epoch", *t.LateLeaseEpoch, "lease_epoch", cmd.LeaseEpoch)
		return problem(protov2.ProblemLeaseSuperseded)
	case lateCurrent:
		v.logger.Info("late sensor report taken as unsolicited: its lease is the command's last one",
			"tenant_id", tenantID.String(), "sensor_id", t.Sensor.ID.String(), "report_id", t.ReportID,
			"command_id", cmd.ID.String(), "lease_epoch", cmd.LeaseEpoch)
	}
	return nil
}
