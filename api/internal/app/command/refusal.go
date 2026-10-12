package command

// A sensor's refusal of a command under its policy (research/25 §3.6,
// owner decision D8). Routed scan work (a scan with a scan run, the
// work the platform chose a sensor for) is re-queued to another eligible
// sensor, and the refuser can no longer claim it; it fails once no other
// eligible sensor accepts it (sensor.Accepts on their reported policies)
// or after commanddom.MaxRefusals refusals, with the aggregated reasons.
// Any other command (one a person pinned to a sensor) fails as before.
//
// A refusal never widens anything: re-queueing only offers the job to
// sensors that could already claim it, minus the ones that refused.

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	commanddom "github.com/openctemio/openctem/api/pkg/domain/command"
	sensordom "github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// RequeueCandidateFinder lists the reported local policies of the sensors,
// other than exclude, that could claim a command now. Implemented by the
// postgres command repository (tenant-scoped).
type RequeueCandidateFinder interface {
	RequeueCandidates(ctx context.Context, tenantID, commandID shared.ID, exclude []shared.ID) ([]*sensordom.LocalPolicyReport, error)
}

// routedWork reports whether cmd is work the platform routed and may hand
// to another sensor: a scan with a scan run (the rule the lease and
// release paths use, postgres.routedScanWork).
func routedWork(cmd *commanddom.Command) bool {
	if cmd.Type != commanddom.CommandTypeScan || len(cmd.Payload) == 0 {
		return false
	}
	var p map[string]json.RawMessage
	if json.Unmarshal(cmd.Payload, &p) != nil {
		return false
	}
	_, ok := p["scan_run_id"]
	return ok
}

// handleRefusal handles a fail that is a policy refusal. done is false
// when the command should simply fail with the sensor's message (not
// routed work, or no store); otherwise out is the re-queued or failed
// command.
func (s *Service) handleRefusal(ctx context.Context, cmd *commanddom.Command, input FailInput, ref *sensordom.DispatchRefusal) (out *commanddom.Command, done bool, err error) {
	store, okStore := s.repo.(commanddom.RefusalStore)
	finder, okFinder := s.repo.(RequeueCandidateFinder)
	if !okStore || !okFinder || cmd.SensorID == nil || !routedWork(cmd) {
		return nil, false, nil
	}
	rec := commanddom.RefusalRecord{SensorID: input.SensorID, Layer: ref.Layer, Rule: ref.Rule, Detail: ref.Detail, At: s.now()}
	prior, err := store.CommandRefusals(ctx, cmd.TenantID, cmd.ID)
	if err != nil {
		return nil, true, err
	}
	all := append(prior, rec) //nolint:gocritic // prior is a fresh slice
	fence := fenceOf(cmd, input.SensorID)

	if len(all) < commanddom.MaxRefusals {
		accepts, err := s.anotherSensorAccepts(ctx, finder, cmd, all)
		if err != nil {
			return nil, true, err
		}
		if accepts {
			ok, err := store.RequeueRefused(ctx, cmd.TenantID, cmd.ID, fence, rec, "re-queued: "+ref.Message())
			if err != nil {
				return nil, true, err
			}
			if !ok {
				return nil, true, ErrLeaseLost
			}
			s.logger.Info("command re-queued after a sensor refused it", "command_id", cmd.ID.String(),
				"sensor_id", logSafe(input.SensorID), "layer", logSafe(ref.Layer), "rule", logSafe(ref.Rule), "refusals", len(all))
			requeued, err := s.Get(ctx, cmd.TenantID.String(), cmd.ID.String())
			return requeued, true, err
		}
	}

	cmd.Fail(truncateUTF8(aggregateRefusals(ref, all), MaxFailErrorMessageBytes))
	if err := s.saveSensorChange(ctx, cmd, fence); err != nil {
		return nil, true, err
	}
	if err := store.AppendRefusal(ctx, cmd.TenantID, cmd.ID, rec); err != nil {
		s.logger.Warn("failed to record the refusal on the failed command", "command_id", cmd.ID.String(), "error", err)
	}
	return cmd, true, nil
}

// anotherSensorAccepts reports whether a sensor that has not refused cmd
// could claim it and its reported policy accepts it.
func (s *Service) anotherSensorAccepts(ctx context.Context, finder RequeueCandidateFinder, cmd *commanddom.Command, refusals []commanddom.RefusalRecord) (bool, error) {
	exclude := make([]shared.ID, 0, len(refusals))
	for _, r := range refusals {
		if id, err := shared.IDFromString(r.SensorID); err == nil {
			exclude = append(exclude, id)
		}
	}
	reports, err := finder.RequeueCandidates(ctx, cmd.TenantID, cmd.ID, exclude)
	if err != nil || len(reports) == 0 {
		return false, err
	}
	opts, err := s.dispatchOptions(ctx, cmd.TenantID, []*commanddom.Command{cmd})
	if err != nil {
		return false, err
	}
	job := sensordom.JobOf(string(cmd.Type), cmd.Payload)
	for _, r := range reports {
		if sensordom.Accepts(r, job, opts) == nil {
			return true, nil
		}
	}
	return false, nil
}

// aggregateRefusals is the failure reason of a command no remaining sensor
// accepts: the last refusal first (its prefix is what older readers
// parse), then the others.
func aggregateRefusals(last *sensordom.DispatchRefusal, all []commanddom.RefusalRecord) string {
	msg := last.Message()
	if len(all) <= 1 {
		return msg + " (no other eligible sensor accepts it)"
	}
	others := make([]string, 0, len(all)-1)
	for _, r := range all[:len(all)-1] {
		others = append(others, fmt.Sprintf("sensor %s: %s/%s", shortID(r.SensorID), r.Layer, r.Rule))
	}
	return fmt.Sprintf("%s (refused by %d sensors; also: %s)", msg, len(all), strings.Join(others, "; "))
}

// logSafe strips line breaks from a value that came from a sensor before it
// is logged (no forged log lines). The values are already sanitized to
// closed sets and patterns; this keeps the log safe on its own.
func logSafe(v string) string {
	return strings.ReplaceAll(strings.ReplaceAll(v, "\n", ""), "\r", "")
}

func shortID(id string) string {
	if len(id) > 8 {
		return id[:8]
	}
	return id
}
