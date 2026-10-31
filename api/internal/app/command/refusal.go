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
	"slices"
	"strconv"
	"strings"
	"time"

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

// RefusalWait bounds how long routed work that a sensor refused waits for
// another eligible sensor when none can take it now (no other sensor, or
// every other sensor's reported policy refuses it too): the host owner may
// still widen a policy (a sensor whose policy changes may claim it again,
// ForgetRefusalsOf), a sensor may come back online, or one may be paired.
// Past it the command expires with the refusals as its reason.
const RefusalWait = 6 * time.Hour

// requeueableLayer reports whether a refusal by this layer is a placement
// signal (another sensor may accept the job): the sensor-local policy, the
// sensor's managed layer and the platform's tool gate on the sensor. The
// built-in deny list is the same on every sensor (a target problem, not a
// sensor one), and a scope refusal means the sensor did not accept the
// platform's signed scope for the job: a platform bug or an attack, which
// is failed closed and never handed to the next sensor.
func requeueableLayer(layer string) bool {
	switch layer {
	case sensordom.RefusalLayerLocal, sensordom.RefusalLayerManaged, sensordom.RefusalLayerPlatformToolGate:
		return true
	}
	return false
}

// handleRefusal handles a fail that is a policy refusal. done is false
// when the command should simply fail with the sensor's message (not
// routed work, or no store); otherwise out is the re-queued or failed
// command.
//
// Routed work a sensor refused under a requeueable layer goes back to the
// queue, the refuser excluded: at once to another eligible sensor whose
// reported policy accepts it, else it waits for one at most RefusalWait.
// It fails at once only after commanddom.MaxRefusals refusals, or for a
// layer that is not a placement signal. Bounded: every refusal is recorded
// and excludes its sensor, so a command cannot circle between sensors.
func (s *Service) handleRefusal(ctx context.Context, cmd *commanddom.Command, input FailInput, ref *sensordom.DispatchRefusal) (out *commanddom.Command, done bool, err error) {
	store, okStore := s.repo.(commanddom.RefusalStore)
	finder, okFinder := s.repo.(RequeueCandidateFinder)
	if !okStore || !okFinder || cmd.SensorID == nil || !routedWork(cmd) {
		return nil, false, nil
	}
	rec := commanddom.RefusalRecord{SensorID: input.SensorID, SensorName: s.sensorName(ctx, cmd.TenantID, input.SensorID),
		Layer: ref.Layer, Rule: ref.Rule, Detail: ref.Detail, At: s.now()}
	prior, err := store.CommandRefusals(ctx, cmd.TenantID, cmd.ID)
	if err != nil {
		return nil, true, err
	}
	all := append(prior, rec) //nolint:gocritic // prior is a fresh slice
	fence := fenceOf(cmd, input.SensorID)

	if ref.Layer == sensordom.RefusalLayerScope {
		// The sensor did not accept the scope the platform signed for this
		// job. Not handed to another sensor: that would only widen the set
		// of sensors that see a job one of them called out of scope.
		s.logger.Warn("SECURITY: a sensor refused a job's signed scope; the job fails closed and is not re-queued",
			"command_id", cmd.ID.String(), "sensor_id", logSafe(input.SensorID), "rule", logSafe(ref.Rule))
	}

	if requeueableLayer(ref.Layer) && len(all) < commanddom.MaxRefusals {
		accepts, err := s.anotherSensorAccepts(ctx, finder, cmd, all)
		if err != nil {
			return nil, true, err
		}
		message := "re-queued: " + ref.Message()
		var waitUntil *time.Time
		if !accepts {
			until := s.now().Add(RefusalWait)
			if cmd.ExpiresAt != nil && cmd.ExpiresAt.Before(until) {
				until = *cmd.ExpiresAt
			}
			waitUntil = &until
			message = fmt.Sprintf("waiting for an eligible sensor until %s: %s", until.UTC().Format(time.RFC3339), ref.Message())
		}
		ok, err := store.RequeueRefused(ctx, cmd.TenantID, cmd.ID, fence, rec, truncateUTF8(message, MaxFailErrorMessageBytes), waitUntil)
		if err != nil {
			return nil, true, err
		}
		if !ok {
			return nil, true, ErrLeaseLost
		}
		s.logger.Info("command re-queued after a sensor refused it", "command_id", cmd.ID.String(),
			"sensor_id", logSafe(input.SensorID), "layer", logSafe(ref.Layer), "rule", logSafe(ref.Rule),
			"refusals", len(all), "waiting", waitUntil != nil)
		requeued, err := s.Get(ctx, cmd.TenantID.String(), cmd.ID.String())
		return requeued, true, err
	}

	cmd.Fail(truncateUTF8(RefusalFailureReason(cmd.Payload, all), MaxFailErrorMessageBytes))
	if err := s.saveSensorChange(ctx, cmd, fence); err != nil {
		return nil, true, err
	}
	if err := store.AppendRefusal(ctx, cmd.TenantID, cmd.ID, rec); err != nil {
		s.logger.Warn("failed to record the refusal on the failed command", "command_id", cmd.ID.String(), "error", err)
	}
	return cmd, true, nil
}

// sensorName is the name of the tenant's sensor id for a refusal record
// ("" when it cannot be read; the record keeps the id).
func (s *Service) sensorName(ctx context.Context, tenantID shared.ID, id string) string {
	sid, err := shared.IDFromString(id)
	if s.sensors == nil || err != nil {
		return ""
	}
	a, err := s.sensors.GetByTenantAndID(ctx, tenantID, sid)
	if err != nil || a == nil {
		return ""
	}
	return a.Name
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

// RefusalFailureReason is the failure reason of routed work that no
// sensor ran because their policies refused it: the last refusal first (its
// prefix is what older readers parse), then a plain sentence naming the
// target, every refusing sensor and where its local policy is edited.
func RefusalFailureReason(payload json.RawMessage, all []commanddom.RefusalRecord) string {
	if len(all) == 0 {
		return "no sensor accepted the job"
	}
	last := all[len(all)-1]
	msg := (&sensordom.DispatchRefusal{Layer: last.Layer, Rule: last.Rule, Detail: last.Detail}).Message()
	target := targetPhrase(payload)
	sensors := make([]string, 0, len(all))
	local := make([]string, 0, len(all))
	for _, r := range all {
		name := r.SensorName
		if name == "" {
			name = "sensor " + shortID(r.SensorID)
		}
		sensors = append(sensors, fmt.Sprintf("%s (%s/%s)", name, r.Layer, r.Rule))
		if r.Layer == sensordom.RefusalLayerLocal && r.SensorName != "" && !slices.Contains(local, r.SensorName) {
			local = append(local, r.SensorName)
		}
	}
	var b strings.Builder
	b.WriteString(msg)
	switch last.Layer {
	case sensordom.RefusalLayerScope:
		fmt.Fprintf(&b, ". The sensor did not accept the scope the platform signed for %s; the job was not sent to another sensor. Check the organization's scope and the sensor's logs", target)
	case sensordom.RefusalLayerBuiltin:
		fmt.Fprintf(&b, ". %s is on every sensor's built-in deny list (loopback, link-local, metadata or reserved addresses) and is not scanned", target)
	default:
		fmt.Fprintf(&b, ". No sensor's policy allows %s: refused by %s", target, strings.Join(sensors, ", "))
		for _, n := range local {
			fmt.Fprintf(&b, ". To let %s scan it, edit sensors/%s/policy/sensor-policy.yaml (or /etc/openctem/sensor-policy.yaml) on its host and restart it", n, n)
		}
		b.WriteString(". Local policy reference: " + LocalPolicyDocsURL)
	}
	return b.String()
}

// LocalPolicyDocsURL documents every key of a sensor-local policy.
const LocalPolicyDocsURL = "https://github.com/openctemio/sensor/blob/main/docs/LOCAL_POLICY.md"

// targetPhrase names a payload's first target and how many more it has.
func targetPhrase(payload json.RawMessage) string {
	targets := sensordom.PayloadTargets(payload)
	switch len(targets) {
	case 0:
		return "the job's targets"
	case 1:
		return strconv.Quote(targets[0])
	default:
		return fmt.Sprintf("%q and %d more target(s)", targets[0], len(targets)-1)
	}
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
