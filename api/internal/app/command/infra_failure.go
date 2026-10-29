package command

// A sensor's failure of a command that is not about the target and not a
// policy refusal (research/302 B1, B7). Routed scan work is re-queued to
// another eligible sensor, and every sensor that already failed it is
// excluded from later claims. The budget is the one every cause shares
// (commanddom.MaxDispatchAttempts); when it runs out, or no other sensor
// can take the work, or the same tool and content version already failed on
// two sensors (the fleet stop rule), the command fails and says why, with
// every cause, never only "max attempts exceeded".
//
// A fact about the target (unreachable, WAF or CDN block or challenge, rate
// limit) is never moved: another sensor would only repeat the request, and
// moving it to find a vantage the target does not block is evasion. Moves
// never widen anything: only sensors that could already claim the work are
// considered (RequeueCandidates and sensor.Accepts).

import (
	"context"
	"strings"

	commanddom "github.com/openctemio/openctem/api/pkg/domain/command"
	"github.com/openctemio/openctem/api/pkg/domain/scanrun"
	sensordom "github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// InfraReport is what a sensor says about the kind of its failure: the
// class it observed, the error code it sent (the platform's vocabulary) and
// bounded evidence. Every member is optional and untrusted.
type InfraReport struct {
	Class     string
	ErrorCode string
	Evidence  commanddom.FailureEvidence
}

// errorCodeClass maps an error code a sensor may send (the platform's
// upper-case vocabulary) to the infrastructure class it names.
var errorCodeClass = map[string]commanddom.FailureClass{
	"TOOL_UNAVAILABLE":    commanddom.ClassToolUnavailable,
	"TOOL_CRASHED":        commanddom.ClassToolCrashed,
	"RESOURCE_MEMORY":     commanddom.ClassResourceMemory,
	"RESOURCE_DISK":       commanddom.ClassResourceDisk,
	"CONTENT_UNAVAILABLE": commanddom.ClassContentUnavailable,
	"SENSOR_NETWORK":      commanddom.ClassSensorNetwork,
	"DNS_RESOLVER":        commanddom.ClassDNSResolver,
}

// infraClassOf decides the class of a failure and its sanitized evidence:
// the class the sensor sent, else the class its error code names, else (a
// sensor that sent neither, or only a generic code) the one the text
// heuristics recover. ok is false when the failure is not an
// infrastructure failure the platform can act on; a target-side class, a
// code that names another kind of failure (TOOL_EXIT, TIMEOUT, a permanent
// scope or placement code) and a text a permanent code explains stop the
// search.
func infraClassOf(in FailInput, msg string) (commanddom.FailureClass, commanddom.FailureEvidence, bool) {
	var ev commanddom.FailureEvidence
	code := ""
	if in.Infra != nil {
		ev = commanddom.SanitizeEvidence(in.Infra.Evidence)
		code = strings.TrimSpace(in.Infra.ErrorCode)
		if c, known := commanddom.ParseFailureClass(in.Infra.Class); known {
			return c, ev, c.Movable()
		}
	}
	if c, ok := errorCodeClass[strings.ToUpper(code)]; ok {
		return c, ev, true
	}
	if c, known := commanddom.ParseFailureClass(code); known {
		return c, ev, c.Movable()
	}
	// A code the platform names (and is not the generic one) is the
	// sensor's own verdict: no guessing from the text.
	if code != "" && code != scanrun.FailureCommandFailed {
		return "", ev, false
	}
	if permanent, _ := scanrun.ClassifyStepFailure(scanrun.FailureCommandFailed, msg); scanrun.IsPermanentFailure(permanent) {
		return "", ev, false
	}
	if c, ok := commanddom.InfraClassFromText(msg); ok {
		return c, ev, c.Movable()
	}
	return "", ev, false
}

// handleInfraFailure moves or ends a command its sensor failed for an
// infrastructure reason. done is false when the command should simply fail
// with the sensor's message (not routed work, a class that is not movable,
// or no store).
func (s *Service) handleInfraFailure(ctx context.Context, cmd *commanddom.Command, input FailInput, class commanddom.FailureClass, ev commanddom.FailureEvidence, msg string) (out *commanddom.Command, done bool, err error) {
	store, okStore := s.repo.(commanddom.InfraStore)
	finder, okFinder := s.repo.(RequeueCandidateFinder)
	if !okStore || !okFinder || !class.Movable() || cmd.SensorID == nil || cmd.IsPlatformJob || !routedWork(cmd) {
		return nil, false, nil
	}
	tool := ev.Tool
	if tool == "" {
		tool = commanddom.PayloadTool(cmd.Payload)
	}
	att := commanddom.InfraAttempt{SensorID: input.SensorID, Class: class, Tool: tool,
		ToolDigest: ev.ToolDigest, ContentDigest: ev.ContentDigest, At: s.now()}
	prior, err := store.CommandAttempts(ctx, cmd.TenantID, cmd.ID)
	if err != nil {
		return nil, true, err
	}
	all := append(prior, att) //nolint:gocritic // prior is a fresh slice
	fence := fenceOf(cmd, input.SensorID)

	// Fleet stop rule: the same tool and content version failed on two
	// sensors, so more sensors are not tried.
	key := commanddom.FleetKey{Tool: tool, ToolDigest: ev.ToolDigest, ContentDigest: ev.ContentDigest}
	if sid, perr := shared.IDFromString(input.SensorID); perr == nil && class.ToolScoped() && key.Valid() {
		tripped, ferr := store.RecordFleetFailure(ctx, cmd.TenantID, key, sid, class, s.now())
		if ferr != nil {
			// The rule is a safeguard; the budget still bounds the moves.
			s.logger.Warn("failed to record the fleet failure", "command_id", cmd.ID.String(), "error", ferr)
		} else if tripped {
			s.logger.Warn("fleet stop rule: a tool failed on two sensors; the command is not moved again",
				"command_id", cmd.ID.String(), "tool", logSafe(key.Tool), "tool_digest", logSafe(key.ToolDigest),
				"content_digest", logSafe(key.ContentDigest), "class", logSafe(string(class)))
			text := "Stopped: " + key.Label() + " failed on more than one sensor (" +
				commanddom.AggregateInfraCauses(all) + "). It was not moved to more sensors."
			return s.endInfraFailure(ctx, store, cmd, fence, att, scanrun.FailureFleetToolFailure, text)
		}
	}

	// The budget every cause shares: this return would be the last attempt.
	if cmd.DispatchAttempts+1 >= commanddom.MaxDispatchAttempts {
		return s.endInfraFailure(ctx, store, cmd, fence, att, scanrun.FailureCodeForInfra(string(class)),
			commanddom.AggregateInfraCauses(all)+": "+msg)
	}

	exclude := make([]shared.ID, 0, len(all)+commanddom.MaxRefusals)
	for _, a := range all {
		if id, perr := shared.IDFromString(a.SensorID); perr == nil {
			exclude = append(exclude, id)
		}
	}
	if rs, ok := s.repo.(commanddom.RefusalStore); ok {
		if refusals, rerr := rs.CommandRefusals(ctx, cmd.TenantID, cmd.ID); rerr == nil {
			for _, r := range refusals {
				if id, perr := shared.IDFromString(r.SensorID); perr == nil {
					exclude = append(exclude, id)
				}
			}
		}
	}
	accepts, err := s.anotherSensorAcceptsExcluding(ctx, finder, cmd, exclude)
	if err != nil {
		return nil, true, err
	}
	if !accepts {
		return s.endInfraFailure(ctx, store, cmd, fence, att, scanrun.FailureCodeForInfra(string(class)),
			commanddom.AggregateInfraCauses(all)+" (no other eligible sensor could take it): "+msg)
	}
	ok, err := store.RequeueFailed(ctx, cmd.TenantID, cmd.ID, fence, att, commanddom.MovedMessage(att, cmd.DispatchAttempts+1, commanddom.MaxDispatchAttempts))
	if err != nil {
		return nil, true, err
	}
	if !ok {
		return nil, true, ErrLeaseLost
	}
	s.logger.Info("command moved to another sensor after an infrastructure failure", "command_id", cmd.ID.String(),
		"sensor_id", logSafe(input.SensorID), "class", logSafe(string(class)), "attempts", len(all))
	requeued, err := s.Get(ctx, cmd.TenantID.String(), cmd.ID.String())
	return requeued, true, err
}

// endInfraFailure fails cmd with code and text and records the failure
// on it (the attempt, the sensor and the class). The record is written
// first, under the lease fence, so the failure event carries the class.
func (s *Service) endInfraFailure(ctx context.Context, store commanddom.InfraStore, cmd *commanddom.Command, fence commanddom.Fence, att commanddom.InfraAttempt, code, text string) (*commanddom.Command, bool, error) {
	if err := store.RecordFailedAttempt(ctx, cmd.TenantID, cmd.ID, fence, att); err != nil {
		s.logger.Warn("failed to record the infrastructure failure on the command", "command_id", cmd.ID.String(), "error", err)
	}
	cmd.Fail(truncateUTF8(text, MaxFailErrorMessageBytes))
	cmd.FailureCode = code
	if err := s.saveSensorChange(ctx, cmd, fence); err != nil {
		return nil, true, err
	}
	return cmd, true, nil
}

// anotherSensorAcceptsExcluding reports whether a sensor outside exclude
// could claim cmd and its reported policy accepts it.
func (s *Service) anotherSensorAcceptsExcluding(ctx context.Context, finder RequeueCandidateFinder, cmd *commanddom.Command, exclude []shared.ID) (bool, error) {
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

// otherSensorCanTake reports whether a sensor other than the one that
// held cmd (and those that failed or refused it) could take work like it:
// the condition for sending its sensor-side failed targets out again. A
// command that is not routed work never is. An error counts as no.
func (s *Service) otherSensorCanTake(ctx context.Context, cmd *commanddom.Command) bool {
	finder, ok := s.repo.(RequeueCandidateFinder)
	if !ok || cmd.SensorID == nil || cmd.IsPlatformJob || !routedWork(cmd) {
		return false
	}
	exclude := []shared.ID{*cmd.SensorID}
	if st, ok := s.repo.(commanddom.InfraStore); ok {
		if prior, err := st.CommandAttempts(ctx, cmd.TenantID, cmd.ID); err == nil {
			for _, a := range prior {
				if id, perr := shared.IDFromString(a.SensorID); perr == nil {
					exclude = append(exclude, id)
				}
			}
		}
	}
	if rs, ok := s.repo.(commanddom.RefusalStore); ok {
		if refusals, err := rs.CommandRefusals(ctx, cmd.TenantID, cmd.ID); err == nil {
			for _, r := range refusals {
				if id, perr := shared.IDFromString(r.SensorID); perr == nil {
					exclude = append(exclude, id)
				}
			}
		}
	}
	accepts, err := s.anotherSensorAcceptsExcluding(ctx, finder, cmd, exclude)
	return err == nil && accepts
}

// inPayloadOrder returns the targets of a and b in the order cmd's payload
// lists them.
func inPayloadOrder(cmd *commanddom.Command, a, b []string) []string {
	want := make(map[string]bool, len(a)+len(b))
	for _, t := range a {
		want[t] = true
	}
	for _, t := range b {
		want[t] = true
	}
	var out []string
	for _, t := range commanddom.PayloadTargets(cmd.Payload) {
		if want[t] {
			out = append(out, t)
			delete(want, t)
		}
	}
	return out
}
