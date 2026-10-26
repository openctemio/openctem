package command

// Requeue only unfinished targets (research/125): a scan command whose
// result says how each of its targets ended (ctis outcome) settles the
// targets with an outcome; the ones it left unfinished go out again as a
// new command carrying only them. A finished target is never run twice
// because a later one stopped the task.

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/openctemio/ctis/outcome"
)

// UnfinishedTargets reads a completed command's result against its own
// targets: the targets the result leaves unfinished (in payload order) and
// how many it settled. ok is false when the command is not a tenant scan
// with targets, a run's command without its step id, or the result
// carries no target_outcomes (a sensor that predates them: the command
// covered every target). The result is the
// sensor's, untrusted: an outcome for a target the command does not carry
// is ignored and a target without a valid outcome is unfinished, so a
// sensor can never add a target.
func UnfinishedTargets(cmd *Command) (remaining []string, settled int, ok bool) {
	remaining, _, settled, ok = SplitUnfinished(cmd)
	return remaining, settled, ok
}

// SensorSide reports whether a failed target's outcome is a fault of the
// sensor's own network or resolver, not a fact about the target: the
// sensor's control probe failed (sensor_network_fault, which includes a
// proxy pool that carried none of its connections), or a name did not
// resolve and the sensor says its own resolver is the cause. Another sensor
// can answer these differently, so the target may go out again on one
// (research/302 B3). It is never true for a fact about the target
// (unreachable, timeout, name gone), for an answer of an edge protection
// (blocked or challenged) or a rate limit, which are never sent from
// another vantage point (that would be evading the answer), nor for a tool
// error or the sensor's own egress refusal, which another sensor would
// repeat.
func SensorSide(o outcome.Target) bool {
	if o.State != outcome.Failed || !o.Valid() {
		return false
	}
	switch o.Class {
	case outcome.SensorNetworkFault:
		return o.Side() == outcome.CauseSensor
	case outcome.ResolverFailed:
		return o.Cause == outcome.CauseSensor
	}
	return false
}

// SplitUnfinished is UnfinishedTargets with the sensor-side failures told
// apart: unfinished are the targets that got no outcome, sensorSide the
// targets whose failure is the sensor's own (SensorSide), both in payload
// order. settled counts the targets with an outcome that is neither: a
// settled target is never run again. Whether sensorSide targets go out again
// is the caller's decision: they only can when another eligible sensor
// exists.
func SplitUnfinished(cmd *Command) (unfinished, sensorSide []string, settled int, ok bool) {
	if cmd == nil || cmd.Type != CommandTypeScan || cmd.IsPlatformJob || len(cmd.Result) == 0 {
		return nil, nil, 0, false
	}
	if cmd.StepRunID == nil && payloadNamesRun(cmd.Payload) {
		// A run step settles with the last command carrying its step id;
		// without it the step would settle before its follow-up ran.
		return nil, nil, 0, false
	}
	targets := PayloadTargets(cmd.Payload)
	if len(targets) == 0 {
		return nil, nil, 0, false
	}
	var res struct {
		Outcomes *[]outcome.Target `json:"target_outcomes"`
	}
	if json.Unmarshal(cmd.Result, &res) != nil || res.Outcomes == nil {
		return nil, nil, 0, false
	}
	normalized := outcome.Normalize(*res.Outcomes, targets)
	for _, o := range normalized {
		switch {
		case o.State == outcome.Unfinished:
			unfinished = append(unfinished, o.Target)
		case SensorSide(o):
			sensorSide = append(sensorSide, o.Target)
		}
	}
	return unfinished, sensorSide, len(normalized) - len(unfinished) - len(sensorSide), true
}

// ConnectorUnfinishedTargets reads a completed connector_scan's result
// against its own targets and returns the targets it left unfinished, in
// payload order. A connector scan is one scan in the connected product, so
// it is never split into follow-ups: its unfinished targets are reported to
// its run instead (recorded there, so the coverage ledger and the next
// scheduled run see them). ok is false for any other command, a command
// without targets, or a result without target_outcomes (a sensor that
// predates them). The result is the sensor's, untrusted: an outcome for a
// target the command does not carry is ignored and a target without a valid
// outcome is unfinished.
func ConnectorUnfinishedTargets(cmd *Command) (remaining []string, ok bool) {
	if cmd == nil || cmd.Type != CommandTypeConnectorScan || cmd.IsPlatformJob || len(cmd.Result) == 0 {
		return nil, false
	}
	targets := PayloadTargets(cmd.Payload)
	if len(targets) == 0 {
		return nil, false
	}
	var res struct {
		Outcomes *[]outcome.Target `json:"target_outcomes"`
	}
	if json.Unmarshal(cmd.Result, &res) != nil || res.Outcomes == nil {
		return nil, false
	}
	for _, o := range outcome.Normalize(*res.Outcomes, targets) {
		if o.State == outcome.Unfinished {
			remaining = append(remaining, o.Target)
		}
	}
	return remaining, true
}

// payloadNamesRun reports whether a payload routes its command to a scan
// run (scan_run_id set).
func payloadNamesRun(payload json.RawMessage) bool {
	var p struct {
		RunID string `json:"scan_run_id"`
	}
	return json.Unmarshal(payload, &p) == nil && p.RunID != ""
}

// FollowUpAttempts is the dispatch attempts a follow-up of a command that
// made attempts dispatch attempts starts with. Attempts count per chunk of
// targets: a run that settled some targets made progress, so the remaining
// chunk keeps the count it had; a run that settled none counts one more
// attempt against them. A chunk that keeps failing reaches the limit on its
// own and the targets settled before it are kept. Each follow-up carries
// fewer targets than the last one or one more attempt, so the chain ends.
func FollowUpAttempts(attempts, settled int) int {
	if settled > 0 {
		return attempts
	}
	return attempts + 1
}

// NewFollowUp builds the command that runs parent's remaining targets: a
// pending scan of the same tenant, type and priority whose payload is the
// parent's with its targets replaced. Its host keys are those of the
// remaining targets among the parent's; the rest of the placement (zone,
// step, gate, sensors that refused it) is copied by the repository from the
// parent row when it is inserted.
func NewFollowUp(parent *Command, remaining []string, settled int) (*Command, error) {
	payload, err := followUpPayload(parent.Payload, remaining)
	if err != nil {
		return nil, err
	}
	fu, err := NewCommand(parent.TenantID, parent.Type, parent.Priority, payload)
	if err != nil {
		return nil, err
	}
	fu.DispatchAttempts = FollowUpAttempts(parent.DispatchAttempts, settled)
	// The hosts of the remaining targets only, among those the parent held
	// (its payload carries the keys it was created with, AssignHostKeys).
	var fields map[string]json.RawMessage
	if json.Unmarshal(payload, &fields) == nil {
		if raw, ok := fields["host_keys"]; ok {
			var held []string
			if json.Unmarshal(raw, &held) == nil {
				fu.HostKeys = followUpHostKeys(held, remaining, payloadHostMeta(fields).network)
			}
		}
	}
	if err := AssignHostKeys(fu); err != nil {
		return nil, err
	}
	return fu, nil
}

// followUpPayload is payload with its targets replaced by targets: the
// "targets" list, and a single "target" only when one target is left (a
// sensor reads "target" as the whole job when it is set).
func followUpPayload(payload json.RawMessage, targets []string) (json.RawMessage, error) {
	if len(targets) == 0 {
		return nil, fmt.Errorf("follow-up without targets")
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(payload, &m); err != nil || m == nil {
		return nil, fmt.Errorf("read the command payload: %w", err)
	}
	list, err := json.Marshal(targets)
	if err != nil {
		return nil, err
	}
	m["targets"] = list
	if _, has := m["target"]; has {
		if len(targets) == 1 {
			one, _ := json.Marshal(targets[0])
			m["target"] = one
		} else {
			delete(m, "target")
		}
	}
	return json.Marshal(m)
}

// FollowUpCompleter completes a command and, in the same transaction,
// inserts its follow-up (nil: none). Like FencedUpdater.FencedUpdate it
// applies only while the command is still held by expect's sensor in its
// state and lease epoch; false when it was not applied (then no follow-up
// is inserted).
type FollowUpCompleter interface {
	CompleteWithFollowUp(ctx context.Context, cmd *Command, expect Fence, followUp *Command) (bool, error)
}
