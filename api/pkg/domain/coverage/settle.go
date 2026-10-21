package coverage

// Settlement per target: a run's step may end with more tasks than chunks
// (claim-time splits, follow-ups of unfinished targets), so a pair is
// settled from what happened to its own target across every task of the
// run, never from the run's or a task's overall status.

import (
	"encoding/json"
	"strings"

	"github.com/openctemio/ctis/outcome"
)

// TaskResult is one task (command) of a run as settlement reads it.
type TaskResult struct {
	Status  string // the command's status: completed, failed, canceled, expired, ...
	Error   string
	Targets []string
	Result  json.RawMessage
}

// Verdict kinds.
const (
	VerdictCovered = "covered"
	VerdictFailed  = "failed"
	VerdictBlocked = "blocked"
)

// Outcomes recorded on pairs settled per target, besides OutcomeOK and
// OutcomeFailed.
const (
	OutcomeUnfinished    = "unfinished"
	OutcomeNotDispatched = "not_dispatched"
)

// Verdict is how one target ended across a run's tasks.
type Verdict struct {
	Kind    string // VerdictCovered, VerdictFailed or VerdictBlocked
	Outcome string // ok, a failure class (unreachable, timeout, tool_error, egress_refused), unfinished, failed
	Reason  string // for blocked: the skip class (refused, excluded)
	Error   string
}

func (v Verdict) rank() int {
	switch {
	case v.Kind == VerdictCovered:
		return 4
	case v.Kind == VerdictBlocked:
		return 3
	case v.Kind == VerdictFailed && v.Outcome != OutcomeUnfinished:
		return 2
	default:
		return 1
	}
}

// TargetKey is how a target is matched across tasks and pairs.
func TargetKey(t string) string { return strings.ToLower(strings.TrimSpace(t)) }

// Verdicts reads a finished run's tasks per target. A task with per-target
// outcomes (ctis outcome, read against the task's own targets: a sensor
// cannot add a target) gives each target its own verdict; a target the
// sensor reported unreached is failed even when it called it done. A task
// without outcomes covers every target when it completed and fails every
// target otherwise. Across tasks the best verdict wins (a follow-up that
// finished a target overrides the task that left it unfinished). The run's
// own unfinished targets fail unless a task covered them.
func Verdicts(tasks []TaskResult, runUnfinished []string) map[string]Verdict {
	out := map[string]Verdict{}
	put := func(target string, v Verdict) {
		k := TargetKey(target)
		if k == "" {
			return
		}
		if old, ok := out[k]; !ok || v.rank() > old.rank() {
			out[k] = v
		}
	}
	for _, t := range tasks {
		outcomes, unreached, has := readResult(t.Result)
		if !has {
			switch t.Status {
			case "completed":
				for _, target := range t.Targets {
					// A target the sensor reported unreached is not covered,
					// whether or not the task carries per-target outcomes
					// (the run does not turn partial for it: the ledger is
					// where it stays visible).
					if unreached[TargetKey(target)] {
						put(target, Verdict{Kind: VerdictFailed, Outcome: string(outcome.Unreachable),
							Error: "the sensor reached no service on the target"})
						continue
					}
					put(target, Verdict{Kind: VerdictCovered, Outcome: OutcomeOK})
				}
			case "failed", "canceled", "expired", "timeout":
				for _, target := range t.Targets {
					put(target, Verdict{Kind: VerdictFailed, Outcome: OutcomeFailed, Error: t.Error})
				}
			}
			continue
		}
		for _, o := range outcome.Normalize(outcomes, t.Targets) {
			switch o.State {
			case outcome.Done:
				if unreached[TargetKey(o.Target)] {
					put(o.Target, Verdict{Kind: VerdictFailed, Outcome: string(outcome.Unreachable),
						Error: "the sensor reached no service on the target"})
					continue
				}
				put(o.Target, Verdict{Kind: VerdictCovered, Outcome: OutcomeOK})
			case outcome.Failed:
				put(o.Target, Verdict{Kind: VerdictFailed, Outcome: string(o.Class), Error: t.Error})
			case outcome.Skipped:
				put(o.Target, Verdict{Kind: VerdictBlocked, Reason: string(o.Class)})
			default:
				put(o.Target, Verdict{Kind: VerdictFailed, Outcome: OutcomeUnfinished,
					Error: "the run did not finish this target"})
			}
		}
	}
	for _, target := range runUnfinished {
		put(target, Verdict{Kind: VerdictFailed, Outcome: OutcomeUnfinished, Error: "the run did not finish this target"})
	}
	return out
}

// readResult returns a task result's per-target outcomes, the targets its
// metadata lists as unreached (also when it carries no outcomes), and
// whether it carries outcomes at all.
func readResult(raw json.RawMessage) ([]outcome.Target, map[string]bool, bool) {
	if len(raw) == 0 {
		return nil, nil, false
	}
	var r struct {
		Outcomes *[]outcome.Target `json:"target_outcomes"`
		Metadata struct {
			Unreached []struct {
				Target string `json:"target"`
			} `json:"unreached_targets"`
		} `json:"metadata"`
	}
	if json.Unmarshal(raw, &r) != nil {
		return nil, nil, false
	}
	unreached := map[string]bool{}
	for _, u := range r.Metadata.Unreached {
		unreached[TargetKey(u.Target)] = true
	}
	if r.Outcomes == nil {
		return nil, unreached, false
	}
	return *r.Outcomes, unreached, true
}
