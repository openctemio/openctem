package coverage

// Settlement per target: a run's step may end with more tasks than chunks
// (claim-time splits, follow-ups of unfinished targets), so a pair is
// settled from what happened to its own target across every task of the
// run, never from the run's or a task's overall status.

import (
	"encoding/json"
	"strings"
	"time"

	"github.com/openctemio/ctis/outcome"

	"github.com/openctemio/openctem/api/pkg/domain/command"
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
// own unfinished targets fail unless a task covered them. A truncated task
// (metadata.truncated: cut short by a deadline, disk or cap) covers nothing:
// its done targets are unfinished, so a later complete task decides them.
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
		if t.Status == "completed" && command.ResultTruncated(t.Result) {
			if has {
				// A done outcome of a truncated task is withheld: the
				// target reads as unfinished (Normalize), and a later
				// complete task decides it.
				outcomes = dropDone(outcomes)
			} else {
				for _, target := range t.Targets {
					if unreached[TargetKey(target)] {
						put(target, Verdict{Kind: VerdictFailed, Outcome: string(outcome.Unreachable),
							Error: "the sensor reached no service on the target"})
						continue
					}
					put(target, Verdict{Kind: VerdictFailed, Outcome: OutcomeUnfinished,
						Error: "the result was cut short; no target of it is treated as covered"})
				}
				continue
			}
		}
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
		norm := outcome.Normalize(outcomes, t.Targets)
		allTargetSide := uniformTargetSideFailure(norm)
		for _, o := range norm {
			switch o.State {
			case outcome.Done:
				if unreached[TargetKey(o.Target)] {
					put(o.Target, Verdict{Kind: VerdictFailed, Outcome: string(outcome.Unreachable),
						Error: "the sensor reached no service on the target"})
					continue
				}
				put(o.Target, Verdict{Kind: VerdictCovered, Outcome: OutcomeOK})
			case outcome.Failed:
				if allTargetSide {
					// Every target of the task failed the same target-side
					// way: that points at the sensor (no route, no egress),
					// not at each target. Until a reach control probe can
					// tell them apart, treat it as a sensor failure with the
					// normal back-off instead of pausing every target.
					msg := t.Error
					if msg == "" {
						msg = "every target of the task failed with " + string(o.Class) + "; treated as a sensor failure"
					}
					put(o.Target, Verdict{Kind: VerdictFailed, Outcome: OutcomeFailed, Error: msg})
					continue
				}
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

// uniformTargetSideFailure reports whether a task with at least two targets
// failed every one of them with the same target-side class (all timeouts,
// or all unreachable). One target cannot be told from its sensor, so a lone
// target keeps its own verdict.
func uniformTargetSideFailure(norm []outcome.Target) bool {
	if len(norm) < 2 {
		return false
	}
	for _, o := range norm {
		if o.State != outcome.Failed || o.Class != norm[0].Class || !IsTargetSide(string(o.Class)) {
			return false
		}
	}
	return true
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

// Target-side outcomes: the target did not answer (it is down, filtered or
// gone), not a failure of the sensor, the tool or the platform. Such a pair
// is not retried on the failure back-off: it is paused with the outcome as
// its reason and rechecked on TargetSideRecheck's schedule; any success
// makes it covered again. Every other failure keeps the back-off.
var targetSideOutcomes = []string{string(outcome.Unreachable), string(outcome.Timeout)}

// TargetSideOutcomes returns the outcomes that pause a pair for a recheck.
func TargetSideOutcomes() []string { return append([]string(nil), targetSideOutcomes...) }

// IsTargetSide reports whether a failure outcome is the target's.
func IsTargetSide(outcome string) bool {
	for _, o := range targetSideOutcomes {
		if o == outcome {
			return true
		}
	}
	return false
}

// TargetSideRechecks is the recheck schedule of a pair whose target did not
// answer: after the first observation 1 day, after the second 3 days, then
// 7 days, and weekly from then on.
var TargetSideRechecks = []time.Duration{24 * time.Hour, 3 * 24 * time.Hour, 7 * 24 * time.Hour}

// TargetSideRecheck is when a pair is rechecked after its n-th consecutive
// target-side observation (n >= 1).
func TargetSideRecheck(n int) time.Duration {
	if n < 1 {
		n = 1
	}
	if n > len(TargetSideRechecks) {
		n = len(TargetSideRechecks)
	}
	return TargetSideRechecks[n-1]
}

// dropDone removes the done outcomes, which a truncated task withholds.
func dropDone(in []outcome.Target) []outcome.Target {
	out := make([]outcome.Target, 0, len(in))
	for _, o := range in {
		if o.State != outcome.Done {
			out = append(out, o)
		}
	}
	return out
}
