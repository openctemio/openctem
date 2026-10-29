package scanrun

// Targets a sensor skipped in a completed task (sensor-local policy, api
// RFC-040 §5.7, docs/rfcs/RFC-040-platform-sensor-mutual-distrust.md). A
// sensor removes a target its local policy refuses or cannot check (the
// name does not resolve, a wildcard pattern) and runs the task on the rest;
// its result metadata lists what it skipped (refused_targets) and how many
// (refused_targets_total). The step and the run end partial.
//
// The list is sensor-supplied: it is parsed defensively, bounded, cleaned
// and only ever shown as text.

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/openctemio/openctem/api/pkg/safetext"
)

// Skipped-target reasons a sensor reports (a sensor says "unresolvable",
// the platform names it SkipReasonTargetUnresolvable). Anything else reads
// as SkipReasonRefused.
const (
	SkipReasonUnresolvable       = "unresolvable"
	SkipReasonTargetUnresolvable = "target_unresolvable"
	SkipReasonWildcard           = "wildcard_pattern"
	SkipReasonDenied             = "denied_by_policy"
	SkipReasonInvalid            = "invalid_target"
	SkipReasonRefused            = "refused"
)

// Bounds of a task's skipped targets.
const (
	// MaxTaskSkippedTargets is how many skipped targets a task lists.
	MaxTaskSkippedTargets = 20
	// MaxSkippedTargetsTotal caps the count a sensor reports.
	MaxSkippedTargetsTotal = 1_000_000
	maxSkippedTargetRunes  = 256
	maxSkippedDetailRunes  = 256
	maxSkippedRuleRunes    = 64
	maxSkippedInSummary    = 5
)

// SkipRuleTargetGuard is the rule of a target the sensor's target guard (its
// built-in network and path checks, not a local policy rule) refused: sdk-go
// core.RefusedTargetRuleGuard.
const SkipRuleTargetGuard = "target_guard"

// GuardRefusedCount is how many of a task's targets the sensor's target
// guard refused, from its result's refused_targets list: guardListed of
// the listed entries carry SkipRuleTargetGuard, total is the task's
// refused_targets_total. A sensor lists a bounded number of entries; when
// every listed one is the guard's, the unlisted rest are counted as the
// guard's too. Never more than the task's targets (sensor-supplied).
func GuardRefusedCount(guardListed, listed, total, targets int) int {
	n := max(guardListed, 0)
	if n > 0 && n == listed && total > listed {
		n = total
	}
	return min(n, max(targets, 0))
}

// ErrCodeTargetsSkipped is the code of a step that completed with targets
// its sensor skipped.
const ErrCodeTargetsSkipped = "TARGETS_SKIPPED"

// SkippedTarget is one target a sensor skipped, and why.
type SkippedTarget struct {
	Target string `json:"target"`
	Reason string `json:"reason"`
	Rule   string `json:"rule,omitempty"`
	Detail string `json:"detail,omitempty"`
}

// ParseSkippedTargets reads a task result's refused_targets list and
// refused_targets_total. It keeps at most MaxTaskSkippedTargets entries,
// cleans every string to one bounded line, maps an unknown reason to
// SkipReasonRefused and drops entries without a target. The total is at
// least the number listed and at most MaxSkippedTargetsTotal. Malformed
// input yields what could be read.
func ParseSkippedTargets(list json.RawMessage, total int) ([]SkippedTarget, int) {
	var raw []map[string]any
	if len(list) > 0 {
		_ = json.Unmarshal(list, &raw)
	}
	out := make([]SkippedTarget, 0, min(len(raw), MaxTaskSkippedTargets))
	seen := 0
	for _, e := range raw {
		target, _ := e["target"].(string)
		target = safetext.SingleLine(target, maxSkippedTargetRunes)
		if target == "" {
			continue
		}
		seen++
		if len(out) >= MaxTaskSkippedTargets {
			continue
		}
		reason, _ := e["reason"].(string)
		rule, _ := e["rule"].(string)
		detail, _ := e["detail"].(string)
		out = append(out, SkippedTarget{
			Target: target,
			Reason: normalizeSkipReason(reason),
			Rule:   safetext.SingleLine(rule, maxSkippedRuleRunes),
			Detail: safetext.SingleLine(detail, maxSkippedDetailRunes),
		})
	}
	if len(out) == 0 {
		out = nil
	}
	total = max(total, seen)
	total = min(total, MaxSkippedTargetsTotal)
	return out, total
}

func normalizeSkipReason(r string) string {
	switch r {
	case SkipReasonUnresolvable, SkipReasonTargetUnresolvable:
		return SkipReasonTargetUnresolvable
	case SkipReasonWildcard, SkipReasonDenied, SkipReasonInvalid:
		return r
	}
	return SkipReasonRefused
}

// SkippedSummary is the step message of a task that completed with
// skipped targets: "Completed with 2 target(s) skipped by the sensor's
// local policy: api.example.com (unresolvable), *.example.com
// (wildcard_pattern)".
func SkippedSummary(list []SkippedTarget, total int) string {
	if total <= 0 {
		return ""
	}
	var b strings.Builder
	if allUnresolvable(list, total) {
		fmt.Fprintf(&b, "%d name(s) no longer resolve", total)
		for i, t := range list {
			if i == maxSkippedInSummary {
				break
			}
			if i == 0 {
				b.WriteString(": ")
			} else {
				b.WriteString(", ")
			}
			b.WriteString(t.Target)
		}
		if n := total - min(len(list), maxSkippedInSummary); n > 0 && len(list) > 0 {
			fmt.Fprintf(&b, ", and %d more", n)
		}
		return b.String()
	}
	fmt.Fprintf(&b, "Completed with %d target(s) skipped by the sensor's local policy", total)
	for i, t := range list {
		if i == maxSkippedInSummary {
			break
		}
		if i == 0 {
			b.WriteString(": ")
		} else {
			b.WriteString(", ")
		}
		fmt.Fprintf(&b, "%s (%s)", t.Target, t.Reason)
	}
	if n := total - min(len(list), maxSkippedInSummary); n > 0 && len(list) > 0 {
		fmt.Fprintf(&b, ", and %d more", n)
	}
	return b.String()
}

// UnresolvableCount is how many of a task's skipped targets are names that
// no longer resolve: all of them when every listed one is (the unlisted rest
// can only be counted), otherwise the listed ones.
func UnresolvableCount(list []SkippedTarget, total int) int {
	if allUnresolvable(list, total) {
		return total
	}
	n := 0
	for _, t := range list {
		if t.Reason == SkipReasonTargetUnresolvable {
			n++
		}
	}
	return n
}

// allUnresolvable reports whether every skipped target (listed, and the
// unlisted rest, which can only be counted) is a name that no longer
// resolves: the listed ones all are.
func allUnresolvable(list []SkippedTarget, total int) bool {
	if len(list) == 0 || total <= 0 {
		return false
	}
	for _, t := range list {
		if t.Reason != SkipReasonTargetUnresolvable {
			return false
		}
	}
	return true
}
