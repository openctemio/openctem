package scanrun

// Per-target reach outcomes of a completed task (RFC-089 §4.2 and §4.7,
// docs/rfcs/RFC-089-reachability-aware-routing.md). A sensor reports, in
// its result metadata, how many of the task's targets it reached (any
// answer, a closed port included) and how many it could not reach (no
// route, refused by a filter, timeout, name not resolving), with a bounded
// list of the unreached ones. Unreachable is not "nothing found": a task
// that reached none of its targets fails the step with TARGET_UNREACHABLE,
// one that missed some ends it partial.
//
// Everything here is sensor-supplied: parsed defensively, bounded, cleaned
// and only ever shown as text. A result without a reach summary (an older
// sensor) keeps today's behavior.

import (
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strings"

	"github.com/openctemio/openctem/api/pkg/safetext"
)

// FailureTargetUnreachable: the sensor could not reach the step's targets
// (no route, a filter refused it, every attempt timed out, the names did
// not resolve in its view). The fix is routing the work to a sensor that
// can reach it, not a retry of the same work.
const FailureTargetUnreachable = "TARGET_UNREACHABLE"

// Reach outcome classes a sensor reports.
const (
	ReachReached         = "reached"
	ReachPortClosed      = "port_closed"
	ReachNoRoute         = "no_route"
	ReachFirewallRefused = "firewall_refused"
	ReachTimeout         = "timeout"
	ReachDNSFailure      = "dns_failure"
	ReachUnknown         = "unknown"
)

// Bounds of a task's reach report.
const (
	// MaxReachTargets caps every count a sensor reports.
	MaxReachTargets = 1_000_000
	// MaxTaskUnreachedTargets is how many unreached targets a task lists.
	MaxTaskUnreachedTargets = 20
	maxUnreachedTargetRunes = 256
	maxUnreachedDetailRunes = 256
	maxUnreachedInSummary   = 5
)

// reachClasses is the closed set, in the order a summary lists them.
var reachClasses = []string{
	ReachReached, ReachPortClosed, ReachNoRoute, ReachFirewallRefused,
	ReachTimeout, ReachDNSFailure, ReachUnknown,
}

// unreachedClass reports whether class says the path to a target does not
// work from the sensor.
func unreachedClass(class string) bool {
	switch class {
	case ReachNoRoute, ReachFirewallRefused, ReachTimeout, ReachDNSFailure:
		return true
	}
	return false
}

func knownReachClass(class string) bool {
	for _, c := range reachClasses {
		if c == class {
			return true
		}
	}
	return false
}

// Reach is a task's reach summary. Present is false when the result has
// none (or it cannot be read): the task's outcome is then decided as before.
type Reach struct {
	Present   bool
	Targets   int
	Reached   int
	Unreached int
	// Classes counts targets per known class (unknown classes dropped).
	Classes map[string]int
}

// AllUnreached reports whether the task tried targets and reached none.
func (r Reach) AllUnreached() bool {
	return r.Present && r.Targets > 0 && r.Reached == 0 && r.Unreached > 0
}

// UnreachedTarget is one target a sensor could not reach, and how.
type UnreachedTarget struct {
	Target string `json:"target"`
	Class  string `json:"class"`
	Detail string `json:"detail,omitempty"`
}

func clampCount(v any) int {
	f, ok := v.(float64)
	if !ok || math.IsNaN(f) || f <= 0 {
		return 0
	}
	if f >= MaxReachTargets {
		return MaxReachTargets
	}
	return int(f)
}

// ParseReach reads a task result's reach summary. Counts are clamped to
// [0, MaxReachTargets]; reached and unreached never exceed targets; a
// summary that is not an object, or has no targets count, is not present.
func ParseReach(raw json.RawMessage) Reach {
	var m map[string]any
	if len(raw) == 0 || json.Unmarshal(raw, &m) != nil || m == nil {
		return Reach{}
	}
	if _, ok := m["targets"].(float64); !ok {
		return Reach{}
	}
	r := Reach{Present: true, Targets: clampCount(m["targets"])}
	r.Reached = min(clampCount(m["reached"]), r.Targets)
	r.Unreached = min(clampCount(m["unreached"]), r.Targets-r.Reached)
	if classes, ok := m["classes"].(map[string]any); ok {
		for k, v := range classes {
			if n := clampCount(v); n > 0 && knownReachClass(k) {
				if r.Classes == nil {
					r.Classes = map[string]int{}
				}
				r.Classes[k] = n
			}
		}
	}
	return r
}

// ParseUnreachedTargets reads a task result's unreached_targets list and
// unreached_targets_total. It keeps at most MaxTaskUnreachedTargets
// entries, cleans every string to one bounded line and drops entries
// without a target or whose class is not an unreached one. The total is at
// least the number listed and at most MaxReachTargets.
func ParseUnreachedTargets(list json.RawMessage, total int) ([]UnreachedTarget, int) {
	var raw []map[string]any
	if len(list) > 0 {
		_ = json.Unmarshal(list, &raw)
	}
	out := make([]UnreachedTarget, 0, min(len(raw), MaxTaskUnreachedTargets))
	seen := 0
	for _, e := range raw {
		target, _ := e["target"].(string)
		target = safetext.SingleLine(target, maxUnreachedTargetRunes)
		class, _ := e["class"].(string)
		if target == "" || !unreachedClass(class) {
			continue
		}
		seen++
		if len(out) >= MaxTaskUnreachedTargets {
			continue
		}
		detail, _ := e["detail"].(string)
		out = append(out, UnreachedTarget{Target: target, Class: class, Detail: safetext.SingleLine(detail, maxUnreachedDetailRunes)})
	}
	if len(out) == 0 {
		out = nil
	}
	total = max(total, seen, 0)
	total = min(total, MaxReachTargets)
	return out, total
}

// unreachedCount is how many targets a task did not reach: the summary's
// count, or the listed total when the summary has none.
func unreachedCount(r Reach, listedTotal int) int {
	if r.Unreached > 0 {
		return r.Unreached
	}
	return listedTotal
}

// classBreakdown is "timeout 2, no_route 1" over the unreached classes,
// largest first.
func classBreakdown(classes map[string]int) string {
	type kv struct {
		k string
		n int
	}
	var list []kv
	for _, c := range reachClasses {
		if n := classes[c]; n > 0 && unreachedClass(c) {
			list = append(list, kv{c, n})
		}
	}
	sort.SliceStable(list, func(i, j int) bool { return list[i].n > list[j].n })
	parts := make([]string, 0, len(list))
	for _, e := range list {
		parts = append(parts, fmt.Sprintf("%s %d", e.k, e.n))
	}
	return strings.Join(parts, ", ")
}

func writeUnreachedList(b *strings.Builder, list []UnreachedTarget, total int) {
	for i, u := range list {
		if i == maxUnreachedInSummary {
			break
		}
		if i == 0 {
			b.WriteString(": ")
		} else {
			b.WriteString(", ")
		}
		fmt.Fprintf(b, "%s (%s)", u.Target, u.Class)
	}
	if n := total - min(len(list), maxUnreachedInSummary); n > 0 && len(list) > 0 {
		fmt.Fprintf(b, ", and %d more", n)
	}
}

// UnreachableFailure is the step message of a task that reached none of
// its targets: "No target was reachable from the sensor (3 target(s):
// timeout 2, no_route 1): 192.0.2.7 (timeout), ...".
func UnreachableFailure(r Reach, list []UnreachedTarget, listedTotal int) string {
	n := unreachedCount(r, listedTotal)
	var b strings.Builder
	fmt.Fprintf(&b, "No target was reachable from the sensor (%d target(s)", n)
	if br := classBreakdown(r.Classes); br != "" {
		b.WriteString(": " + br)
	}
	b.WriteString(")")
	writeUnreachedList(&b, list, listedTotal)
	return b.String()
}

// UnreachedSummary is the step message of a task that completed with some
// targets unreached ("" when none): "Completed with 3 of 12 target(s)
// unreachable from the sensor (timeout 2, no_route 1): ...".
func UnreachedSummary(r Reach, list []UnreachedTarget, listedTotal int) string {
	n := unreachedCount(r, listedTotal)
	if n <= 0 {
		return ""
	}
	var b strings.Builder
	if r.Targets >= n {
		fmt.Fprintf(&b, "Completed with %d of %d target(s) unreachable from the sensor", n, r.Targets)
	} else {
		fmt.Fprintf(&b, "Completed with %d target(s) unreachable from the sensor", n)
	}
	if br := classBreakdown(r.Classes); br != "" {
		b.WriteString(" (" + br + ")")
	}
	writeUnreachedList(&b, list, listedTotal)
	return b.String()
}
