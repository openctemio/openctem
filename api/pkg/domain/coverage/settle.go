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
	"github.com/openctemio/openctem/api/pkg/domain/scanrun"
	"github.com/openctemio/openctem/api/pkg/safetext"
)

// TaskResult is one task (command) of a run as settlement reads it.
type TaskResult struct {
	Status  string // the command's status: completed, failed, canceled, expired, ...
	Error   string
	Targets []string
	Result  json.RawMessage
	// Observer is who ran the task: ObserverKey of its scan zone or its
	// sensor ("" when no sensor took it).
	Observer string
}

// ObserverKey is the key a target-side observation is recorded under:
// "zone:<id>" when the task ran for a scan zone (any sensor of the zone
// sees the same network), else "sensor:<id>", "" when neither is known.
func ObserverKey(zoneID, sensorID string) string {
	switch {
	case zoneID != "":
		return "zone:" + zoneID
	case sensorID != "":
		return "sensor:" + sensorID
	}
	return ""
}

// Verdict kinds.
const (
	VerdictCovered = "covered"
	VerdictFailed  = "failed"
	VerdictBlocked = "blocked"
	// VerdictUnresolved: the target is a name that does not resolve. Its
	// Outcome is OutcomeNoAnswer (the resolver answered that the name has
	// no address: NXDOMAIN or NODATA) or ReasonResolverFailed (the lookup
	// itself failed). A fact about the name, never a failure of the scan.
	VerdictUnresolved = "unresolved"
)

// CapabilityResolveDNS is the DNS resolution capability: for it, a name
// that does not resolve is the answer (OutcomeNoAnswer), not a refusal.
const CapabilityResolveDNS = "resolve.dns"

// Dead-name outcomes and reasons.
const (
	// OutcomeNoAnswer: the DNS resolution of the name answered that it has
	// no address. The resolve.dns pair is covered with this outcome and
	// the name is parked (IsParked).
	OutcomeNoAnswer = "no_answer"
	// ReasonUnresolvable blocks a pair of another capability whose target
	// the sensor could not resolve, on the dead-name recheck schedule.
	ReasonUnresolvable = "unresolvable"
	// ReasonResolverFailed: the lookup failed (SERVFAIL, REFUSED, a resolver
	// timeout); ambiguous, it may be the sensor's own DNS.
	ReasonResolverFailed = "resolver_failed"
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
	// Observer is the task's TaskResult.Observer for a failed verdict.
	Observer string
	// Vendor is the edge protection behind an edge_blocked or
	// edge_challenged outcome (a token), "" when unknown.
	Vendor string
}

func (v Verdict) rank() int {
	switch {
	case v.Kind == VerdictCovered:
		return 4
	case v.Kind == VerdictBlocked, v.Kind == VerdictUnresolved:
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
	for _, task := range tasks {
		t := task
		put := func(target string, v Verdict) {
			if v.Kind == VerdictFailed {
				v.Observer = t.Observer
			}
			put(target, v)
		}
		outcomes, unreached, has := readResult(t.Result)
		refused := readRefused(t.Result)
		gaps := readGaps(t.Result)
		// A target the sensor refused before any tool saw it (listed in
		// the result's refused_targets, read against the task's own
		// targets: a sensor cannot settle a target of another task) is
		// never covered. A name that does not resolve is unresolved; any
		// other refusal blocks the target with its reason.
		for _, target := range t.Targets {
			if r, ok := refused[TargetKey(target)]; ok {
				put(target, r)
			}
		}
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
					if _, ok := refused[TargetKey(target)]; ok {
						continue
					}
					// A host the sensor lists as a coverage gap (an edge
					// protection blocked it, it kept pushing back, it
					// stopped answering, the proxy failed) was not
					// scanned, however the task ended.
					if v, ok := gaps.verdict(target); ok {
						put(target, v)
						continue
					}
					if gaps.short {
						put(target, Verdict{Kind: VerdictFailed, Outcome: OutcomeUnfinished,
							Error: "the result lists fewer coverage gaps than it counts; no target of it is treated as covered"})
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
				// A gap names the host: the gap wins over a done outcome.
				if v, ok := gaps.verdict(o.Target); ok {
					put(o.Target, v)
					continue
				}
				put(o.Target, Verdict{Kind: VerdictCovered, Outcome: OutcomeOK})
			case outcome.Failed:
				if o.Class == outcome.NameGone || o.Class == outcome.ResolverFailed {
					put(o.Target, unresolvedVerdict(string(o.Class)))
					continue
				}
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
				put(o.Target, Verdict{Kind: VerdictFailed, Outcome: string(o.Class), Error: t.Error,
					Vendor: edgeVendor(o)})
			case outcome.Skipped:
				if r, ok := refused[TargetKey(o.Target)]; ok {
					put(o.Target, r)
					continue
				}
				if o.Class == outcome.EdgeBlocked || o.Class == outcome.EdgeChallenged {
					// An edge protection answered in place of the service:
					// not covered, an observation of the target.
					put(o.Target, Verdict{Kind: VerdictFailed, Outcome: string(o.Class),
						Error: edgeError(string(o.Class)), Vendor: edgeVendor(o)})
					continue
				}
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

// unresolvedVerdict is the verdict of a name that does not resolve, from
// the sensor's DNS kind: "resolver_failed" when the lookup failed, else
// (name_gone, or a sensor that does not say) no answer.
func unresolvedVerdict(dns string) Verdict {
	if dns == ReasonResolverFailed {
		return Verdict{Kind: VerdictUnresolved, Outcome: ReasonResolverFailed,
			Error: "the sensor's DNS lookup of the name failed"}
	}
	return Verdict{Kind: VerdictUnresolved, Outcome: OutcomeNoAnswer, Error: "the name has no address"}
}

// Refused-target reasons a sensor lists in refused_targets (sdk-go
// core.RefusedTarget*).
const refusedUnresolvable = "unresolvable"

// readRefused returns the targets a task result's metadata lists as
// refused by the sensor (refused_targets), by TargetKey: a name that does
// not resolve as unresolved (with its DNS kind), any other refusal as
// blocked with its reason. The list is sensor-supplied and bounded; the
// caller reads it only for the task's own targets.
func readRefused(raw json.RawMessage) map[string]Verdict {
	if len(raw) == 0 {
		return nil
	}
	var r struct {
		Metadata struct {
			Refused []struct {
				Target string `json:"target"`
				Reason string `json:"reason"`
				DNS    string `json:"dns"`
			} `json:"refused_targets"`
		} `json:"metadata"`
	}
	if json.Unmarshal(raw, &r) != nil || len(r.Metadata.Refused) == 0 {
		return nil
	}
	out := make(map[string]Verdict, min(len(r.Metadata.Refused), maxRefusedRead))
	for i, e := range r.Metadata.Refused {
		if i == maxRefusedRead {
			break
		}
		k := TargetKey(e.Target)
		if k == "" {
			continue
		}
		if e.Reason == refusedUnresolvable {
			out[k] = unresolvedVerdict(e.DNS)
			continue
		}
		out[k] = Verdict{Kind: VerdictBlocked, Reason: string(outcome.Refused)}
	}
	return out
}

// maxRefusedRead bounds the refused targets read from one result.
const maxRefusedRead = 1000

// DeadNameRechecks is the recheck schedule of a name that does not
// resolve (a resolve.dns pair covered with no answer, or a pair of another
// capability blocked as unresolvable): the target-side schedule, 1 day,
// 3 days, 7 days, then weekly.
func DeadNameRechecks() []time.Duration { return append([]time.Duration(nil), TargetSideRechecks...) }

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

// edgeVendor is the vendor token of an edge outcome ("" for any other, or
// when the sensor's value is not a token).
func edgeVendor(o outcome.Target) string {
	if o.Class != outcome.EdgeBlocked && o.Class != outcome.EdgeChallenged {
		return ""
	}
	return safetext.VendorToken(o.Vendor)
}

func edgeError(class string) string {
	if class == string(outcome.EdgeChallenged) {
		return "an edge protection challenged the scan"
	}
	return "an edge protection blocked the scan"
}

// maxGapsRead bounds the coverage gaps read from one result.
const maxGapsRead = 1000

// resultGaps is a task result's metadata.coverage_gaps, by host.
type resultGaps struct {
	byHost map[string]scanrun.CoverageGap
	// short: the list names fewer hosts than the result counts (or an entry
	// has no host), so the hosts it leaves out are unknown.
	short bool
}

// readGaps reads a task result's coverage gaps. The list is sensor-supplied
// and bounded; it is read only for the task's own targets (verdict).
func readGaps(raw json.RawMessage) resultGaps {
	if len(raw) == 0 {
		return resultGaps{}
	}
	var r struct {
		Metadata struct {
			Gaps  []json.RawMessage `json:"coverage_gaps"`
			Total int               `json:"coverage_gaps_total"`
		} `json:"metadata"`
	}
	if json.Unmarshal(raw, &r) != nil {
		return resultGaps{}
	}
	m := r.Metadata
	g := resultGaps{short: len(m.Gaps) < m.Total}
	if len(m.Gaps) > maxGapsRead {
		m.Gaps = m.Gaps[:maxGapsRead]
		g.short = true
	}
	g.byHost = make(map[string]scanrun.CoverageGap, len(m.Gaps))
	for _, e := range m.Gaps {
		var one struct {
			Host   string `json:"host"`
			Reason string `json:"reason"`
			Edge   string `json:"edge"`
			Vendor string `json:"vendor"`
		}
		if json.Unmarshal(e, &one) != nil || gapHostKey(one.Host) == "" {
			g.short = true
			continue
		}
		gap := scanrun.CoverageGap{Host: one.Host, Reason: one.Reason}
		if one.Reason == scanrun.GapReasonBlocked {
			if one.Edge == scanrun.EdgeChallenged || one.Edge == scanrun.EdgeBlocked {
				gap.Edge = one.Edge
			}
			gap.Vendor = safetext.VendorToken(one.Vendor)
		}
		k := gapHostKey(one.Host)
		if old, ok := g.byHost[k]; ok && gapRank(old) >= gapRank(gap) {
			continue
		}
		g.byHost[k] = gap
	}
	return g
}

// gapRank orders two gaps of one host: an edge answer is the most telling.
func gapRank(g scanrun.CoverageGap) int {
	if g.Reason == scanrun.GapReasonBlocked {
		return 2
	}
	return 1
}

// gapHostKey is the comparison form of a host or a target: its host name
// lower-cased, without scheme, path, credentials or port.
func gapHostKey(s string) string {
	s = TargetKey(s)
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	if i := strings.IndexAny(s, "/?#"); i >= 0 {
		s = s[:i]
	}
	if i := strings.LastIndex(s, "@"); i >= 0 {
		s = s[i+1:]
	}
	if strings.HasPrefix(s, "[") {
		if i := strings.Index(s, "]"); i > 0 {
			return s[1:i]
		}
		return s
	}
	if strings.Count(s, ":") == 1 {
		s, _, _ = strings.Cut(s, ":")
	}
	return s
}

// verdict is the failed verdict of a task target whose host the result
// lists as a gap, mapped like the sensor's own per-target outcomes: blocked
// is edge_blocked (edge_challenged when the sensor says challenged),
// rate_floor is rate_limited, breaker_open is unreachable and
// proxy_unavailable is sensor_network_fault (the platform's side). A reason
// this package does not know is unfinished: never covered.
func (g resultGaps) verdict(target string) (Verdict, bool) {
	if len(g.byHost) == 0 {
		return Verdict{}, false
	}
	gap, ok := g.byHost[gapHostKey(target)]
	if !ok {
		return Verdict{}, false
	}
	switch gap.Reason {
	case scanrun.GapReasonBlocked:
		class := string(outcome.EdgeBlocked)
		if gap.Edge == scanrun.EdgeChallenged {
			class = string(outcome.EdgeChallenged)
		}
		return Verdict{Kind: VerdictFailed, Outcome: class, Error: edgeError(class), Vendor: gap.Vendor}, true
	case scanrun.GapReasonRateFloor:
		return Verdict{Kind: VerdictFailed, Outcome: string(outcome.RateLimited),
			Error: "the target kept pushing back at the lowest scan rate"}, true
	case scanrun.GapReasonBreakerOpen:
		return Verdict{Kind: VerdictFailed, Outcome: string(outcome.Unreachable), Error: "stopped answering"}, true
	case scanrun.GapReasonProxyUnavailable:
		return Verdict{Kind: VerdictFailed, Outcome: string(outcome.SensorNetworkFault),
			Error: "the scan's proxy failed, so the host was not judged"}, true
	}
	return Verdict{Kind: VerdictFailed, Outcome: OutcomeUnfinished,
		Error: "the sensor listed the host as a coverage gap"}, true
}
