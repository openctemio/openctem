package command

// Per-host politeness on the shared fleet, across organizations
// (docs/rfcs/RFC-129-shared-fleet-scheduling.md §5). A shared job's traffic
// leaves through the platform's egress whichever organization asked, so the
// target is protected across organizations: at most a few shared jobs hold
// one host at once. An organization's own sensors keep per-organization
// keys (their own egress).

// Shared-fleet host limits: how many shared jobs, of any organizations, may
// hold a conflicting host key at once.
const (
	// SharedFleetHostLimit is the limit for ordinary (passive or safe
	// active) shared work.
	SharedFleetHostLimit = 2
	// SharedFleetIntrusiveHostLimit is the limit for a shared job queued at
	// the intrusive tier: one at a time per host.
	SharedFleetIntrusiveHostLimit = 1
)

// SharedFleetHostLimitFor is the shared-fleet host limit of a job whose
// dispatch gate is g: SharedFleetIntrusiveHostLimit when it was queued
// under the intrusive intensity or checked at the intrusive tier.
func SharedFleetHostLimitFor(g DispatchGate) int {
	if g.Intensity == "intrusive" || g.Tier >= 2 {
		return SharedFleetIntrusiveHostLimit
	}
	return SharedFleetHostLimit
}

// SharedFleetHostsAllowed decides which of a batch of shared jobs may start
// now. held counts, per host key, the shared jobs in flight that still hold
// it; jobs are visited in order, each with its stored keys and its limit. A
// job is kept when, for each key it conflicts with (HostKeyConflicts), fewer
// than its limit hold that key; a kept job then holds its own keys for the
// jobs after it. Jobs without keys are always kept. held is updated.
func SharedFleetHostsAllowed(held map[string]int, jobs []SharedFleetJob) []string {
	out := make([]string, 0, len(jobs))
next:
	for _, j := range jobs {
		for _, k := range HostKeyConflicts(j.Keys) {
			if held[k] >= j.Limit {
				continue next
			}
		}
		for _, k := range j.Keys {
			held[k]++
		}
		out = append(out, j.ID)
	}
	return out
}

// SharedFleetJob is one candidate of SharedFleetHostsAllowed.
type SharedFleetJob struct {
	ID    string
	Keys  []string
	Limit int
}
