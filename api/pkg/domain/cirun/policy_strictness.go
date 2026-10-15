package cirun

// AtLeastAsStrictAs reports whether policy p fails every run q fails: on each
// setting p is the same as q or stricter (enabled, enforce, a lower severity
// threshold, every finding rather than new only, KEV failing, a lower EPSS
// threshold, no fixable-only relief, no repository file, and a mode at least
// as strong for every capability and rule; a mode not set is block).
func (p GatePolicy) AtLeastAsStrictAs(q GatePolicy) bool {
	switch {
	case q.Enabled && !p.Enabled,
		q.Mode == ModeEnforce && p.Mode != ModeEnforce,
		rank(p.FailOnSeverity) > rank(q.FailOnSeverity),
		p.NewFindingsOnly && !q.NewFindingsOnly,
		q.FailOnKEV && !p.FailOnKEV,
		q.EPSSThreshold != nil && (p.EPSSThreshold == nil || *p.EPSSThreshold > *q.EPSSThreshold),
		p.FixableOnly && !q.FixableOnly,
		p.AllowRepoPolicy && !q.AllowRepoPolicy:
		return false
	}
	return modesAtLeast(p.Modes.Capabilities, q.Modes.Capabilities) && modesAtLeast(p.Modes.Rules, q.Modes.Rules)
}

// modesAtLeast reports whether every key's mode in p is at least as strong as
// in q, a key missing on either side meaning block.
func modesAtLeast(p, q map[string]string) bool {
	get := func(m map[string]string, k string) int {
		if v, ok := m[k]; ok {
			return modeRank(v)
		}
		return modeRank(FindingModeBlock)
	}
	for k := range p {
		if get(p, k) < get(q, k) {
			return false
		}
	}
	for k := range q {
		if get(p, k) < get(q, k) {
			return false
		}
	}
	return true
}

// StrictestPolicy returns the index of a policy at least as strict as every
// other one, and false when there is none (the policies are stricter on
// different settings, so keeping any one would loosen the gate).
func StrictestPolicy(ps []GatePolicy) (int, bool) {
	for i := range ps {
		all := true
		for j := range ps {
			if i != j && !ps[i].AtLeastAsStrictAs(ps[j]) {
				all = false
				break
			}
		}
		if all {
			return i, true
		}
	}
	return -1, false
}
