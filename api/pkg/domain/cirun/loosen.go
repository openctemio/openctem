package cirun

import (
	"maps"
	"slices"
)

// Loosens lists what the policy after a change lets pass that the policy
// before it did not (empty when nothing loosens): a policy change that
// weakens the gate needs step-up and is announced to every administrator
// (docs/rfcs/RFC-051-ci-runner-identity-and-gate.md section 6), the same as
// a break-glass. before and after are the policies that apply to the scope
// (what it inherits when it has no enabled policy of its own).
func Loosens(before, after GatePolicy) []string {
	var out []string
	if before.Mode == ModeEnforce && after.Mode != ModeEnforce {
		out = append(out, "mode")
	}
	if rank(after.FailOnSeverity) > rank(before.FailOnSeverity) {
		out = append(out, "fail_on_severity")
	}
	if !before.NewFindingsOnly && after.NewFindingsOnly {
		out = append(out, "new_findings_only")
	}
	if before.FailOnKEV && !after.FailOnKEV {
		out = append(out, "fail_on_kev")
	}
	if before.EPSSThreshold != nil && (after.EPSSThreshold == nil || *after.EPSSThreshold > *before.EPSSThreshold) {
		out = append(out, "epss_threshold")
	}
	if !before.FixableOnly && after.FixableOnly {
		out = append(out, "fixable_only")
	}
	if !before.BaselineOnFirstRun && after.BaselineOnFirstRun {
		out = append(out, "baseline_on_first_run")
	}
	if before.BaselineGraceDays != nil && (after.BaselineGraceDays == nil || *after.BaselineGraceDays > *before.BaselineGraceDays) {
		out = append(out, "baseline_grace_days")
	}
	if before.BaselineSecretsBlock && !after.BaselineSecretsBlock {
		out = append(out, "baseline_secrets_block")
	}
	if modesLoosen(before.Modes, after.Modes) {
		out = append(out, "modes")
	}
	return out
}

// modesLoosen reports whether any capability or rule gets a weaker mode.
// Unset means block. A rule override that goes away falls back to its
// capability's mode, which is not known here: removing a stronger rule
// override counts as loosening when any capability of the new policy is
// weaker than that override.
func modesLoosen(before, after PolicyModes) bool {
	capMode := func(m PolicyModes, c string) int {
		if v, ok := m.Capabilities[c]; ok {
			return modeRank(v)
		}
		return modeRank(FindingModeBlock)
	}
	caps := slices.Collect(maps.Keys(modeCapabilities))
	for _, c := range caps {
		if capMode(after, c) < capMode(before, c) {
			return true
		}
	}
	weakestCap := modeRank(FindingModeBlock)
	for _, c := range caps {
		weakestCap = min(weakestCap, capMode(after, c))
	}
	for r, v := range after.Rules {
		was, ok := before.Rules[r]
		if !ok {
			// A new rule override is weaker than block (the most any
			// capability can be).
			if modeRank(v) < modeRank(FindingModeBlock) {
				return true
			}
			continue
		}
		if modeRank(v) < modeRank(was) {
			return true
		}
	}
	for r, was := range before.Rules {
		if _, ok := after.Rules[r]; !ok && weakestCap < modeRank(was) {
			return true
		}
	}
	return false
}
