package scan

// What a scan does with each target, grouped by why a target is skipped.
// Architecture: docs/architecture/scan-targets.md ("Skipped targets").
// The routing preview and the run record build the groups with the same
// code, so the New Scan review and the run's Dispatch card agree.

import (
	"cmp"
	"slices"

	"github.com/openctemio/openctem/api/pkg/domain/scanzone"
)

// Why a target is skipped: the Skip* reasons of the Quick Scan preview
// (quick_preview.go), the zone kinds (scanzone.Kind*) as they are, and:
const (
	SkipNotResolving = ReasonNotResolving   // no recent proof the name resolves
	SkipInvalid      = scanzone.KindInvalid // not a target scan creation accepts
)

// maxSkipSamples bounds the names listed per reason in a preview;
// maxRunSkipSamples in a run record.
const (
	maxSkipSamples    = 200
	maxRunSkipSamples = 25
)

// RunContextKeySkipped holds a run's skip groups ([]SkipGroup).
const RunContextKeySkipped = "skipped_targets"

// Tones of a skip group: info is an expected outcome of the inventory (a
// name that does not resolve, an exclusion the team set); warning asks for
// a fix (a zone without sensors, a scope entry with too low a tier).
const (
	SkipToneInfo    = "info"
	SkipToneWarning = "warning"
)

// SkipGroup is every target skipped for one reason.
type SkipGroup struct {
	Reason string `json:"reason"`
	Tone   string `json:"tone"`
	Count  int    `json:"count"`
	// Targets: up to the sample limit; Count is the full number. Empty for
	// reasons known only as a count (archived, incompatible).
	Targets []string `json:"targets"`
}

// infoReasons are expected outcomes: nothing is wrong with the scan.
var infoReasons = map[string]bool{
	SkipExcluded:         true,
	SkipArchived:         true,
	SkipIncompatibleType: true,
	SkipNotResolving:     true,
	// A name only a wildcard record answers may not exist: expected, and
	// passive runs still take it.
	SkipWildcardOnly:        true,
	scanzone.KindUnresolved: true,
}

type skipCollector struct {
	limit  int
	groups map[string]*SkipGroup
}

func newSkipCollector(limit int) *skipCollector {
	return &skipCollector{limit: limit, groups: map[string]*SkipGroup{}}
}

func (c *skipCollector) group(reason string) *SkipGroup {
	g, ok := c.groups[reason]
	if !ok {
		tone := SkipToneWarning
		if infoReasons[reason] {
			tone = SkipToneInfo
		}
		g = &SkipGroup{Reason: reason, Tone: tone, Targets: []string{}}
		c.groups[reason] = g
	}
	return g
}

func (c *skipCollector) add(reason string, targets ...string) {
	if len(targets) == 0 {
		return
	}
	g := c.group(reason)
	g.Count += len(targets)
	for _, t := range targets {
		if len(g.Targets) >= c.limit {
			break
		}
		g.Targets = append(g.Targets, t)
	}
}

// count adds a reason known only as a number (or with fewer names than
// the count): the names given are listed, the count is n.
func (c *skipCollector) count(reason string, n int, names []string) {
	if n <= 0 {
		return
	}
	g := c.group(reason)
	g.Count += n
	for _, t := range names {
		if len(g.Targets) >= c.limit {
			break
		}
		g.Targets = append(g.Targets, t)
	}
}

// result returns the groups, largest first (ties: reason).
func (c *skipCollector) result() []SkipGroup {
	out := make([]SkipGroup, 0, len(c.groups))
	for _, g := range c.groups {
		out = append(out, *g)
	}
	slices.SortFunc(out, func(a, b SkipGroup) int {
		if a.Count != b.Count {
			return b.Count - a.Count
		}
		return cmp.Compare(a.Reason, b.Reason)
	})
	return out
}

// skipGroups groups every target a run skips: what scan creation refuses,
// what the target gate leaves out, the names without resolution evidence,
// and what zone routing cannot place (plan may be nil: no zone routing).
func skipGroups(limit int, rejected []rejectedTarget, r *resolvedTargets, notResolving []string, plan *zonePlan) []SkipGroup {
	c := newSkipCollector(limit)
	for _, rj := range rejected {
		c.add(rejectedReason(rj), rj.Target)
	}
	if r != nil {
		c.count(SkipExcluded, r.Excluded, r.ExcludedNames)
		c.count(SkipOutOfScope, r.OutOfScope, r.SkippedNames[SkipOutOfScope])
		c.count(SkipNotConfirmed, r.Unconfirmed, r.SkippedNames[SkipNotConfirmed])
		c.count(SkipWildcardOnly, r.WildcardOnly, r.SkippedNames[SkipWildcardOnly])
		c.count(SkipTierExceeded, r.TierExceeded, r.SkippedNames[SkipTierExceeded])
		c.count(SkipInternalNoZone, r.InternalOutsideZones, r.SkippedNames[SkipInternalNoZone])
		c.count(SkipArchived, r.Archived, nil)
		c.count(SkipIncompatibleType, r.Incompatible, nil)
	}
	c.add(SkipNotResolving, notResolving...)
	if plan != nil {
		for _, u := range plan.Uncovered {
			reason := u.Kind
			if reason == "" {
				reason = scanzone.KindOutsideZones
			}
			c.add(reason, u.Target)
		}
	}
	return c.result()
}

// rejectedReason: the act-scope check refuses with its own reason text; the
// validator's refusals are invalid targets.
func rejectedReason(rj rejectedTarget) string {
	if rj.ActScope {
		return SkipOutOfScope
	}
	return SkipInvalid
}

// skipTotal is the number of targets the groups skip.
func skipTotal(groups []SkipGroup) int {
	n := 0
	for _, g := range groups {
		n += g.Count
	}
	return n
}

// recordSkipGroups stores a run's skip groups (bounded samples) for its
// Dispatch card; an empty list says nothing was skipped.
func recordSkipGroups(runContext map[string]any, groups []SkipGroup) {
	out := make([]SkipGroup, len(groups))
	for i, g := range groups {
		g.Targets = g.Targets[:min(len(g.Targets), maxRunSkipSamples)]
		out[i] = g
	}
	runContext[RunContextKeySkipped] = out
}
