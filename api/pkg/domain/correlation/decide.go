package correlation

import (
	"sort"
	"strings"
	"time"
)

// Tiers and reasons of a correlation.
const (
	TierAuto      = "auto"
	TierSuggested = "suggested"

	ReasonSameCVE         = "same_cve"
	ReasonGenericSpecific = "generic_specific"
	ReasonRelated         = "possibly_related"
)

// Candidate is one finding the correlator may group. Only open findings are
// candidates, plus findings that are currently another's correlated
// duplicate (so their link is re-derived).
type Candidate struct {
	ID        string
	AssetID   string
	CVE       string   // "" for a generic detection
	CWEs      []string // normalized
	Point     InjectionPoint
	Severity  int // rank, higher is worse
	CreatedAt time.Time
	// Open: the finding is in an open status (or is a correlated duplicate
	// whose own status before correlation was open).
	Open bool
	// Sighted: the scan being ingested reported it (re-derivation).
	Sighted bool
}

// Link is a correlation that exists.
type Link struct {
	PrimaryID, MemberID string
	Tier                string
	// Rejected: a person released it; never linked automatically again.
	Rejected bool
}

// Options are the tenant's switches.
type Options struct {
	Auto, Suggestions bool
	// SightingAware: the input comes from a scan, and Sighted is meaningful.
	SightingAware bool
}

// Plan is what to change: links to make, active auto links to release, and
// suggestions to record.
type Plan struct {
	Link     []Link // auto: member becomes a duplicate of primary
	Release  []Link // auto links that no longer hold
	Suggest  []Link
	Reasons  map[string]string // member -> reason, for Link and Suggest
	Releases map[string]string // member -> why released
}

// Decide computes the plan for one asset's candidates. existing holds the
// active and rejected links among them.
func Decide(cands []Candidate, existing []Link, opt Options) Plan {
	plan := Plan{Reasons: map[string]string{}, Releases: map[string]string{}}
	byID := map[string]Candidate{}
	for _, c := range cands {
		byID[c.ID] = c
	}
	rejected := map[[2]string]bool{}
	active := map[string]Link{} // member -> active auto link
	for _, l := range existing {
		if l.Rejected {
			rejected[[2]string{l.PrimaryID, l.MemberID}] = true
			continue
		}
		if l.Tier == TierAuto {
			active[l.MemberID] = l
		}
	}

	want := map[string]Link{} // member -> desired auto link
	if opt.Auto {
		for _, group := range groups(cands) {
			for _, pr := range autoPairs(group) {
				member, primary := pr[0], pr[1]
				if rejected[[2]string{primary.ID, member.ID}] {
					continue
				}
				// A member the scan saw while its primary was not seen is its
				// own finding again (the specific issue may be fixed while the
				// generic detection still fires).
				if opt.SightingAware && member.Sighted && !primary.Sighted {
					continue
				}
				want[member.ID] = Link{PrimaryID: primary.ID, MemberID: member.ID, Tier: TierAuto}
				if primary.CVE != "" && primary.CVE == member.CVE {
					plan.Reasons[member.ID] = ReasonSameCVE
				} else {
					plan.Reasons[member.ID] = ReasonGenericSpecific
				}
			}
		}
	}
	for member, l := range active {
		w, ok := want[member]
		if ok && w.PrimaryID == l.PrimaryID {
			delete(want, member) // still holds
			continue
		}
		plan.Release = append(plan.Release, l)
		switch p, okp := byID[l.PrimaryID]; {
		case !opt.Auto:
			plan.Releases[member] = "auto_correlation_off"
		case !okp || !p.Open:
			plan.Releases[member] = "primary_not_open"
		case opt.SightingAware && byID[member].Sighted && !p.Sighted:
			plan.Releases[member] = "primary_not_seen"
		default:
			plan.Releases[member] = "no_longer_correlated"
		}
	}
	for _, l := range want {
		plan.Link = append(plan.Link, l)
	}
	if opt.Suggestions {
		linked := map[string]bool{}
		for _, l := range plan.Link {
			linked[l.MemberID] = true
		}
		for m, l := range active {
			if _, released := plan.Releases[m]; !released {
				linked[l.MemberID] = true
			}
		}
		plan.Suggest = suggestions(cands, linked, rejected, plan.Reasons)
	}
	sortLinks(plan.Link)
	sortLinks(plan.Release)
	sortLinks(plan.Suggest)
	return plan
}

// groups are the open candidates with the same asset, the same CWE set (all
// of it injection CWEs) and the same injection point.
func groups(cands []Candidate) [][]Candidate {
	m := map[string][]Candidate{}
	for _, c := range cands {
		if !c.Open || !c.Point.Valid() || len(c.CWEs) == 0 {
			continue
		}
		ok := true
		for _, w := range c.CWEs {
			if !IsInjectionCWE(w) {
				ok = false
			}
		}
		if !ok {
			continue
		}
		cwes := append([]string(nil), c.CWEs...)
		sort.Strings(cwes)
		k := c.AssetID + "\x00" + strings.Join(cwes, ",") + "\x00" + c.Point.Key()
		m[k] = append(m[k], c)
	}
	out := make([][]Candidate, 0, len(m))
	for _, g := range m {
		if len(g) > 1 {
			out = append(out, g)
		}
	}
	return out
}

// autoPairs picks, in one group, the members and their primary. The primary
// is the earliest-created finding with the group's one CVE; members are the
// generic detections and the same-CVE ones. A group naming two CVEs links
// only same-CVE findings; its generic detections stay apart (suggestions).
// Generic detections alone are never linked.
func autoPairs(g []Candidate) [][2]Candidate {
	byCVE := map[string][]Candidate{}
	var generic []Candidate
	for _, c := range g {
		if c.CVE == "" {
			generic = append(generic, c)
		} else {
			byCVE[c.CVE] = append(byCVE[c.CVE], c)
		}
	}
	var out [][2]Candidate
	for _, same := range byCVE {
		sort.Slice(same, func(a, b int) bool { return older(same[a], same[b]) })
		for _, m := range same[1:] {
			out = append(out, [2]Candidate{m, same[0]})
		}
	}
	if len(byCVE) == 1 {
		for _, same := range byCVE {
			for _, m := range generic {
				out = append(out, [2]Candidate{m, same[0]})
			}
		}
	}
	return out
}

// suggestions pair open findings on one asset and origin with the same
// payload-free path that are not linked: a person confirms them.
func suggestions(cands []Candidate, linked map[string]bool, rejected map[[2]string]bool, reasons map[string]string) []Link {
	m := map[string][]Candidate{}
	for _, c := range cands {
		if !c.Open || linked[c.ID] || !c.Point.Valid() {
			continue
		}
		k := c.AssetID + "\x00" + c.Point.Origin + c.Point.Path
		m[k] = append(m[k], c)
	}
	var out []Link
	for _, g := range m {
		if len(g) < 2 {
			continue
		}
		sort.Slice(g, func(a, b int) bool { return moreSpecific(g[a], g[b]) })
		p := g[0]
		for _, c := range g[1:] {
			if p.CVE != "" && c.CVE != "" && p.CVE != c.CVE {
				continue // different CVEs are never one issue
			}
			if rejected[[2]string{p.ID, c.ID}] {
				continue
			}
			out = append(out, Link{PrimaryID: p.ID, MemberID: c.ID, Tier: TierSuggested})
			reasons[c.ID] = ReasonRelated
		}
	}
	return out
}

func older(a, b Candidate) bool {
	if !a.CreatedAt.Equal(b.CreatedAt) {
		return a.CreatedAt.Before(b.CreatedAt)
	}
	return a.ID < b.ID
}

// moreSpecific orders a CVE detection before a generic one, then oldest.
func moreSpecific(a, b Candidate) bool {
	if (a.CVE != "") != (b.CVE != "") {
		return a.CVE != ""
	}
	return older(a, b)
}

func sortLinks(l []Link) {
	sort.Slice(l, func(a, b int) bool {
		if l[a].PrimaryID != l[b].PrimaryID {
			return l[a].PrimaryID < l[b].PrimaryID
		}
		return l[a].MemberID < l[b].MemberID
	})
}
