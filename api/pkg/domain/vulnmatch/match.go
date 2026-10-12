package vulnmatch

import (
	"strings"
)

// Scheme names how a version is compared. Only SchemeGeneric has a
// comparator so far; a range is compared only with a version of the same
// scheme, so a version under another scheme never matches until its
// comparator exists.
type Scheme string

// Version schemes (RFC-066 §5.1).
const (
	SchemeGeneric Scheme = "generic"
	SchemeSemver  Scheme = "semver"
	SchemePEP440  Scheme = "pep440"
	SchemeMaven   Scheme = "maven"
	SchemeNPM     Scheme = "npm"
	SchemeGo      Scheme = "go"
	SchemeDeb     Scheme = "deb"
	SchemeRPM     Scheme = "rpm"
	SchemeAPK     Scheme = "apk"
)

// Schemes lists every scheme, in the order of the database CHECK.
func Schemes() []Scheme {
	return []Scheme{SchemeGeneric, SchemeSemver, SchemePEP440, SchemeMaven, SchemeNPM, SchemeGo, SchemeDeb, SchemeRPM, SchemeAPK}
}

// Comparable reports whether versions of the scheme can be compared.
func (s Scheme) Comparable() bool { return s == SchemeGeneric }

// Range is one affected-version statement of a vulnerability for one
// product: an exact version, or a start and an end bound (either may be
// missing), or neither ("all versions"). A vulnerability may have many
// ranges for the same product (one per release branch that got its own
// fix); a version is affected when any of them covers it.
type Range struct {
	ID        string // the statement's id, kept as evidence
	VulnID    string // canonical vulnerability id (the CVE)
	Scheme    Scheme
	Exact     string
	Start     string
	StartIncl bool
	End       string
	EndIncl   bool
	// Edition and Target narrow the statement to one edition of the product
	// (CPE sw_edition: "community" vs "enterprise") or one platform it is
	// built for (CPE target_sw). Empty or "*" means any.
	Edition string
	Target  string
	// Condition identifies a platform the product must run on for the
	// statement to apply ("running on"), or is empty. It is checked per
	// asset (Confidence), not per version.
	Condition string
}

// Observed is a product version as the inventory knows it.
type Observed struct {
	Version string
	Scheme  Scheme
	// Edition and Target, when known; empty when the observation does not
	// say.
	Edition string
	Target  string
}

// Label tells how sure a match is.
type Label string

const (
	// LabelLikely is a match at or above LikelyThreshold.
	LabelLikely Label = "likely"
	// LabelPotential is a match below LikelyThreshold.
	LabelPotential Label = "potential"
)

// LikelyThreshold is the confidence from which a match is likely.
const LikelyThreshold = 80

// AllVersionsCap is the highest confidence of an "all versions" match: it
// is at most a low-confidence potential match and never becomes a finding.
const AllVersionsCap = 40

// Confidence adjustments (RFC-066 §7).
const (
	AdjustEditionUnknown   = -10
	AdjustConditionUnknown = -20
)

// Reason codes recorded with a match.
const (
	ReasonAllVersions      = "all_versions"
	ReasonEditionUnknown   = "edition_unverified"
	ReasonConditionUnknown = "platform_condition_unverified"
)

// Result is one vulnerability that applies to a version.
type Result struct {
	VulnID string
	// Range is the statement that matched, kept as evidence.
	Range Range
	// AllVersions is set when the matching statement has no version bound
	// at all. Such a match is shown, never turned into a finding.
	AllVersions bool
	// Adjustment is the sum of the version-level adjustments (<= 0);
	// Reasons are their codes.
	Adjustment int
	Reasons    []string
}

// Findable reports whether a match may become a finding at all (before the
// organization's policy): an "all versions" statement says nothing about the
// version the asset runs.
func (r Result) Findable() bool { return !r.AllVersions }

// MatchVersion returns the vulnerabilities whose ranges cover the observed
// version. The ranges are those of the version's product. A vulnerability
// covered by several ranges is returned once, with the most specific one
// (bounded before "all versions", then the smallest adjustment, then no
// platform condition); results keep the order of each vulnerability's first
// covering range. A version that does not parse, or whose scheme has no
// comparator, matches nothing.
func MatchVersion(o Observed, ranges []Range) []Result {
	if !o.Scheme.Comparable() {
		return nil
	}
	v, ok := ParseVersion(o.Version)
	if !ok {
		return nil
	}
	out := make([]Result, 0, 4)
	index := map[string]int{}
	for _, r := range ranges {
		if r.VulnID == "" || r.Scheme != o.Scheme {
			continue
		}
		res, ok := matchOne(v, o, r)
		if !ok {
			continue
		}
		if i, seen := index[r.VulnID]; seen {
			if better(res, out[i]) {
				out[i] = res
			}
			continue
		}
		index[r.VulnID] = len(out)
		out = append(out, res)
	}
	return out
}

func matchOne(v Version, o Observed, r Range) (Result, bool) {
	res := Result{VulnID: r.VulnID, Range: r}
	for _, q := range [][2]string{{r.Edition, o.Edition}, {r.Target, o.Target}} {
		want, have := qualifier(q[0]), qualifier(q[1])
		switch {
		case want == "":
		case have == "":
			res.Adjustment += AdjustEditionUnknown
			res.Reasons = append(res.Reasons, ReasonEditionUnknown)
		case want != have:
			return Result{}, false
		}
	}
	applies, all := Applies(v, r)
	if !applies {
		return Result{}, false
	}
	if all {
		res.AllVersions = true
		res.Reasons = append(res.Reasons, ReasonAllVersions)
	}
	return res, true
}

func qualifier(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == Any || s == NA {
		return ""
	}
	return s
}

func better(a, b Result) bool {
	if a.AllVersions != b.AllVersions {
		return !a.AllVersions
	}
	if a.Adjustment != b.Adjustment {
		return a.Adjustment > b.Adjustment
	}
	return a.Range.Condition == "" && b.Range.Condition != ""
}

// Confidence combines the identity confidence of an asset's software link
// with a version-level result. conditionMet tells whether the asset runs
// the range's "running on" platform (ignored when there is none).
func Confidence(base int, r Result, conditionMet bool) (int, Label, []string) {
	c := base + r.Adjustment
	reasons := append([]string(nil), r.Reasons...)
	if r.Range.Condition != "" && !conditionMet {
		c += AdjustConditionUnknown
		reasons = append(reasons, ReasonConditionUnknown)
	}
	if r.AllVersions && c > AllVersionsCap {
		c = AllVersionsCap
	}
	c = clamp(c)
	return c, LabelFor(c), reasons
}

// Applies reports whether version v is inside range r, and whether r is an
// "all versions" statement. A bound that does not parse makes the range not
// apply: an unreadable bound must not widen a range.
func Applies(v Version, r Range) (applies, allVersions bool) {
	exact := strings.TrimSpace(r.Exact)
	start := strings.TrimSpace(r.Start)
	end := strings.TrimSpace(r.End)
	if exact == NA {
		return false, false
	}
	if exact != "" && exact != Any {
		e, ok := ParseVersion(exact)
		return ok && v.Compare(e) == 0, false
	}
	if start == "" && end == "" {
		return true, true
	}
	if start != "" {
		s, ok := ParseVersion(start)
		if !ok {
			return false, false
		}
		c := v.Compare(s)
		if c < 0 || (c == 0 && !r.StartIncl) {
			return false, false
		}
	}
	if end != "" {
		e, ok := ParseVersion(end)
		if !ok {
			return false, false
		}
		c := v.Compare(e)
		if c > 0 || (c == 0 && !r.EndIncl) {
			return false, false
		}
	}
	return true, false
}

// LabelFor returns the label of a confidence.
func LabelFor(confidence int) Label {
	if confidence >= LikelyThreshold {
		return LabelLikely
	}
	return LabelPotential
}

// Describe renders a range for people: "= 1.2.3", ">= 2.4.0, < 2.4.62",
// "all versions".
func (r Range) Describe() string {
	if e := strings.TrimSpace(r.Exact); e != "" && e != Any {
		return "= " + e
	}
	var parts []string
	if r.Start != "" {
		op := "> "
		if r.StartIncl {
			op = ">= "
		}
		parts = append(parts, op+r.Start)
	}
	if r.End != "" {
		op := "< "
		if r.EndIncl {
			op = "<= "
		}
		parts = append(parts, op+r.End)
	}
	if len(parts) == 0 {
		return "all versions"
	}
	return strings.Join(parts, ", ")
}

func clamp(c int) int {
	switch {
	case c < 0:
		return 0
	case c > 100:
		return 100
	}
	return c
}
