package vulnmatch

import (
	"testing"
)

func rng(start string, startIncl bool, end string, endIncl bool) Range {
	return Range{VulnID: "CVE-2021-23017", Scheme: SchemeGeneric, Start: start, StartIncl: startIncl, End: end, EndIncl: endIncl}
}

func gen(v string) Observed { return Observed{Version: v, Scheme: SchemeGeneric} }

func TestApplies(t *testing.T) {
	cases := []struct {
		name    string
		version string
		r       Range
		want    bool
		all     bool
	}{
		{"inside start incl end excl", "1.18.0", rng("0.6.18", true, "1.20.1", false), true, false},
		{"at start incl", "0.6.18", rng("0.6.18", true, "1.20.1", false), true, false},
		{"at start excl", "0.6.18", rng("0.6.18", false, "1.20.1", false), false, false},
		{"at end excl", "1.20.1", rng("0.6.18", true, "1.20.1", false), false, false},
		{"at end incl", "1.20.1", rng("0.6.18", true, "1.20.1", true), true, false},
		{"above end", "1.21.0", rng("0.6.18", true, "1.20.1", false), false, false},
		{"below start", "0.6.17", rng("0.6.18", true, "1.20.1", false), false, false},
		{"only upper bound, below", "1.0", rng("", false, "1.20.1", false), true, false},
		{"only upper bound, at excl", "1.20.1", rng("", false, "1.20.1", false), false, false},
		{"only upper bound, at incl", "1.20.1", rng("", false, "1.20.1", true), true, false},
		{"only lower bound, above", "9.9", rng("1.0", true, "", false), true, false},
		{"only lower bound, below", "0.9", rng("1.0", true, "", false), false, false},
		{"only lower bound, at excl", "1.0", rng("1.0", false, "", false), false, false},
		{"all versions", "1.2.3", rng("", false, "", false), true, true},
		{"exact equal", "2.4.49", Range{Exact: "2.4.49"}, true, false},
		{"exact equal normalised", "2.4.49.0", Range{Exact: "2.4.49"}, true, false},
		{"exact other", "2.4.50", Range{Exact: "2.4.49"}, false, false},
		{"exact any is all", "2.4.50", Range{Exact: "*"}, true, true},
		{"exact NA never", "2.4.50", Range{Exact: "-"}, false, false},
		{"bad start bound", "1.0", rng("x", true, "2.0", false), false, false},
		{"bad end bound", "1.0", rng("0.1", true, "zz", false), false, false},
		{"bad exact", "1.0", Range{Exact: "n/a"}, false, false},
		{"pre-release inside", "1.20.1rc1", rng("0.6.18", true, "1.20.1", false), true, false},
		{"pre-release of the fix is still affected", "1.20.1-beta.2", rng("", false, "1.20.1", false), true, false},
		{"pre-release below an inclusive start", "2.0rc1", rng("2.0", true, "3.0", false), false, false},
		{"release after pre-release end", "2.0", rng("1.0", true, "2.0rc2", true), false, false},
		{"patch letter outside", "8.5p1", rng("", false, "8.5", true), false, false},
		{"patch letter inside", "8.4p1", rng("", false, "8.5", false), true, false},
		{"openssl letters", "1.1.1k", rng("1.1.1", true, "1.1.1l", false), true, false},
		{"openssl letters fixed", "1.1.1l", rng("1.1.1", true, "1.1.1l", false), false, false},
	}
	for _, c := range cases {
		v, ok := ParseVersion(c.version)
		if !ok {
			t.Fatalf("%s: parse %q", c.name, c.version)
		}
		got, all := Applies(v, c.r)
		if got != c.want || all != c.all {
			t.Errorf("%s: Applies(%q, %s) = %v,%v want %v,%v", c.name, c.version, c.r.Describe(), got, all, c.want, c.all)
		}
	}
}

// Per-branch fixes: affected when any range covers the version.
func TestMatchVersion_ManyRangesPerVulnerability(t *testing.T) {
	ranges := []Range{
		{ID: "r1", VulnID: "CVE-2023-0001", Scheme: SchemeGeneric, Start: "15.0", StartIncl: true, End: "15.11.10"},
		{ID: "r2", VulnID: "CVE-2023-0001", Scheme: SchemeGeneric, Start: "16.0", StartIncl: true, End: "16.0.6"},
		{ID: "r3", VulnID: "CVE-2023-0001", Scheme: SchemeGeneric, Start: "16.1", StartIncl: true, End: "16.1.3"},
	}
	cases := []struct {
		version string
		rangeID string // "" = not affected
	}{
		{"14.9.9", ""},
		{"15.0", "r1"},
		{"15.11.9", "r1"},
		{"15.11.10", ""}, // backport fix on 15.11
		{"15.12", ""},    // between branches
		{"16.0.5", "r2"},
		{"16.0.6", ""},
		{"16.1.0", "r3"},
		{"16.1.2", "r3"},
		{"16.1.3", ""},
		{"16.2", ""},
	}
	for _, c := range cases {
		got := MatchVersion(gen(c.version), ranges)
		switch {
		case c.rangeID == "" && len(got) != 0:
			t.Errorf("%s: matched %+v", c.version, got)
		case c.rangeID != "" && (len(got) != 1 || got[0].Range.ID != c.rangeID):
			t.Errorf("%s: got %+v, want range %s", c.version, got, c.rangeID)
		}
	}
}

func TestMatchVersion_ExactVersionList(t *testing.T) {
	ranges := []Range{
		{ID: "a", VulnID: "CVE-1", Scheme: SchemeGeneric, Exact: "2.4.49"},
		{ID: "b", VulnID: "CVE-1", Scheme: SchemeGeneric, Exact: "2.4.50"},
	}
	for v, want := range map[string]string{"2.4.49": "a", "2.4.50": "b", "2.4.51": "", "2.4.48": ""} {
		got := MatchVersion(gen(v), ranges)
		if (want == "") != (len(got) == 0) || (want != "" && got[0].Range.ID != want) {
			t.Errorf("%s: got %+v, want %q", v, got, want)
		}
	}
}

func TestMatchVersion_AllVersionsIsNeverFindable(t *testing.T) {
	got := MatchVersion(gen("1.18.0"), []Range{{VulnID: "CVE-B", Scheme: SchemeGeneric}})
	if len(got) != 1 || !got[0].AllVersions || got[0].Findable() {
		t.Fatalf("got %+v", got)
	}
	c, label, reasons := Confidence(95, got[0], false)
	if c > AllVersionsCap || label != LabelPotential || len(reasons) != 1 || reasons[0] != ReasonAllVersions {
		t.Fatalf("confidence %d %s %v", c, label, reasons)
	}
	// A bounded range of the same CVE wins over the all-versions one.
	got = MatchVersion(gen("1.18.0"), []Range{
		{ID: "all", VulnID: "CVE-B", Scheme: SchemeGeneric},
		{ID: "bounded", VulnID: "CVE-B", Scheme: SchemeGeneric, End: "1.20"},
	})
	if len(got) != 1 || got[0].Range.ID != "bounded" || !got[0].Findable() {
		t.Fatalf("got %+v", got)
	}
}

func TestMatchVersion_Edition(t *testing.T) {
	ce := Range{ID: "ce", VulnID: "CVE-E", Scheme: SchemeGeneric, End: "16.1.3", Edition: "community"}
	ee := Range{ID: "ee", VulnID: "CVE-F", Scheme: SchemeGeneric, End: "16.1.3", Edition: "enterprise"}
	anyEd := Range{ID: "any", VulnID: "CVE-G", Scheme: SchemeGeneric, End: "16.1.3", Edition: "*"}
	ranges := []Range{ce, ee, anyEd}

	got := MatchVersion(Observed{Version: "16.1.0", Scheme: SchemeGeneric, Edition: "Community"}, ranges)
	if len(got) != 2 || got[0].VulnID != "CVE-E" || got[1].VulnID != "CVE-G" || got[0].Adjustment != 0 {
		t.Fatalf("community: %+v", got)
	}
	// Unknown edition: matches both editions, lowered.
	got = MatchVersion(gen("16.1.0"), ranges)
	if len(got) != 3 || got[0].Adjustment != AdjustEditionUnknown || got[2].Adjustment != 0 {
		t.Fatalf("unknown edition: %+v", got)
	}
	// Target platform mismatch: no match.
	wp := Range{VulnID: "CVE-W", Scheme: SchemeGeneric, End: "9", Target: "wordpress"}
	if got := MatchVersion(Observed{Version: "1.0", Scheme: SchemeGeneric, Target: "joomla"}, []Range{wp}); len(got) != 0 {
		t.Fatalf("target mismatch matched: %+v", got)
	}
}

func TestMatchVersion_SchemesAndOrder(t *testing.T) {
	ranges := []Range{
		{VulnID: "CVE-A", Scheme: SchemeGeneric, Start: "0.6.18", StartIncl: true, End: "1.20.1"},
		{VulnID: "CVE-C", Scheme: SchemeGeneric, End: "1.2.0"}, // fixed long ago
		{VulnID: "CVE-D", Scheme: SchemeSemver, End: "9.0"},    // other scheme: ignored
		{VulnID: "CVE-E", Scheme: SchemeGeneric, End: "2.0", Condition: "linux"},
		{VulnID: "", Scheme: SchemeGeneric}, // no id: ignored
	}
	got := MatchVersion(gen("1.18.0"), ranges)
	if len(got) != 2 || got[0].VulnID != "CVE-A" || got[1].VulnID != "CVE-E" {
		t.Fatalf("got %+v", got)
	}
}

func TestMatchVersion_UnknownOrUnparseableVersion(t *testing.T) {
	r := []Range{{VulnID: "CVE-1", Scheme: SchemeGeneric, End: "99"}}
	for _, v := range []string{"", "latest", "unknown", "1.0 (Ubuntu)", "x.y"} {
		if got := MatchVersion(gen(v), r); len(got) != 0 {
			t.Errorf("version %q matched: %+v", v, got)
		}
	}
	if got := MatchVersion(Observed{Version: "1.0", Scheme: SchemeSemver}, []Range{{VulnID: "CVE-1", Scheme: SchemeSemver, End: "2"}}); got != nil {
		t.Fatalf("semver has no comparator yet: %+v", got)
	}
}

func TestMatchVersion_PreferNoCondition(t *testing.T) {
	ranges := []Range{
		{ID: "cond", VulnID: "CVE-X", Scheme: SchemeGeneric, End: "1.20.0", Condition: "x"},
		{ID: "plain", VulnID: "CVE-X", Scheme: SchemeGeneric, Start: "1.0", End: "1.19"},
	}
	got := MatchVersion(gen("1.18.0"), ranges)
	if len(got) != 1 || got[0].Range.ID != "plain" {
		t.Fatalf("got %+v", got)
	}
}

func TestConfidence(t *testing.T) {
	bounded := Result{VulnID: "CVE-A", Range: Range{End: "2"}}
	ed := Result{VulnID: "CVE-B", Adjustment: AdjustEditionUnknown, Reasons: []string{ReasonEditionUnknown}}
	cond := Result{VulnID: "CVE-C", Range: Range{End: "2", Condition: "linux"}}
	cases := []struct {
		base    int
		r       Result
		met     bool
		want    int
		label   Label
		reasons int
	}{
		{80, bounded, false, 80, LabelLikely, 0},
		{79, bounded, false, 79, LabelPotential, 0},
		{80, ed, false, 70, LabelPotential, 1},
		{80, cond, true, 80, LabelLikely, 0},
		{80, cond, false, 60, LabelPotential, 1},
		{10, cond, false, 0, LabelPotential, 1},
		{150, bounded, false, 100, LabelLikely, 0},
	}
	for i, c := range cases {
		got, label, reasons := Confidence(c.base, c.r, c.met)
		if got != c.want || label != c.label || len(reasons) != c.reasons {
			t.Errorf("case %d: %d %s %v, want %d %s %d", i, got, label, reasons, c.want, c.label, c.reasons)
		}
	}
	_, _, _ = Confidence(80, cond, false)
	if len(cond.Reasons) != 0 {
		t.Fatal("Confidence changed its input")
	}
}

func TestRangeDescribe(t *testing.T) {
	cases := []struct {
		r    Range
		want string
	}{
		{Range{Exact: "1.2.3"}, "= 1.2.3"},
		{Range{Start: "2.4.0", StartIncl: true, End: "2.4.62"}, ">= 2.4.0, < 2.4.62"},
		{Range{Start: "1.0", End: "2.0", EndIncl: true}, "> 1.0, <= 2.0"},
		{Range{End: "3"}, "< 3"},
		{Range{}, "all versions"},
		{Range{Exact: "*"}, "all versions"},
	}
	for _, c := range cases {
		if got := c.r.Describe(); got != c.want {
			t.Errorf("Describe(%+v) = %q, want %q", c.r, got, c.want)
		}
	}
}

func TestSchemes(t *testing.T) {
	if len(Schemes()) != 9 || !SchemeGeneric.Comparable() || SchemeDeb.Comparable() {
		t.Fatal("schemes")
	}
}
