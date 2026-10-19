package vulnmatch

import (
	"math/rand"
	"strings"
	"testing"
)

// ascending lists versions in strictly increasing order under each scheme.
// The vectors come from each ecosystem's own specification and test data:
// semver.org §11, the Go module reference, PEP 440, the Maven
// ComparableVersion tests, Debian policy §5.6.12 and dpkg, the rpmvercmp
// tests, and the apk version format.
var ascending = map[Scheme][]string{
	SchemeSemver: {
		"1.0.0-alpha", "1.0.0-alpha.1", "1.0.0-alpha.beta", "1.0.0-beta", "1.0.0-beta.2",
		"1.0.0-beta.11", "1.0.0-rc.1", "1.0.0", "2.0.0", "2.1.0", "2.1.1", "2.1.1.1", "10.0.0",
	},
	SchemeNPM: {
		"0.0.1", "1.2.3-beta.9", "1.2.3-beta.10", "1.2.3", "=1.2.4", "v1.2.5", "1.10.0",
	},
	SchemeGo: {
		"v0.0.0-20191109021931-daa7c04131f5", "v0.0.0", "v1.2.3",
		"v1.2.4-0.20191109021931-daa7c04131f5", "v1.2.4-pre", "v1.2.4", "v1.9.0", "v2.0.0+incompatible", "v2.0.1",
	},
	SchemePEP440: {
		"1.0.dev456", "1.0a1", "1.0a2.dev456", "1.0a12.dev456", "1.0a12", "1.0b1.dev456", "1.0b2",
		"1.0b2.post345.dev456", "1.0b2.post345", "1.0rc1.dev456", "1.0rc1", "1.0", "1.0+abc.5", "1.0+abc.7",
		"1.0+5", "1.0.post456.dev34", "1.0.post456", "1.0.15", "1.1.dev1", "2.0", "1!0.1",
	},
	SchemeMaven: {
		"1-alpha2snapshot", "1-alpha2", "1-alpha-123", "1-beta-2", "1-beta123", "1-m2", "1-m11", "1-rc",
		"1-cr2", "1-rc123", "1-SNAPSHOT", "1", "1-sp", "1-sp2", "1-sp123", "1-abc", "1-def", "1-pom-1",
		"1-1-snapshot", "1-1", "1-2", "1-123",
	},
	SchemeDeb: {
		"1.0~~", "1.0~~a", "1.0~", "1.0", "1.0-1", "1.0a", "1.0.1", "1.1.1n-0+deb11u3", "1.1.1n-0+deb11u4",
		"1.1.1o-1", "2.4.62-1~deb12u1", "2.4.62-1", "2.4.62-1+b1", "1:0.9",
	},
	SchemeRPM: {
		"1.0~rc1~git123", "1.0~rc1", "1.0~rc1^git1", "1.0", "1.0^20160101", "1.0^20160101^git1", "1.0.1",
		"1.01a", "2.0", "2.0.1", "2.0.1a", "5.5p1", "5.5p2", "5.5p10", "1:0.1",
	},
	SchemeAPK: {
		"1.0_alpha", "1.0_beta", "1.0_pre", "1.0_rc1", "1.0_rc2", "1.0", "1.0-r1", "1.0-r2", "1.0_p1",
		"1.0a", "1.0.1", "1.05.1", "1.5", "2.0_alpha1", "2.0",
	},
}

// equal lists pairs that compare equal.
var equal = map[Scheme][][2]string{
	SchemeSemver: {{"1.0.0+build.1", "1.0.0"}, {"v1.2.3", "1.2.3"}, {"2.0", "2.0.0"}, {"1.0.0-rc.1+b", "1.0.0-rc.1"}},
	SchemeNPM:    {{"=1.2.3", "1.2.3"}, {"v1.2.3", "1.2.3"}, {"01.2.3", "1.2.3"}},
	SchemeGo:     {{"v2.0.0+incompatible", "v2.0.0"}, {"v1.2.3", "1.2.3"}},
	SchemePEP440: {
		{"1.0.0-RC1", "1.0rc1"}, {"1.0-1", "1.0.post1"}, {"1.0", "1.0.0"}, {"1.0alpha1", "1.0a1"},
		{"1.0c1", "1.0rc1"}, {"v1.0", "1.0"}, {"1.0.post", "1.0.post0"}, {"1.0-dev", "1.0.dev0"},
		{"1.0.rev3", "1.0.post3"}, {"0!1.0", "1.0"}, {"1.0+UBUNTU.1", "1.0+ubuntu-1"},
	},
	SchemeMaven: {
		{"1", "1.0"}, {"1", "1.0.0"}, {"1.0", "1.0.0"}, {"1", "1-0"}, {"1", "1.0-0"}, {"1a", "1-a"},
		{"1a", "1.0-a"}, {"1a", "1.0.0-a"}, {"1x", "1-x"}, {"1ga", "1"}, {"1release", "1"}, {"1final", "1"},
		{"1cr", "1rc"}, {"1a1", "1-alpha-1"}, {"1b2", "1-beta-2"}, {"1m3", "1-milestone-3"}, {"1X", "1x"},
		{"1A", "1a"}, {"1.0.GA", "1"},
	},
	SchemeDeb: {{"0:1.0", "1.0"}, {"1.0", "1.0-0"}, {"1.01", "1.1"}, {"1.0-1", "1.0-01"}},
	SchemeRPM: {{"1.05", "1.5"}, {"fc4", "fc.4"}, {"1.0", "1.0-5"}, {"0:1.0-1", "1.0-1"}, {"1.0", "1.0"}},
	SchemeAPK: {{"1.0", "1.0"}, {"1.0_rc", "1.0_rc0"}, {"1.10", "1.10"}},
}

// invalid lists strings that are not versions of the scheme.
var invalid = map[Scheme][]string{
	SchemeSemver: {"", "latest", "1.x", "1.2.3.4.5", "1.0.0-", "1.0.0-a..b", "1.0.0+", "1.0.0-be ta"},
	SchemeNPM:    {"*", "^1.2.3", ">=1.0.0", "1.2.x"},
	SchemeGo:     {"vX", "v1.2.3-"},
	SchemePEP440: {"", "french toast", "1.0+", "1.0+ubuntu..1", "1.0-", "1.0.a.b.c"},
	SchemeMaven:  {"", "snapshot", "1.0 beta", "1.0;rm"},
	SchemeDeb:    {"", "a1.0", "1.0-", "x:1.0", "1.0 1", "1.0-1:2"},
	SchemeRPM:    {"", "1.0-", "x:1.0", "abc", "1.0 1"},
	SchemeAPK:    {"", "v1.0", "1.0-1", "1.0_foo", "1.0~abc", "1..0", "1.0aa"},
}

func mustParse(t *testing.T, s Scheme, v string) SchemeVersion {
	t.Helper()
	p, ok := ParseSchemeVersion(s, v)
	if !ok {
		t.Fatalf("%s: %q does not parse", s, v)
	}
	return p
}

func TestSchemeOrdering(t *testing.T) {
	for s, list := range ascending {
		parsed := make([]SchemeVersion, len(list))
		for i, v := range list {
			parsed[i] = mustParse(t, s, v)
		}
		for i := range parsed {
			for j := range parsed {
				want := cmpInt(i, j)
				got, ok := parsed[i].Compare(parsed[j])
				if !ok || got != want {
					t.Errorf("%s: Compare(%q, %q) = %d, want %d", s, list[i], list[j], got, want)
				}
			}
		}
	}
}

func TestSchemeEquality(t *testing.T) {
	for s, pairs := range equal {
		for _, p := range pairs {
			if c, ok := CompareVersions(s, p[0], p[1]); !ok || c != 0 {
				t.Errorf("%s: %q vs %q = %d,%v, want equal", s, p[0], p[1], c, ok)
			}
			if c, ok := CompareVersions(s, p[1], p[0]); !ok || c != 0 {
				t.Errorf("%s: %q vs %q = %d,%v, want equal", s, p[1], p[0], c, ok)
			}
		}
	}
}

func TestSchemeInvalid(t *testing.T) {
	for s, list := range invalid {
		for _, v := range list {
			if _, ok := ParseSchemeVersion(s, v); ok {
				t.Errorf("%s: %q parsed", s, v)
			}
		}
	}
	long := "1." + strings.Repeat("1", MaxSchemeVersionLen)
	for _, s := range Schemes() {
		if _, ok := ParseSchemeVersion(s, long); ok {
			t.Errorf("%s: an over-long version parsed", s)
		}
	}
	if _, ok := ParseSchemeVersion(Scheme("unknown"), "1.0"); ok {
		t.Error("a scheme without a comparator parsed")
	}
}

func TestRPMVerCmpSegments(t *testing.T) {
	// From the rpmvercmp test suite.
	cases := []struct {
		a, b string
		want int
	}{
		{"1.0", "1.0", 0}, {"1.0", "2.0", -1}, {"2.0.1", "2.0", 1}, {"2.0.1a", "2.0.1", 1},
		{"5.5p1", "5.5p2", -1}, {"5.5p10", "5.5p1", 1}, {"10xyz", "10.1xyz", -1}, {"xyz10", "xyz10.1", -1},
		{"xyz.4", "8", -1}, {"1.0010", "1.9", 1}, {"1.05", "1.5", 0}, {"1.0", "1", 1}, {"2.50", "2.5", 1},
		{"fc4", "fc.4", 0}, {"FC5", "fc4", -1}, {"2a", "2.0", -1}, {"1.0a", "1.0", 1}, {"a+", "a_", 0},
		{"+a", "_a", 0}, {"+_", "_+", 0}, {"1.0~rc1", "1.0", -1}, {"1.0~rc1", "1.0~rc2", -1},
		{"1.0~rc1~git123", "1.0~rc1", -1}, {"1.0^", "1.0", 1}, {"1.0^git1", "1.0", 1},
		{"1.0^git1", "1.01", -1}, {"1.0^20160101", "1.0.1", -1}, {"1.0^20160101^git1", "1.0^20160101", 1},
		{"1.0~rc1^git1", "1.0~rc1", 1}, {"1.0~rc1^git1", "1.0", -1}, {"1.0^git1~pre", "1.0^git1", -1},
	}
	for _, c := range cases {
		if got := rpmvercmp(c.a, c.b); got != c.want {
			t.Errorf("rpmvercmp(%q, %q) = %d, want %d", c.a, c.b, got, c.want)
		}
		if got := rpmvercmp(c.b, c.a); got != -c.want {
			t.Errorf("rpmvercmp(%q, %q) = %d, want %d", c.b, c.a, got, -c.want)
		}
	}
}

// TestSchemeOrderProperties checks reflexivity, antisymmetry and
// transitivity on random triples drawn from every scheme's vectors.
func TestSchemeOrderProperties(t *testing.T) {
	rnd := rand.New(rand.NewSource(184)) //nolint:gosec // deterministic test sampling
	for s, list := range ascending {
		pool := append([]string(nil), list...)
		// An RPM version without a release equals every release of it (a
		// bound "1.0" covers 1.0-1 and 1.0-5), which is not a total order;
		// keep those pairs out of the transitivity sample.
		for _, p := range equal[s] {
			if s == SchemeRPM {
				break
			}
			pool = append(pool, p[0], p[1])
		}
		vs := make([]SchemeVersion, len(pool))
		for i, v := range pool {
			vs[i] = mustParse(t, s, v)
		}
		cmp := func(a, b SchemeVersion) int { c, _ := a.Compare(b); return c }
		for k := 0; k < 2000; k++ {
			a, b, c := vs[rnd.Intn(len(vs))], vs[rnd.Intn(len(vs))], vs[rnd.Intn(len(vs))]
			if cmp(a, a) != 0 {
				t.Fatalf("%s: %q != itself", s, a)
			}
			if cmp(a, b) != -cmp(b, a) {
				t.Fatalf("%s: antisymmetry fails for %q, %q", s, a, b)
			}
			if cmp(a, b) <= 0 && cmp(b, c) <= 0 && cmp(a, c) > 0 {
				t.Fatalf("%s: transitivity fails for %q <= %q <= %q", s, a, b, c)
			}
		}
	}
}

func TestSchemeVersionCompareAcrossSchemes(t *testing.T) {
	a := mustParse(t, SchemeNPM, "1.0.0")
	b := mustParse(t, SchemeSemver, "1.0.0")
	if _, ok := a.Compare(b); ok {
		t.Fatal("versions of two schemes compared")
	}
	if _, ok := (SchemeVersion{}).Compare(a); ok {
		t.Fatal("the zero value compared")
	}
}

// TestMatchVersion_PackageSchemes is the matcher-level proof: a package
// version stored under its ecosystem's scheme is matched against the
// product's ranges. Before scheme comparators, every such version matched
// nothing.
func TestMatchVersion_PackageSchemes(t *testing.T) {
	cases := []struct {
		name     string
		obs      Observed
		r        Range
		want     bool
		backport bool
	}{
		{"npm inside a generic range", Observed{Version: "4.17.20", Scheme: SchemeNPM},
			Range{VulnID: "CVE-1", Scheme: SchemeGeneric, End: "4.17.21"}, true, false},
		{"npm at the fix", Observed{Version: "4.17.21", Scheme: SchemeNPM},
			Range{VulnID: "CVE-1", Scheme: SchemeGeneric, End: "4.17.21"}, false, false},
		{"npm pre-release of the fix is affected", Observed{Version: "4.17.21-beta.1", Scheme: SchemeNPM},
			Range{VulnID: "CVE-1", Scheme: SchemeNPM, End: "4.17.21"}, true, false},
		{"empty range scheme is generic", Observed{Version: "1.0.0", Scheme: SchemeNPM},
			Range{VulnID: "CVE-1", End: "2.0.0"}, true, false},
		{"pypi normalised", Observed{Version: "2.0.0-RC1", Scheme: SchemePEP440},
			Range{VulnID: "CVE-2", Scheme: SchemePEP440, Start: "1.0", StartIncl: true, End: "2.0"}, true, false},
		{"pypi post-release is after the fix", Observed{Version: "2.0.post1", Scheme: SchemePEP440},
			Range{VulnID: "CVE-2", End: "2.0"}, false, false},
		{"maven qualifier", Observed{Version: "2.14.1", Scheme: SchemeMaven},
			Range{VulnID: "CVE-3", Start: "2.0-beta9", StartIncl: true, End: "2.15.0"}, true, false},
		{"maven release after rc", Observed{Version: "2.15.0", Scheme: SchemeMaven},
			Range{VulnID: "CVE-3", Start: "2.0-beta9", StartIncl: true, End: "2.15.0-rc1", EndIncl: true}, false, false},
		{"go pseudo-version before the fix", Observed{Version: "v0.0.0-20210220033148-5ea612d1eb83", Scheme: SchemeGo},
			Range{VulnID: "CVE-4", Scheme: SchemeGo, End: "v0.0.0-20220314234659-1baeb1ce4c0b"}, true, false},
		{"go incompatible build metadata", Observed{Version: "v2.1.0+incompatible", Scheme: SchemeGo},
			Range{VulnID: "CVE-4", End: "2.2.0"}, true, false},
		{"deb with epoch is after the range", Observed{Version: "1:1.0-1", Scheme: SchemeDeb},
			Range{VulnID: "CVE-5", Scheme: SchemeDeb, End: "2.0-1"}, false, false},
		{"deb against its own scheme", Observed{Version: "1.1.1n-0+deb11u3", Scheme: SchemeDeb},
			Range{VulnID: "CVE-5", Scheme: SchemeDeb, End: "1.1.1n-0+deb11u4"}, true, false},
		{"deb against an upstream range is a possible backport", Observed{Version: "1.1.1n-0+deb11u3", Scheme: SchemeDeb},
			Range{VulnID: "CVE-5", Scheme: SchemeGeneric, End: "1.1.1o"}, true, true},
		{"rpm against an upstream range is a possible backport", Observed{Version: "2.4.37-51.el8", Scheme: SchemeRPM},
			Range{VulnID: "CVE-6", End: "2.4.52"}, true, true},
		{"apk against an upstream range is a possible backport", Observed{Version: "3.0.8-r0", Scheme: SchemeAPK},
			Range{VulnID: "CVE-7", End: "3.0.9"}, true, true},
		{"a range of another scheme never applies", Observed{Version: "1.0.0", Scheme: SchemeNPM},
			Range{VulnID: "CVE-8", Scheme: SchemePEP440, End: "2.0"}, false, false},
		{"a generic version never takes a specific range", Observed{Version: "1.0.0", Scheme: SchemeGeneric},
			Range{VulnID: "CVE-8", Scheme: SchemeNPM, End: "2.0.0"}, false, false},
		{"a bound unreadable under the scheme does not widen", Observed{Version: "1.0.0", Scheme: SchemeNPM},
			Range{VulnID: "CVE-9", Start: "0.9", StartIncl: true, End: "1.2.3.4.5"}, false, false},
		{"exact match under the scheme", Observed{Version: "v1.2.3", Scheme: SchemeGo},
			Range{VulnID: "CVE-10", Exact: "1.2.3"}, true, false},
	}
	for _, c := range cases {
		got := MatchVersion(c.obs, []Range{c.r})
		if (len(got) == 1) != c.want {
			t.Errorf("%s: got %+v, want match=%v", c.name, got, c.want)
			continue
		}
		if !c.want {
			continue
		}
		hasBackport := false
		for _, r := range got[0].Reasons {
			hasBackport = hasBackport || r == ReasonBackportPossible
		}
		if hasBackport != c.backport {
			t.Errorf("%s: reasons %v, want backport=%v", c.name, got[0].Reasons, c.backport)
		}
		if c.backport {
			if conf, label, _ := Confidence(100, got[0], true); label != LabelPotential || conf != 100+AdjustBackportPossible {
				t.Errorf("%s: confidence %d %s, want potential", c.name, conf, label)
			}
		}
	}
}

func FuzzParseSchemeVersion(f *testing.F) {
	for _, list := range ascending {
		for _, v := range list {
			f.Add(v)
		}
	}
	f.Fuzz(func(t *testing.T, s string) {
		for _, sc := range Schemes() {
			v, ok := ParseSchemeVersion(sc, s)
			if !ok {
				continue
			}
			if c, ok := v.Compare(v); !ok || c != 0 {
				t.Fatalf("%s: %q != itself", sc, s)
			}
		}
	})
}
