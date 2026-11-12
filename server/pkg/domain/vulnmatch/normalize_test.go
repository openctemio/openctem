package vulnmatch

import (
	"reflect"
	"strings"
	"testing"
)

func TestRangeFromNVD(t *testing.T) {
	const crit = "cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*"
	cases := []struct {
		name string
		m    NVDMatch
		want Range
		key  string
		ok   bool
	}{
		{"start incl end excl", NVDMatch{Criteria: crit, VersionStartIncluding: "0.6.18", VersionEndExcluding: "1.20.1"},
			Range{Start: "0.6.18", StartIncl: true, End: "1.20.1"}, "cpe:a:f5:nginx", true},
		{"start excl end incl", NVDMatch{Criteria: crit, VersionStartExcluding: "1.0", VersionEndIncluding: "1.5"},
			Range{Start: "1.0", End: "1.5", EndIncl: true}, "cpe:a:f5:nginx", true},
		{"only upper", NVDMatch{Criteria: crit, VersionEndExcluding: "1.20.1"},
			Range{End: "1.20.1"}, "cpe:a:f5:nginx", true},
		{"only lower", NVDMatch{Criteria: crit, VersionStartIncluding: "1.0"},
			Range{Start: "1.0", StartIncl: true}, "cpe:a:f5:nginx", true},
		{"all versions", NVDMatch{Criteria: crit}, Range{}, "cpe:a:f5:nginx", true},
		{"exact", NVDMatch{Criteria: "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"},
			Range{Exact: "2.4.49"}, "cpe:a:apache:http_server", true},
		{"exact with update", NVDMatch{Criteria: "cpe:2.3:a:openbsd:openssh:8.2:p1:*:*:*:*:*:*"},
			Range{Exact: "8.2p1"}, "cpe:a:openbsd:openssh", true},
		{"exact with rc update", NVDMatch{Criteria: "cpe:2.3:a:vendor:prod:2.0:rc1:*:*:*:*:*:*"},
			Range{Exact: "2.0rc1"}, "cpe:a:vendor:prod", true},
		{"edition", NVDMatch{Criteria: "cpe:2.3:a:gitlab:gitlab:*:*:*:*:community:*:*:*", VersionStartIncluding: "16.0", VersionEndExcluding: "16.0.6"},
			Range{Start: "16.0", StartIncl: true, End: "16.0.6", Edition: "community"}, "cpe:a:gitlab:gitlab", true},
		{"target", NVDMatch{Criteria: "cpe:2.3:a:vendor:plugin:*:*:*:*:*:wordpress:*:*", VersionEndExcluding: "2.1"},
			Range{End: "2.1", Target: "wordpress"}, "cpe:a:vendor:plugin", true},
		{"not applicable version", NVDMatch{Criteria: "cpe:2.3:o:vendor:fw:-:*:*:*:*:*:*:*"}, Range{}, "", false},
		{"exact plus bounds", NVDMatch{Criteria: "cpe:2.3:a:f5:nginx:1.0:*:*:*:*:*:*:*", VersionEndExcluding: "2"}, Range{}, "", false},
		{"bad bound", NVDMatch{Criteria: crit, VersionEndExcluding: "n/a"}, Range{}, "", false},
		{"huge bound", NVDMatch{Criteria: crit, VersionEndExcluding: strings.Repeat("1", 70)}, Range{}, "", false},
		{"wildcard vendor", NVDMatch{Criteria: "cpe:2.3:a:*:nginx:*:*:*:*:*:*:*:*"}, Range{}, "", false},
		{"garbage", NVDMatch{Criteria: "nginx"}, Range{}, "", false},
	}
	for _, c := range cases {
		got, cpe, ok := RangeFromNVD("CVE-1", c.m)
		if ok != c.ok {
			t.Errorf("%s: ok=%v", c.name, ok)
			continue
		}
		if !ok {
			continue
		}
		c.want.VulnID, c.want.Scheme = "CVE-1", SchemeGeneric
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s: got %+v, want %+v", c.name, got, c.want)
		}
		if cpe.Key() != c.key {
			t.Errorf("%s: key %q", c.name, cpe.Key())
		}
	}
}

func TestRangesFromOSV(t *testing.T) {
	ev := func(kind, v string) OSVEvent {
		switch kind {
		case "i":
			return OSVEvent{Introduced: v}
		case "f":
			return OSVEvent{Fixed: v}
		}
		return OSVEvent{LastAffected: v}
	}
	cases := []struct {
		name     string
		events   []OSVEvent
		versions []string
		want     []Range
	}{
		{"introduced 0 fixed", []OSVEvent{ev("i", "0"), ev("f", "1.2.3")}, nil,
			[]Range{{End: "1.2.3"}}},
		{"introduced fixed", []OSVEvent{ev("i", "1.0"), ev("f", "1.2.3")}, nil,
			[]Range{{Start: "1.0", StartIncl: true, End: "1.2.3"}}},
		{"last affected", []OSVEvent{ev("i", "1.0"), ev("l", "1.4")}, nil,
			[]Range{{Start: "1.0", StartIncl: true, End: "1.4", EndIncl: true}}},
		{"branches", []OSVEvent{ev("i", "15.0"), ev("f", "15.11.10"), ev("i", "16.0"), ev("f", "16.0.6"), ev("i", "16.1"), ev("f", "16.1.3")}, nil,
			[]Range{
				{Start: "15.0", StartIncl: true, End: "15.11.10"},
				{Start: "16.0", StartIncl: true, End: "16.0.6"},
				{Start: "16.1", StartIncl: true, End: "16.1.3"},
			}},
		{"never fixed", []OSVEvent{ev("i", "2.0")}, nil,
			[]Range{{Start: "2.0", StartIncl: true}}},
		{"introduced 0 never fixed is all versions", []OSVEvent{ev("i", "0")}, nil,
			[]Range{{}}},
		{"fixed without introduced is dropped", []OSVEvent{ev("f", "1.0")}, nil, []Range{}},
		{"exact versions", nil, []string{"1.0.1", " ", "1.0.2"},
			[]Range{{Exact: "1.0.1"}, {Exact: "1.0.2"}}},
	}
	for _, c := range cases {
		got := RangesFromOSV("GHSA-x", SchemeGeneric, c.events, c.versions)
		for i := range c.want {
			c.want[i].VulnID, c.want[i].Scheme = "GHSA-x", SchemeGeneric
		}
		if len(got) != len(c.want) || (len(got) > 0 && !reflect.DeepEqual(got, c.want)) {
			t.Errorf("%s: got %+v, want %+v", c.name, got, c.want)
		}
	}
}

// OSV branch ranges and NVD branch ranges of the same issue answer alike.
func TestOSVAndNVDAgree(t *testing.T) {
	osv := RangesFromOSV("CVE-1", SchemeGeneric,
		[]OSVEvent{{Introduced: "16.0"}, {Fixed: "16.0.6"}, {Introduced: "16.1"}, {Fixed: "16.1.3"}}, nil)
	var nvd []Range
	for _, m := range []NVDMatch{
		{Criteria: "cpe:2.3:a:gitlab:gitlab:*:*:*:*:*:*:*:*", VersionStartIncluding: "16.0", VersionEndExcluding: "16.0.6"},
		{Criteria: "cpe:2.3:a:gitlab:gitlab:*:*:*:*:*:*:*:*", VersionStartIncluding: "16.1", VersionEndExcluding: "16.1.3"},
	} {
		r, _, ok := RangeFromNVD("CVE-1", m)
		if !ok {
			t.Fatal("nvd")
		}
		nvd = append(nvd, r)
	}
	for _, v := range []string{"15.9", "16.0", "16.0.5", "16.0.6", "16.1.2", "16.1.3", "17"} {
		a := len(MatchVersion(gen(v), osv)) > 0
		b := len(MatchVersion(gen(v), nvd)) > 0
		if a != b {
			t.Errorf("%s: osv=%v nvd=%v", v, a, b)
		}
	}
}
