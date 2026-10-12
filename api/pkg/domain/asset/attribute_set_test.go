package asset

import (
	"reflect"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func TestNormalizeSetElement(t *testing.T) {
	tests := []struct {
		attr    SetAttribute
		in      string
		want    string
		wantErr bool
	}{
		{SetAttrIPAddresses, " 203.0.113.5 ", "203.0.113.5", false},
		{SetAttrIPAddresses, "2001:DB8::1", "2001:db8::1", false},
		{SetAttrIPAddresses, "not-an-ip", "", true},
		{SetAttrOpenPorts, "443", "443/tcp", false},
		{SetAttrOpenPorts, "53/UDP", "53/udp", false},
		{SetAttrOpenPorts, "70000/tcp", "", true},
		{SetAttrOpenPorts, "22/sctp", "", true},
		{SetAttrTechnologies, " nginx:1.25 ", "nginx:1.25", false},
		{SetAttrTechnologies, "", "", true},
		{SetAttribute("tags"), "x", "", true},
	}
	for _, tc := range tests {
		got, err := NormalizeSetElement(tc.attr, tc.in)
		if (err != nil) != tc.wantErr || got != tc.want {
			t.Errorf("NormalizeSetElement(%s, %q) = %q, %v; want %q, err=%v", tc.attr, tc.in, got, err, tc.want, tc.wantErr)
		}
	}
}

func TestPortScanCoverage(t *testing.T) {
	c := PortScanCoverage("80,443,8000-8100", "")
	if c.Mode != CoverageRanges || c.Key != "ports:80,443,8000-8100" {
		t.Fatalf("explicit list: %+v", c)
	}
	for e, want := range map[string]bool{"80/tcp": true, "8050/tcp": true, "22/tcp": false, "80/udp": false} {
		if got := c.Covers(SetAttrOpenPorts, e, "ports:other"); got != want {
			t.Errorf("Covers(%s) = %v, want %v", e, got, want)
		}
	}
	if full := PortScanCoverage("full", ""); !full.CoversUnattributed(SetAttrOpenPorts, "65000/tcp") {
		t.Error("a full scan covers every TCP port")
	}
	top := PortScanCoverage("", "100")
	if top.Mode != CoverageKeyed || top.Key != "ports:top-100" {
		t.Fatalf("top ports: %+v", top)
	}
	if top.Covers(SetAttrOpenPorts, "8443/tcp", "ports:full") {
		t.Error("a top-100 scan must not cover a port a full scan found")
	}
	if !top.Covers(SetAttrOpenPorts, "8443/tcp", "ports:top-100") {
		t.Error("a top-100 scan covers what an earlier top-100 scan found")
	}
	if top.CoversUnattributed(SetAttrOpenPorts, "80/tcp") {
		t.Error("a keyed scan never covers an element no source recorded")
	}
	if d := PortScanCoverage("", ""); d.Key != "ports:default" {
		t.Fatalf("default: %+v", d)
	}
	if bad := PortScanCoverage("80-", ""); bad.Mode != CoverageKeyed {
		t.Fatalf("an unreadable list falls back to keyed: %+v", bad)
	}
}

func TestPlanSetObservation(t *testing.T) {
	id := shared.NewID()
	t0 := time.Date(2026, 10, 10, 8, 0, 0, 0, time.UTC)
	row := func(e, key string, last time.Time, removed *time.Time) SetElement {
		return SetElement{AssetID: id, Attribute: SetAttrOpenPorts, Kind: SourceKindScan, Name: "naabu",
			Element: e, CoverageKey: key, FirstSeen: last, LastSeen: last, RemovedAt: removed}
	}
	obs := func(at time.Time, cov SetCoverage, elems ...string) SetObservation {
		return SetObservation{AssetID: id, Attribute: SetAttrOpenPorts, Kind: SourceKindScan, Name: "naabu",
			ObservedAt: at, Coverage: cov, Elements: elems}
	}
	full := PortScanCoverage("full", "")
	top := PortScanCoverage("top-100", "")
	elems := func(w []SetElement) map[string]bool {
		out := map[string]bool{}
		for _, e := range w {
			out[e.Element] = e.Live()
		}
		return out
	}

	t.Run("a partial scan keeps what lies outside its coverage", func(t *testing.T) {
		v := map[ObservationVerdict]int{}
		stored := []SetElement{row("80/tcp", "ports:full", t0, nil), row("8443/tcp", "ports:full", t0, nil)}
		w := PlanSetObservation(stored, obs(t0.Add(2*time.Hour), PortScanCoverage("1-1000", ""), "80/tcp"), v)
		if got := elems(w); !reflect.DeepEqual(got, map[string]bool{"80/tcp": true}) {
			t.Fatalf("writes = %v (8443 is outside 1-1000 and must stay untouched)", got)
		}
		w = PlanSetObservation(stored, obs(t0.Add(2*time.Hour), top, "80/tcp"), v)
		if got := elems(w); !reflect.DeepEqual(got, map[string]bool{"80/tcp": true}) {
			t.Fatalf("top-100 writes = %v", got)
		}
	})
	t.Run("the same coverage again without an element removes it", func(t *testing.T) {
		v := map[ObservationVerdict]int{}
		stored := []SetElement{row("80/tcp", "ports:full", t0, nil), row("8443/tcp", "ports:full", t0, nil)}
		w := PlanSetObservation(stored, obs(t0.Add(2*time.Hour), full, "80/tcp"), v)
		if got := elems(w); !reflect.DeepEqual(got, map[string]bool{"80/tcp": true, "8443/tcp": false}) {
			t.Fatalf("writes = %v", got)
		}
		if v[ObservationRemoved] != 1 {
			t.Fatalf("verdicts = %v", v)
		}
	})
	t.Run("a re-sighting within the hour writes nothing", func(t *testing.T) {
		v := map[ObservationVerdict]int{}
		w := PlanSetObservation([]SetElement{row("80/tcp", "ports:full", t0, nil)}, obs(t0.Add(10*time.Minute), full, "80/tcp"), v)
		if len(w) != 0 || v[ObservationResighted] != 1 {
			t.Fatalf("writes = %v verdicts = %v", w, v)
		}
	})
	t.Run("an older or replayed observation changes nothing", func(t *testing.T) {
		v := map[ObservationVerdict]int{}
		stored := []SetElement{row("80/tcp", "ports:full", t0, nil), row("22/tcp", "ports:full", t0, nil)}
		if w := PlanSetObservation(stored, obs(t0.Add(-time.Hour), full, "80/tcp"), v); len(w) != 0 {
			t.Fatalf("an older observation wrote %v", w)
		}
		if w := PlanSetObservation(stored, obs(t0, full), v); len(w) != 0 {
			t.Fatalf("a replay wrote %v", w)
		}
		if v[ObservationOutOfOrder] != 1 {
			t.Fatalf("verdicts = %v", v)
		}
	})
	t.Run("an element removed later is not revived by an older sighting", func(t *testing.T) {
		v := map[ObservationVerdict]int{}
		gone := t0.Add(3 * time.Hour)
		stored := []SetElement{row("8443/tcp", "ports:full", t0, &gone)}
		if w := PlanSetObservation(stored, obs(t0.Add(time.Hour), top, "8443/tcp"), v); len(w) != 0 {
			t.Fatalf("revived by an older report: %v", w)
		}
		w := PlanSetObservation(stored, obs(t0.Add(4*time.Hour), top, "8443/tcp"), v)
		if got := elems(w); !reflect.DeepEqual(got, map[string]bool{"8443/tcp": true}) {
			t.Fatalf("a newer sighting re-adds: %v", got)
		}
	})
	t.Run("sightings never remove", func(t *testing.T) {
		v := map[ObservationVerdict]int{}
		w := PlanSetObservation([]SetElement{row("80/tcp", "", t0, nil)},
			obs(t0.Add(2*time.Hour), SetCoverage{Mode: CoverageSightings}, "443/tcp"), v)
		if got := elems(w); !reflect.DeepEqual(got, map[string]bool{"443/tcp": true}) {
			t.Fatalf("writes = %v", got)
		}
	})
}

func TestResolveSet(t *testing.T) {
	id := shared.NewID()
	now := time.Date(2026, 10, 10, 8, 0, 0, 0, time.UTC)
	gone := now.Add(-time.Hour)
	rows := []SetElement{
		{AssetID: id, Attribute: SetAttrIPAddresses, Kind: SourceKindScan, Name: "dnsx", Element: "203.0.113.1", LastSeen: now.Add(-time.Hour)},
		{AssetID: id, Attribute: SetAttrIPAddresses, Kind: SourceKindIntegration, Name: "cmdb", Element: "203.0.113.2", LastSeen: now.Add(-time.Hour)},
		// Removed by dnsx, still reported by the CMDB: kept.
		{AssetID: id, Attribute: SetAttrIPAddresses, Kind: SourceKindScan, Name: "dnsx", Element: "203.0.113.2", LastSeen: now.Add(-2 * time.Hour), RemovedAt: &gone},
		// Removed by its only source: gone.
		{AssetID: id, Attribute: SetAttrIPAddresses, Kind: SourceKindScan, Name: "dnsx", Element: "203.0.113.3", LastSeen: now.Add(-2 * time.Hour), RemovedAt: &gone},
		// Past the scan TTL (30 days): gone.
		{AssetID: id, Attribute: SetAttrIPAddresses, Kind: SourceKindScan, Name: "httpx", Element: "203.0.113.4", LastSeen: now.AddDate(0, 0, -31)},
		// A feed is not trusted for identity when the policy says so.
		{AssetID: id, Attribute: SetAttrIPAddresses, Kind: SourceKindFeed, Name: "pdns", Element: "203.0.113.5", LastSeen: now},
	}
	p := DefaultReconciliationPolicy()
	p.Classes[AttrClassIdentity] = []SourceRule{
		{Source: "integration", TTL: 30 * 24 * time.Hour, Trusted: true},
		{Source: "scan", TTL: 30 * 24 * time.Hour, Trusted: true},
		{Source: "feed", TTL: 30 * 24 * time.Hour, Trusted: false},
	}
	prev := []string{"203.0.113.1", "203.0.113.3", "198.51.100.9", "198.51.100.10"}
	res := ResolveSet(SetAttrIPAddresses, rows, prev, map[string]bool{"198.51.100.10": true}, p, now)
	want := []string{"198.51.100.9", "203.0.113.1", "203.0.113.2"}
	if !reflect.DeepEqual(res.Elements, want) {
		t.Fatalf("resolved = %v, want %v", res.Elements, want)
	}
	if !reflect.DeepEqual(res.Unattributed, []string{"198.51.100.9"}) {
		t.Fatalf("unattributed = %v", res.Unattributed)
	}
	added, removed := DiffSets(prev, res.Elements)
	if !reflect.DeepEqual(added, []string{"203.0.113.2"}) || !reflect.DeepEqual(removed, []string{"198.51.100.10", "203.0.113.3"}) {
		t.Fatalf("diff = +%v -%v", added, removed)
	}
}
