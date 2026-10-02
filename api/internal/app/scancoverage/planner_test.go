package scancoverage

import (
	"testing"
	"time"
)

func TestHeadroom_Unlimited(t *testing.T) {
	p := LicensePolicy{Mode: LicenseUnlimited}
	if got := p.Headroom(9999, 500); got != 500 {
		t.Fatalf("unlimited headroom should be the default batch, got %d", got)
	}
}

func TestHeadroom_ActiveIPCap(t *testing.T) {
	p := LicensePolicy{Mode: LicenseActiveIPCap, Cap: 500, SafetyMargin: 20}
	cases := []struct {
		active, want int
	}{
		{0, 480},
		{300, 180},
		{480, 0},
		{500, 0}, // clamp, never negative
		{9999, 0},
	}
	for _, c := range cases {
		if got := p.Headroom(c.active, 500); got != c.want {
			t.Errorf("Headroom(active=%d) = %d, want %d", c.active, got, c.want)
		}
	}
}

func TestCountIPs(t *testing.T) {
	cases := map[string]int{
		"10.0.0.5":        1,
		"10.0.0.0/24":     256,
		"10.0.0.0/30":     4,
		"10.0.0.5/32":     1,
		"host.corp.local": 1,
		"":                0,
		"2001:db8::1":     1,
		"0.0.0.0/0":       2147483647, // MaxInt32 cap
	}
	for target, want := range cases {
		if got := CountIPs(target); got != want {
			t.Errorf("CountIPs(%q) = %d, want %d", target, got, want)
		}
	}
}

func ptrTime(s string) *time.Time {
	t, _ := time.Parse(time.RFC3339, s)
	return &t
}

func TestSelectBatch_OrdersByCriticalityThenStaleness(t *testing.T) {
	old := ptrTime("2026-01-01T00:00:00Z")
	recent := ptrTime("2026-06-01T00:00:00Z")
	cands := []Candidate{
		{AssetID: "low-recent", Target: "10.0.0.1", Criticality: "low", LastScannedAt: recent},
		{AssetID: "crit-recent", Target: "10.0.0.2", Criticality: "critical", LastScannedAt: recent},
		{AssetID: "crit-old", Target: "10.0.0.3", Criticality: "critical", LastScannedAt: old},
		{AssetID: "crit-never", Target: "10.0.0.4", Criticality: "critical", LastScannedAt: nil},
	}
	sel, ips := SelectBatch(cands, 100)
	if ips != 4 || len(sel) != 4 {
		t.Fatalf("expected all 4 selected (4 IPs), got %d (%d ips)", len(sel), ips)
	}
	// critical never-scanned first, then critical-old, then critical-recent, then low.
	want := []string{"crit-never", "crit-old", "crit-recent", "low-recent"}
	for i, w := range want {
		if sel[i].AssetID != w {
			t.Errorf("position %d = %q, want %q (order: %v)", i, sel[i].AssetID, w, ids(sel))
		}
	}
}

func TestSelectBatch_FillsToHeadroom(t *testing.T) {
	cands := []Candidate{
		{AssetID: "a", Target: "10.0.0.0/24", Criticality: "critical"}, // 256
		{AssetID: "b", Target: "10.0.1.0/25", Criticality: "high"},     // 128
		{AssetID: "c", Target: "10.0.2.5", Criticality: "high"},        // 1
	}
	sel, ips := SelectBatch(cands, 300)
	// a (256) fits; b (128) would make 384 > 300 → skipped; c (1) fits → 257.
	if ips != 257 {
		t.Fatalf("expected 257 ips (a+c), got %d (%v)", ips, ids(sel))
	}
	if len(sel) != 2 || sel[0].AssetID != "a" || sel[1].AssetID != "c" {
		t.Fatalf("expected [a c], got %v", ids(sel))
	}
}

func TestSelectBatch_AlwaysTakesTopEvenIfOversized(t *testing.T) {
	cands := []Candidate{
		{AssetID: "big", Target: "10.0.0.0/16", Criticality: "critical"}, // 65536 > cap
		{AssetID: "small", Target: "10.0.1.1", Criticality: "low"},
	}
	sel, ips := SelectBatch(cands, 500)
	if len(sel) != 1 || sel[0].AssetID != "big" {
		t.Fatalf("oversized top candidate must still be taken to avoid starvation, got %v", ids(sel))
	}
	if ips != 65536 {
		t.Fatalf("expected 65536 ips, got %d", ips)
	}
}

func TestSelectBatch_Empty(t *testing.T) {
	if sel, ips := SelectBatch(nil, 500); sel != nil || ips != 0 {
		t.Fatalf("nil candidates → empty")
	}
	if sel, ips := SelectBatch([]Candidate{{AssetID: "a", Target: "1.1.1.1"}}, 0); sel != nil || ips != 0 {
		t.Fatalf("maxIPs=0 → empty")
	}
}

func ids(cs []Candidate) []string {
	out := make([]string, len(cs))
	for i, c := range cs {
		out[i] = c.AssetID
	}
	return out
}
