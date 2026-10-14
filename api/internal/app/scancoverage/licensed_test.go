package scancoverage

import (
	"testing"
	"time"
)

func TestSelectLicensedBatch(t *testing.T) {
	seen := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	c := []Candidate{
		{AssetID: "old1", Target: "10.0.0.1", Criticality: "critical", LastScannedAt: &seen, Assessed: true},
		{AssetID: "new1", Target: "10.0.1.1", Criticality: "critical"},
		{AssetID: "new2", Target: "10.0.2.0/30", Criticality: "high"},
		{AssetID: "old2", Target: "10.0.0.2", Criticality: "low", LastScannedAt: &seen, Assessed: true},
		{AssetID: "new3", Target: "10.0.3.1", Criticality: "low"},
	}
	ids := func(b LicensedBatch) []string {
		out := make([]string, 0, len(b.Selected))
		for _, s := range b.Selected {
			out = append(out, s.AssetID)
		}
		return out
	}

	// Off: already counted assets are rescanned without headroom; new ones
	// only while 2 new addresses fit; the /30 (4) and the rest are blocked.
	b := SelectLicensedBatch(c, 100, 2, false)
	if got := ids(b); len(got) != 4 || b.NewIPs != 2 || b.IPs != 4 || b.Blocked != 1 {
		t.Fatalf("off: %v %+v", got, b)
	}

	// Rotation: every address counts against the headroom.
	b = SelectLicensedBatch(c, 100, 5, true)
	if b.NewIPs > 5 || b.IPs != b.NewIPs {
		t.Fatalf("rotation: %+v", b)
	}

	// The batch limit applies to every address, new or not.
	if b = SelectLicensedBatch(c, 2, 100, false); b.IPs > 2 {
		t.Fatalf("batch limit: %+v", b)
	}

	// No headroom: only rescans; nothing forced in.
	if b = SelectLicensedBatch(c, 100, 0, false); len(b.Selected) != 2 || b.NewIPs != 0 || b.Blocked != 3 {
		t.Fatalf("no headroom: %+v", b)
	}
	if b = SelectLicensedBatch(c, 100, 0, true); len(b.Selected) != 0 {
		t.Fatalf("rotation without headroom selects nothing: %+v", b)
	}
	if b = SelectLicensedBatch(nil, 100, 100, false); len(b.Selected) != 0 {
		t.Fatal("empty")
	}
}
