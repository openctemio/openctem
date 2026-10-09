package scope

import (
	"testing"
	"time"
)

func TestSnapshot_CanonicalIsOrderIndependent(t *testing.T) {
	at := time.Date(2026, 10, 9, 1, 2, 3, 456789123, time.FixedZone("x", 7*3600))
	a := &Snapshot{Targets: 3, Entries: []SnapshotEntry{
		{ID: "b", Pattern: "*.b.example", Source: "program", ProgramID: "p1", MaxTier: "t1"},
		{ID: "a", Pattern: "a.example", Source: "ownership", MaxTier: "t1", ApprovedAt: &at},
	}, Programs: []SnapshotProgram{{ID: "p1", TermsSHA256: "h", Exclusions: []string{"domain:z.b.example", "domain:b.example"}}}}
	utcAt := at.UTC()
	b := &Snapshot{Targets: 3, Entries: []SnapshotEntry{
		{ID: "a", Pattern: "a.example", Source: "ownership", MaxTier: "t1", ApprovedAt: &utcAt},
		{ID: "b", Pattern: "*.b.example", Source: "program", ProgramID: "p1", MaxTier: "t1"},
	}, Programs: []SnapshotProgram{{ID: "p1", TermsSHA256: "h", Exclusions: []string{"domain:b.example", "domain:z.b.example"}}}}
	ba, ha, err := a.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	bb, hb, _ := b.Canonical()
	if ha != hb || string(ba) != string(bb) || len(ha) != 64 {
		t.Fatalf("order or time zone changed the hash:\n%s\n%s", ba, bb)
	}
	b.Programs[0].TermsSHA256 = "other"
	if _, hc, _ := b.Canonical(); hc == ha {
		t.Fatal("a different attestation must change the hash")
	}
	empty := &Snapshot{}
	body, _, _ := empty.Canonical()
	if string(body) != `{"version":1,"targets":0,"entries":[],"programs":[],"uncovered":0}` {
		t.Fatalf("empty body: %s", body)
	}
}
