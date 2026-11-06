package asset

import (
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func TestBuildLineage_OrdersByDepthAndTruncates(t *testing.T) {
	rows := []LineageNode{
		{Depth: 2, Name: "example.com", Via: LineageViaContains},
		{Depth: 0, Name: "a.b.example.com"},
		{Depth: 1, Name: "b.example.com", Via: LineageViaContains},
	}
	l := BuildLineage(rows, 5)
	if l.Truncated || len(l.Nodes) != 3 {
		t.Fatalf("got %+v", l)
	}
	for i, want := range []string{"a.b.example.com", "b.example.com", "example.com"} {
		if l.Nodes[i].Name != want || l.Nodes[i].Depth != i {
			t.Fatalf("node %d = %+v, want %s", i, l.Nodes[i], want)
		}
	}

	// One row past the cap: dropped, and the lineage says it goes on.
	l = BuildLineage(rows, 1)
	if !l.Truncated || len(l.Nodes) != 2 || l.Nodes[1].Name != "b.example.com" {
		t.Fatalf("capped: %+v", l)
	}
}

// A hidden node keeps only its depth and edge, even if a reader filled in
// its fields by mistake.
func TestBuildLineage_StripsHiddenNodes(t *testing.T) {
	now := time.Now()
	rows := []LineageNode{
		{Depth: 0, Name: "in.example.com", ID: shared.NewID()},
		{
			Depth: 1, Hidden: true, Via: LineageViaContains, ID: shared.NewID(), Name: "secret.example.com",
			Type: AssetTypeDomain, DiscoverySource: "dns", DiscoveryTool: "subfinder",
			DiscoveredAt: &now, FirstSeen: &now,
		},
	}
	l := BuildLineage(rows, LineageMaxDepth)
	got := l.Nodes[1]
	if got.Depth != 1 || !got.Hidden || got.Via != LineageViaContains || !got.ID.IsZero() || got.Name != "" ||
		got.Type != "" || got.DiscoverySource != "" || got.DiscoveryTool != "" || got.DiscoveredAt != nil || got.FirstSeen != nil {
		t.Fatalf("hidden node leaked fields: %+v", got)
	}
	if l.Nodes[0].Name != "in.example.com" {
		t.Fatalf("visible node changed: %+v", l.Nodes[0])
	}
}
