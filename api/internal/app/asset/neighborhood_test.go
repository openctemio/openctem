package asset

import (
	"errors"
	"testing"

	assetdom "github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func TestParseNeighborhoodInput_BoundsAndFilters(t *testing.T) {
	q, err := parseNeighborhoodInput(NeighborhoodInput{})
	if err != nil || q.Depth != 2 || q.Direction != "both" || q.MaxNodes != 150 {
		t.Fatalf("defaults: %+v %v", q, err)
	}
	q, err = parseNeighborhoodInput(NeighborhoodInput{Depth: 50, MaxNodes: 1 << 20, Direction: "in",
		Types: []string{"ip_address"}, Relations: []string{"resolves_to"}})
	if err != nil || q.Depth != 3 || q.MaxNodes != 300 || q.Direction != "in" || len(q.Types) != 1 || len(q.Relations) != 1 {
		t.Fatalf("clamped: %+v %v", q, err)
	}
	many := make([]string, assetdom.NeighborhoodMaxFilters+1)
	for i := range many {
		many[i] = "domain"
	}
	for name, in := range map[string]NeighborhoodInput{
		"direction":      {Direction: "up"},
		"type":           {Types: []string{"bogus"}},
		"relation":       {Relations: []string{"bogus"}},
		"too many types": {Types: many},
	} {
		if _, err := parseNeighborhoodInput(in); !errors.Is(err, shared.ErrValidation) {
			t.Fatalf("%s: want validation error, got %v", name, err)
		}
	}
}

func TestNeighborhoodWalk_CapClustersLineageAndCycles(t *testing.T) {
	self := assetdom.NeighborhoodNode{ID: shared.NewID(), Name: "self", Type: assetdom.AssetTypeIPAddress}
	root := shared.NewID()
	w := newNeighborhoodWalk(assetdom.NeighborhoodQuery{Depth: 2, MaxNodes: 2}, self)
	w.addLineage(assetdom.Lineage{Nodes: []assetdom.LineageNode{
		{Depth: 0, ID: self.ID},
		{Depth: 1, Hidden: true, Via: "resolves_to"},
		{Depth: 2, ID: root, Name: "root", Type: assetdom.AssetTypeDomain, Via: "contains"},
	}})
	// The lineage root is drawn but not walked and does not count.
	if len(w.order) != 2 || w.walked != 1 || w.nodes[root].Distance != -1 {
		t.Fatalf("lineage: %+v walked %d", w.order, w.walked)
	}

	a, b := shared.NewID(), shared.NewID()
	w.apply(&assetdom.NeighborhoodHop{
		Edges: []assetdom.NeighborhoodEdge{
			{Anchor: self.ID, Other: assetdom.NeighborhoodNode{ID: a, Type: assetdom.AssetTypeService}, Type: assetdom.RelTypeExposes, Direction: assetdom.RelationshipDirectionOutgoing},
			{Anchor: self.ID, Other: assetdom.NeighborhoodNode{ID: b, Type: assetdom.AssetTypeService}, Type: assetdom.RelTypeExposes, Direction: assetdom.RelationshipDirectionOutgoing},
			// The same edge twice (both ends in the frontier) is drawn once.
			{Anchor: self.ID, Other: assetdom.NeighborhoodNode{ID: a, Type: assetdom.AssetTypeService}, Type: assetdom.RelTypeExposes, Direction: assetdom.RelationshipDirectionOutgoing},
		},
		HiddenByAnchor: map[shared.ID]int{self.ID: 3},
	}, 1)
	if !w.truncated || len(w.edges) != 1 || w.edges[0].Source != self.ID || w.edges[0].Target != a {
		t.Fatalf("cap: truncated %v edges %+v", w.truncated, w.edges)
	}
	if len(w.clusters) != 1 || w.clusters[0].Count() != 1 || w.clusters[0].ByType[assetdom.AssetTypeService] != 1 {
		t.Fatalf("over-cap cluster: %+v", w.clusters)
	}
	res := w.result(assetdom.Lineage{})
	if res.HiddenCount != 3 || !res.Nodes[0].Expanded || res.Nodes[0].HiddenNeighbors != 3 {
		t.Fatalf("hidden: %+v", res.Nodes[0])
	}
	if len(w.frontier) != 1 || w.frontier[0] != a {
		t.Fatalf("next frontier: %+v", w.frontier)
	}

	// An incoming edge back to the asset (a cycle) adds no node and keeps
	// the stored direction; reaching the lineage root gives it a distance.
	w2 := newNeighborhoodWalk(assetdom.NeighborhoodQuery{Depth: 3, MaxNodes: 10}, self)
	w2.addLineage(assetdom.Lineage{Nodes: []assetdom.LineageNode{{Depth: 0, ID: self.ID}, {Depth: 1, ID: root, Type: assetdom.AssetTypeDomain, Via: "contains"}}})
	w2.apply(&assetdom.NeighborhoodHop{Edges: []assetdom.NeighborhoodEdge{
		{Anchor: self.ID, Other: assetdom.NeighborhoodNode{ID: root, Name: "root", Type: assetdom.AssetTypeDomain, Criticality: "high"}, Type: assetdom.RelTypeContains, Direction: assetdom.RelationshipDirectionIncoming, Known: true},
	}}, 1)
	w2.apply(&assetdom.NeighborhoodHop{Edges: []assetdom.NeighborhoodEdge{
		{Anchor: root, Other: self, Type: assetdom.RelTypeContains, Direction: assetdom.RelationshipDirectionOutgoing, Known: true},
	}}, 2)
	if len(w2.order) != 2 || len(w2.edges) != 1 || w2.edges[0].Source != root || w2.nodes[root].Distance != 1 || w2.nodes[root].Criticality != "high" {
		t.Fatalf("cycle: order %v edges %+v root %+v", w2.order, w2.edges, w2.nodes[root])
	}
	if len(w2.frontier) != 0 {
		t.Fatalf("cycle revisited: %+v", w2.frontier)
	}
}
