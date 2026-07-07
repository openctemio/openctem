package attack

import (
	"testing"

	"github.com/openctemio/api/pkg/domain/asset"
)

func node(id, exposure, criticality string, crownJewel bool) asset.AssetNode {
	return asset.AssetNode{
		ID:           id,
		Name:         id,
		AssetType:    "host",
		Exposure:     exposure,
		Criticality:  criticality,
		IsCrownJewel: crownJewel,
	}
}

func edge(src, tgt string, typ asset.RelationshipType) asset.RelationshipEdge {
	return asset.RelationshipEdge{SourceAssetID: src, TargetAssetID: tgt, Type: typ}
}

// A public web asset reaches an internal critical DB through an app tier: the
// engine must emit the full hop chain web → app → db.
func TestBuildExposureChains_MultiHop(t *testing.T) {
	nodes := []asset.AssetNode{
		node("web", "public", "medium", false),
		node("app", "private", "high", false),
		node("db", "private", "critical", true),
		node("orphan", "private", "low", false),
	}
	edges := []asset.RelationshipEdge{
		edge("web", "app", asset.RelTypeExposes),
		edge("app", "db", asset.RelTypeDependsOn),
	}
	kev := map[string]int{"db": 2}
	critical := map[string]int{"db": 1}

	res := buildExposureChains(nodes, edges, kev, critical)

	if len(res.Chains) != 1 {
		t.Fatalf("expected 1 chain, got %d", len(res.Chains))
	}
	c := res.Chains[0]
	if c.EntryPointID != "web" || c.TargetID != "db" {
		t.Errorf("expected web→db, got %s→%s", c.EntryPointID, c.TargetID)
	}
	if c.Length != 2 {
		t.Errorf("expected length 2, got %d", c.Length)
	}
	wantHops := []string{"web", "app", "db"}
	if len(c.Hops) != 3 {
		t.Fatalf("expected 3 hops, got %d", len(c.Hops))
	}
	for i, h := range c.Hops {
		if h.AssetID != wantHops[i] {
			t.Errorf("hop %d: expected %s, got %s", i, wantHops[i], h.AssetID)
		}
	}
	if c.KEVCount != 2 || c.CriticalCount != 1 {
		t.Errorf("expected kev=2 critical=1, got kev=%d critical=%d", c.KEVCount, c.CriticalCount)
	}
	if !c.IsCrownJewel {
		t.Error("target db should be flagged crown jewel")
	}
	if c.ReachableFromEntryPoints != 1 {
		t.Errorf("expected reachable from 1 entry point, got %d", c.ReachableFromEntryPoints)
	}
	if res.Summary.EntryPoints != 1 || res.Summary.TargetsAtRisk != 1 {
		t.Errorf("summary: entryPoints=%d targetsAtRisk=%d", res.Summary.EntryPoints, res.Summary.TargetsAtRisk)
	}
}

// A public asset that itself carries a dangerous finding is a length-0 chain
// (directly exposed) and must rank above a deeper chain of equal danger.
func TestBuildExposureChains_DirectlyExposedRanksHighest(t *testing.T) {
	nodes := []asset.AssetNode{
		node("edge", "public", "critical", false), // directly dangerous
		node("web", "public", "medium", false),
		node("app", "private", "critical", false),
	}
	edges := []asset.RelationshipEdge{
		edge("web", "app", asset.RelTypeExposes),
	}
	kev := map[string]int{"edge": 1, "app": 1}
	critical := map[string]int{}

	res := buildExposureChains(nodes, edges, kev, critical)

	if len(res.Chains) != 2 {
		t.Fatalf("expected 2 chains, got %d", len(res.Chains))
	}
	// Directly-exposed "edge" (length 0, critical) must outrank "app" (length 1).
	if res.Chains[0].TargetID != "edge" {
		t.Errorf("expected directly-exposed 'edge' ranked first, got %s", res.Chains[0].TargetID)
	}
	if res.Chains[0].Length != 0 {
		t.Errorf("expected length 0 for directly-exposed target, got %d", res.Chains[0].Length)
	}
	if len(res.Chains[0].Hops) != 1 || res.Chains[0].Hops[0].AssetID != "edge" {
		t.Errorf("directly-exposed chain should have a single hop [edge], got %+v", res.Chains[0].Hops)
	}
}

// Two entry points reach the same target: only the shortest chain is kept, and
// ReachableFromEntryPoints reflects the blast-radius width.
func TestBuildExposureChains_ShortestPathAndBlastRadius(t *testing.T) {
	nodes := []asset.AssetNode{
		node("near", "public", "low", false),
		node("far", "public", "low", false),
		node("hop", "private", "low", false),
		node("target", "private", "critical", false),
	}
	edges := []asset.RelationshipEdge{
		edge("near", "target", asset.RelTypeDependsOn), // near → target (len 1)
		edge("far", "hop", asset.RelTypeDependsOn),     // far → hop → target (len 2)
		edge("hop", "target", asset.RelTypeDependsOn),
	}
	kev := map[string]int{}
	critical := map[string]int{"target": 1}

	res := buildExposureChains(nodes, edges, kev, critical)

	if len(res.Chains) != 1 {
		t.Fatalf("expected 1 chain to the single target, got %d", len(res.Chains))
	}
	c := res.Chains[0]
	if c.Length != 1 || c.EntryPointID != "near" {
		t.Errorf("expected shortest chain near→target (len 1), got %s (len %d)", c.EntryPointID, c.Length)
	}
	if c.ReachableFromEntryPoints != 2 {
		t.Errorf("expected target reachable from 2 entry points, got %d", c.ReachableFromEntryPoints)
	}
}

// Non-attack-path relationship types (e.g. protected_by/monitors) must NOT create
// a traversable path, and unreachable dangerous assets produce no chain.
func TestBuildExposureChains_IgnoresNonAttackEdgesAndUnreachable(t *testing.T) {
	nodes := []asset.AssetNode{
		node("web", "public", "medium", false),
		node("control", "private", "low", false),
		node("isolated", "isolated", "critical", false), // dangerous but unreachable
	}
	edges := []asset.RelationshipEdge{
		edge("web", "control", asset.RelTypeProtectedBy), // not an attack-path edge
	}
	kev := map[string]int{"isolated": 3}
	critical := map[string]int{}

	res := buildExposureChains(nodes, edges, kev, critical)

	if len(res.Chains) != 0 {
		t.Fatalf("expected 0 chains (no attack-path edge, target unreachable), got %d", len(res.Chains))
	}
	if !res.Summary.HasRelationshipData {
		t.Error("HasRelationshipData should be true when edges exist")
	}
}

// No finding-risk data → no targets → empty chains, but entry points still counted.
func TestBuildExposureChains_NoTargets(t *testing.T) {
	nodes := []asset.AssetNode{
		node("web", "public", "medium", false),
		node("app", "private", "high", false),
	}
	edges := []asset.RelationshipEdge{edge("web", "app", asset.RelTypeExposes)}

	res := buildExposureChains(nodes, edges, nil, nil)

	if len(res.Chains) != 0 {
		t.Fatalf("expected 0 chains with no KEV/critical data, got %d", len(res.Chains))
	}
	if res.Summary.EntryPoints != 1 {
		t.Errorf("expected 1 entry point counted, got %d", res.Summary.EntryPoints)
	}
}

// A target reachable only through a DANGLING hop (an edge to an asset missing
// from the node set — a stale relationship) must NOT be emitted as a gapped,
// wrong-length chain; the whole chain is skipped.
func TestBuildExposureChains_SkipsDanglingHop(t *testing.T) {
	nodes := []asset.AssetNode{
		node("web", "public", "medium", false),
		node("db", "private", "critical", false),
		// "ghost" intentionally absent from nodes (dangling relationship).
	}
	edges := []asset.RelationshipEdge{
		edge("web", "ghost", asset.RelTypeExposes),
		edge("ghost", "db", asset.RelTypeDependsOn),
	}
	res := buildExposureChains(nodes, edges, map[string]int{}, map[string]int{"db": 1})
	if len(res.Chains) != 0 {
		t.Fatalf("expected 0 chains (target only reachable via a dangling hop), got %d", len(res.Chains))
	}
}
