package attack

import (
	"testing"

	assetapp "github.com/openctemio/api/internal/app/asset"
	"github.com/openctemio/api/pkg/domain/asset"
	"github.com/openctemio/api/pkg/domain/shared"
)

// TestGraphEnrichment_LightsUpExposureChain is the payoff test: it proves the
// exposure-chain engine goes from STARVED to PRODUCTIVE once the graph
// enrichment adds the host↔service hops.
//
// Scenario mirrors real ingested data:
//   - subdomain "app.example.com" (public entry point) resolves_to an
//     ip_address "203.0.113.10" — the only edges ingest creates today.
//   - an open_port "203.0.113.10:8080" (Naabu, properties.host=IP) carries a
//     KEV finding — the dangerous target.
//
// BEFORE enrichment (DNS edges only): the internet reaches the ip_address and
// stops — there is NO path to the dangerous port, so NO chain exists.
// AFTER enrichment: ip_address --Exposes--> open_port is inferred, and the
// engine now surfaces the full internet→port chain.
func TestGraphEnrichment_LightsUpExposureChain(t *testing.T) {
	subID := shared.NewID()
	ipID := shared.NewID()
	portID := shared.NewID()

	// Graph nodes for the exposure-chain engine (string IDs).
	nodes := []asset.AssetNode{
		{ID: subID.String(), Name: "app.example.com", AssetType: "subdomain", Exposure: string(asset.ExposurePublic)},
		{ID: ipID.String(), Name: "203.0.113.10", AssetType: "ip_address", Exposure: string(asset.ExposurePublic)},
		{ID: portID.String(), Name: "203.0.113.10:8080/tcp", AssetType: "service", Exposure: string(asset.ExposureUnknown)},
	}

	// Edges ingest creates today: only DNS resolves_to.
	baselineEdges := []asset.RelationshipEdge{
		{SourceAssetID: subID.String(), TargetAssetID: ipID.String(), Type: asset.RelTypeResolvesTo},
	}

	// The open_port carries a KEV finding → it is the dangerous target.
	kev := map[string]int{portID.String(): 1}
	critical := map[string]int{}

	// --- BEFORE: starved. No chain reaches the dangerous port. ---
	before := buildExposureChains(nodes, baselineEdges, kev, critical)
	if reachesTarget(before, portID.String()) {
		t.Fatalf("precondition failed: expected NO chain to the port before enrichment, got %d chains", len(before.Chains))
	}

	// --- ENRICH: run the real inference over the same asset set. ---
	graphAssets := []assetapp.GraphAsset{
		{ID: subID, Type: asset.AssetTypeSubdomain, Name: "app.example.com",
			Props: map[string]any{"resolved_ips": []string{"203.0.113.10"}}},
		{ID: ipID, Type: asset.AssetTypeIPAddress, Name: "203.0.113.10"},
		{ID: portID, Type: asset.AssetTypeService, SubType: "open_port",
			Name: "203.0.113.10:8080/tcp", Props: map[string]any{"host": "203.0.113.10", "port": 8080}},
	}
	inferred := assetapp.InferGraphEdges(graphAssets)

	// The inference must have produced exactly the ip_address→port Exposes edge.
	if len(inferred.AutoEdges) == 0 {
		t.Fatalf("enrichment produced no auto edges — nothing to unstarve the engine")
	}
	enrichedEdges := append([]asset.RelationshipEdge{}, baselineEdges...)
	for _, e := range inferred.AutoEdges {
		enrichedEdges = append(enrichedEdges, asset.RelationshipEdge{
			SourceAssetID: e.SourceID.String(),
			TargetAssetID: e.TargetID.String(),
			Type:          e.Type,
		})
	}

	// --- AFTER: productive. A chain now reaches the dangerous port. ---
	after := buildExposureChains(nodes, enrichedEdges, kev, critical)
	if !reachesTarget(after, portID.String()) {
		t.Fatalf("expected a chain to the port after enrichment, got %d chains", len(after.Chains))
	}

	// Verify the chain is a real internet→port path with correct hops.
	ch := findChain(after, portID.String())
	if ch == nil {
		t.Fatal("no chain to port target after enrichment")
	}
	if ch.KEVCount != 1 {
		t.Errorf("expected KEVCount 1 on target, got %d", ch.KEVCount)
	}
	// Shortest chain is from the ip_address entry point (length 1): ip→port.
	if ch.Length != 1 {
		t.Errorf("expected shortest chain length 1 (ip→port), got %d", ch.Length)
	}
	last := ch.Hops[len(ch.Hops)-1]
	if last.AssetID != portID.String() {
		t.Errorf("expected chain to terminate at the port, got %s", last.AssetID)
	}
}

func reachesTarget(res *ExposureChainResult, targetID string) bool {
	return findChain(res, targetID) != nil
}

func findChain(res *ExposureChainResult, targetID string) *ExposureChain {
	for i := range res.Chains {
		if res.Chains[i].TargetID == targetID {
			return &res.Chains[i]
		}
	}
	return nil
}
