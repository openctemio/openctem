package attack

import (
	"fmt"
	"math/rand"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/asset"
)

// randomGraph builds a reproducible random directed graph of n assets with
// about 2n attack-path edges, publicPct percent public and dangerPct percent
// carrying a critical finding.
func randomGraph(n, publicPct, dangerPct int, seed int64) ([]asset.AssetNode, []asset.RelationshipEdge, map[string]int) {
	rng := rand.New(rand.NewSource(seed))
	nodes := make([]asset.AssetNode, n)
	critical := map[string]int{}
	for i := range nodes {
		exp := "private"
		if rng.Intn(100) < publicPct {
			exp = "public"
		}
		nodes[i] = node(fmt.Sprintf("a%06d", i), exp, "medium", false)
		if rng.Intn(100) < dangerPct {
			critical[nodes[i].ID] = 1
		}
	}
	types := []asset.RelationshipType{asset.RelTypeExposes, asset.RelTypeDependsOn, asset.RelTypeRunsOn, asset.RelTypeResolvesTo}
	edges := make([]asset.RelationshipEdge, 0, 2*n)
	for i := 0; i < 2*n; i++ {
		edges = append(edges, edge(nodes[rng.Intn(n)].ID, nodes[rng.Intn(n)].ID, types[rng.Intn(len(types))]))
	}
	return nodes, edges, critical
}

// referenceShortest is the original algorithm, one breadth-first search per
// entry point, reduced to what must agree: the shortest length to each target.
func referenceShortest(nodes []asset.AssetNode, edges []asset.RelationshipEdge, critical map[string]int) map[string]int {
	adj := map[string][]string{}
	live := map[string]bool{}
	for _, n := range nodes {
		live[n.ID] = true
	}
	for _, e := range edges {
		if attackPathRelationshipTypes[e.Type] && live[e.SourceAssetID] && live[e.TargetAssetID] {
			adj[e.SourceAssetID] = append(adj[e.SourceAssetID], e.TargetAssetID)
		}
	}
	best := map[string]int{}
	for _, n := range nodes {
		if n.Exposure != "public" {
			continue
		}
		dist := map[string]int{n.ID: 0}
		queue := []string{n.ID}
		for len(queue) > 0 {
			cur := queue[0]
			queue = queue[1:]
			if critical[cur] > 0 {
				if d, ok := best[cur]; !ok || dist[cur] < d {
					best[cur] = dist[cur]
				}
			}
			for _, nb := range adj[cur] {
				if _, seen := dist[nb]; !seen {
					dist[nb] = dist[cur] + 1
					queue = append(queue, nb)
				}
			}
		}
	}
	return best
}

// The one-pass builder agrees with the per-entry-point search on which assets
// are reachable and how short the chain to each is, and every chain it returns
// is a real path of attack-path edges from a public entry point.
func TestBuildExposureChains_ParityWithPerEntrySearch(t *testing.T) {
	for seed := int64(1); seed <= 20; seed++ {
		nodes, edges, critical := randomGraph(300, 10, 8, seed)
		want := referenceShortest(nodes, edges, critical)
		res := buildExposureChains(nodes, edges, nil, critical)

		if len(res.Chains) != len(want) {
			t.Fatalf("seed %d: %d chains, want %d", seed, len(res.Chains), len(want))
		}
		isEdge := map[[2]string]bool{}
		for _, e := range edges {
			if attackPathRelationshipTypes[e.Type] {
				isEdge[[2]string{e.SourceAssetID, e.TargetAssetID}] = true
			}
		}
		pub := map[string]bool{}
		for _, n := range nodes {
			pub[n.ID] = n.Exposure == "public"
		}
		for _, c := range res.Chains {
			if d, ok := want[c.TargetID]; !ok || d != c.Length {
				t.Fatalf("seed %d: target %s length %d, want %d (reachable %v)", seed, c.TargetID, c.Length, d, ok)
			}
			if !pub[c.Hops[0].AssetID] || c.Hops[0].AssetID != c.EntryPointID || c.Hops[len(c.Hops)-1].AssetID != c.TargetID {
				t.Fatalf("seed %d: chain to %s does not run from a public entry point to the target", seed, c.TargetID)
			}
			for i := 1; i < len(c.Hops); i++ {
				if !isEdge[[2]string{c.Hops[i-1].AssetID, c.Hops[i].AssetID}] {
					t.Fatalf("seed %d: hop %d of chain to %s is not an attack-path edge", seed, i, c.TargetID)
				}
			}
		}
	}
}

// A path never runs through an asset that no longer exists: the target is
// found through the live route even when a dead edge is shorter.
func TestBuildExposureChains_SkipsEdgesToMissingAssets(t *testing.T) {
	nodes := []asset.AssetNode{
		node("web", "public", "low", false),
		node("a", "private", "low", false),
		node("db", "private", "critical", false),
	}
	edges := []asset.RelationshipEdge{
		edge("web", "ghost", asset.RelTypeExposes),
		edge("ghost", "db", asset.RelTypeDependsOn),
		edge("web", "a", asset.RelTypeExposes),
		edge("a", "db", asset.RelTypeDependsOn),
	}
	res := buildExposureChains(nodes, edges, nil, map[string]int{"db": 1})
	if len(res.Chains) != 1 || res.Chains[0].Length != 2 || res.Chains[0].Hops[1].AssetID != "a" {
		t.Fatalf("chains = %+v, want web→a→db", res.Chains)
	}
}

// BenchmarkBuildExposureChains_50k is the target of the one-pass builder:
// 50,000 assets, 100,000 edges, 10% public, under 500 ms.
func BenchmarkBuildExposureChains_50k(b *testing.B) {
	nodes, edges, critical := randomGraph(50_000, 10, 2, 7)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		buildExposureChains(nodes, edges, nil, critical)
	}
}

// A coarse guard so the quadratic version cannot return: a 50k-asset tenant
// (156 s with a search per entry point) must finish in seconds, race detector
// included.
func TestBuildExposureChains_LargeGraphStaysLinear(t *testing.T) {
	if testing.Short() {
		t.Skip("large graph")
	}
	nodes, edges, critical := randomGraph(50_000, 10, 2, 7)
	start := time.Now()
	res := buildExposureChains(nodes, edges, nil, critical)
	if d := time.Since(start); d > 5*time.Second {
		t.Fatalf("50k assets took %v, want well under 5s", d)
	}
	if len(res.Chains) == 0 {
		t.Fatal("expected chains on the synthetic graph")
	}
}
