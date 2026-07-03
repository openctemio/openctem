package attack

import (
	"context"
	"fmt"
	"sort"

	"github.com/openctemio/api/pkg/domain/asset"
	"github.com/openctemio/api/pkg/domain/shared"
)

// FindingRiskCounter provides, per asset, the number of open KEV and critical
// findings. Implemented by the finding repository; injected via a setter so the
// attack-surface service stays decoupled from the vulnerability layer.
type FindingRiskCounter interface {
	KEVCriticalCountsByAsset(ctx context.Context, tenantID shared.ID) (kev, critical map[string]int, err error)
}

// exposureChainCap bounds the number of chains returned (highest-scored first).
const exposureChainCap = 100

// ChainHop is one asset on an exposure chain.
type ChainHop struct {
	AssetID   string `json:"asset_id"`
	Name      string `json:"name"`
	AssetType string `json:"asset_type"`
	Exposure  string `json:"exposure"`
}

// ExposureChain is the shortest path from a public entry point to an asset that
// carries a KEV or critical finding — the concrete "how the internet reaches a
// dangerous asset" story that plain reachability scoring doesn't surface.
type ExposureChain struct {
	// EntryPointID/Name is the nearest public entry point that reaches the target.
	EntryPointID   string `json:"entry_point_id"`
	EntryPointName string `json:"entry_point_name"`
	// TargetID/Name is the reached asset carrying KEV/critical findings.
	TargetID          string `json:"target_id"`
	TargetName        string `json:"target_name"`
	TargetCriticality string `json:"target_criticality"`
	IsCrownJewel      bool   `json:"is_crown_jewel"`
	// Hops is the ordered path entry → … → target (inclusive). Length 1 means the
	// entry point itself is the target (a directly-exposed dangerous asset).
	Hops []ChainHop `json:"hops"`
	// Length is the number of edges traversed (len(Hops)-1); 0 = directly exposed.
	Length int `json:"length"`
	// ReachableFromEntryPoints is how many distinct public entry points can reach
	// this target (blast-radius width).
	ReachableFromEntryPoints int `json:"reachable_from_entry_points"`
	// KEVCount/CriticalCount are the open KEV / critical findings on the target.
	KEVCount      int `json:"kev_count"`
	CriticalCount int `json:"critical_count"`
	// Score ranks urgency: dangerous + close-to-internet + crown-jewel = higher.
	Score float64 `json:"score"`
}

// ExposureChainSummary holds aggregate metrics for the tenant.
type ExposureChainSummary struct {
	EntryPoints         int  `json:"entry_points"`
	TargetsAtRisk       int  `json:"targets_at_risk"`
	TotalChains         int  `json:"total_chains"`
	HasRelationshipData bool `json:"has_relationship_data"`
}

// ExposureChainResult is the full result returned by ComputeExposureChains.
type ExposureChainResult struct {
	Summary ExposureChainSummary `json:"summary"`
	Chains  []ExposureChain      `json:"chains"`
}

// GetExposureChains computes exposure chains for the tenant. Returns an empty
// result (not an error) when no finding-risk counter is wired.
func (s *SurfaceService) GetExposureChains(ctx context.Context, tenantID shared.ID) (*ExposureChainResult, error) {
	nodes, err := s.assetRepo.ListAllNodes(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("load nodes: %w", err)
	}
	edges, err := s.relRepo.ListAllEdges(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("load edges: %w", err)
	}

	var kev, critical map[string]int
	if s.findingRisk != nil {
		kev, critical, err = s.findingRisk.KEVCriticalCountsByAsset(ctx, tenantID)
		if err != nil {
			return nil, fmt.Errorf("load kev/critical counts: %w", err)
		}
	}

	return buildExposureChains(nodes, edges, kev, critical), nil
}

// buildExposureChains is the pure core (no IO) so it is unit-testable with
// synthetic graphs. For every asset that carries a KEV or critical finding it
// finds the shortest path from any public entry point, following attack-path
// relationship types, and ranks the resulting chains by urgency.
func buildExposureChains(
	nodes []asset.AssetNode,
	edges []asset.RelationshipEdge,
	kev, critical map[string]int,
) *ExposureChainResult {
	nodeByID := make(map[string]*asset.AssetNode, len(nodes))
	for i := range nodes {
		nodeByID[nodes[i].ID] = &nodes[i]
	}

	// Directed adjacency over attack-path edges only (same set the scorer uses).
	adj := make(map[string][]string, len(nodes))
	for _, e := range edges {
		if attackPathRelationshipTypes[e.Type] {
			adj[e.SourceAssetID] = append(adj[e.SourceAssetID], e.TargetAssetID)
		}
	}

	// A "target" is any node carrying at least one KEV or critical finding.
	isTarget := func(id string) bool { return kev[id] > 0 || critical[id] > 0 }

	entryPoints := make([]string, 0)
	for i := range nodes {
		if nodes[i].Exposure == string(asset.ExposurePublic) {
			entryPoints = append(entryPoints, nodes[i].ID)
		}
	}

	// best[target] = the shortest chain found so far to that target.
	best := make(map[string]*ExposureChain)
	// reachCount[target] = number of distinct entry points that can reach it.
	reachCount := make(map[string]int)

	for _, ep := range entryPoints {
		// BFS from this entry point capturing predecessors, so we can reconstruct
		// the actual hop path (the scorer discards these).
		parent := map[string]string{ep: ""}
		visited := map[string]bool{ep: true}
		queue := []string{ep}
		reachedTargets := map[string]bool{}

		// The entry point itself may be a dangerous asset (directly exposed).
		if isTarget(ep) {
			reachedTargets[ep] = true
			considerChain(best, ep, ep, parent, nodeByID, kev, critical)
		}

		for len(queue) > 0 {
			cur := queue[0]
			queue = queue[1:]
			for _, nb := range adj[cur] {
				if visited[nb] {
					continue
				}
				visited[nb] = true
				parent[nb] = cur
				queue = append(queue, nb)
				if isTarget(nb) {
					reachedTargets[nb] = true
					considerChain(best, ep, nb, parent, nodeByID, kev, critical)
				}
			}
		}
		for tgt := range reachedTargets {
			reachCount[tgt]++
		}
	}

	chains := make([]ExposureChain, 0, len(best))
	for tgt, ch := range best {
		ch.ReachableFromEntryPoints = reachCount[tgt]
		ch.Score = chainScore(ch)
		chains = append(chains, *ch)
	}

	// Rank by urgency, then blast-radius, then shorter path, then name for stability.
	sort.Slice(chains, func(i, j int) bool {
		if chains[i].Score != chains[j].Score {
			return chains[i].Score > chains[j].Score
		}
		if chains[i].ReachableFromEntryPoints != chains[j].ReachableFromEntryPoints {
			return chains[i].ReachableFromEntryPoints > chains[j].ReachableFromEntryPoints
		}
		if chains[i].Length != chains[j].Length {
			return chains[i].Length < chains[j].Length
		}
		return chains[i].TargetName < chains[j].TargetName
	})

	totalChains := len(chains)
	if len(chains) > exposureChainCap {
		chains = chains[:exposureChainCap]
	}

	return &ExposureChainResult{
		Summary: ExposureChainSummary{
			EntryPoints:         len(entryPoints),
			TargetsAtRisk:       len(best),
			TotalChains:         totalChains,
			HasRelationshipData: len(edges) > 0,
		},
		Chains: chains,
	}
}

// considerChain reconstructs the path entry→…→target via the parent map and keeps
// it if it is shorter than any chain already recorded for that target.
func considerChain(
	best map[string]*ExposureChain,
	entry, target string,
	parent map[string]string,
	nodeByID map[string]*asset.AssetNode,
	kev, critical map[string]int,
) {
	// Reconstruct target → entry, then reverse.
	var rev []string
	for cur := target; cur != ""; cur = parent[cur] {
		rev = append(rev, cur)
		if cur == entry {
			break
		}
	}
	hops := make([]ChainHop, 0, len(rev))
	for i := len(rev) - 1; i >= 0; i-- {
		n := nodeByID[rev[i]]
		if n == nil {
			continue
		}
		hops = append(hops, ChainHop{
			AssetID:   n.ID,
			Name:      n.Name,
			AssetType: n.AssetType,
			Exposure:  n.Exposure,
		})
	}
	length := len(hops) - 1
	if existing, ok := best[target]; ok && existing.Length <= length {
		return
	}

	tn := nodeByID[target]
	ch := &ExposureChain{
		EntryPointID:  entry,
		TargetID:      target,
		KEVCount:      kev[target],
		CriticalCount: critical[target],
		Hops:          hops,
		Length:        length,
	}
	if en := nodeByID[entry]; en != nil {
		ch.EntryPointName = en.Name
	}
	if tn != nil {
		ch.TargetName = tn.Name
		ch.TargetCriticality = tn.Criticality
		ch.IsCrownJewel = tn.IsCrownJewel
	}
	best[target] = ch
}

// chainScore ranks a chain: dangerous findings (KEV weighted heavily) scaled by
// target criticality and crown-jewel status, and amplified the closer the target
// sits to the internet (shorter path = more urgent).
func chainScore(ch *ExposureChain) float64 {
	base := float64(ch.KEVCount)*10 + float64(ch.CriticalCount)*3
	base *= criticalityMultiplier(ch.TargetCriticality)
	if ch.IsCrownJewel {
		base *= 1.5
	}
	// Proximity amplifier: length 0 → ÷1, length 1 → ÷2, … Directly-exposed
	// dangerous assets rank highest.
	return base / float64(ch.Length+1)
}
