package attack

import (
	"context"
	"fmt"
	"sort"

	"github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// FindingRiskCounter provides, per asset, the number of open KEV and critical
// findings. Implemented by the finding repository; injected via a setter so the
// attack-surface service stays decoupled from the vulnerability layer.
type FindingRiskCounter interface {
	KEVCriticalCountsByAsset(ctx context.Context, tenantID shared.ID) (kev, critical map[string]int, err error)
}

// exposureChainCap bounds the number of chains an API response returns
// (highest-scored first). It applies to what a caller is shown, after the
// caller's data scope; GetExposureChains itself returns every chain, because
// priority classification and threat models need the whole result.
const exposureChainCap = 100

// ChainHop is one asset on an exposure chain. A hop the caller may not see
// (outside their data scope) is returned with Hidden set and every other field
// empty: it says only that something sits at that step.
type ChainHop struct {
	Hidden    bool   `json:"hidden,omitempty"`
	AssetID   string `json:"asset_id"`
	Name      string `json:"name"`
	AssetType string `json:"asset_type"`
	SubType   string `json:"sub_type,omitempty"`
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

// GetExposureChains returns the tenant's exposure chains: every chain, not a
// capped page. The result comes from a short-lived per-tenant cache shared by
// every reader (API, MCP, priority oracle, threat models); concurrent callers
// for the same tenant wait on one computation. Returns an empty result (not an
// error) when no finding-risk counter is wired.
//
// The returned value is the caller's own copy of the chain list; hops are shared
// and must not be modified.
func (s *SurfaceService) GetExposureChains(ctx context.Context, tenantID shared.ID) (*ExposureChainResult, error) {
	return s.chains.get(ctx, tenantID, func(ctx context.Context) (*ExposureChainResult, error) {
		return s.computeExposureChains(ctx, tenantID)
	})
}

func (s *SurfaceService) computeExposureChains(ctx context.Context, tenantID shared.ID) (*ExposureChainResult, error) {
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
// synthetic graphs. It returns every chain (no cap). One breadth-first pass
// starts from all public entry points at once, so each asset is visited once
// (O(nodes + edges)) and every asset that carries a KEV or critical finding
// gets the shortest path from its nearest entry point, following attack-path
// relationship types. The chains are ranked by urgency.
func buildExposureChains(
	nodes []asset.AssetNode,
	edges []asset.RelationshipEdge,
	kev, critical map[string]int,
) *ExposureChainResult {
	nodeByID := make(map[string]*asset.AssetNode, len(nodes))
	for i := range nodes {
		nodeByID[nodes[i].ID] = &nodes[i]
	}

	// Directed adjacency over attack-path edges only (same set the scorer
	// uses). An edge whose end is not a live asset is dropped, so a path never
	// runs through a deleted asset.
	adj := make(map[string][]string, len(nodes))
	for _, e := range edges {
		if !attackPathRelationshipTypes[e.Type] {
			continue
		}
		if nodeByID[e.SourceAssetID] == nil || nodeByID[e.TargetAssetID] == nil {
			continue
		}
		adj[e.SourceAssetID] = append(adj[e.SourceAssetID], e.TargetAssetID)
	}

	// A "target" is any node carrying at least one KEV or critical finding.
	isTarget := func(id string) bool { return kev[id] > 0 || critical[id] > 0 }

	entryPoints := make([]string, 0)
	for i := range nodes {
		if nodes[i].Exposure == string(asset.ExposurePublic) {
			entryPoints = append(entryPoints, nodes[i].ID)
		}
	}

	// Multi-source BFS. parent[x] is the previous hop on the shortest path
	// from the nearest entry point (empty for an entry point itself).
	parent := make(map[string]string, len(nodes))
	queue := make([]string, 0, len(nodes))
	for _, ep := range entryPoints {
		parent[ep] = ""
		queue = append(queue, ep)
	}
	best := make(map[string]*ExposureChain)
	for head := 0; head < len(queue); head++ {
		cur := queue[head]
		if isTarget(cur) {
			considerChain(best, cur, parent, nodeByID, kev, critical)
		}
		for _, nb := range adj[cur] {
			if _, seen := parent[nb]; seen {
				continue
			}
			parent[nb] = cur
			queue = append(queue, nb)
		}
	}

	chains := make([]ExposureChain, 0, len(best))
	for _, ch := range best {
		ch.Score = chainScore(ch)
		chains = append(chains, *ch)
	}

	// Rank by urgency, then shorter path, then name for stability.
	sort.Slice(chains, func(i, j int) bool {
		if chains[i].Score != chains[j].Score {
			return chains[i].Score > chains[j].Score
		}
		if chains[i].Length != chains[j].Length {
			return chains[i].Length < chains[j].Length
		}
		if chains[i].TargetName != chains[j].TargetName {
			return chains[i].TargetName < chains[j].TargetName
		}
		return chains[i].TargetID < chains[j].TargetID
	})

	return &ExposureChainResult{
		Summary: ExposureChainSummary{
			EntryPoints:         len(entryPoints),
			TargetsAtRisk:       len(best),
			TotalChains:         len(chains),
			HasRelationshipData: len(edges) > 0,
		},
		Chains: chains,
	}
}

// considerChain reconstructs the path entry→…→target via the parent map and
// records it for the target.
func considerChain(
	best map[string]*ExposureChain,
	target string,
	parent map[string]string,
	nodeByID map[string]*asset.AssetNode,
	kev, critical map[string]int,
) {
	// Reconstruct target → entry (the entry has no parent), then reverse.
	var rev []string
	for cur := target; ; cur = parent[cur] {
		rev = append(rev, cur)
		if parent[cur] == "" {
			break
		}
	}
	entry := rev[len(rev)-1]
	hops := make([]ChainHop, 0, len(rev))
	for i := len(rev) - 1; i >= 0; i-- {
		n := nodeByID[rev[i]]
		hops = append(hops, ChainHop{
			AssetID:   n.ID,
			Name:      n.Name,
			AssetType: n.AssetType,
			SubType:   n.SubType,
			Exposure:  n.Exposure,
		})
	}

	tn, en := nodeByID[target], nodeByID[entry]
	best[target] = &ExposureChain{
		EntryPointID:      entry,
		EntryPointName:    en.Name,
		TargetID:          target,
		TargetName:        tn.Name,
		TargetCriticality: tn.Criticality,
		IsCrownJewel:      tn.IsCrownJewel,
		KEVCount:          kev[target],
		CriticalCount:     critical[target],
		Hops:              hops,
		Length:            len(hops) - 1,
	}
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
