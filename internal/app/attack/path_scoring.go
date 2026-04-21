package attack

import (
	"context"
	"fmt"
	"sort"

	"github.com/openctemio/api/pkg/domain/asset"
	"github.com/openctemio/api/pkg/domain/shared"
)

// attackPathRelationshipTypes are the relationship types that represent
// lateral movement and attack progression. We traverse ONLY these types
// when computing reachability from public entry points.
var attackPathRelationshipTypes = map[asset.RelationshipType]bool{
	asset.RelTypeRunsOn:          true,
	asset.RelTypeDeployedTo:      true,
	asset.RelTypeContains:        true,
	asset.RelTypeExposes:         true,
	asset.RelTypeResolvesTo:      true,
	asset.RelTypeDependsOn:       true,
	asset.RelTypeSendsDataTo:     true,
	asset.RelTypeStoresDataIn:    true,
	asset.RelTypeAuthenticatesTo: true,
	asset.RelTypeGrantedTo:       true,
	asset.RelTypeHasAccessTo:     true,
	asset.RelTypeLoadBalances:    true,
}

// controlRelationshipTypes are relationships that indicate security controls.
// Assets protected by these add a "protected" flag to scored nodes.
var controlRelationshipTypes = map[asset.RelationshipType]bool{
	asset.RelTypeProtectedBy: true,
	asset.RelTypeMonitors:    true,
}

// AssetPathScore holds the computed attack path score for a single asset.
type AssetPathScore struct {
	// AssetID is the UUID of the asset.
	AssetID string `json:"asset_id"`
	// Name is the human-readable name of the asset.
	Name string `json:"name"`
	// AssetType is the type of the asset (e.g., "host", "application").
	AssetType string `json:"asset_type"`
	// Exposure is the asset's configured exposure level.
	Exposure string `json:"exposure"`
	// Criticality is the asset's criticality level.
	Criticality string `json:"criticality"`
	// RiskScore is the asset-level risk score (1-10).
	RiskScore int `json:"risk_score"`
	// IsCrownJewel marks high-value target assets.
	IsCrownJewel bool `json:"is_crown_jewel"`
	// FindingCount is the number of open findings on this asset.
	FindingCount int `json:"finding_count"`

	// ReachableFrom is the count of distinct public entry points that can
	// reach this asset following attack-path relationship types.
	ReachableFrom int `json:"reachable_from"`
	// PathScore is the composite attack path score:
	//   (reachable_from * impact_weight) where impact_weight = risk_score * criticality_multiplier
	// Higher = more urgent to remediate.
	PathScore float64 `json:"path_score"`
	// IsEntryPoint is true when this asset is itself a public entry point.
	IsEntryPoint bool `json:"is_entry_point"`
	// IsProtected is true when the asset has at least one "protected_by" or "monitors" relationship.
	IsProtected bool `json:"is_protected"`
}

// PathSummary holds aggregate attack path metrics for the tenant.
type PathSummary struct {
	// TotalPaths is the total number of directed attack paths discovered
	// (entry point → reachable asset pairs).
	TotalPaths int `json:"total_paths"`
	// EntryPoints is the count of public-exposure assets that act as entry points.
	EntryPoints int `json:"entry_points"`
	// ReachableAssets is the count of non-public assets reachable from at least one entry point.
	ReachableAssets int `json:"reachable_assets"`
	// MaxDepth is the longest BFS chain found.
	MaxDepth int `json:"max_depth"`
	// CriticalReachable is the count of critical/high assets reachable from entry points.
	CriticalReachable int `json:"critical_reachable"`
	// CrownJewelsAtRisk is the count of crown-jewel assets reachable from entry points.
	CrownJewelsAtRisk int `json:"crown_jewels_at_risk"`
	// HasRelationshipData indicates whether the tenant has any relationship data at all.
	HasRelationshipData bool `json:"has_relationship_data"`
}

// PathScoringResult is the full result returned by ComputeAttackPathScores.
type PathScoringResult struct {
	Summary PathSummary `json:"summary"`
	// TopAssets is the ranked list of assets by PathScore (descending), limited to 50.
	TopAssets []AssetPathScore `json:"top_assets"`
}

// criticalityMultiplier returns an impact multiplier for a criticality level.
func criticalityMultiplier(criticality string) float64 {
	switch criticality {
	case "critical":
		return 4.0
	case "high":
		return 3.0
	case "medium":
		return 2.0
	case "low":
		return 1.0
	default:
		return 1.0
	}
}

// ComputeAttackPathScores performs in-memory attack path analysis for the
// tenant. It:
//  1. Loads all assets (nodes) and relationships (edges)
//  2. Identifies public-exposure assets as entry points
//  3. Runs BFS from each entry point following attack-path edges
//  4. Counts how many entry points can reach each internal asset
//  5. Computes a composite PathScore from reachability + risk + criticality
//  6. Returns top 50 assets by PathScore + aggregate summary
func (s *SurfaceService) ComputeAttackPathScores(
	ctx context.Context,
	tenantID shared.ID,
	relRepo asset.RelationshipRepository,
) (*PathScoringResult, error) {
	// Step 1 — load nodes
	nodes, err := s.assetRepo.ListAllNodes(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("load nodes: %w", err)
	}

	// Step 2 — load edges
	edges, err := relRepo.ListAllEdges(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("load edges: %w", err)
	}

	// Build lookup maps
	nodeByID := make(map[string]*asset.AssetNode, len(nodes))
	for i := range nodes {
		nodeByID[nodes[i].ID] = &nodes[i]
	}

	// Build adjacency list (directed: source → targets) for attack-path edges
	adj := make(map[string][]string, len(nodes))
	// Track which assets are "protected"
	protected := make(map[string]bool)

	for _, e := range edges {
		if controlRelationshipTypes[e.Type] {
			// source asset is protected (protected_by / monitors points FROM protected TO control)
			// convention: "A protected_by B" means A is target, B is source when edge direction
			// is stored as source=A → target=B? Let's treat target as the protected asset.
			protected[e.TargetAssetID] = true
			continue
		}
		if attackPathRelationshipTypes[e.Type] {
			adj[e.SourceAssetID] = append(adj[e.SourceAssetID], e.TargetAssetID)
		}
	}

	// Step 3 — identify public entry points
	entryPoints := make([]string, 0)
	for _, n := range nodes {
		if n.Exposure == "public" {
			entryPoints = append(entryPoints, n.ID)
		}
	}

	// Step 4 — BFS from each entry point, counting reachability per node
	reachableFrom := make(map[string]int, len(nodes)) // assetID → count of entry points that can reach it
	maxDepth := 0

	for _, ep := range entryPoints {
		visited := make(map[string]bool)
		visited[ep] = true
		queue := []struct {
			id    string
			depth int
		}{{ep, 0}}

		for len(queue) > 0 {
			cur := queue[0]
			queue = queue[1:]

			if cur.depth > maxDepth {
				maxDepth = cur.depth
			}

			for _, neighborID := range adj[cur.id] {
				if visited[neighborID] {
					continue
				}
				visited[neighborID] = true
				// Only count non-public assets as "reachable internal assets"
				if n, ok := nodeByID[neighborID]; ok && n.Exposure != "public" {
					reachableFrom[neighborID]++
				}
				queue = append(queue, struct {
					id    string
					depth int
				}{neighborID, cur.depth + 1})
			}
		}
	}

	// Step 5 — compute scores and build result
	totalPaths := 0
	reachableSet := make(map[string]bool)
	criticalReachable := 0
	crownJewelsAtRisk := 0

	scored := make([]AssetPathScore, 0, len(nodes))
	for _, n := range nodes {
		rc := reachableFrom[n.ID]
		isEntry := n.Exposure == "public"

		if rc > 0 {
			reachableSet[n.ID] = true
			totalPaths += rc
			if n.Criticality == "critical" || n.Criticality == "high" {
				criticalReachable++
			}
			if n.IsCrownJewel {
				crownJewelsAtRisk++
			}
		}

		riskScore := n.RiskScore
		if riskScore == 0 {
			riskScore = 5 // default mid-range when not set
		}

		pathScore := float64(rc) * float64(riskScore) * criticalityMultiplier(n.Criticality)
		if n.FindingCount > 0 {
			// Boost path score proportional to number of open findings
			pathScore += float64(n.FindingCount) * 0.5
		}

		scored = append(scored, AssetPathScore{
			AssetID:       n.ID,
			Name:          n.Name,
			AssetType:     n.AssetType,
			Exposure:      n.Exposure,
			Criticality:   n.Criticality,
			RiskScore:     n.RiskScore,
			IsCrownJewel:  n.IsCrownJewel,
			FindingCount:  n.FindingCount,
			ReachableFrom: rc,
			PathScore:     pathScore,
			IsEntryPoint:  isEntry,
			IsProtected:   protected[n.ID],
		})
	}

	// Sort by PathScore descending, then by ReachableFrom, then by name for stability
	sort.Slice(scored, func(i, j int) bool {
		if scored[i].PathScore != scored[j].PathScore {
			return scored[i].PathScore > scored[j].PathScore
		}
		if scored[i].ReachableFrom != scored[j].ReachableFrom {
			return scored[i].ReachableFrom > scored[j].ReachableFrom
		}
		return scored[i].Name < scored[j].Name
	})

	// Cap at 50
	if len(scored) > 50 {
		scored = scored[:50]
	}

	summary := PathSummary{
		TotalPaths:          totalPaths,
		EntryPoints:         len(entryPoints),
		ReachableAssets:     len(reachableSet),
		MaxDepth:            maxDepth,
		CriticalReachable:   criticalReachable,
		CrownJewelsAtRisk:   crownJewelsAtRisk,
		HasRelationshipData: len(edges) > 0,
	}

	return &PathScoringResult{
		Summary:   summary,
		TopAssets: scored,
	}, nil
}
