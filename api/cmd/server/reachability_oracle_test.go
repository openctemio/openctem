package main

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/internal/app/attack"
	"github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

type oracleNodes struct {
	asset.Repository
	nodes []asset.AssetNode
}

func (o oracleNodes) ListAllNodes(context.Context, shared.ID) ([]asset.AssetNode, error) {
	return o.nodes, nil
}

type oracleEdges struct {
	asset.RelationshipRepository
	edges []asset.RelationshipEdge
}

func (o oracleEdges) ListAllEdges(context.Context, shared.ID) ([]asset.RelationshipEdge, error) {
	return o.edges, nil
}

type oracleRisk map[string]int

func (r oracleRisk) KEVCriticalCountsByAsset(context.Context, shared.ID) (map[string]int, map[string]int, error) {
	return r, map[string]int{}, nil
}

// The oracle sees every chain, not only the 100 best: an asset on the 150th
// chain is still "reachable" for priority classification.
func TestReachabilityOracle_SeesChainsBeyondTheAPICap(t *testing.T) {
	nodes := []asset.AssetNode{{ID: "entry", Name: "entry", AssetType: "host", Exposure: "public", Criticality: "low"}}
	var edges []asset.RelationshipEdge
	risk := oracleRisk{}
	const n = 150
	for i := 0; i < n; i++ {
		id := fmt.Sprintf("t%03d", i)
		nodes = append(nodes, asset.AssetNode{ID: id, Name: id, AssetType: "host", Exposure: "private", Criticality: "medium"})
		edges = append(edges, asset.RelationshipEdge{SourceAssetID: "entry", TargetAssetID: id, Type: asset.RelTypeExposes})
		risk[id] = n - i
	}
	surface := attack.NewSurfaceService(oracleNodes{nodes: nodes}, oracleEdges{edges: edges}, logger.NewNop())
	surface.SetFindingRiskCounter(risk)

	set, err := newReachabilityOracle(surface, time.Minute).ReachableFromPublic(context.Background(), shared.NewID())
	if err != nil {
		t.Fatal(err)
	}
	if !set["t149"] || !set["t100"] || !set["entry"] {
		t.Fatalf("oracle misses assets beyond the first 100 chains (set size %d)", len(set))
	}
}
