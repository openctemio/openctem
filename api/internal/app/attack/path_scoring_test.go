package attack

import (
	"context"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

func scoreByID(res *PathScoringResult) map[string]AssetPathScore {
	m := map[string]AssetPathScore{}
	for _, a := range res.basis.all {
		m[a.AssetID] = a
	}
	return m
}

// "website protected_by WAF": the website is the protected asset, not the WAF.
// "siem monitors host": the host is the monitored (protected) asset.
func TestComputeAttackPathScores_ControlDirection(t *testing.T) {
	nodes := []asset.AssetNode{
		node("website", "public", "high", false),
		node("waf", "private", "medium", false),
		node("siem", "private", "medium", false),
		node("host", "private", "medium", false),
	}
	edges := []asset.RelationshipEdge{
		edge("website", "waf", asset.RelTypeProtectedBy),
		edge("siem", "host", asset.RelTypeMonitors),
	}
	svc := NewSurfaceService(&fakeGraphNodes{nodes: nodes}, nil, logger.NewNop())
	res, err := svc.ComputeAttackPathScores(context.Background(), shared.NewID(), &fakeGraphEdges{edges: edges})
	if err != nil {
		t.Fatal(err)
	}
	got := scoreByID(res)
	want := map[string]bool{"website": true, "waf": false, "siem": false, "host": true}
	for id, w := range want {
		if got[id].IsProtected != w {
			t.Errorf("%s: IsProtected = %v, want %v", id, got[id].IsProtected, w)
		}
	}
}

// A relationship to an asset that no longer exists does not bridge a path: db
// is reachable through the live "app" route only.
func TestComputeAttackPathScores_EdgeViaDeletedAssetDoesNotBridge(t *testing.T) {
	nodes := []asset.AssetNode{
		node("web", "public", "high", false),
		node("db", "private", "high", false),
		node("cache", "private", "high", false),
	}
	edges := []asset.RelationshipEdge{
		edge("web", "ghost", asset.RelTypeExposes), // ghost was deleted
		edge("ghost", "db", asset.RelTypeDependsOn),
		edge("web", "cache", asset.RelTypeExposes),
	}
	svc := NewSurfaceService(&fakeGraphNodes{nodes: nodes}, nil, logger.NewNop())
	res, err := svc.ComputeAttackPathScores(context.Background(), shared.NewID(), &fakeGraphEdges{edges: edges})
	if err != nil {
		t.Fatal(err)
	}
	got := scoreByID(res)
	if got["db"].ReachableFrom != 0 {
		t.Errorf("db reachable through a deleted asset: %d", got["db"].ReachableFrom)
	}
	if got["cache"].ReachableFrom != 1 {
		t.Errorf("cache (live route) reachable from %d, want 1", got["cache"].ReachableFrom)
	}
}

// Scores are cached per tenant and a reader's copy can be narrowed freely.
func TestGetAttackPathScores_CachedPerTenant(t *testing.T) {
	nodes := []asset.AssetNode{node("web", "public", "high", false), node("db", "private", "high", false)}
	edges := []asset.RelationshipEdge{edge("web", "db", asset.RelTypeExposes)}
	repo := &fakeGraphNodes{nodes: nodes}
	svc := NewSurfaceService(repo, &fakeGraphEdges{edges: edges}, logger.NewNop())
	a, b := shared.NewID(), shared.NewID()

	first, err := svc.GetAttackPathScores(context.Background(), a)
	if err != nil {
		t.Fatal(err)
	}
	first.TopAssets = nil // a caller narrowing its own copy
	first.basis = nil
	second, err := svc.GetAttackPathScores(context.Background(), a)
	if err != nil {
		t.Fatal(err)
	}
	if repo.calls != 1 {
		t.Fatalf("second read of one tenant recomputed (%d computations)", repo.calls)
	}
	if len(second.TopAssets) != 2 || second.basis == nil {
		t.Fatalf("cached copy was modified by an earlier reader: %d rows", len(second.TopAssets))
	}
	if _, err := svc.GetAttackPathScores(context.Background(), b); err != nil || repo.calls != 2 {
		t.Fatalf("another tenant must compute on its own (calls=%d, err=%v)", repo.calls, err)
	}
}
