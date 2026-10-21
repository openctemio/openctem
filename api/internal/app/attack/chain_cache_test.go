package attack

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// riskFake answers the KEV/critical counts and counts its calls; gate, when
// set, blocks the answer until it is closed.
type riskFake struct {
	kev   map[string]int
	gate  chan struct{}
	mu    sync.Mutex
	calls int
}

func (r *riskFake) KEVCriticalCountsByAsset(context.Context, shared.ID) (map[string]int, map[string]int, error) {
	if r.gate != nil {
		<-r.gate
	}
	r.mu.Lock()
	r.calls++
	r.mu.Unlock()
	return r.kev, map[string]int{}, nil
}

// manyChainsGraph is one public entry point reaching n dangerous targets
// t0..t(n-1); t0 is the most dangerous, so it ranks first and t(n-1) last.
func manyChainsGraph(n int) ([]asset.AssetNode, []asset.RelationshipEdge, map[string]int) {
	nodes := []asset.AssetNode{node("entry", "public", "low", false)}
	var edges []asset.RelationshipEdge
	kev := map[string]int{}
	for i := 0; i < n; i++ {
		id := fmt.Sprintf("t%03d", i)
		nodes = append(nodes, node(id, "private", "medium", false))
		edges = append(edges, edge("entry", id, asset.RelTypeExposes))
		kev[id] = n - i
	}
	return nodes, edges, kev
}

func chainService(nodes []asset.AssetNode, edges []asset.RelationshipEdge, risk FindingRiskCounter) (*SurfaceService, *fakeGraphNodes) {
	repo := &fakeGraphNodes{nodes: nodes}
	svc := NewSurfaceService(repo, &fakeGraphEdges{edges: edges}, logger.NewNop())
	svc.SetFindingRiskCounter(risk)
	return svc, repo
}

// The internal result is not capped: priority and threat models need chain
// number 150 as much as chain number 1.
func TestGetExposureChains_ReturnsEveryChain(t *testing.T) {
	nodes, edges, kev := manyChainsGraph(150)
	svc, _ := chainService(nodes, edges, &riskFake{kev: kev})
	res, err := svc.GetExposureChains(context.Background(), shared.NewID())
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Chains) != 150 || res.Summary.TotalChains != 150 {
		t.Fatalf("chains = %d, total = %d, want 150/150", len(res.Chains), res.Summary.TotalChains)
	}
	if res.Chains[149].TargetID != "t149" {
		t.Errorf("last chain = %s, want t149", res.Chains[149].TargetID)
	}
}

// The API read caps what is shown, and capping its copy leaves the cache whole.
func TestExposureChainsForCaller_CapsAfterScopeAndKeepsCacheWhole(t *testing.T) {
	nodes, edges, kev := manyChainsGraph(150)
	svc, _ := chainService(nodes, edges, &riskFake{kev: kev})
	svc.SetDataScope(ownerEnforcer())
	tenant := shared.NewID()

	got, err := svc.ExposureChainsForCaller(context.Background(), tenant)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Chains) != exposureChainCap || got.Summary.TotalChains != 150 {
		t.Fatalf("chains = %d, total = %d, want %d/150", len(got.Chains), got.Summary.TotalChains, exposureChainCap)
	}
	full, err := svc.GetExposureChains(context.Background(), tenant)
	if err != nil {
		t.Fatal(err)
	}
	if len(full.Chains) != 150 {
		t.Fatalf("cache shrank to %d chains after an API read", len(full.Chains))
	}
}

// Concurrent callers for one tenant share a single computation; another
// tenant is computed on its own; after the TTL the result is recomputed.
func TestChainCache_SingleComputationPerTenantAndTTL(t *testing.T) {
	nodes, edges, kev := manyChainsGraph(5)
	risk := &riskFake{kev: kev, gate: make(chan struct{})}
	svc, repo := chainService(nodes, edges, risk)
	now := time.Now()
	svc.chains.now = func() time.Time { return now }
	tenantA, tenantB := shared.NewID(), shared.NewID()

	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := svc.GetExposureChains(context.Background(), tenantA); err != nil {
				t.Error(err)
			}
		}()
	}
	time.Sleep(50 * time.Millisecond)
	close(risk.gate)
	wg.Wait()
	if repo.calls != 1 {
		t.Fatalf("10 concurrent callers computed %d times, want 1", repo.calls)
	}

	if _, err := svc.GetExposureChains(context.Background(), tenantA); err != nil || repo.calls != 1 {
		t.Fatalf("second read recomputed (calls=%d, err=%v)", repo.calls, err)
	}
	if _, err := svc.GetExposureChains(context.Background(), tenantB); err != nil || repo.calls != 2 {
		t.Fatalf("another tenant must compute on its own (calls=%d, err=%v)", repo.calls, err)
	}
	now = now.Add(chainCacheTTL + time.Second)
	if _, err := svc.GetExposureChains(context.Background(), tenantA); err != nil || repo.calls != 3 {
		t.Fatalf("expired entry not recomputed (calls=%d, err=%v)", repo.calls, err)
	}
}

// A restricted member sees an in-scope chain that ranks below the cap: the
// scope is applied before the cap.
func TestExposureChainsForCaller_ScopeBeforeCap(t *testing.T) {
	nodes, edges, kev := manyChainsGraph(150)
	entry, last := shared.NewID(), shared.NewID()
	// Rename the ids to real ones so the scope repository can match them.
	for i := range nodes {
		switch nodes[i].ID {
		case "entry":
			nodes[i].ID = entry.String()
		case "t149":
			nodes[i].ID = last.String()
		}
	}
	for i := range edges {
		if edges[i].SourceAssetID == "entry" {
			edges[i].SourceAssetID = entry.String()
		}
		if edges[i].TargetAssetID == "t149" {
			edges[i].TargetAssetID = last.String()
		}
	}
	kev[last.String()] = kev["t149"]
	svc, _ := chainService(nodes, edges, &riskFake{kev: kev})
	svc.SetDataScope(restrictedEnforcer(entry, last))

	got, err := svc.ExposureChainsForCaller(context.Background(), shared.NewID())
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Chains) != 1 || got.Chains[0].TargetID != last.String() {
		t.Fatalf("restricted member sees %d chains, want the one in-scope chain ranked 150th", len(got.Chains))
	}
}
