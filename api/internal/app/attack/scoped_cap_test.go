package attack

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

func uuidNode(name, exposure string, risk int) asset.AssetNode {
	n := node(shared.NewID().String(), exposure, "medium", false)
	n.Name = name
	n.RiskScore = risk
	return n
}

// A restricted viewer whose only asset ranks 60th tenant-wide still sees it:
// the scope is applied before the top-50 cap.
func TestAttackPathScoresForCaller_ScopeBeforeCap(t *testing.T) {
	entry := uuidNode("entry", "public", 5)
	nodes := []asset.AssetNode{entry}
	var edges []asset.RelationshipEdge
	var mine asset.AssetNode
	for i := 0; i < 60; i++ {
		n := uuidNode("t", "private", 100-i) // t[0] ranks first, t[59] last
		n.Name = "target-" + string(rune('a'+i%26))
		nodes = append(nodes, n)
		edges = append(edges, edge(entry.ID, n.ID, asset.RelTypeExposes))
		mine = n
	}
	svc := NewSurfaceService(&fakeGraphNodes{nodes: nodes}, &fakeGraphEdges{edges: edges}, logger.NewNop())
	id, _ := shared.IDFromString(mine.ID)
	svc.SetDataScope(restrictedEnforcer(id))

	res, err := svc.AttackPathScoresForCaller(context.Background(), shared.NewID())
	if err != nil {
		t.Fatal(err)
	}
	if len(res.TopAssets) != 1 || res.TopAssets[0].AssetID != mine.ID {
		t.Fatalf("restricted viewer sees %d rows, want their one asset ranked 60th", len(res.TopAssets))
	}

	// An organization owner still gets the 50 best rows.
	svc.SetDataScope(ownerEnforcer())
	all, err := svc.AttackPathScoresForCaller(context.Background(), shared.NewID())
	if err != nil {
		t.Fatal(err)
	}
	if len(all.TopAssets) != attackPathTopN {
		t.Fatalf("owner sees %d rows, want %d", len(all.TopAssets), attackPathTopN)
	}
}

// A scoped viewer sees the path to their asset, with the steps outside their
// scope returned as hidden steps: never an id, name or type. A chain to an
// out-of-scope target is not shown at all.
func TestExposureChainsForCaller_HiddenStepsForOutOfScopeHops(t *testing.T) {
	entry := uuidNode("secret-entry-host", "public", 5)
	mid := uuidNode("secret-mid-db", "private", 5)
	mine := uuidNode("my-crown-jewel", "private", 5)
	other := uuidNode("someone-elses-app", "private", 5)
	nodes := []asset.AssetNode{entry, mid, mine, other}
	edges := []asset.RelationshipEdge{
		edge(entry.ID, mid.ID, asset.RelTypeExposes),
		edge(mid.ID, mine.ID, asset.RelTypeDependsOn),
		edge(entry.ID, other.ID, asset.RelTypeExposes),
	}
	risk := &riskFake{kev: map[string]int{mine.ID: 2, other.ID: 5}}
	svc, _ := chainService(nodes, edges, risk)
	mineID, _ := shared.IDFromString(mine.ID)
	svc.SetDataScope(restrictedEnforcer(mineID))

	tenant := shared.NewID()
	res, err := svc.ExposureChainsForCaller(context.Background(), tenant)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Chains) != 1 || res.Chains[0].TargetID != mine.ID {
		t.Fatalf("chains = %+v, want only the path to the in-scope target", res.Chains)
	}
	c := res.Chains[0]
	if len(c.Hops) != 3 || !c.Hops[0].Hidden || !c.Hops[1].Hidden || c.Hops[2].Hidden || c.Hops[2].AssetID != mine.ID {
		t.Fatalf("hops = %+v, want hidden, hidden, visible target", c.Hops)
	}
	if res.Summary.TotalChains != 1 || res.Summary.TargetsAtRisk != 1 {
		t.Errorf("summary = %+v, want one chain and one target", res.Summary)
	}
	body, _ := json.Marshal(res)
	for _, leaked := range []string{entry.ID, entry.Name, mid.ID, mid.Name, other.ID, other.Name} {
		if strings.Contains(string(body), leaked) {
			t.Errorf("response leaks %q", leaked)
		}
	}

	// The shared cache still holds the real hops: redaction worked on a copy.
	full, err := svc.GetExposureChains(context.Background(), tenant)
	if err != nil {
		t.Fatal(err)
	}
	for _, fc := range full.Chains {
		for _, h := range fc.Hops {
			if h.Hidden {
				t.Fatal("redaction leaked into the shared cache")
			}
		}
	}
}
