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
