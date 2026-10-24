package scan

import (
	"context"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/scan"
	"github.com/openctemio/openctem/api/pkg/domain/scanrun"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

type recentRunsStub struct {
	scanrun.RunRepository
	tenant shared.ID
	asked  []shared.ID
	limit  int
}

func (s *recentRunsStub) RecentByScans(_ context.Context, tenantID shared.ID, ids []shared.ID, limit int) (map[shared.ID][]scanrun.RecentRun, error) {
	s.tenant, s.asked, s.limit = tenantID, ids, limit
	out := map[shared.ID][]scanrun.RecentRun{}
	for _, id := range ids {
		out[id] = []scanrun.RecentRun{{ID: shared.NewID(), Status: scanrun.RunStatusCompleted}}
	}
	return out, nil
}

// The list asks only for its own tenant's scans that have run at least once,
// with the tenant id, and with the shared window size.
func TestRecentRuns_AsksOnlyForTheTenantsScansThatRan(t *testing.T) {
	tenant, other := shared.NewID(), shared.NewID()
	runID := shared.NewID()
	ran := &scan.Scan{ID: shared.NewID(), TenantID: tenant, LastRunID: &runID}
	never := &scan.Scan{ID: shared.NewID(), TenantID: tenant}
	foreign := &scan.Scan{ID: shared.NewID(), TenantID: other, LastRunID: &runID}
	stub := &recentRunsStub{}
	svc := &Service{runRepo: stub, logger: logger.NewNop()}

	got := svc.RecentRuns(context.Background(), tenant, []*scan.Scan{ran, never, foreign})
	if stub.tenant != tenant || stub.limit != RecentRunsLimit {
		t.Fatalf("asked tenant %v limit %d", stub.tenant, stub.limit)
	}
	if len(stub.asked) != 1 || stub.asked[0] != ran.ID {
		t.Fatalf("asked for %v, want only the tenant's scan that ran", stub.asked)
	}
	if len(got[ran.ID]) != 1 || got[foreign.ID] != nil {
		t.Fatalf("got %v", got)
	}
	if none := svc.RecentRuns(context.Background(), tenant, []*scan.Scan{never}); none != nil {
		t.Fatalf("no scan ran: got %v", none)
	}
}
