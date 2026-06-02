package finding

import (
	"context"
	"testing"

	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/domain/vulnerability"
	"github.com/openctemio/api/pkg/logger"
	"github.com/openctemio/api/pkg/pagination"
)

// pageRecordingFindingRepo implements vulnerability.FindingRepository by
// embedding the interface (so unused methods are never called) and serves a
// fixed list of pages, recording the page numbers requested. This lets us
// assert AutoAssignToOwners walks pages 1..N in order and terminates — the
// pre-fix code passed pagination.New(batchSize, offset), which pinned OFFSET
// to one window and could loop forever or skip findings.
type pageRecordingFindingRepo struct {
	vulnerability.FindingRepository // embedded; nil — must never be called for unused methods
	pages                           [][]*vulnerability.Finding
	requested                       []int
}

func (r *pageRecordingFindingRepo) List(_ context.Context, _ vulnerability.FindingFilter, _ vulnerability.FindingListOptions, page pagination.Pagination) (pagination.Result[*vulnerability.Finding], error) {
	r.requested = append(r.requested, page.Page)
	idx := page.Page - 1
	var data []*vulnerability.Finding
	if idx >= 0 && idx < len(r.pages) {
		data = r.pages[idx]
	}
	return pagination.Result[*vulnerability.Finding]{Data: data}, nil
}

func assignedFinding(t *testing.T, tenantID, assetID, owner shared.ID) *vulnerability.Finding {
	t.Helper()
	f, err := vulnerability.NewFinding(tenantID, assetID, vulnerability.FindingSourceSCA, "trivy", vulnerability.SeverityHigh, "x")
	if err != nil {
		t.Fatalf("NewFinding: %v", err)
	}
	// Pre-assign so AutoAssignToOwners skips it (no asset/Update needed) and
	// the test isolates the pagination walk.
	if err := f.Assign(owner, owner); err != nil {
		t.Fatalf("Assign: %v", err)
	}
	return f
}

func TestAutoAssignToOwners_WalksPagesInOrderAndTerminates(t *testing.T) {
	tenantID := shared.NewID()
	assetID := shared.NewID()
	owner := shared.NewID()

	mkPage := func(n int) []*vulnerability.Finding {
		out := make([]*vulnerability.Finding, n)
		for i := range out {
			out[i] = assignedFinding(t, tenantID, assetID, owner)
		}
		return out
	}

	repo := &pageRecordingFindingRepo{
		// two full pages of 100, then a partial page, then the loop should stop
		pages: [][]*vulnerability.Finding{mkPage(100), mkPage(100), mkPage(7)},
	}
	svc := NewFindingActionsService(repo, nil, nil, nil, nil, nil, logger.NewNop())

	res, err := svc.AutoAssignToOwners(context.Background(), tenantID.String(), shared.NewID().String(), vulnerability.NewFindingFilter())
	if err != nil {
		t.Fatalf("AutoAssignToOwners: %v", err)
	}
	if res == nil {
		t.Fatal("expected a result")
	}

	// Pages requested must be 1,2,3,4 — three data pages then an empty page
	// that ends the loop. Crucially each request is a DISTINCT increasing page
	// (the bug pinned every request to the same window).
	want := []int{1, 2, 3, 4}
	if len(repo.requested) != len(want) {
		t.Fatalf("requested pages = %v, want %v", repo.requested, want)
	}
	for i, p := range want {
		if repo.requested[i] != p {
			t.Fatalf("requested pages = %v, want %v", repo.requested, want)
		}
	}
}
