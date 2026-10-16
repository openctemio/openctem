package finding

import (
	"context"
	"testing"

	lc "github.com/openctemio/openctem/api/pkg/domain/findinglifecycle"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/pagination"
)

// fixAppliedRepo lists fix_applied findings and records the source statuses
// the batch write was limited to.
type fixAppliedRepo struct {
	bulkStubRepo
	list []*vulnerability.Finding
	from []vulnerability.FindingStatus
	to   vulnerability.FindingStatus
}

func (r *fixAppliedRepo) Count(context.Context, vulnerability.FindingFilter) (int64, error) {
	return int64(len(r.list)), nil
}

func (r *fixAppliedRepo) List(_ context.Context, _ vulnerability.FindingFilter, _ vulnerability.FindingListOptions, _ pagination.Pagination) (pagination.Result[*vulnerability.Finding], error) {
	return pagination.Result[*vulnerability.Finding]{Data: r.list}, nil
}

func (r *fixAppliedRepo) UpdateStatusBatchFrom(_ context.Context, _ shared.ID, ids []shared.ID, from []vulnerability.FindingStatus, to vulnerability.FindingStatus, _ string, _ *shared.ID, _ vulnerability.Closure) error {
	r.from, r.to = from, to
	r.written = append(r.written, ids...)
	return nil
}

// The filter-driven verify and reject-fix decisions are written only against
// findings that are still fix_applied, so a finding that moved on since it was
// read (an approved false positive, an accepted risk) is never overwritten.
func TestBulkVerifyAndRejectByFilter_WriteOnlyFromFixApplied(t *testing.T) {
	tenantID := shared.NewID()
	uid := shared.NewID()
	for name, run := range map[string]func(*FindingActionsService) (int64, error){
		"verify": func(s *FindingActionsService) (int64, error) {
			return s.BulkVerifyByFilter(context.Background(), tenantID.String(), uid.String(), VerifyByFilterInput{})
		},
		"reject": func(s *FindingActionsService) (int64, error) {
			s.SetLifecycles(stubSchemes{}) // an organization lifecycle: the per-finding path
			return s.BulkRejectByFilter(context.Background(), tenantID.String(), uid.String(), RejectByFilterInput{Reason: "not fixed"})
		},
	} {
		t.Run(name, func(t *testing.T) {
			repo := &fixAppliedRepo{list: []*vulnerability.Finding{fixAppliedFinding(t, tenantID)}}
			s := NewFindingActionsService(repo, nil, nil, nil, nil, nil, logger.NewNop())
			if _, err := run(s); err != nil {
				t.Fatal(err)
			}
			if len(repo.written) != 1 || len(repo.from) != 1 || repo.from[0] != vulnerability.FindingStatusFixApplied {
				t.Fatalf("written %v from %v, want one finding limited to fix_applied", repo.written, repo.from)
			}
		})
	}
}

type stubSchemes struct{}

func (stubSchemes) Candidates(context.Context, shared.ID) ([]lc.Candidate, error) {
	return []lc.Candidate{{Default: true}}, nil
}
