package finding

import (
	"context"
	"slices"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

// racingRepo is a store whose rows moved after the request read them: the
// finding the service reads says "new", the stored status is another one. Its
// guarded write honors the from-statuses like the database does.
type racingRepo struct {
	bulkStubRepo
	stored map[shared.ID]vulnerability.FindingStatus
	froms  [][]vulnerability.FindingStatus
}

func (r *racingRepo) MoveStatusBatch(_ context.Context, _ shared.ID, ids []shared.ID, from []vulnerability.FindingStatus,
	to vulnerability.FindingStatus, _ string, _ *shared.ID, _ vulnerability.Closure,
) ([]shared.ID, error) {
	r.froms = append(r.froms, from)
	var moved []shared.ID
	for _, id := range ids {
		if slices.Contains(from, r.stored[id]) {
			r.stored[id] = to
			moved = append(moved, id)
		}
	}
	return moved, nil
}

// A bulk move writes each row only while it is still in the status it was
// read in: a row an approver turned into a false positive after the read is
// not overwritten, and the response names it as a conflict.
func TestBulkStatus_RowThatChangedSinceReadIsNotOverwritten(t *testing.T) {
	tenantID := shared.NewID()
	ok := mkFinding(t, tenantID, vulnerability.FindingSourceDAST)
	raced := mkFinding(t, tenantID, vulnerability.FindingSourceDAST)
	repo := &racingRepo{
		bulkStubRepo: bulkStubRepo{byID: map[string]*vulnerability.Finding{ok.ID().String(): ok, raced.ID().String(): raced}},
		stored: map[shared.ID]vulnerability.FindingStatus{
			ok.ID(): vulnerability.FindingStatusNew, raced.ID(): vulnerability.FindingStatusFalsePositive,
		},
	}
	res, err := newBulkTestService(repo).BulkUpdateFindingsStatus(context.Background(), tenantID.String(), BulkUpdateStatusInput{
		FindingIDs: []string{ok.ID().String(), raced.ID().String()},
		Status:     vulnerability.FindingStatusConfirmed.String(),
		ActorID:    shared.NewID().String(),
		// A person's bulk move carries findings:status (#2633).
		HasStatusPermission: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Updated != 1 || res.Failed != 1 {
		t.Fatalf("updated=%d failed=%d, want 1 and 1", res.Updated, res.Failed)
	}
	if repo.stored[raced.ID()] != vulnerability.FindingStatusFalsePositive {
		t.Fatalf("the false positive was overwritten with %s", repo.stored[raced.ID()])
	}
	if repo.stored[ok.ID()] != vulnerability.FindingStatusConfirmed {
		t.Fatalf("the unchanged row is %s, want confirmed", repo.stored[ok.ID()])
	}
	if len(res.Rows) != 1 || res.Rows[0].FindingID != raced.ID().String() || res.Rows[0].Outcome != BulkRowConflict || res.Rows[0].Reason == "" {
		t.Fatalf("rows = %+v, want one conflict row for the raced finding", res.Rows)
	}
	for _, f := range repo.froms {
		if len(f) != 1 || f[0] != vulnerability.FindingStatusNew {
			t.Fatalf("write guarded by %v, want exactly the status the rows were read in", f)
		}
	}
}
