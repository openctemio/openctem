package finding

import (
	"context"
	"testing"

	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/domain/vulnerability"
	"github.com/openctemio/api/pkg/logger"
)

// bulkStubRepo implements only the two methods BulkUpdateFindingsStatus uses:
// GetByIDs (batch fetch) and UpdateStatusBatch (batch write). It records which
// IDs were actually written so tests can prove the approval guard skipped them.
type bulkStubRepo struct {
	vulnerability.FindingRepository
	byID    map[string]*vulnerability.Finding
	written []shared.ID
}

func (r *bulkStubRepo) GetByIDs(_ context.Context, _ shared.ID, ids []shared.ID) ([]*vulnerability.Finding, error) {
	out := make([]*vulnerability.Finding, 0, len(ids))
	for _, id := range ids {
		if f, ok := r.byID[id.String()]; ok {
			out = append(out, f)
		}
	}
	return out, nil
}

func (r *bulkStubRepo) UpdateStatusBatch(_ context.Context, _ shared.ID, ids []shared.ID, _ vulnerability.FindingStatus, _ string, _ *shared.ID) error {
	r.written = append(r.written, ids...)
	return nil
}

func newBulkTestService(repo vulnerability.FindingRepository) *VulnerabilityService {
	return &VulnerabilityService{findingRepo: repo, logger: logger.NewNop()}
}

// TestBulkUpdateStatus_ApprovalRequired_Rejected proves that bulk-transitioning
// findings to an approval-requiring disposition (false_positive / accepted) is
// rejected per-finding and never reaches the batch writer — mirroring the
// single-finding approval gate in UpdateFindingStatus.
func TestBulkUpdateStatus_ApprovalRequired_Rejected(t *testing.T) {
	tenantID := shared.NewID()

	t.Run("false_positive from new is rejected", func(t *testing.T) {
		f := mkFinding(t, tenantID, vulnerability.FindingSourceDAST) // status: new
		repo := &bulkStubRepo{byID: map[string]*vulnerability.Finding{f.ID().String(): f}}
		svc := newBulkTestService(repo)

		res, err := svc.BulkUpdateFindingsStatus(context.Background(), tenantID.String(), BulkUpdateStatusInput{
			FindingIDs: []string{f.ID().String()},
			Status:     vulnerability.FindingStatusFalsePositive.String(),
			ActorID:    shared.NewID().String(),
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if res.Updated != 0 || res.Failed != 1 {
			t.Fatalf("want Updated=0 Failed=1, got Updated=%d Failed=%d (%v)", res.Updated, res.Failed, res.Errors)
		}
		if len(repo.written) != 0 {
			t.Fatalf("approval-requiring status must not reach the batch writer, wrote %v", repo.written)
		}
	})

	t.Run("accepted from confirmed is rejected", func(t *testing.T) {
		f := mkFinding(t, tenantID, vulnerability.FindingSourceDAST)
		if err := f.TransitionStatus(vulnerability.FindingStatusConfirmed, "", nil); err != nil {
			t.Fatalf("seed transition to confirmed: %v", err)
		}
		repo := &bulkStubRepo{byID: map[string]*vulnerability.Finding{f.ID().String(): f}}
		svc := newBulkTestService(repo)

		res, err := svc.BulkUpdateFindingsStatus(context.Background(), tenantID.String(), BulkUpdateStatusInput{
			FindingIDs: []string{f.ID().String()},
			Status:     vulnerability.FindingStatusAccepted.String(),
			ActorID:    shared.NewID().String(),
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if res.Updated != 0 || res.Failed != 1 {
			t.Fatalf("want Updated=0 Failed=1, got Updated=%d Failed=%d (%v)", res.Updated, res.Failed, res.Errors)
		}
		if len(repo.written) != 0 {
			t.Fatalf("approval-requiring status must not reach the batch writer, wrote %v", repo.written)
		}
	})
}

// TestBulkUpdateStatus_NonApproval_StillUpdates proves the guard is narrow: a
// non-approval transition (new → confirmed) still bulk-updates as before.
func TestBulkUpdateStatus_NonApproval_StillUpdates(t *testing.T) {
	tenantID := shared.NewID()
	f := mkFinding(t, tenantID, vulnerability.FindingSourceDAST) // status: new
	repo := &bulkStubRepo{byID: map[string]*vulnerability.Finding{f.ID().String(): f}}
	svc := newBulkTestService(repo)

	res, err := svc.BulkUpdateFindingsStatus(context.Background(), tenantID.String(), BulkUpdateStatusInput{
		FindingIDs: []string{f.ID().String()},
		Status:     vulnerability.FindingStatusConfirmed.String(),
		ActorID:    shared.NewID().String(),
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Updated != 1 || res.Failed != 0 {
		t.Fatalf("want Updated=1 Failed=0, got Updated=%d Failed=%d (%v)", res.Updated, res.Failed, res.Errors)
	}
	if len(repo.written) != 1 || repo.written[0] != f.ID() {
		t.Fatalf("non-approval status must reach the batch writer, wrote %v", repo.written)
	}
}

// TestBulkUpdateStatus_PerFindingTolerant proves the batch is per-finding
// tolerant: a valid transition still writes while an unresolvable id in the same
// call is recorded as Failed rather than aborting the whole batch — the same
// collect-and-continue contract the approval guard relies on.
func TestBulkUpdateStatus_PerFindingTolerant(t *testing.T) {
	tenantID := shared.NewID()
	ok := mkFinding(t, tenantID, vulnerability.FindingSourceDAST) // new → confirmed (allowed)
	repo := &bulkStubRepo{byID: map[string]*vulnerability.Finding{ok.ID().String(): ok}}
	svc := newBulkTestService(repo)

	res, err := svc.BulkUpdateFindingsStatus(context.Background(), tenantID.String(), BulkUpdateStatusInput{
		FindingIDs: []string{ok.ID().String(), shared.NewID().String()}, // 2nd id: not found
		Status:     vulnerability.FindingStatusConfirmed.String(),
		ActorID:    shared.NewID().String(),
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Updated != 1 || res.Failed != 1 {
		t.Fatalf("want Updated=1 Failed=1, got Updated=%d Failed=%d (%v)", res.Updated, res.Failed, res.Errors)
	}
	if len(repo.written) != 1 || repo.written[0] != ok.ID() {
		t.Fatalf("only the valid finding should be written, wrote %v", repo.written)
	}
}
