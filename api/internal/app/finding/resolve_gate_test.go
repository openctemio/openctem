package finding

import (
	"context"
	"errors"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

// methodStubRepo records the resolution method the bulk path writes.
type methodStubRepo struct {
	bulkStubRepo
	method vulnerability.ResolutionMethod
	by     *shared.ID
}

func (r *methodStubRepo) UpdateStatusBatch(ctx context.Context, tid shared.ID, ids []shared.ID, st vulnerability.FindingStatus, res string, by *shared.ID, m vulnerability.ResolutionMethod) error {
	r.method, r.by = m, by
	return r.bulkStubRepo.UpdateStatusBatch(ctx, tid, ids, st, res, by, m)
}

func fixAppliedFinding(t *testing.T, tenantID shared.ID) *vulnerability.Finding {
	t.Helper()
	f := mkFinding(t, tenantID, vulnerability.FindingSourceDAST)
	for _, st := range []vulnerability.FindingStatus{
		vulnerability.FindingStatusConfirmed, vulnerability.FindingStatusInProgress, vulnerability.FindingStatusFixApplied,
	} {
		if err := f.TransitionStatus(st, "", nil); err != nil {
			t.Fatalf("seed %s: %v", st, err)
		}
	}
	return f
}

// A member who holds findings:fix_apply and findings:bulk_update but not
// findings:verify cannot close fix_applied findings through the bulk path
// (it used to pass: the old guard skipped fix_applied sources). The whole
// request is refused and nothing is written.
func TestBulkResolve_WithoutVerify_RefusedForEverySource(t *testing.T) {
	tenantID := shared.NewID()
	fixApplied := fixAppliedFinding(t, tenantID)
	confirmed := mkFinding(t, tenantID, vulnerability.FindingSourceDAST)
	if err := confirmed.TransitionStatus(vulnerability.FindingStatusConfirmed, "", nil); err != nil {
		t.Fatal(err)
	}
	repo := &methodStubRepo{bulkStubRepo: bulkStubRepo{byID: map[string]*vulnerability.Finding{
		fixApplied.ID().String(): fixApplied, confirmed.ID().String(): confirmed,
	}}}
	svc := newBulkTestService(repo)

	_, err := svc.BulkUpdateFindingsStatus(context.Background(), tenantID.String(), BulkUpdateStatusInput{
		FindingIDs: []string{fixApplied.ID().String(), confirmed.ID().String()},
		Status:     vulnerability.FindingStatusResolved.String(),
		ActorID:    shared.NewID().String(),
	})
	if !errors.Is(err, shared.ErrForbidden) {
		t.Fatalf("bulk resolve without findings:verify: err = %v, want ErrForbidden", err)
	}
	if len(repo.written) != 0 {
		t.Fatalf("a refused bulk resolve wrote %v", repo.written)
	}
}

// With findings:verify the bulk resolve goes through and records the actor
// and the resolution method (admin_direct: no per-finding checklist read).
func TestBulkResolve_WithVerify_RecordsMethodAndActor(t *testing.T) {
	tenantID := shared.NewID()
	f := fixAppliedFinding(t, tenantID)
	repo := &methodStubRepo{bulkStubRepo: bulkStubRepo{byID: map[string]*vulnerability.Finding{f.ID().String(): f}}}
	svc := newBulkTestService(repo)
	actor := shared.NewID()

	res, err := svc.BulkUpdateFindingsStatus(context.Background(), tenantID.String(), BulkUpdateStatusInput{
		FindingIDs:          []string{f.ID().String()},
		Status:              vulnerability.FindingStatusResolved.String(),
		ActorID:             actor.String(),
		HasVerifyPermission: true,
	})
	if err != nil || res.Updated != 1 {
		t.Fatalf("verify holder bulk resolve = %+v, %v; want 1 updated", res, err)
	}
	if repo.method != vulnerability.ResolutionMethodAdminDirect {
		t.Errorf("resolution method = %q, want admin_direct", repo.method)
	}
	if repo.by == nil || *repo.by != actor {
		t.Errorf("resolved_by = %v, want the actor %s", repo.by, actor)
	}
}

// Moving to fix_applied (the member's own step) is unaffected by the gate.
func TestBulkFixApplied_WithoutVerify_StillAllowed(t *testing.T) {
	tenantID := shared.NewID()
	f := mkFinding(t, tenantID, vulnerability.FindingSourceDAST)
	for _, st := range []vulnerability.FindingStatus{vulnerability.FindingStatusConfirmed, vulnerability.FindingStatusInProgress} {
		if err := f.TransitionStatus(st, "", nil); err != nil {
			t.Fatal(err)
		}
	}
	repo := &methodStubRepo{bulkStubRepo: bulkStubRepo{byID: map[string]*vulnerability.Finding{f.ID().String(): f}}}
	res, err := newBulkTestService(repo).BulkUpdateFindingsStatus(context.Background(), tenantID.String(), BulkUpdateStatusInput{
		FindingIDs: []string{f.ID().String()},
		Status:     vulnerability.FindingStatusFixApplied.String(),
	})
	if err != nil || res.Updated != 1 {
		t.Fatalf("bulk fix_applied without verify = %+v, %v; want 1 updated", res, err)
	}
	if repo.method != vulnerability.ResolutionMethodAdminDirect {
		// The service always names admin_direct; the repository ignores it for
		// any status other than resolved (it stores NULL).
		t.Errorf("method passed = %q", repo.method)
	}
}

func TestAuthorizeHumanResolve(t *testing.T) {
	for _, st := range vulnerability.AllFindingStatuses() {
		err := authorizeHumanResolve(st, false)
		if st == vulnerability.FindingStatusResolved {
			if !errors.Is(err, shared.ErrForbidden) {
				t.Errorf("resolved without verify: %v, want ErrForbidden", err)
			}
			continue
		}
		if err != nil {
			t.Errorf("%s without verify: %v, want allowed", st, err)
		}
	}
	if err := authorizeHumanResolve(vulnerability.FindingStatusResolved, true); err != nil {
		t.Errorf("resolved with verify: %v", err)
	}
}
