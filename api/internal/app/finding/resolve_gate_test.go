package finding

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

// methodStubRepo records the closure the bulk path writes.
type methodStubRepo struct {
	bulkStubRepo
	method vulnerability.Closure
	by     *shared.ID
}

// AcceptUntil records an accept like UpdateStatusBatch does.
func (r *methodStubRepo) AcceptUntil(ctx context.Context, tenantID, id shared.ID, _ time.Time, by *shared.ID, _ vulnerability.ClosureReason) error {
	return r.UpdateStatusBatch(ctx, tenantID, []shared.ID{id}, vulnerability.FindingStatusAccepted, "", by, vulnerability.Closure{})
}

func (r *methodStubRepo) UpdateStatusBatch(ctx context.Context, tid shared.ID, ids []shared.ID, st vulnerability.FindingStatus, res string, by *shared.ID, m vulnerability.Closure) error {
	r.method, r.by = m, by
	return r.bulkStubRepo.UpdateStatusBatch(ctx, tid, ids, st, res, by, m)
}

func fixAppliedFinding(t *testing.T, tenantID shared.ID) *vulnerability.Finding {
	t.Helper()
	return fixAppliedFindingOf(t, tenantID, vulnerability.SeverityMedium)
}

func fixAppliedFindingOf(t *testing.T, tenantID shared.ID, sev vulnerability.Severity) *vulnerability.Finding {
	t.Helper()
	f, err := vulnerability.NewFinding(tenantID, shared.NewID(), vulnerability.FindingSourceDAST, "nuclei", sev, "test finding")
	if err != nil {
		t.Fatal(err)
	}
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
// and the closure (fixed, attested: no per-finding checklist read).
func TestBulkResolve_WithVerify_RecordsMethodAndActor(t *testing.T) {
	tenantID := shared.NewID()
	f := fixAppliedFinding(t, tenantID)
	repo := &methodStubRepo{bulkStubRepo: bulkStubRepo{byID: map[string]*vulnerability.Finding{f.ID().String(): f}}}
	svc := newBulkTestService(repo)
	actor := shared.NewID()

	res, err := svc.BulkUpdateFindingsStatus(context.Background(), tenantID.String(), BulkUpdateStatusInput{
		FindingIDs:          []string{f.ID().String()},
		Status:              vulnerability.FindingStatusResolved.String(),
		Resolution:          "patched in 4.2", // an attested close carries a note
		ActorID:             actor.String(),
		HasVerifyPermission: true,
	})
	if err != nil || res.Updated != 1 {
		t.Fatalf("verify holder bulk resolve = %+v, %v; want 1 updated", res, err)
	}
	if repo.method != vulnerability.Fixed(vulnerability.VerificationAttested) {
		t.Errorf("closure = %+v, want fixed / attested", repo.method)
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
		// A fix claim is a person's, with findings:fix_apply and a note.
		Resolution:            "patched",
		ActorID:               shared.NewID().String(),
		HasFixApplyPermission: true,
	})
	if err != nil || res.Updated != 1 {
		t.Fatalf("bulk fix_applied without verify = %+v, %v; want 1 updated", res, err)
	}
	if repo.method != vulnerability.Fixed(vulnerability.VerificationAttested) {
		// The service always names its resolve closure; the repository
		// ignores it for an open status (it stores NULL).
		t.Errorf("closure passed = %+v", repo.method)
	}
}

// The evidence a person's resolve needs grows with risk: a medium
// finding may be attested with a note, a high one needs the verification
// checklist, a critical one a retest or a second verifier. With no evidence
// recorded, the bulk resolve refuses the high and critical rows and closes
// the medium one.
func TestBulkResolve_EvidenceByRisk(t *testing.T) {
	tenantID := shared.NewID()
	medium := fixAppliedFindingOf(t, tenantID, vulnerability.SeverityMedium)
	high := fixAppliedFindingOf(t, tenantID, vulnerability.SeverityHigh)
	critical := fixAppliedFindingOf(t, tenantID, vulnerability.SeverityCritical)
	repo := &methodStubRepo{bulkStubRepo: bulkStubRepo{byID: map[string]*vulnerability.Finding{
		medium.ID().String(): medium, high.ID().String(): high, critical.ID().String(): critical,
	}}}
	res, err := newBulkTestService(repo).BulkUpdateFindingsStatus(context.Background(), tenantID.String(), BulkUpdateStatusInput{
		FindingIDs: []string{medium.ID().String(), high.ID().String(), critical.ID().String()},
		Status:     vulnerability.FindingStatusResolved.String(), Resolution: "patched",
		ActorID: shared.NewID().String(), HasVerifyPermission: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Updated != 1 || res.Failed != 2 {
		t.Fatalf("result = %+v, want the medium one closed and the high and critical ones refused", res)
	}
	reasons := map[string]string{}
	for _, r := range res.Rows {
		reasons[r.FindingID] = r.Reason
	}
	if !strings.Contains(reasons[high.ID().String()], "checklist") || !strings.Contains(reasons[critical.ID().String()], "retest") {
		t.Errorf("reasons = %v", reasons)
	}
}
