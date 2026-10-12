package unit

// The scope service's feed of the job signer's ledger (RFC-040 §5.6 points
// 4 and 5): a widening reaches the signer before it is saved and fails when
// the signer does not accept it; a narrowing is saved first and never
// blocked; the approvals sent are the ones the scope policy recorded.

import (
	"context"
	"errors"
	"testing"

	"github.com/openctemio/openctem/api/internal/app/scope"
	scopedom "github.com/openctemio/openctem/api/pkg/domain/scope"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/tenant"
	"github.com/openctemio/openctem/api/pkg/jobsign"
	"github.com/openctemio/openctem/api/pkg/logger"
)

type fakeLedger struct {
	changes []jobsign.LedgerChange
	syncs   []jobsign.LedgerSnapshot
	refuse  bool
	down    bool
	tenants []string
}

func (f *fakeLedger) ApplyLedger(_ context.Context, ch jobsign.LedgerChange) (jobsign.LedgerApplyResult, error) {
	f.changes = append(f.changes, ch)
	switch {
	case f.down:
		return jobsign.LedgerApplyResult{}, errors.New("dial unix: no such file")
	case f.refuse:
		return jobsign.LedgerApplyResult{}, &jobsign.RefusalError{Status: 403, Reason: jobsign.ReasonLedgerNotApproved}
	}
	return jobsign.LedgerApplyResult{Kind: jobsign.ChangeWiden, Mode: jobsign.LedgerEnforce}, nil
}

func (f *fakeLedger) SyncLedger(_ context.Context, snap jobsign.LedgerSnapshot) (jobsign.LedgerSyncResult, error) {
	f.syncs = append(f.syncs, snap)
	return jobsign.LedgerSyncResult{Mode: jobsign.LedgerEnforce}, nil
}

func (f *fakeLedger) LedgerStatus(context.Context) (jobsign.LedgerStatus, error) {
	return jobsign.LedgerStatus{Mode: jobsign.LedgerEnforce, Tenants: f.tenants}, nil
}

// countingTargets counts the writes that reach the repository.
type countingTargets struct {
	*mockTargetRepo
	writes int
}

func (c *countingTargets) Create(ctx context.Context, t *scopedom.Target) error {
	c.writes++
	return c.mockTargetRepo.Create(ctx, t)
}

func (c *countingTargets) Update(ctx context.Context, t *scopedom.Target) error {
	c.writes++
	return c.mockTargetRepo.Update(ctx, t)
}

func ledgerScopeService(t *testing.T, admins int) (*scope.Service, *countingTargets, *mockExclusionRepo, *fakeLedger) {
	t.Helper()
	tr := &countingTargets{mockTargetRepo: newMockTargetRepo()}
	er := newMockExclusionRepo()
	svc := scope.NewService(tr, er, newMockAssetRepo(), logger.NewNop())
	svc.SetStepUpGate(passGate{})
	svc.SetEntryPolicy(fixedSettings{tenant.ScopeSettings{}}, adminDir{admins}, &noticeLog{})
	l := &fakeLedger{}
	svc.SetLedger(l)
	return svc, tr, er, l
}

func uuidActor() scope.Actor { return scope.Actor{UserID: shared.NewID().String(), CanApprove: true} }

func domainCode(err error) string {
	var de *shared.DomainError
	if errors.As(err, &de) {
		return de.Code
	}
	return ""
}

func TestScopeLedger_WideningIsNotSavedWhenTheSignerRefusesOrIsDown(t *testing.T) {
	for _, tc := range []struct {
		name string
		set  func(*fakeLedger)
		code string
	}{
		{"refused", func(l *fakeLedger) { l.refuse = true }, "SCOPE_LEDGER_REFUSED"},
		{"down", func(l *fakeLedger) { l.down = true }, "SCOPE_LEDGER_UNAVAILABLE"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			svc, tr, _, l := ledgerScopeService(t, 1)
			tc.set(l)
			_, err := create(svc, shared.NewID(), uuidActor(), "*.ours.example", nil)
			if domainCode(err) != tc.code {
				t.Fatalf("error %v, want %s", err, tc.code)
			}
			if tr.writes != 0 || len(tr.targets) != 0 {
				t.Fatalf("the entry was saved (%d writes) without the signer", tr.writes)
			}
			if len(l.changes) != 1 || l.changes[0].Ops[0].Op != jobsign.OpPutEntry {
				t.Fatalf("changes %+v", l.changes)
			}
		})
	}
}

func TestScopeLedger_ApprovalCarriesRequesterApprovalsAndPolicy(t *testing.T) {
	svc, _, _, l := ledgerScopeService(t, 3) // default policy: one approval
	tenantID := shared.NewID()
	a, b := uuidActor(), uuidActor()
	e, err := create(svc, tenantID, a, "*.ours.example", nil)
	if err != nil {
		t.Fatal(err)
	}
	if !e.IsPending() || len(l.changes) != 0 {
		t.Fatalf("a pending entry reached the ledger: %s %d", e.Status(), len(l.changes))
	}
	if _, effective, err := svc.ApproveTarget(context.Background(), e.ID().String(), tenantID.String(), b); err != nil || !effective {
		t.Fatalf("approve: %v %v", effective, err)
	}
	if len(l.changes) != 1 {
		t.Fatalf("changes %d", len(l.changes))
	}
	ch := l.changes[0]
	if ch.TenantID != tenantID.String() || ch.Requester != a.UserID || ch.RequiredApprovals != 1 ||
		len(ch.Approvals) != 1 || ch.Approvals[0].UserID != b.UserID {
		t.Fatalf("change %+v", ch)
	}
	op := ch.Ops[0]
	if op.Op != jobsign.OpPutEntry || op.Entry.ID != e.ID().String() || op.Entry.Pattern != "*.ours.example" || op.Entry.MaxTier != 1 {
		t.Fatalf("op %+v", op)
	}

	// The signer refusing the approval leaves the entry pending.
	e2, _ := create(svc, tenantID, a, "*.theirs.example", nil)
	l.refuse = true
	if _, _, err := svc.ApproveTarget(context.Background(), e2.ID().String(), tenantID.String(), b); domainCode(err) != "SCOPE_LEDGER_REFUSED" {
		t.Fatalf("approve with the signer refusing: %v", err)
	}
}

func TestScopeLedger_NarrowingIsSavedEvenWithTheSignerDown(t *testing.T) {
	svc, tr, _, l := ledgerScopeService(t, 1)
	tenantID := shared.NewID()
	e, err := create(svc, tenantID, uuidActor(), "*.ours.example", nil)
	if err != nil {
		t.Fatal(err)
	}
	l.down = true
	writes := tr.writes
	if _, err := svc.DeactivateTarget(context.Background(), e.ID().String(), tenantID.String()); err != nil {
		t.Fatalf("narrowing blocked by the signer: %v", err)
	}
	if tr.writes != writes+1 {
		t.Fatal("the deactivation was not saved")
	}
	last := l.changes[len(l.changes)-1]
	if last.Ops[0].Op != jobsign.OpRemoveEntry || last.Ops[0].ID != e.ID().String() || len(last.Approvals) != 0 {
		t.Fatalf("narrowing change %+v", last)
	}

	// A change that does not touch what is authorized is not sent at all.
	l.down = false
	e2, _ := create(svc, tenantID, uuidActor(), "*.other.example", nil)
	sent := len(l.changes)
	desc := "new description"
	if _, err := svc.UpdateTarget(context.Background(), e2.ID().String(), tenantID.String(), scope.UpdateTargetInput{Description: &desc}); err != nil {
		t.Fatal(err)
	}
	if len(l.changes) != sent {
		t.Fatalf("a description change reached the ledger")
	}
}

func TestScopeLedger_ExclusionsFeedTheLedger(t *testing.T) {
	svc, _, _, l := ledgerScopeService(t, 2)
	ctx := context.Background()
	tenantID := shared.NewID()
	creator, approver, reviewer := shared.NewID().String(), shared.NewID().String(), shared.NewID().String()
	x, err := svc.CreateExclusion(ctx, scope.CreateExclusionInput{TenantID: tenantID.String(), ExclusionType: "domain",
		Pattern: "prod.ours.example", Reason: "production", CreatedBy: creator})
	if err != nil {
		t.Fatal(err)
	}
	if len(l.changes) != 0 {
		t.Fatal("a pending exclusion reached the ledger")
	}
	if _, err := svc.ApproveExclusion(ctx, x.ID().String(), tenantID.String(), approver); err != nil {
		t.Fatal(err)
	}
	if len(l.changes) != 1 || l.changes[0].Ops[0].Op != jobsign.OpPutExclusion || l.changes[0].Ops[0].Exclusion.Pattern != "prod.ours.example" {
		t.Fatalf("approval: %+v", l.changes)
	}

	// Taking it out of effect widens: sent first, with the reviewer as the
	// approval and the creator as the requester; refused, nothing changes.
	l.refuse = true
	err = svc.DeleteExclusion(ctx, x.ID().String(), tenantID.String(), scopedom.Reviewer{UserID: reviewer, CanApprove: true})
	if domainCode(err) != "SCOPE_LEDGER_REFUSED" {
		t.Fatalf("delete with the signer refusing: %v", err)
	}
	if _, err := svc.GetExclusion(ctx, tenantID.String(), x.ID().String()); err != nil {
		t.Fatalf("the exclusion was deleted although the signer refused: %v", err)
	}
	ch := l.changes[len(l.changes)-1]
	if ch.Ops[0].Op != jobsign.OpRemoveExclusion || ch.Requester != creator || ch.RequiredApprovals != 1 ||
		len(ch.Approvals) != 1 || ch.Approvals[0].UserID != reviewer {
		t.Fatalf("removal change %+v", ch)
	}
}

func TestScopeLedger_SyncSendsOnlyScopeInEffect(t *testing.T) {
	svc, _, _, l := ledgerScopeService(t, 1)
	tenantID := shared.NewID()
	active, _ := create(svc, tenantID, uuidActor(), "*.ours.example", nil)
	inactive, _ := create(svc, tenantID, uuidActor(), "*.old.example", nil)
	if _, err := svc.DeactivateTarget(context.Background(), inactive.ID().String(), tenantID.String()); err != nil {
		t.Fatal(err)
	}
	l.tenants = []string{tenantID.String()}
	if err := svc.SyncLedger(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(l.syncs) != 1 || len(l.syncs[0].Entries) != 1 || l.syncs[0].Entries[0].ID != active.ID().String() {
		t.Fatalf("sync %+v", l.syncs)
	}
}

func TestScopeLedger_CommitEntriesForOtherPaths(t *testing.T) {
	svc, _, _, l := ledgerScopeService(t, 2)
	tenantID, importer := shared.NewID(), shared.NewID().String()
	e, _ := scopedom.NewEntry(tenantID, scopedom.TargetTypeDomain, "*.program.example", "", importer, scopedom.EntryOptions{MaxTier: scopedom.TierActive})
	gone := shared.NewID()
	saved := false
	if err := svc.CommitEntries(context.Background(), tenantID, importer, []*scopedom.Target{e}, []shared.ID{gone}, scope.ProgramAttestation,
		func() error { saved = true; return nil }); err != nil || !saved {
		t.Fatalf("commit: %v saved=%v", err, saved)
	}
	if len(l.changes) != 2 {
		t.Fatalf("changes %d", len(l.changes))
	}
	w, n := l.changes[0], l.changes[1]
	if w.Requester != importer || w.PlatformPolicy != scope.ProgramAttestation || w.Ops[0].Op != jobsign.OpPutEntry ||
		n.Ops[0].Op != jobsign.OpRemoveEntry || n.Ops[0].ID != gone.String() {
		t.Fatalf("widen %+v narrow %+v", w, n)
	}
	l.refuse, saved = true, false
	if err := svc.CommitEntries(context.Background(), tenantID, importer, []*scopedom.Target{e}, nil, scope.ProgramAttestation,
		func() error { saved = true; return nil }); domainCode(err) != "SCOPE_LEDGER_REFUSED" || saved {
		t.Fatalf("refused commit: %v saved=%v", err, saved)
	}
}
