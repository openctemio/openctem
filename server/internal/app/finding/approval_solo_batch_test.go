package finding

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/openctem/server/pkg/domain/approvalpolicy"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
	tenantdom "github.com/openctemio/openctem/server/pkg/domain/tenant"
	"github.com/openctemio/openctem/server/pkg/domain/vulnerability"
	"github.com/openctemio/openctem/server/pkg/logger"
	"github.com/openctemio/openctem/server/pkg/pagination"
)

// fakeBatchStore is an approval repository with group exceptions in memory.
// Methods the tests do not reach are left to the embedded nil interface.
type fakeBatchStore struct {
	vulnerability.ApprovalRepository
	batch     *vulnerability.ApprovalBatch
	members   []vulnerability.ApprovalBatchMember
	approvals map[shared.ID]*vulnerability.Approval
	signed    int
	leftOut   []shared.ID
}

func (f *fakeBatchStore) GetByTenantAndID(_ context.Context, tenantID, id shared.ID) (*vulnerability.Approval, error) {
	a, ok := f.approvals[id]
	if !ok || a.TenantID != tenantID {
		return nil, shared.ErrNotFound
	}
	return a, nil
}

func (f *fakeBatchStore) PendingBatchForSource(context.Context, shared.ID, string, shared.ID) (bool, error) {
	return false, nil
}

func (f *fakeBatchStore) PendingFindingIDs(context.Context, shared.ID, []shared.ID) (map[shared.ID]bool, error) {
	return nil, nil
}

func (f *fakeBatchStore) CreateBatch(context.Context, *vulnerability.ApprovalBatch, []*vulnerability.Approval) error {
	return nil
}

func (f *fakeBatchStore) GetBatch(_ context.Context, tenantID, id shared.ID) (*vulnerability.ApprovalBatch, error) {
	if f.batch == nil || f.batch.TenantID != tenantID || f.batch.ID != id {
		return nil, shared.ErrNotFound
	}
	b := *f.batch
	return &b, nil
}

func (f *fakeBatchStore) ListBatches(context.Context, shared.ID, string, *shared.ID, *shared.DataScope, pagination.Pagination) (pagination.Result[*vulnerability.ApprovalBatch], error) {
	return pagination.Result[*vulnerability.ApprovalBatch]{}, nil
}

func (f *fakeBatchStore) BatchMembers(context.Context, shared.ID, shared.ID) ([]vulnerability.ApprovalBatchMember, error) {
	return f.members, nil
}

func (f *fakeBatchStore) BatchSignoffs(context.Context, shared.ID, shared.ID) ([]approvalpolicy.Signoff, error) {
	return nil, nil
}

func (f *fakeBatchStore) SignOffBatch(_ context.Context, _, _, _ shared.ID, _ SignoffRecord,
	decide func(prior []approvalpolicy.Signoff) (bool, error),
	finish func(a *vulnerability.Approval) (*vulnerability.FindingActivity, bool, error),
) (*vulnerability.ApprovalBatch, int, []shared.ID, error) {
	f.signed++
	if _, err := decide(nil); err != nil {
		return nil, 0, nil, err
	}
	applied := 0
	for _, m := range f.members {
		a := f.approvals[m.ApprovalID]
		if a == nil || !a.IsPending() {
			continue
		}
		_, ok, err := finish(a)
		if err != nil {
			return nil, 0, nil, err
		}
		if ok {
			applied++
		}
	}
	b := *f.batch
	b.Status = vulnerability.ApprovalStatusApproved
	return &b, applied, nil, nil
}

func (f *fakeBatchStore) CloseBatch(context.Context, shared.ID, shared.ID, shared.ID, vulnerability.ApprovalStatus, string) (*vulnerability.ApprovalBatch, error) {
	return f.batch, nil
}

func (f *fakeBatchStore) RejectBatchMember(_ context.Context, _, _, findingID, _ shared.ID, _ string) (*vulnerability.ApprovalBatch, shared.ID, error) {
	f.leftOut = append(f.leftOut, findingID)
	return f.batch, shared.NewID(), nil
}

// soloFindings serves findings by id.
type soloFindings struct {
	vulnerability.FindingRepository
	byID map[shared.ID]*vulnerability.Finding
}

func (r *soloFindings) GetByID(_ context.Context, _, id shared.ID) (*vulnerability.Finding, error) {
	if f, ok := r.byID[id]; ok {
		return f, nil
	}
	return nil, shared.ErrNotFound
}

func (r *soloFindings) GetByIDs(_ context.Context, _ shared.ID, ids []shared.ID) ([]*vulnerability.Finding, error) {
	out := make([]*vulnerability.Finding, 0, len(ids))
	for _, id := range ids {
		if f, ok := r.byID[id]; ok {
			out = append(out, f)
		}
	}
	return out, nil
}

type soleOwnerStub struct {
	sole    bool
	removed *time.Time
	calls   int
}

func (s *soleOwnerStub) IsSoleActiveOwner(context.Context, shared.ID, string) (bool, error) {
	s.calls++
	return s.sole, nil
}

func (s *soleOwnerStub) RecentMemberRemoval(context.Context, shared.ID, time.Duration) (*time.Time, error) {
	return s.removed, nil
}

type codeStub struct {
	valid map[string]bool
	spent []string
}

func (c *codeStub) VerifyFreshTOTP(_ context.Context, _, code string) error {
	if !c.valid[code] {
		return vulnerability.ErrSoloApprovalBadCode
	}
	delete(c.valid, code)
	c.spent = append(c.spent, code)
	return nil
}

type acceptLevelStub struct{ level string }

func (a acceptLevelStub) GetFindingApprovalSettings(context.Context, string) (*tenantdom.FindingApprovalSettings, error) {
	return &tenantdom.FindingApprovalSettings{AcceptApproval: a.level}, nil
}

type soloBatchFixture struct {
	svc       *VulnerabilityService
	store     *fakeBatchStore
	owners    *soleOwnerStub
	codes     *codeStub
	tenant    shared.ID
	requester shared.ID
	findings  []*vulnerability.Finding
}

func newSoloBatchFixture(t *testing.T, status vulnerability.FindingStatus, members int) *soloBatchFixture {
	t.Helper()
	fx := &soloBatchFixture{tenant: shared.NewID(), requester: shared.NewID(),
		owners: &soleOwnerStub{sole: true}, codes: &codeStub{valid: map[string]bool{"123456": true, "654321": true}}}
	b := &vulnerability.ApprovalBatch{ID: shared.NewID(), TenantID: fx.tenant, SourceType: vulnerability.ApprovalBatchSourceVulnerabilities,
		SourceLabel: "CVE-2026-0001", RequestedStatus: status, RequestedBy: fx.requester, Status: vulnerability.ApprovalStatusPending,
		DecideBy: time.Now().Add(72 * time.Hour), MemberCount: members, Tier: "peer", RequiredApprovals: 1}
	repo := &soloFindings{byID: map[shared.ID]*vulnerability.Finding{}}
	fx.store = &fakeBatchStore{batch: b, approvals: map[shared.ID]*vulnerability.Approval{}}
	for i := 0; i < members; i++ {
		f := mkFinding(t, fx.tenant, vulnerability.FindingSourceDAST)
		if err := f.TransitionStatus(vulnerability.FindingStatusConfirmed, "", nil); err != nil {
			t.Fatalf("confirm: %v", err)
		}
		repo.byID[f.ID()] = f
		fx.findings = append(fx.findings, f)
		var end *time.Time
		if status == vulnerability.FindingStatusAccepted {
			e := time.Now().Add(300 * 24 * time.Hour)
			end = &e
		}
		a := vulnerability.NewApproval(fx.tenant, f.ID(), fx.requester, string(status), "group note", end)
		a.BatchID = &b.ID
		fx.store.approvals[a.ID] = a
		fx.store.members = append(fx.store.members, vulnerability.ApprovalBatchMember{
			ApprovalID: a.ID, FindingID: f.ID(), Status: vulnerability.ApprovalStatusPending,
		})
	}
	fx.svc = &VulnerabilityService{findingRepo: repo, approvalRepo: fx.store, logger: logger.NewNop()}
	fx.svc.SetSoloApproval(fx.owners, fx.codes, acceptLevelStub{level: tenantdom.FPApprovalAll})
	return fx
}

func (fx *soloBatchFixture) in(code string) SelfApproveBatchInput {
	return SelfApproveBatchInput{TenantID: fx.tenant, BatchID: fx.store.batch.ID, UserID: fx.requester,
		Reason: "one-person company; checked each one", Code: code}
}

// A refused self-approval of a group changes nothing and spends no code.
func TestSelfApproveSoloBatch_Refusals(t *testing.T) {
	recent := time.Now().Add(-48 * time.Hour)
	cases := []struct {
		name  string
		setup func(fx *soloBatchFixture) SelfApproveBatchInput
		want  error
	}{
		{"another person's group", func(fx *soloBatchFixture) SelfApproveBatchInput {
			in := fx.in("123456")
			in.UserID = shared.NewID()
			return in
		}, vulnerability.ErrSoloApprovalNotAllowed},
		{"a second active member", func(fx *soloBatchFixture) SelfApproveBatchInput {
			fx.owners.sole = false
			return fx.in("123456")
		}, vulnerability.ErrSoloApprovalNotAllowed},
		{"a member removed within 7 days", func(fx *soloBatchFixture) SelfApproveBatchInput {
			fx.owners.removed = &recent
			return fx.in("123456")
		}, shared.ErrForbidden},
		{"a wrong code", func(fx *soloBatchFixture) SelfApproveBatchInput { return fx.in("000000") }, vulnerability.ErrSoloApprovalBadCode},
		{"no reason", func(fx *soloBatchFixture) SelfApproveBatchInput {
			in := fx.in("123456")
			in.Reason = "  "
			return in
		}, vulnerability.ErrSoloApprovalNeedsReason},
		{"the group is decided", func(fx *soloBatchFixture) SelfApproveBatchInput {
			fx.store.batch.Status = vulnerability.ApprovalStatusRejected
			return fx.in("123456")
		}, vulnerability.ErrBatchNotPending},
		{"the group is overdue", func(fx *soloBatchFixture) SelfApproveBatchInput {
			fx.store.batch.DecideBy = time.Now().Add(-time.Minute)
			return fx.in("123456")
		}, vulnerability.ErrDecisionOverdue},
		{"another tenant", func(fx *soloBatchFixture) SelfApproveBatchInput {
			in := fx.in("123456")
			in.TenantID = shared.NewID()
			return in
		}, shared.ErrNotFound},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fx := newSoloBatchFixture(t, vulnerability.FindingStatusFalsePositive, 2)
			_, err := fx.svc.SelfApproveSoloBatch(context.Background(), tc.setup(fx))
			if !errors.Is(err, tc.want) {
				t.Fatalf("want %v, got %v", tc.want, err)
			}
			if fx.store.signed != 0 {
				t.Fatal("a refused self-approval reached the store")
			}
			if tc.want != vulnerability.ErrSoloApprovalBadCode && len(fx.codes.spent) != 0 {
				t.Fatalf("a refusal spent a code: %v", fx.codes.spent)
			}
		})
	}
}

// A used code cannot be replayed on another group.
func TestSelfApproveSoloBatch_ReplayedCodeRefused(t *testing.T) {
	fx := newSoloBatchFixture(t, vulnerability.FindingStatusFalsePositive, 1)
	if _, err := fx.svc.SelfApproveSoloBatch(context.Background(), fx.in("123456")); err != nil {
		t.Fatalf("first self-approval: %v", err)
	}
	again := newSoloBatchFixture(t, vulnerability.FindingStatusFalsePositive, 1)
	again.svc.SetSoloApproval(again.owners, fx.codes, acceptLevelStub{level: tenantdom.FPApprovalAll})
	if _, err := again.svc.SelfApproveSoloBatch(context.Background(), again.in("123456")); !errors.Is(err, vulnerability.ErrSoloApprovalBadCode) {
		t.Fatalf("replayed code: %v", err)
	}
}

// Every pending member is approved, marked self-approved with the reason.
func TestSelfApproveSoloBatch_AppliesEveryMemberSelfApproved(t *testing.T) {
	fx := newSoloBatchFixture(t, vulnerability.FindingStatusFalsePositive, 3)
	d, err := fx.svc.SelfApproveSoloBatch(context.Background(), fx.in("123456"))
	if err != nil {
		t.Fatalf("self-approve: %v", err)
	}
	if d.Applied != 3 || d.Batch.Status != vulnerability.ApprovalStatusApproved {
		t.Fatalf("decision: applied %d, status %s", d.Applied, d.Batch.Status)
	}
	for _, a := range fx.store.approvals {
		if !a.SelfApproved || a.Status != vulnerability.ApprovalStatusApproved || !strings.Contains(a.SelfApprovalReason, "one-person") {
			t.Fatalf("member not self-approved: %+v", a)
		}
	}
}

// An accepted risk under the risk acceptance level "all" stays four-eyes,
// refused before any code is spent; under high_and_above it is applied and
// every end is cut to the member's self-approval limit.
func TestSelfApproveSoloBatch_AcceptedRisk(t *testing.T) {
	fx := newSoloBatchFixture(t, vulnerability.FindingStatusAccepted, 2)
	if _, err := fx.svc.SelfApproveSoloBatch(context.Background(), fx.in("123456")); !errors.Is(err, vulnerability.ErrSoloApprovalFalsePositiveOnly) {
		t.Fatalf("accepted risk under all: %v", err)
	}
	if len(fx.codes.spent) != 0 || fx.owners.calls != 0 {
		t.Fatal("the refusal ran the member check or spent a code")
	}
	fx.svc.SetSoloApproval(fx.owners, fx.codes, acceptLevelStub{level: tenantdom.FPApprovalHighAndAbove})
	d, err := fx.svc.SelfApproveSoloBatch(context.Background(), fx.in("123456"))
	if err != nil {
		t.Fatalf("accepted risk under high_and_above: %v", err)
	}
	if d.Applied != 2 || d.Shortened != 2 {
		t.Fatalf("applied %d, shortened %d", d.Applied, d.Shortened)
	}
	for _, f := range fx.findings {
		limit := time.Now().Add(vulnerability.SoloAcceptanceLimit(f) + time.Minute)
		for _, a := range fx.store.approvals {
			if a.FindingID == f.ID() && (a.ExpiresAt == nil || a.ExpiresAt.After(limit)) {
				t.Fatalf("member end past the self-approval limit: %v", a.ExpiresAt)
			}
		}
	}
}

// A member that an AI application asked for is never self-approved: the
// whole call is refused.
func TestSelfApproveSoloBatch_AIApplicationMemberRefused(t *testing.T) {
	fx := newSoloBatchFixture(t, vulnerability.FindingStatusFalsePositive, 2)
	for _, a := range fx.store.approvals {
		a.RequestedVia = "assistant"
		break
	}
	if _, err := fx.svc.SelfApproveSoloBatch(context.Background(), fx.in("123456")); !errors.Is(err, vulnerability.ErrSoloApprovalNotAllowed) {
		t.Fatalf("AI member: %v", err)
	}
}

// The requester never leaves out a member of their own group; another
// approver may, with a reason.
func TestLeaveOutGroupMember_FourEyes(t *testing.T) {
	fx := newSoloBatchFixture(t, vulnerability.FindingStatusFalsePositive, 2)
	ctx := context.Background()
	member := fx.findings[0].ID()
	if _, err := fx.svc.LeaveOutGroupMember(ctx, fx.tenant, fx.store.batch.ID, member, fx.requester, "not this one"); !errors.Is(err, vulnerability.ErrSelfApproval) {
		t.Fatalf("requester leaving out: %v", err)
	}
	approver := shared.NewID()
	if _, err := fx.svc.LeaveOutGroupMember(ctx, fx.tenant, fx.store.batch.ID, member, approver, " "); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("no reason: %v", err)
	}
	if _, err := fx.svc.LeaveOutGroupMember(ctx, shared.NewID(), fx.store.batch.ID, member, approver, "x"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("another tenant: %v", err)
	}
	if len(fx.store.leftOut) != 0 {
		t.Fatal("a refused leave-out reached the store")
	}
	if _, err := fx.svc.LeaveOutGroupMember(ctx, fx.tenant, fx.store.batch.ID, member, approver, "still exploitable"); err != nil {
		t.Fatalf("leave out: %v", err)
	}
	if len(fx.store.leftOut) != 1 || fx.store.leftOut[0] != member {
		t.Fatalf("left out: %v", fx.store.leftOut)
	}
}

// A bulk call is bounded, needs a reason to reject, reports ids of another
// tenant or malformed ids as not found and a decided request as not pending,
// and lists a repeated id once.
func TestBulkDecide_ValidationAndPerItemIsolation(t *testing.T) {
	fx := newSoloBatchFixture(t, vulnerability.FindingStatusFalsePositive, 1)
	ctx := context.Background()
	user := shared.NewID().String()
	tooMany := make([]string, MaxBulkApprovalDecisions+1)
	for i := range tooMany {
		tooMany[i] = shared.NewID().String()
	}
	if _, err := fx.svc.BulkApproveApprovals(ctx, BulkDecisionInput{TenantID: fx.tenant.String(), UserID: user, ApprovalIDs: tooMany}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("101 ids: %v", err)
	}
	if _, err := fx.svc.BulkApproveApprovals(ctx, BulkDecisionInput{TenantID: fx.tenant.String(), UserID: user}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("no ids: %v", err)
	}
	if _, err := fx.svc.BulkRejectApprovals(ctx, BulkDecisionInput{TenantID: fx.tenant.String(), UserID: user, ApprovalIDs: []string{tooMany[0]}}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("reject without a reason: %v", err)
	}
	// A decided request of this tenant, a request of another tenant, a
	// malformed id, the same id twice and a group of another tenant.
	decided := vulnerability.NewApproval(fx.tenant, fx.findings[0].ID(), shared.NewID(), "false_positive", "n", nil)
	decided.Status = vulnerability.ApprovalStatusRejected
	fx.store.approvals[decided.ID] = decided
	foreign := vulnerability.NewApproval(shared.NewID(), shared.NewID(), shared.NewID(), "false_positive", "n", nil)
	fx.store.approvals[foreign.ID] = foreign
	items, err := fx.svc.BulkApproveApprovals(ctx, BulkDecisionInput{TenantID: fx.tenant.String(), UserID: user,
		ApprovalIDs: []string{decided.ID.String(), foreign.ID.String(), "not-an-id", decided.ID.String()},
		BatchIDs:    []string{shared.NewID().String()},
	})
	if err != nil {
		t.Fatalf("bulk approve: %v", err)
	}
	if len(items) != 4 {
		t.Fatalf("items: %d", len(items))
	}
	wantNotFound := map[string]bool{foreign.ID.String(): true, "not-an-id": true}
	for _, it := range items {
		switch {
		case it.ID == decided.ID.String():
			if !errors.Is(it.Err, ErrApprovalNotPending) {
				t.Fatalf("decided request: %v", it.Err)
			}
		case wantNotFound[it.ID] || it.Kind == BulkItemBatch:
			if !errors.Is(it.Err, shared.ErrNotFound) {
				t.Fatalf("%s %s: %v", it.Kind, it.ID, it.Err)
			}
		default:
			t.Fatalf("unexpected item %+v", it)
		}
	}
	if fx.store.signed != 0 {
		t.Fatal("a skipped item reached the store")
	}
}

// The cap of a bulk approval counts the findings inside groups: a group
// counts every member, so a group of 1,001 is refused with a clear error
// before anything is approved, while the same group named twice and a few
// requests beside a group of 501 stay within the cap.
func TestBulkDecide_CapCountsFindingsInsideGroups(t *testing.T) {
	fx := newSoloBatchFixture(t, vulnerability.FindingStatusFalsePositive, 1)
	ctx := context.Background()
	user := shared.NewID().String()
	grow := func(n int) {
		for i := 0; i < n; i++ {
			fx.store.members = append(fx.store.members, vulnerability.ApprovalBatchMember{
				ApprovalID: shared.NewID(), FindingID: shared.NewID(), Status: vulnerability.ApprovalStatusPending,
			})
		}
	}
	batch := fx.store.batch.ID.String()
	ids := make([]string, 99)
	for i := range ids {
		ids[i] = shared.NewID().String()
	}
	grow(500) // 501 members
	within := BulkDecisionInput{TenantID: fx.tenant.String(), UserID: user, ApprovalIDs: ids, BatchIDs: []string{batch, batch}}
	if err := fx.svc.checkBulkApprovalFindings(ctx, fx.tenant, within); err != nil {
		t.Fatalf("99 requests and one group of 501: %v", err)
	}
	grow(500) // 1,001 members
	_, err := fx.svc.BulkApproveApprovals(ctx, BulkDecisionInput{TenantID: fx.tenant.String(), UserID: user, BatchIDs: []string{batch}})
	if !errors.Is(err, shared.ErrValidation) || !strings.Contains(err.Error(), "1001 findings") {
		t.Fatalf("a group of 1001: %v", err)
	}
	if fx.store.signed != 0 {
		t.Fatal("a refused call reached the store")
	}
}
