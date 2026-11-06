package unit

// Who approves a pending scope entry, reminders, and an owner's own approval
// when no other approver exists (RFC-054 §7, amendment 2026-10-09).

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/internal/app/outbox"
	"github.com/openctemio/openctem/api/internal/app/scope"
	"github.com/openctemio/openctem/api/pkg/domain/integration"
	notificationdom "github.com/openctemio/openctem/api/pkg/domain/notification"
	scopedom "github.com/openctemio/openctem/api/pkg/domain/scope"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/tenant"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// remindRepo adds the atomic reminder mark to the in-memory repository.
type remindRepo struct {
	*mockTargetRepo
	mu   sync.Mutex
	last map[string]time.Time
}

func (r *remindRepo) MarkReminded(_ context.Context, tenantID, id shared.ID, now time.Time, minInterval time.Duration) (bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	t, ok := r.targets[id.String()]
	if !ok || t.TenantID() != tenantID || !t.IsPending() {
		return false, nil
	}
	if at, ok := r.last[id.String()]; ok && at.After(now.Add(-minInterval)) {
		return false, nil
	}
	r.last[id.String()] = now
	return true, nil
}

type fixedApprovers struct{ list []scopedom.Approver }

func (f fixedApprovers) ScopeApprovers(context.Context, shared.ID) ([]scopedom.Approver, error) {
	return f.list, nil
}

type fakeTOTP struct {
	err   error
	calls int
}

func (f *fakeTOTP) VerifyFreshTOTP(context.Context, string, string) error {
	f.calls++
	return f.err
}

type mailLog struct {
	mu  sync.Mutex
	to  [][]string
	sub []string
}

func (m *mailLog) SendScopeApprovalMail(_ context.Context, _ string, to []string, subject, _ string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.to = append(m.to, to)
	m.sub = append(m.sub, subject)
}

type channelLog struct{ events []outbox.EnqueueParams }

func (c *channelLog) Enqueue(_ context.Context, p outbox.EnqueueParams) error {
	c.events = append(c.events, p)
	return nil
}

type userNotes struct{ to []string }

func (n *userNotes) Notify(_ context.Context, p notificationdom.NotificationParams) error {
	if p.AudienceID != nil {
		n.to = append(n.to, p.AudienceID.String())
	}
	return nil
}

type approverHarness struct {
	svc      *scope.Service
	repo     *remindRepo
	totp     *fakeTOTP
	mail     *mailLog
	channels *channelLog
	notes    *userNotes
}

func newApproverHarness(t *testing.T, admins int, approvers []scopedom.Approver) approverHarness {
	t.Helper()
	repo := &remindRepo{mockTargetRepo: newMockTargetRepo(), last: map[string]time.Time{}}
	svc := scope.NewService(repo, newMockExclusionRepo(), newMockAssetRepo(), logger.NewNop())
	svc.SetStepUpGate(passGate{})
	h := approverHarness{svc: svc, repo: repo, totp: &fakeTOTP{}, mail: &mailLog{}, channels: &channelLog{}, notes: &userNotes{}}
	svc.SetEntryPolicy(fixedSettings{tenant.ScopeSettings{}}, adminDir{admins}, h.notes)
	svc.SetApprovers(fixedApprovers{approvers}, h.totp, h.mail, h.channels, "https://app.example")
	return h
}

var (
	ownerID   = shared.NewID().String()
	adminID   = shared.NewID().String()
	approver3 = shared.NewID().String()
	owner     = scope.Actor{UserID: ownerID, CanApprove: true}
	admin2    = scope.Actor{UserID: adminID, CanApprove: true}
)

// The approver list names everyone who can still approve: never the
// requester, never someone who already approved.
func TestScopeApprovers_ListExcludesRequesterAndPriorApprovers(t *testing.T) {
	two := 2
	all := []scopedom.Approver{
		{UserID: ownerID, Name: "Olivia", Email: "o@example.test", Owner: true},
		{UserID: adminID, Name: "Adam", Email: "a@example.test"},
		{UserID: approver3, Name: "Carla", Email: "c@example.test"},
	}
	h := newApproverHarness(t, 3, all)
	h.svc.SetEntryPolicy(fixedSettings{tenant.ScopeSettings{WideningApprovals: &two}}, adminDir{3}, h.notes)
	tenantID := shared.NewID()
	e, err := create(h.svc, tenantID, owner, "*.ours.example", nil)
	if err != nil || !e.IsPending() {
		t.Fatalf("create: %v pending=%v", err, e != nil && e.IsPending())
	}
	st, err := h.svc.ApprovalStatuses(context.Background(), tenantID, []*scopedom.Target{e}, admin2)
	if err != nil {
		t.Fatal(err)
	}
	got := st[e.ID().String()]
	if got.Remaining != 2 || len(got.Eligible) != 2 || got.SelfApprovalAvailable {
		t.Fatalf("status %+v, want 2 remaining, 2 eligible (not the requester), no self-approval", got)
	}
	for _, a := range got.Eligible {
		if a.UserID == ownerID {
			t.Fatal("the requester is listed as an approver")
		}
	}
	if _, _, err := h.svc.ApproveTarget(context.Background(), e.ID().String(), tenantID.String(), admin2); err != nil {
		t.Fatal(err)
	}
	st, _ = h.svc.ApprovalStatuses(context.Background(), tenantID, []*scopedom.Target{e}, owner)
	got = st[e.ID().String()]
	if got.Remaining != 1 || len(got.Eligible) != 1 || got.Eligible[0].UserID != approver3 {
		t.Fatalf("after one approval: %+v, want only Carla left", got)
	}
	// Another tenant's view of the entry has no status.
	other, _ := h.svc.ApprovalStatuses(context.Background(), shared.NewID(), []*scopedom.Target{e}, owner)
	if len(other) != 0 {
		t.Fatal("approval status answered for another tenant")
	}
}

// A new pending entry reaches its approvers: in-app, email and channels.
func TestScopeApprovers_RequestNotifiesEligibleApprovers(t *testing.T) {
	member3 := shared.NewID().String()
	all := []scopedom.Approver{
		{UserID: ownerID, Name: "Olivia", Email: "o@example.test", Owner: true},
		{UserID: member3, Name: "Custom role approver", Email: "c@example.test"},
	}
	h := newApproverHarness(t, 1, all)
	tenantID := shared.NewID()
	e, err := create(h.svc, tenantID, owner, "t2.ours.example", func(in *scope.CreateTargetInput) {
		in.MaxTier, in.ExpiresInDays, in.Reason = "t2", days(3), "pentest window"
	})
	if err != nil || !e.IsPending() {
		t.Fatalf("t2 create: %v", err)
	}
	if len(h.mail.to) != 1 || len(h.mail.to[0]) != 1 || h.mail.to[0][0] != "c@example.test" {
		t.Fatalf("emails %v, want only the other approver", h.mail.to)
	}
	found := false
	for _, id := range h.notes.to {
		if id == member3 {
			found = true
		}
	}
	if !found {
		t.Fatal("the approver who is not an administrator got no in-app request")
	}
	if len(h.channels.events) == 0 || h.channels.events[0].EventType != string(integration.EventTypeApprovalRequested) {
		t.Fatalf("channels %v, want approval_requested", h.channels.events)
	}
	if h.channels.events[0].TenantID != tenantID {
		t.Fatal("channel event for the wrong tenant")
	}
}

func singleOwnerT2(t *testing.T) (approverHarness, shared.ID, *scopedom.Target) {
	t.Helper()
	h := newApproverHarness(t, 1, []scopedom.Approver{{UserID: ownerID, Name: "Olivia", Email: "o@example.test", Owner: true}})
	tenantID := shared.NewID()
	e, err := create(h.svc, tenantID, owner, "t2.ours.example", func(in *scope.CreateTargetInput) {
		in.MaxTier, in.ExpiresInDays, in.Reason = "t2", days(3), "pentest window"
	})
	if err != nil {
		t.Fatal(err)
	}
	if !e.IsPending() || e.ApprovalsRequired() != 1 {
		t.Fatalf("a t2 entry in a one-owner tenant: status %s approvals %d, want pending/1 (never 0 for t2)", e.Status(), e.ApprovalsRequired())
	}
	return h, tenantID, e
}

// The single owner of an organization approves their own intrusive entry
// with a fresh authenticator code and a reason; it is never automatic.
func TestScopeApprovers_SingleOwnerSelfApproves(t *testing.T) {
	h, tenantID, e := singleOwnerT2(t)
	st, _ := h.svc.ApprovalStatuses(context.Background(), tenantID, []*scopedom.Target{e}, owner)
	if !st[e.ID().String()].SelfApprovalAvailable {
		t.Fatal("self-approval not offered to the only owner")
	}
	if _, err := h.svc.SelfApproveTarget(context.Background(), e.ID().String(), tenantID.String(), owner, " ", "123456"); !errors.Is(err, scopedom.ErrSelfApprovalNeedsReason) {
		t.Fatalf("no reason: %v", err)
	}
	if h.totp.calls != 0 {
		t.Fatal("a code was spent on a request refused for its reason")
	}
	h.totp.err = scopedom.ErrSelfApprovalBadCode
	if _, err := h.svc.SelfApproveTarget(context.Background(), e.ID().String(), tenantID.String(), owner, "only owner", "000000"); !errors.Is(err, scopedom.ErrSelfApprovalBadCode) {
		t.Fatalf("bad code: %v", err)
	}
	if !e.IsPending() {
		t.Fatal("a wrong code approved the entry")
	}
	// Another tenant cannot reach the entry.
	h.totp.err = nil
	if _, err := h.svc.SelfApproveTarget(context.Background(), e.ID().String(), shared.NewID().String(), owner, "x", "123456"); !errors.Is(err, scopedom.ErrTargetNotFound) {
		t.Fatalf("cross-tenant self-approval: %v", err)
	}
	notesBefore := len(h.notes.to)
	got, err := h.svc.SelfApproveTarget(context.Background(), e.ID().String(), tenantID.String(), owner, "only owner, pentest window", "123456")
	if err != nil {
		t.Fatal(err)
	}
	if !got.InEffect(time.Now()) || len(got.Approvals()) != 1 || !got.Approvals()[0].Self || got.Approvals()[0].Reason == "" {
		t.Fatalf("self-approved entry: status %s approvals %+v", got.Status(), got.Approvals())
	}
	if len(h.notes.to) == notesBefore {
		t.Fatal("no administrator was told about the self-approval")
	}
	last := h.channels.events[len(h.channels.events)-1]
	if last.EventType != string(integration.EventTypeSecurityAlert) || last.Severity != notificationdom.SeverityHigh {
		t.Fatalf("channel event %+v, want a high security alert", last)
	}
}

// Self-approval is refused while another approver exists, for a non-owner,
// and for anyone but the requester.
func TestScopeApprovers_SelfApprovalRefusals(t *testing.T) {
	two := []scopedom.Approver{
		{UserID: ownerID, Name: "Olivia", Owner: true},
		{UserID: adminID, Name: "Adam"},
	}
	h := newApproverHarness(t, 2, two)
	tenantID := shared.NewID()
	e, _ := create(h.svc, tenantID, owner, "*.ours.example", nil)
	if _, err := h.svc.SelfApproveTarget(context.Background(), e.ID().String(), tenantID.String(), owner, "hurry", "123456"); !errors.Is(err, scopedom.ErrSelfApprovalNotAllowed) {
		t.Fatalf("self-approval with another approver present: %v", err)
	}
	if h.totp.calls != 0 {
		t.Fatal("a code was spent on a refused self-approval")
	}

	// The only approver who requested is an administrator, not an owner.
	h2 := newApproverHarness(t, 1, []scopedom.Approver{{UserID: adminID, Name: "Adam"}})
	e2, _ := create(h2.svc, tenantID, admin2, "t2.ours.example", func(in *scope.CreateTargetInput) {
		in.MaxTier, in.ExpiresInDays, in.Reason = "t2", days(3), "window"
	})
	if _, err := h2.svc.SelfApproveTarget(context.Background(), e2.ID().String(), tenantID.String(), admin2, "x", "123456"); !errors.Is(err, scopedom.ErrSelfApprovalNotAllowed) {
		t.Fatalf("an administrator self-approved: %v", err)
	}

	// Someone who did not request it uses the normal approval.
	h3, tid3, e3 := singleOwnerT2(t)
	other := scope.Actor{UserID: shared.NewID().String(), CanApprove: true}
	if _, err := h3.svc.SelfApproveTarget(context.Background(), e3.ID().String(), tid3.String(), other, "x", "123456"); !errors.Is(err, scopedom.ErrSelfApprovalNotAllowed) {
		t.Fatalf("a non-requester self-approved: %v", err)
	}
	// Without the approval permission.
	if _, err := h3.svc.SelfApproveTarget(context.Background(), e3.ID().String(), tid3.String(), scope.Actor{UserID: ownerID}, "x", "123456"); !errors.Is(err, scope.ErrWideningNeedsApprove) {
		t.Fatalf("self-approval without the permission: %v", err)
	}
	// Without a verifier wired the service fails closed.
	h3.svc.SetApprovers(fixedApprovers{[]scopedom.Approver{{UserID: ownerID, Owner: true}}}, nil, nil, nil, "")
	if _, err := h3.svc.SelfApproveTarget(context.Background(), e3.ID().String(), tid3.String(), owner, "x", "123456"); !errors.Is(err, scope.ErrStepUpNotWired) {
		t.Fatalf("self-approval without a verifier: %v", err)
	}
}

// A reminder reaches the approvers again, at most once an hour per entry.
func TestScopeApprovers_RemindIsRateLimited(t *testing.T) {
	all := []scopedom.Approver{
		{UserID: ownerID, Name: "Olivia", Email: "o@example.test", Owner: true},
		{UserID: adminID, Name: "Adam", Email: "a@example.test"},
	}
	h := newApproverHarness(t, 2, all)
	tenantID := shared.NewID()
	e, _ := create(h.svc, tenantID, owner, "*.ours.example", nil)
	mails := len(h.mail.to)
	_, n, err := h.svc.RemindApprovers(context.Background(), e.ID().String(), tenantID.String(), owner)
	if err != nil || n != 1 {
		t.Fatalf("reminder: n=%d err=%v", n, err)
	}
	if len(h.mail.to) != mails+1 || h.mail.to[len(h.mail.to)-1][0] != "a@example.test" {
		t.Fatalf("reminder emails %v", h.mail.to)
	}
	if _, _, err := h.svc.RemindApprovers(context.Background(), e.ID().String(), tenantID.String(), owner); !errors.Is(err, scopedom.ErrReminderTooSoon) {
		t.Fatalf("second reminder within the hour: %v", err)
	}
	if _, _, err := h.svc.RemindApprovers(context.Background(), e.ID().String(), shared.NewID().String(), owner); !errors.Is(err, scopedom.ErrTargetNotFound) {
		t.Fatalf("cross-tenant reminder: %v", err)
	}
	if _, _, err := h.svc.ApproveTarget(context.Background(), e.ID().String(), tenantID.String(), admin2); err != nil {
		t.Fatal(err)
	}
	if _, _, err := h.svc.RemindApprovers(context.Background(), e.ID().String(), tenantID.String(), owner); !errors.Is(err, scopedom.ErrEntryNotPending) {
		t.Fatalf("reminder for an active entry: %v", err)
	}
}

// The owner's own approval reaches the job signer's ledger marked
// self_approved, before it is saved; a refusal fails the approval.
func TestScopeApprovers_SelfApprovalGoesToTheLedger(t *testing.T) {
	h, tenantID, e := singleOwnerT2(t)
	led := &fakeLedger{refuse: true}
	h.svc.SetLedger(led)
	if _, err := h.svc.SelfApproveTarget(context.Background(), e.ID().String(), tenantID.String(), owner, "only owner", "123456"); err == nil {
		t.Fatal("a self-approval the signer refused was saved")
	}
	led.refuse = false
	h2, tid2, e2 := singleOwnerT2(t)
	h2.svc.SetLedger(led)
	if _, err := h2.svc.SelfApproveTarget(context.Background(), e2.ID().String(), tid2.String(), owner, "only owner", "123456"); err != nil {
		t.Fatal(err)
	}
	last := led.changes[len(led.changes)-1]
	if len(last.Approvals) != 1 || !last.Approvals[0].SelfApproved || last.Requester != ownerID {
		t.Fatalf("ledger change %+v, want one self-approved approval by the requester", last)
	}
}
