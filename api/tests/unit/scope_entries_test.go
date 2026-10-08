package unit

// Scope entries: one-off expiry, requests, widening approvals, step-up and
// administrator notification (RFC-054 §6.1, §7; S3, S5, S6), including the
// abuse cases of research/48 §4 (compromised admin, typo widening).

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/internal/app/scope"
	notificationdom "github.com/openctemio/openctem/api/pkg/domain/notification"
	scopedom "github.com/openctemio/openctem/api/pkg/domain/scope"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/tenant"
	"github.com/openctemio/openctem/api/pkg/logger"
)

type passGate struct{}

func (passGate) RequireRecentAuth(context.Context, string) error { return nil }

type staleGate struct{}

var errNeedsStepUp = errors.New("step-up re-authentication required")

func (staleGate) RequireRecentAuth(context.Context, string) error { return errNeedsStepUp }

type fixedSettings struct{ s tenant.ScopeSettings }

func (f fixedSettings) GetScopeSettings(context.Context, string) (*tenant.ScopeSettings, error) {
	s := f.s
	return &s, nil
}

type adminDir struct{ n int }

func (a adminDir) ActiveAdminIDs(context.Context, shared.ID) ([]shared.ID, error) {
	out := make([]shared.ID, a.n)
	for i := range out {
		out[i] = shared.NewID()
	}
	return out, nil
}

type noticeLog struct{ titles []string }

func (n *noticeLog) Notify(_ context.Context, p notificationdom.NotificationParams) error {
	n.titles = append(n.titles, p.Title)
	return nil
}

var (
	approverA = scope.Actor{UserID: "admin-a", CanApprove: true}
	approverB = scope.Actor{UserID: "admin-b", CanApprove: true}
	member    = scope.Actor{UserID: "member-1"}
)

func entryService(t *testing.T, admins int, st tenant.ScopeSettings) (*scope.Service, *mockTargetRepo, *noticeLog) {
	t.Helper()
	svc, tr, _, _ := newTestScopeService()
	notes := &noticeLog{}
	svc.SetEntryPolicy(fixedSettings{st}, adminDir{admins}, notes)
	return svc, tr, notes
}

func days(n int) *int { return &n }

func create(svc *scope.Service, tenantID shared.ID, actor scope.Actor, pattern string, mut func(*scope.CreateTargetInput)) (*scopedom.Target, error) {
	in := scope.CreateTargetInput{TenantID: tenantID.String(), TargetType: "domain", Pattern: pattern, CreatedBy: actor.UserID, Actor: actor}
	if mut != nil {
		mut(&in)
	}
	return svc.CreateTarget(context.Background(), in)
}

func TestScopeEntry_ApproverInOneAdminTenantIsEffectiveAtOnce(t *testing.T) {
	svc, _, notes := entryService(t, 1, tenant.ScopeSettings{})
	tenantID := shared.NewID()
	got, err := create(svc, tenantID, approverA, "*.ours.example", nil)
	if err != nil {
		t.Fatal(err)
	}
	if !got.InEffect(time.Now()) || got.ApprovalsRequired() != 0 || got.MaxTier() != scopedom.TierActive {
		t.Fatalf("status %s approvals %d tier %s, want active/0/t1", got.Status(), got.ApprovalsRequired(), got.MaxTier())
	}
	if len(notes.titles) == 0 {
		t.Fatal("a widening that took effect notified no administrator")
	}
}

// A compromised or careless admin in a tenant with two admins cannot widen
// alone: the entry waits for the other admin, and the requester cannot
// approve their own entry.
func TestScopeEntry_TwoAdminTenantNeedsTheOtherAdmin(t *testing.T) {
	svc, tr, notes := entryService(t, 2, tenant.ScopeSettings{})
	tenantID := shared.NewID()
	got, err := create(svc, tenantID, approverA, "*.victim.example", nil)
	if err != nil {
		t.Fatal(err)
	}
	if got.InEffect(time.Now()) || got.Status() != scopedom.StatusPending || got.ApprovalsRequired() != 1 {
		t.Fatalf("status %s approvals %d, want pending/1", got.Status(), got.ApprovalsRequired())
	}
	if active, _ := tr.ListActive(context.Background(), tenantID); len(active) != 0 {
		t.Fatal("a pending entry authorizes probes")
	}
	if len(notes.titles) == 0 {
		t.Fatal("a pending entry notified nobody")
	}
	if _, _, err := svc.ApproveTarget(context.Background(), got.ID().String(), tenantID.String(), approverA); !errors.Is(err, scopedom.ErrEntrySelfApproval) {
		t.Fatalf("self approval: %v", err)
	}
	if _, _, err := svc.ApproveTarget(context.Background(), got.ID().String(), tenantID.String(), member); !errors.Is(err, scope.ErrWideningNeedsApprove) {
		t.Fatalf("a member approved: %v", err)
	}
	// Another tenant cannot approve it (not found).
	if _, _, err := svc.ApproveTarget(context.Background(), got.ID().String(), shared.NewID().String(), approverB); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cross-tenant approval: %v", err)
	}
	approved, effective, err := svc.ApproveTarget(context.Background(), got.ID().String(), tenantID.String(), approverB)
	if err != nil || !effective || !approved.InEffect(time.Now()) {
		t.Fatalf("second admin approval: effective=%v err=%v status=%s", effective, err, approved.Status())
	}
	if _, _, err := svc.ApproveTarget(context.Background(), got.ID().String(), tenantID.String(), approverB); !errors.Is(err, scopedom.ErrEntryNotPending) {
		t.Fatalf("approving an active entry: %v", err)
	}
}

func TestScopeEntry_TwoApprovals(t *testing.T) {
	two := 2
	svc, _, _ := entryService(t, 3, tenant.ScopeSettings{WideningApprovals: &two})
	tenantID := shared.NewID()
	got, _ := create(svc, tenantID, approverA, "*.x.example", nil)
	if _, eff, err := svc.ApproveTarget(context.Background(), got.ID().String(), tenantID.String(), approverB); err != nil || eff {
		t.Fatalf("first of two approvals: eff=%v err=%v", eff, err)
	}
	if _, _, err := svc.ApproveTarget(context.Background(), got.ID().String(), tenantID.String(), approverB); !errors.Is(err, scopedom.ErrEntryApprovedOnce) {
		t.Fatalf("approving twice: %v", err)
	}
	if _, eff, err := svc.ApproveTarget(context.Background(), got.ID().String(), tenantID.String(), scope.Actor{UserID: "admin-c", CanApprove: true}); err != nil || !eff {
		t.Fatalf("second approval: eff=%v err=%v", eff, err)
	}
}

// A setting of 0 cannot remove the second admin from a two-admin tenant, and
// intrusive entries always need an approver.
func TestScopeEntry_ApprovalFloors(t *testing.T) {
	zero, two := 0, 2
	cases := []struct {
		admins    int
		setting   *int
		intrusive bool
		want      int
	}{
		{1, nil, false, 0}, {2, nil, false, 1}, {5, nil, false, 1},
		{2, &zero, false, 1}, {1, &zero, false, 0}, {1, nil, true, 1}, {1, &zero, true, 1},
		{2, &two, false, 1}, {3, &two, false, 2}, {1, &two, false, 0},
	}
	for _, c := range cases {
		got := tenant.ScopeSettings{WideningApprovals: c.setting}.EffectiveApprovals(c.admins, c.intrusive)
		if got != c.want {
			t.Errorf("admins=%d setting=%v intrusive=%v: %d, want %d", c.admins, c.setting, c.intrusive, got, c.want)
		}
	}
}

func TestScopeEntry_IntrusiveNeedsExpiryReasonAndApprover(t *testing.T) {
	svc, _, _ := entryService(t, 1, tenant.ScopeSettings{})
	tenantID := shared.NewID()
	if _, err := create(svc, tenantID, approverA, "pentest.example", func(in *scope.CreateTargetInput) { in.MaxTier = "t2" }); !errors.Is(err, scopedom.ErrIntrusiveNeeds) {
		t.Fatalf("t2 without expiry: %v", err)
	}
	got, err := create(svc, tenantID, approverA, "pentest.example", func(in *scope.CreateTargetInput) {
		in.MaxTier, in.ExpiresInDays, in.Reason = "t2", days(5), "RoE #42"
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.Status() != scopedom.StatusPending || got.ApprovalsRequired() != 1 {
		t.Fatalf("t2 in a one-admin tenant: %s/%d, want pending/1", got.Status(), got.ApprovalsRequired())
	}
}

func TestScopeEntry_OneOffBounds(t *testing.T) {
	svc, _, _ := entryService(t, 1, tenant.ScopeSettings{OneOffMaxDays: 10})
	tenantID := shared.NewID()
	if _, err := create(svc, tenantID, approverA, "a.example", func(in *scope.CreateTargetInput) { in.ExpiresInDays, in.Reason = days(11), "x" }); !errors.Is(err, scope.ErrOneOffTooLong) {
		t.Fatalf("11 days with a 10-day limit: %v", err)
	}
	far := time.Now().Add(40 * 24 * time.Hour)
	if _, err := create(svc, tenantID, approverA, "a.example", func(in *scope.CreateTargetInput) { in.ExpiresAt, in.Reason = &far, "x" }); !errors.Is(err, scope.ErrOneOffTooLong) {
		t.Fatalf("40 days: %v", err)
	}
	if _, err := create(svc, tenantID, approverA, "a.example", func(in *scope.CreateTargetInput) { in.ExpiresInDays = days(3) }); !errors.Is(err, scopedom.ErrReasonRequiredFor) {
		t.Fatalf("one-off without reason: %v", err)
	}
	got, err := create(svc, tenantID, approverA, "a.example", func(in *scope.CreateTargetInput) { in.ExpiresInDays, in.Reason = days(3), "marketing site" })
	if err != nil || got.ExpiresAt() == nil || !got.InEffect(time.Now()) {
		t.Fatalf("a 3-day one-off: %v %+v", err, got)
	}

	off, _, _ := entryService(t, 1, tenant.ScopeSettings{OneOffTargets: tenant.OneOffDisabled})
	if _, err := create(off, tenantID, approverA, "b.example", func(in *scope.CreateTargetInput) { in.ExpiresInDays, in.Reason = days(3), "x" }); !errors.Is(err, scope.ErrOneOffDisabled) {
		t.Fatalf("one-offs disabled: %v", err)
	}
}

// A member only requests: a one-off for one name or address, with a reason,
// pending until an approver approves; never a wildcard, a range or t2.
func TestScopeEntry_MemberRequests(t *testing.T) {
	svc, _, _ := entryService(t, 1, tenant.ScopeSettings{})
	tenantID := shared.NewID()
	one := func(in *scope.CreateTargetInput) { in.ExpiresInDays, in.Reason = days(7), "bought last week" }
	if _, err := create(svc, tenantID, member, "promo.example", nil); !errors.Is(err, scope.ErrRequestMustBeOneOff) {
		t.Fatalf("permanent request: %v", err)
	}
	if _, err := create(svc, tenantID, member, "*.promo.example", one); !errors.Is(err, scope.ErrRequestMustBeSingle) {
		t.Fatalf("wildcard request: %v", err)
	}
	if _, err := svc.CreateTarget(context.Background(), scope.CreateTargetInput{TenantID: tenantID.String(), TargetType: "cidr", Pattern: "203.0.113.0/24",
		ExpiresInDays: days(7), Reason: "x", Actor: member}); !errors.Is(err, scope.ErrRequestMustBeSingle) {
		t.Fatalf("range request: %v", err)
	}
	if _, err := create(svc, tenantID, member, "promo.example", func(in *scope.CreateTargetInput) { in.ExpiresInDays = days(7) }); !errors.Is(err, scopedom.ErrReasonRequiredFor) {
		t.Fatalf("request without reason: %v", err)
	}
	if _, err := create(svc, tenantID, member, "promo.example", func(in *scope.CreateTargetInput) {
		one(in)
		in.MaxTier = "t2"
	}); !errors.Is(err, scope.ErrRequestTier) && !errors.Is(err, scopedom.ErrIntrusiveNeeds) {
		t.Fatalf("t2 request: %v", err)
	}
	req, err := create(svc, tenantID, member, "promo.example", one)
	if err != nil {
		t.Fatal(err)
	}
	if req.Status() != scopedom.StatusPending || req.ApprovalsRequired() != 1 {
		t.Fatalf("request in a one-admin tenant: %s/%d, want pending/1", req.Status(), req.ApprovalsRequired())
	}
	if _, eff, err := svc.ApproveTarget(context.Background(), req.ID().String(), tenantID.String(), approverA); err != nil || !eff {
		t.Fatalf("admin approval of a request: %v %v", eff, err)
	}

	strict, _, _ := entryService(t, 1, tenant.ScopeSettings{OneOffTargets: tenant.OneOffAdmins})
	if _, err := create(strict, tenantID, member, "promo2.example", one); !errors.Is(err, scope.ErrRequestNotAllowed) {
		t.Fatalf("requests off: %v", err)
	}
}

// A stolen session that has not re-authenticated cannot widen.
func TestScopeEntry_WideningNeedsStepUp(t *testing.T) {
	svc, tr, _ := entryService(t, 1, tenant.ScopeSettings{})
	svc.SetStepUpGate(staleGate{})
	tenantID := shared.NewID()
	if _, err := create(svc, tenantID, approverA, "*.victim.example", nil); !errors.Is(err, errNeedsStepUp) {
		t.Fatalf("create without step-up: %v", err)
	}
	if len(tr.targets) != 0 {
		t.Fatal("a refused widening saved an entry")
	}
	// A member's request authorizes nothing and needs no step-up.
	if _, err := create(svc, tenantID, member, "promo.example", func(in *scope.CreateTargetInput) { in.ExpiresInDays, in.Reason = days(2), "x" }); err != nil {
		t.Fatalf("request: %v", err)
	}
	// With no gate wired a person's widening is refused (fail closed).
	unwired := scope.NewService(newMockTargetRepo(), newMockExclusionRepo(), newMockAssetRepo(), logger.NewNop())
	if _, err := create(unwired, tenantID, approverA, "*.y.example", nil); !errors.Is(err, scope.ErrStepUpNotWired) {
		t.Fatalf("unwired gate: %v", err)
	}
}

func TestScopeEntry_UpdateWidensOrNarrows(t *testing.T) {
	svc, _, _ := entryService(t, 2, tenant.ScopeSettings{})
	tenantID := shared.NewID()
	got, err := svc.CreateTarget(context.Background(), scope.CreateTargetInput{TenantID: tenantID.String(), TargetType: "domain",
		Pattern: "a.example", ExpiresInDays: days(5), Reason: "x"}) // system: effective
	if err != nil || !got.InEffect(time.Now()) {
		t.Fatalf("system create: %v", err)
	}
	id := got.ID().String()
	// Narrowing (an earlier expiry) by a member stays in effect.
	if u, err := svc.UpdateTarget(context.Background(), id, tenantID.String(), scope.UpdateTargetInput{ExpiresInDays: days(1), Actor: member}); err != nil || !u.InEffect(time.Now()) {
		t.Fatalf("narrowing: %v", err)
	}
	// Widening by a member is refused.
	if _, err := svc.UpdateTarget(context.Background(), id, tenantID.String(), scope.UpdateTargetInput{ExpiresInDays: days(7), Actor: member}); !errors.Is(err, scope.ErrWideningNeedsApprove) {
		t.Fatalf("member widening: %v", err)
	}
	if _, err := svc.UpdateTarget(context.Background(), id, tenantID.String(), scope.UpdateTargetInput{ClearExpiry: true, Actor: member}); !errors.Is(err, scope.ErrWideningNeedsApprove) {
		t.Fatalf("member making it permanent: %v", err)
	}
	// Widening by an approver in a two-admin tenant goes back to review.
	u, err := svc.UpdateTarget(context.Background(), id, tenantID.String(), scope.UpdateTargetInput{ExpiresInDays: days(7), Actor: approverA})
	if err != nil || u.Status() != scopedom.StatusPending || u.InEffect(time.Now()) {
		t.Fatalf("approver widening: %v %s", err, u.Status())
	}
	if _, _, err := svc.ApproveTarget(context.Background(), id, tenantID.String(), approverA); !errors.Is(err, scopedom.ErrEntrySelfApproval) {
		t.Fatalf("the widener approved their own widening: %v", err)
	}
	tier := "t1"
	if _, err := svc.UpdateTarget(context.Background(), id, tenantID.String(), scope.UpdateTargetInput{MaxTier: &tier, Actor: member}); err != nil {
		t.Fatalf("same tier is not a widening: %v", err)
	}
}

func TestScopeEntry_ActivateIsWidening(t *testing.T) {
	svc, _, _ := entryService(t, 2, tenant.ScopeSettings{})
	tenantID := shared.NewID()
	got, _ := svc.CreateTarget(context.Background(), scope.CreateTargetInput{TenantID: tenantID.String(), TargetType: "domain", Pattern: "a.example"})
	if _, err := svc.DeactivateTarget(context.Background(), got.ID().String(), tenantID.String()); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.ActivateTarget(context.Background(), got.ID().String(), tenantID.String(), member); !errors.Is(err, scope.ErrWideningNeedsApprove) {
		t.Fatalf("member activation: %v", err)
	}
	a, err := svc.ActivateTarget(context.Background(), got.ID().String(), tenantID.String(), approverA)
	if err != nil || a.Status() != scopedom.StatusPending {
		t.Fatalf("approver activation in a two-admin tenant: %v %s", err, a.Status())
	}
}

// An expired entry stops authorizing at once, before any sweep.
func TestScopeEntry_ExpiredStopsAuthorizing(t *testing.T) {
	svc, tr, _ := entryService(t, 1, tenant.ScopeSettings{})
	tenantID := shared.NewID()
	got, err := create(svc, tenantID, approverA, "short.example", func(in *scope.CreateTargetInput) { in.ExpiresInDays, in.Reason = days(1), "x" })
	if err != nil {
		t.Fatal(err)
	}
	past := time.Now().Add(-time.Minute)
	got.SetExpiry(&past, time.Now())
	tr.targets[got.ID().String()] = got
	active, err := svc.ListActiveTargets(context.Background(), tenantID.String())
	if err != nil || len(active) != 0 {
		t.Fatalf("an expired entry is still active: %v %d", err, len(active))
	}
	if _, err := svc.ActivateTarget(context.Background(), got.ID().String(), tenantID.String(), approverA); !errors.Is(err, scopedom.ErrEntryExpired) {
		t.Fatalf("activating an expired entry: %v", err)
	}
}

// The platform's guardrails apply to every new entry, an approver's too: no
// public suffix, no government name, no oversized public range.
func TestScopeEntry_PlatformGuardrails(t *testing.T) {
	svc, tr, _ := entryService(t, 1, tenant.ScopeSettings{})
	tenantID := shared.NewID()
	for _, c := range []struct {
		typ, pattern string
		want         error
	}{
		{"domain", "*.com.vn", scopedom.ErrPublicSuffix},
		{"domain", "*.gov.vn", scopedom.ErrDenyList},
		{"cidr", "0.0.0.0/0", scopedom.ErrDenyList},
		{"cidr", "8.0.0.0/8", scopedom.ErrCIDRTooLarge},
	} {
		_, err := svc.CreateTarget(context.Background(), scope.CreateTargetInput{TenantID: tenantID.String(), TargetType: c.typ, Pattern: c.pattern, Actor: approverA})
		if !errors.Is(err, c.want) {
			t.Errorf("%s %s: %v, want %v", c.typ, c.pattern, err, c.want)
		}
	}
	if len(tr.targets) != 0 {
		t.Fatal("a refused pattern was saved")
	}
	if _, err := svc.CreateTarget(context.Background(), scope.CreateTargetInput{TenantID: tenantID.String(), TargetType: "domain", Pattern: "*.example.co.uk", Actor: approverA}); err != nil {
		t.Fatalf("a registrable domain: %v", err)
	}
}
