package adminapproval_test

// Four-eyes approvals against a migrated private database: the single-admin
// fallback, self-approval refused (service and table constraint), break-glass
// accounts never approve, an approval is bound to its requester, action and
// target, is single use (also under concurrency), can be handed back after a
// failed action, and expires.

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	_ "github.com/lib/pq"

	"github.com/openctemio/openctem/api/internal/app/adminapproval"
	"github.com/openctemio/openctem/api/internal/app/adminconsole"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/internal/testdb"
	"github.com/openctemio/openctem/api/pkg/domain/admin"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

type harness struct {
	t      *testing.T
	db     *sql.DB
	admins *postgres.AdminRepository
	svc    *adminapproval.Service
	clock  time.Time
	notes  []string
}

func (h *harness) NotifyRosterChange(_ context.Context, _ *admin.AdminUser, kind, _ string, _ adminconsole.ClientInfo) {
	h.notes = append(h.notes, kind)
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	raw := testdb.PrivateDatabase(t, "admin_approvals", "../../../migrations")
	db := &postgres.DB{DB: raw}
	h := &harness{t: t, db: raw, admins: postgres.NewAdminRepository(db), clock: time.Now().UTC().Truncate(time.Microsecond)}
	h.svc = adminapproval.NewService(postgres.NewAdminApprovalRepository(db), h.admins, postgres.NewAuditLogRepository(db), logger.NewNop())
	h.svc.SetClock(func() time.Time { return h.clock })
	h.svc.SetNotifier(h)
	return h
}

// addAdmin inserts an administrator and returns it as loaded by the repository.
func (h *harness) addAdmin(role admin.AdminRole, active, breakGlass bool) *admin.AdminUser {
	h.t.Helper()
	id := uuid.NewString()
	if _, err := h.db.Exec(`INSERT INTO admin_users (id, email, name, role, is_active, is_break_glass) VALUES ($1, $2, 'Approval IT', $3, $4, $5)`,
		id, "approval-"+id[:8]+"@example.com", string(role), active, breakGlass); err != nil {
		h.t.Fatalf("seed admin: %v", err)
	}
	return h.reload(id)
}

func (h *harness) reload(id string) *admin.AdminUser {
	h.t.Helper()
	sid, err := shared.IDFromString(id)
	if err != nil {
		h.t.Fatal(err)
	}
	a, err := h.admins.GetByID(context.Background(), sid)
	if err != nil {
		h.t.Fatalf("load admin: %v", err)
	}
	return a
}

func (h *harness) auditCount(action string) int {
	h.t.Helper()
	var n int
	if err := h.db.QueryRow(`SELECT count(*) FROM admin_audit_logs WHERE action = $1 AND severity = 'critical'`, action).Scan(&n); err != nil {
		h.t.Fatalf("count audit: %v", err)
	}
	return n
}

var client = adminconsole.ClientInfo{IP: "192.0.2.10", UserAgent: "test"}

func requireApproval(t *testing.T, err error) *admin.ApprovalRequiredError {
	t.Helper()
	var req *admin.ApprovalRequiredError
	if !errors.As(err, &req) {
		t.Fatalf("want ApprovalRequiredError, got %v", err)
	}
	return req
}

func TestFourEyesApprovals_DB(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	a := h.addAdmin(admin.AdminRoleSuperAdmin, true, false)
	h.addAdmin(admin.AdminRoleSuperAdmin, true, true) // break-glass: never a second admin
	h.addAdmin(admin.AdminRoleReadonly, true, false)
	b := h.addAdmin(admin.AdminRoleSuperAdmin, false, false)
	target := "email:new-super@example.com"

	// One named super admin: the action runs alone, audited critical and
	// announced; nothing can be requested.
	st, err := h.svc.Status(ctx, a)
	if err != nil || st.Active || st.Approvers != 1 {
		t.Fatalf("single admin status = %+v, %v; want inactive with 1 approver", st, err)
	}
	g, err := h.svc.Require(ctx, a, admin.ApprovalGrantSuperAdmin, target, client)
	if err != nil || g == nil || !g.SingleAdmin || g.ApprovalID != nil {
		t.Fatalf("single admin gate = %+v, %v; want the single-admin fallback", g, err)
	}
	if h.auditCount(adminapproval.ActionSingleAdmin) != 1 || len(h.notes) != 1 {
		t.Fatalf("fallback: critical audit rows %d, notices %v", h.auditCount(adminapproval.ActionSingleAdmin), h.notes)
	}
	if _, err := h.svc.Request(ctx, a, admin.ApprovalGrantSuperAdmin, target, "need a second", client); !errors.Is(err, admin.ErrFourEyesInactive) {
		t.Fatalf("request with no approver: %v, want ErrFourEyesInactive", err)
	}

	// A second named super admin turns approvals on.
	if _, err := h.db.Exec(`UPDATE admin_users SET is_active = true WHERE id = $1`, b.ID().String()); err != nil {
		t.Fatal(err)
	}
	b = h.reload(b.ID().String())
	req := requireApproval(t, func() error {
		_, err := h.svc.Require(ctx, a, admin.ApprovalGrantSuperAdmin, target, client)
		return err
	}())
	if req.PendingID != nil {
		t.Fatalf("no request yet, got pending %v", req.PendingID)
	}

	// Validation.
	for _, bad := range []struct{ action, target, reason string }{
		{"admin.unknown", target, "x"},
		{string(admin.ApprovalGrantSuperAdmin), "tenant:" + uuid.NewString(), "x"},
		{string(admin.ApprovalGrantSuperAdmin), target, "   "},
		{string(admin.ApprovalSignupOpen), "mode=everyone;accounts=open", "x"},
	} {
		if _, err := h.svc.Request(ctx, a, admin.ApprovalAction(bad.action), bad.target, bad.reason, client); !errors.Is(err, admin.ErrInvalidApproval) {
			t.Errorf("Request(%q, %q, %q) = %v, want ErrInvalidApproval", bad.action, bad.target, bad.reason, err)
		}
	}

	p, err := h.svc.Request(ctx, a, admin.ApprovalGrantSuperAdmin, target, "onboard the new on-call lead", client)
	if err != nil || p.Status(h.clock) != admin.ApprovalPending || !p.ExpiresAt.Equal(h.clock.Add(admin.ApprovalTTL)) {
		t.Fatalf("request = %+v, %v", p, err)
	}
	again, err := h.svc.Request(ctx, a, admin.ApprovalGrantSuperAdmin, target, "again", client)
	if err != nil || again.ID != p.ID {
		t.Fatalf("second request for the same target = %v, %v; want the open one %s", again, err, p.ID)
	}
	req = requireApproval(t, func() error {
		_, err := h.svc.Require(ctx, a, admin.ApprovalGrantSuperAdmin, target, client)
		return err
	}())
	if req.PendingID == nil || *req.PendingID != p.ID {
		t.Fatalf("gate names pending %v, want %s", req.PendingID, p.ID)
	}

	// Nobody decides on their own request; break-glass never approves; only
	// the requester cancels.
	if _, err := h.svc.Approve(ctx, a, p.ID, "", client); !errors.Is(err, admin.ErrSelfApproval) {
		t.Fatalf("self approval: %v", err)
	}
	if _, err := h.svc.Reject(ctx, a, p.ID, "", client); !errors.Is(err, admin.ErrSelfApproval) {
		t.Fatalf("self rejection: %v", err)
	}
	bg := h.addAdmin(admin.AdminRoleSuperAdmin, true, true)
	if _, err := h.svc.Approve(ctx, bg, p.ID, "", client); !errors.Is(err, admin.ErrApproverNotEligible) {
		t.Fatalf("break-glass approval: %v", err)
	}
	ops := h.addAdmin(admin.AdminRoleOpsAdmin, true, false)
	if _, err := h.svc.Approve(ctx, ops, p.ID, "", client); !errors.Is(err, admin.ErrApproverNotEligible) {
		t.Fatalf("ops admin approval: %v", err)
	}
	if _, err := h.svc.Cancel(ctx, b, p.ID, client); !errors.Is(err, admin.ErrNotRequester) {
		t.Fatalf("cancel by another admin: %v", err)
	}
	// The table refuses a self-approval written around the service.
	if _, err := h.db.Exec(`UPDATE admin_approvals SET decision = 'approved', decided_by = requested_by, decided_at = NOW() WHERE id = $1`, p.ID.String()); err == nil ||
		!strings.Contains(err.Error(), "admin_approvals_not_self") {
		t.Fatalf("self approval in SQL: %v, want the admin_approvals_not_self constraint", err)
	}

	approved, err := h.svc.Approve(ctx, b, p.ID, "checked with A by phone", client)
	if err != nil || approved.Status(h.clock) != admin.ApprovalApproved || approved.DecidedBy == nil || *approved.DecidedBy != b.ID() {
		t.Fatalf("approve = %+v, %v", approved, err)
	}
	if _, err := h.svc.Approve(ctx, b, p.ID, "", client); !errors.Is(err, admin.ErrApprovalNotPending) {
		t.Fatalf("second approval: %v", err)
	}

	// Bound to requester and target.
	requireApproval(t, func() error {
		_, err := h.svc.Require(ctx, b, admin.ApprovalGrantSuperAdmin, target, client)
		return err
	}())
	requireApproval(t, func() error {
		_, err := h.svc.Require(ctx, a, admin.ApprovalGrantSuperAdmin, "email:someone-else@example.com", client)
		return err
	}())
	requireApproval(t, func() error { _, err := h.svc.Require(ctx, a, admin.ApprovalConsoleMFAOff, "off", client); return err }())

	// Single use, handed back once after a failed action, then spent.
	g, err = h.svc.Require(ctx, a, admin.ApprovalGrantSuperAdmin, target, client)
	if err != nil || g.ApprovalID == nil || *g.ApprovalID != p.ID {
		t.Fatalf("use = %+v, %v", g, err)
	}
	requireApproval(t, func() error {
		_, err := h.svc.Require(ctx, a, admin.ApprovalGrantSuperAdmin, target, client)
		return err
	}())
	h.svc.Release(ctx, a, g, client)
	if g, err = h.svc.Require(ctx, a, admin.ApprovalGrantSuperAdmin, target, client); err != nil || g.ApprovalID == nil {
		t.Fatalf("use after release = %+v, %v", g, err)
	}
	requireApproval(t, func() error {
		_, err := h.svc.Require(ctx, a, admin.ApprovalGrantSuperAdmin, target, client)
		return err
	}())
	for action, want := range map[string]int{
		adminapproval.ActionRequested: 1, adminapproval.ActionApproved: 1, adminapproval.ActionUsed: 2,
	} {
		if got := h.auditCount(action); got != want {
			t.Errorf("critical audit rows %s = %d, want %d", action, got, want)
		}
	}

	// Concurrent uses of one approval: exactly one wins.
	tenantTarget := "tenant:" + uuid.NewString()
	p2, err := h.svc.Request(ctx, a, admin.ApprovalAuditChainRebaseline, tenantTarget, "explained breaks after restore", client)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.svc.Approve(ctx, b, p2.ID, "", client); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	var mu sync.Mutex
	wins := 0
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if g, err := h.svc.Require(ctx, a, admin.ApprovalAuditChainRebaseline, tenantTarget, client); err == nil && g.ApprovalID != nil {
				mu.Lock()
				wins++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if wins != 1 {
		t.Fatalf("concurrent uses won %d times, want 1", wins)
	}

	// Rejected requests are not usable.
	p3, err := h.svc.Request(ctx, a, admin.ApprovalConsoleMFAOff, "off", "key vendor outage", client)
	if err != nil {
		t.Fatal(err)
	}
	if r, err := h.svc.Reject(ctx, b, p3.ID, "use recovery codes instead", client); err != nil || r.Status(h.clock) != admin.ApprovalRejected {
		t.Fatalf("reject = %+v, %v", r, err)
	}
	requireApproval(t, func() error { _, err := h.svc.Require(ctx, a, admin.ApprovalConsoleMFAOff, "off", client); return err }())

	// Labels are read on the server.
	p4, err := h.svc.Request(ctx, a, admin.ApprovalRevokeSuperAdmin, "admin:"+b.ID().String(), "leaving the team", client)
	if err != nil || !strings.Contains(p4.TargetLabel, b.Email()) {
		t.Fatalf("label = %q, %v; want %s", p4.TargetLabel, err, b.Email())
	}
	if c, err := h.svc.Cancel(ctx, a, p4.ID, client); err != nil || c.Status(h.clock) != admin.ApprovalCanceled {
		t.Fatalf("cancel = %+v, %v", c, err)
	}

	// Expiry: an approval not used within its 24 hours is dead, and a
	// request not decided in time cannot be approved.
	p5, err := h.svc.Request(ctx, a, admin.ApprovalPlatformIdPRemove, "remove", "moving to a new provider", client)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.svc.Approve(ctx, b, p5.ID, "", client); err != nil {
		t.Fatal(err)
	}
	p6, err := h.svc.Request(ctx, a, admin.ApprovalSignupOpen, "mode=self_service;accounts=open", "launch", client)
	if err != nil {
		t.Fatal(err)
	}
	h.clock = h.clock.Add(admin.ApprovalTTL + time.Minute)
	requireApproval(t, func() error {
		_, err := h.svc.Require(ctx, a, admin.ApprovalPlatformIdPRemove, "remove", client)
		return err
	}())
	if _, err := h.svc.Approve(ctx, b, p6.ID, "", client); !errors.Is(err, admin.ErrApprovalNotPending) {
		t.Fatalf("approve expired: %v", err)
	}

	list, err := h.svc.List(ctx)
	if err != nil || len(list) < 6 {
		t.Fatalf("list = %d items, %v", len(list), err)
	}
	for _, it := range list {
		if it.RequestedByEmail != a.Email() {
			t.Errorf("list item %s requested by %q, want %s", it.ID, it.RequestedByEmail, a.Email())
		}
	}
}

// Removing the other approver is protected too: once the second super admin
// exists, demoting them is gated (the handler maps the change to
// ApprovalRevokeSuperAdmin), so a session cannot fall back to acting alone.
func TestFourEyesRevokeNeedsTheOtherAdmin_DB(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	a := h.addAdmin(admin.AdminRoleSuperAdmin, true, false)
	b := h.addAdmin(admin.AdminRoleSuperAdmin, true, false)
	target := "admin:" + b.ID().String()
	requireApproval(t, func() error {
		_, err := h.svc.Require(ctx, a, admin.ApprovalRevokeSuperAdmin, target, client)
		return err
	}())
	p, err := h.svc.Request(ctx, a, admin.ApprovalRevokeSuperAdmin, target, "role change", client)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.svc.Approve(ctx, b, p.ID, "agreed", client); err != nil {
		t.Fatalf("the admin being removed approves: %v", err)
	}
	if g, err := h.svc.Require(ctx, a, admin.ApprovalRevokeSuperAdmin, target, client); err != nil || g.ApprovalID == nil {
		t.Fatalf("use = %+v, %v", g, err)
	}
}
