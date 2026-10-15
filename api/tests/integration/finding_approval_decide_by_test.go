package integration

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/internal/app/finding"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/internal/testdb"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// approvalFixture is two tenants, a requester and an approver, and the
// finding service wired to the real approval repository.
type approvalFixture struct {
	db                  *sql.DB
	tenant, other       shared.ID
	requester, approver shared.ID
	svc                 *finding.VulnerabilityService
	repo                *postgres.FindingApprovalRepository
}

func newApprovalFixture(t *testing.T, name string) *approvalFixture {
	t.Helper()
	db := setupTestDB(t)
	pdb := &postgres.DB{DB: db}
	f := &approvalFixture{db: db, tenant: createTestTenant(t, db, name), other: createTestTenant(t, db, name+"-other"),
		requester: shared.NewID(), approver: shared.NewID()}
	t.Cleanup(func() {
		for _, id := range []shared.ID{f.tenant, f.other} {
			_, _ = db.Exec(`DELETE FROM finding_status_approvals WHERE tenant_id = $1`, id.String())
			_, _ = db.Exec(`DELETE FROM tenants WHERE id = $1`, id.String())
		}
		for _, id := range []shared.ID{f.requester, f.approver} {
			_, _ = db.Exec(`DELETE FROM users WHERE id = $1`, id.String())
		}
		_ = db.Close()
	})
	for _, u := range []shared.ID{f.requester, f.approver} {
		f.exec(t, `INSERT INTO users (id, email, name) VALUES ($1, $2, 'person')`, u.String(), u.String()+"@example.com")
	}
	f.repo = postgres.NewFindingApprovalRepository(pdb)
	f.svc = finding.NewVulnerabilityService(nil, postgres.NewFindingRepository(pdb), logger.NewNop())
	f.svc.SetApprovalRepository(f.repo)
	return f
}

func (f *approvalFixture) exec(t *testing.T, q string, args ...any) {
	t.Helper()
	if _, err := f.db.Exec(q, args...); err != nil {
		t.Fatalf("%v\n%s", err, q)
	}
}

func (f *approvalFixture) finding(t *testing.T, tenant shared.ID, severity string) shared.ID {
	t.Helper()
	id := shared.NewID()
	f.exec(t, `INSERT INTO findings (id, tenant_id, source, tool_name, message, severity, fingerprint, status)
		VALUES ($1::uuid, $2, 'sast', 'approval-test', 'm', $3, $1::text, 'confirmed')`, id.String(), tenant.String(), severity)
	return id
}

func (f *approvalFixture) request(t *testing.T, tenant, findingID shared.ID, status string) (*vulnerability.Approval, error) {
	t.Helper()
	return f.svc.RequestApproval(context.Background(), finding.RequestApprovalInput{
		TenantID: tenant.String(), FindingID: findingID.String(), RequestedStatus: status,
		Justification: "the input is a constant", RequestedBy: f.requester.String(),
	})
}

func (f *approvalFixture) approvalStatus(t *testing.T, id shared.ID) string {
	t.Helper()
	var s string
	if err := f.db.QueryRow(`SELECT status FROM finding_status_approvals WHERE id = $1`, id.String()).Scan(&s); err != nil {
		t.Fatal(err)
	}
	return s
}

func (f *approvalFixture) findingStatus(t *testing.T, id shared.ID) string {
	t.Helper()
	var s string
	if err := f.db.QueryRow(`SELECT status FROM findings WHERE id = $1`, id.String()).Scan(&s); err != nil {
		t.Fatal(err)
	}
	return s
}

func (f *approvalFixture) count(t *testing.T, q string, args ...any) int {
	t.Helper()
	var n int
	if err := f.db.QueryRow(q, args...).Scan(&n); err != nil {
		t.Fatalf("%v\n%s", err, q)
	}
	return n
}

// A request has a decide-by time separate from the acceptance end; a
// pending request past it cannot be decided and the expiry job expires it
// (timeline + audit), leaving other tenants' and in-time requests alone.
func TestFindingApproval_DecideByIsSeparateAndOverdueRequestsExpire(t *testing.T) {
	f := newApprovalFixture(t, "decide-by")
	ctx := context.Background()

	accept := f.finding(t, f.tenant, "medium")
	a, err := f.request(t, f.tenant, accept, "accepted")
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	if a.DecideBy == nil || a.ExpiresAt == nil {
		t.Fatalf("decide_by %v, expires_at %v", a.DecideBy, a.ExpiresAt)
	}
	if d := time.Until(*a.DecideBy); d < 13*24*time.Hour || d > 15*24*time.Hour {
		t.Fatalf("decide_by in %v, want about 14 days", d)
	}
	if !a.ExpiresAt.After(a.DecideBy.Add(24 * time.Hour)) {
		t.Fatalf("acceptance end %v is not separate from decide_by %v", a.ExpiresAt, a.DecideBy)
	}
	var stored time.Time
	if err := f.db.QueryRow(`SELECT decide_by FROM finding_status_approvals WHERE id = $1`, a.ID.String()).Scan(&stored); err != nil {
		t.Fatalf("decide_by not stored: %v", err)
	}

	inTime := f.finding(t, f.tenant, "low")
	b, err := f.request(t, f.tenant, inTime, "false_positive")
	if err != nil {
		t.Fatal(err)
	}
	otherFinding := f.finding(t, f.other, "low")
	c, err := f.request(t, f.other, otherFinding, "false_positive")
	if err != nil {
		t.Fatal(err)
	}
	// The first and the other tenant's request are overdue.
	f.exec(t, `UPDATE finding_status_approvals SET decide_by = now() - interval '1 minute' WHERE id = ANY($1::uuid[])`,
		"{"+a.ID.String()+","+c.ID.String()+"}")

	_, err = f.svc.ApproveStatus(ctx, finding.ApproveStatusInput{TenantID: f.tenant.String(), ApprovalID: a.ID.String(), ApprovedBy: f.approver.String()})
	if !errors.Is(err, vulnerability.ErrDecisionOverdue) {
		t.Fatalf("approve after decide_by: %v", err)
	}
	if s := f.findingStatus(t, accept); s != "confirmed" {
		t.Fatalf("an overdue request changed the finding: %s", s)
	}

	n, err := f.repo.ExpireOverdueRequests(ctx)
	if err != nil || n < 2 {
		t.Fatalf("expire overdue: %d %v", n, err)
	}
	if s := f.approvalStatus(t, a.ID); s != "expired" {
		t.Fatalf("overdue request: %s", s)
	}
	if s := f.approvalStatus(t, c.ID); s != "expired" {
		t.Fatalf("other tenant overdue request: %s", s)
	}
	if s := f.approvalStatus(t, b.ID); s != "pending" {
		t.Fatalf("in-time request: %s", s)
	}
	if n := f.count(t, `SELECT COUNT(*) FROM finding_activities WHERE tenant_id = $1 AND finding_id = $2
		AND changes->>'reason' = 'decision_overdue'`, f.tenant.String(), accept.String()); n != 1 {
		t.Fatalf("timeline entries for the expiry: %d", n)
	}
	if n := f.count(t, `SELECT COUNT(*) FROM audit_logs WHERE tenant_id = $1 AND action = 'finding_approval.expired'
		AND resource_id = $2`, f.tenant.String(), a.ID.String()); n != 1 {
		t.Fatalf("audit rows for the expiry: %d", n)
	}
	// The other tenant's audit row stays in the other tenant.
	if n := f.count(t, `SELECT COUNT(*) FROM audit_logs WHERE tenant_id = $1 AND resource_id = $2`,
		f.tenant.String(), c.ID.String()); n != 0 {
		t.Fatalf("other tenant's expiry audited in this tenant: %d", n)
	}
	// A new request is possible once the old one expired.
	if _, err := f.request(t, f.tenant, accept, "accepted"); err != nil {
		t.Fatalf("request after expiry: %v", err)
	}
}

// One pending request per finding, whoever made it: a second person request
// is refused with a conflict, as is an actor proposal next to a person's
// request; another tenant's finding is unaffected.
func TestFindingApproval_OnePendingRequestPerFinding(t *testing.T) {
	f := newApprovalFixture(t, "one-pending")
	ctx := context.Background()
	fid := f.finding(t, f.tenant, "medium")
	first, err := f.request(t, f.tenant, fid, "false_positive")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.request(t, f.tenant, fid, "accepted"); !errors.Is(err, vulnerability.ErrPendingRequestExists) || !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("second pending request: %v", err)
	}
	// An actor request straight through the repository hits the same index.
	actor, err := vulnerability.NewActorApproval(f.tenant, fid, vulnerability.ApprovalActorAITriage, "false_positive", "likely a fixture")
	if err != nil {
		t.Fatal(err)
	}
	if err := f.repo.Create(ctx, actor); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("actor request next to a pending person request: %v", err)
	}
	if n := f.count(t, `SELECT COUNT(*) FROM finding_status_approvals WHERE finding_id = $1 AND status = 'pending'`, fid.String()); n != 1 {
		t.Fatalf("pending requests: %d", n)
	}
	// Once decided (cancelled), a new request may be made.
	if _, err := f.svc.CancelApproval(ctx, finding.CancelApprovalInput{TenantID: f.tenant.String(), ApprovalID: first.ID.String(), CanceledBy: f.requester.String()}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.request(t, f.tenant, fid, "accepted"); err != nil {
		t.Fatalf("request after cancel: %v", err)
	}
}

// Approving writes the request, the finding status and the timeline entry
// in one transaction: of two approvers only one applies it, and a finding
// that moved in between rolls everything back with the request still pending.
func TestFindingApproval_ApproveIsOneTransaction(t *testing.T) {
	f := newApprovalFixture(t, "approve-tx")
	ctx := context.Background()
	second := shared.NewID()
	f.exec(t, `INSERT INTO users (id, email, name) VALUES ($1, $2, 'second')`, second.String(), second.String()+"@example.com")
	t.Cleanup(func() { _, _ = f.db.Exec(`DELETE FROM users WHERE id = $1`, second.String()) })

	// Two approvers race on one request.
	fid := f.finding(t, f.tenant, "medium")
	req, err := f.request(t, f.tenant, fid, "accepted")
	if err != nil {
		t.Fatal(err)
	}
	one, _ := f.repo.GetByTenantAndID(ctx, f.tenant, req.ID)
	two, _ := f.repo.GetByTenantAndID(ctx, f.tenant, req.ID)
	if err := one.Approve(f.approver); err != nil {
		t.Fatal(err)
	}
	if err := two.Approve(second); err != nil {
		t.Fatal(err)
	}
	if err := f.repo.ApproveAndApply(ctx, one, nil); err != nil {
		t.Fatalf("first approver: %v", err)
	}
	if err := f.repo.ApproveAndApply(ctx, two, nil); !errors.Is(err, vulnerability.ErrConcurrentModification) {
		t.Fatalf("second approver: %v", err)
	}
	var approvedBy string
	if err := f.db.QueryRow(`SELECT approved_by::text FROM finding_status_approvals WHERE id = $1`, req.ID.String()).Scan(&approvedBy); err != nil || approvedBy != f.approver.String() {
		t.Fatalf("approved_by %q %v", approvedBy, err)
	}
	if s := f.findingStatus(t, fid); s != "accepted" {
		t.Fatalf("finding after approve: %s", s)
	}

	// The finding moves after the approver read it: nothing is written.
	moved := f.finding(t, f.tenant, "medium")
	req2, err := f.request(t, f.tenant, moved, "false_positive")
	if err != nil {
		t.Fatal(err)
	}
	read, _ := f.repo.GetByTenantAndID(ctx, f.tenant, req2.ID)
	if err := read.Approve(f.approver); err != nil {
		t.Fatal(err)
	}
	f.exec(t, `UPDATE findings SET status = 'resolved' WHERE id = $1`, moved.String())
	entry, err := vulnerability.NewFindingActivity(f.tenant, moved, vulnerability.ActivityApprovalApproved, &f.approver,
		vulnerability.ActorTypeUser, map[string]any{"approval_id": req2.ID.String()}, vulnerability.SourceAPI, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.repo.ApproveAndApply(ctx, read, entry); err == nil {
		t.Fatal("approve applied to a finding that moved")
	}
	if s := f.approvalStatus(t, req2.ID); s != "pending" {
		t.Fatalf("request after a failed apply: %s", s)
	}
	if n := f.count(t, `SELECT COUNT(*) FROM finding_activities WHERE finding_id = $1 AND activity_type = 'approval_approved'`, moved.String()); n != 0 {
		t.Fatalf("timeline entry of a rolled-back approve: %d", n)
	}

	// The service path writes the timeline entry with the decision.
	fid3 := f.finding(t, f.tenant, "low")
	req3, err := f.request(t, f.tenant, fid3, "false_positive")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.ApproveStatus(ctx, finding.ApproveStatusInput{TenantID: f.tenant.String(), ApprovalID: req3.ID.String(), ApprovedBy: f.approver.String()}); err != nil {
		t.Fatal(err)
	}
	if n := f.count(t, `SELECT COUNT(*) FROM finding_activities WHERE finding_id = $1 AND activity_type = 'approval_approved'`, fid3.String()); n != 1 {
		t.Fatalf("timeline entries of an approve: %d", n)
	}
	// Another tenant cannot approve it.
	if _, err := f.svc.ApproveStatus(ctx, finding.ApproveStatusInput{TenantID: f.other.String(), ApprovalID: req2.ID.String(), ApprovedBy: f.approver.String()}); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cross-tenant approve: %v", err)
	}
}

// Migration finding_approval_pending_dedupe keeps the newest pending request
// of each finding and cancels the older ones (with a timeline entry); the
// unique index then holds.
func TestMigrationFindingApprovalPendingDedupe(t *testing.T) {
	const dir = "../../migrations"
	v := testdb.MigrationVersion(t, dir, "finding_approval_pending_dedupe")
	idx := testdb.MigrationVersion(t, dir, "finding_approval_one_pending")
	db := testdb.PrivateDatabase(t, "migapd", dir)
	testdb.Migrate(t, db, dir, v, idx, true)

	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := db.Exec(q, args...); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	const (
		tenant = "a1111111-1111-4111-8111-111111111111"
		fid    = "b1111111-1111-4111-8111-111111111111"
		other  = "b2222222-2222-4222-8222-222222222222"
	)
	exec(`INSERT INTO tenants (id, name, slug) VALUES ($1, 't', 'mig-apd')`, tenant)
	exec(`INSERT INTO findings (id, tenant_id, source, tool_name, message, severity, fingerprint, status) VALUES
		($1, $3, 'sast', 't', 'm', 'low', 'f1', 'confirmed'), ($2, $3, 'sast', 't', 'm', 'low', 'f2', 'confirmed')`, fid, other, tenant)
	exec(`INSERT INTO finding_status_approvals (id, tenant_id, finding_id, requested_status, status, created_at) VALUES
		('c1111111-1111-4111-8111-111111111111', $1, $2, 'false_positive', 'pending', now() - interval '3 days'),
		('c2222222-2222-4222-8222-222222222222', $1, $2, 'accepted', 'pending', now() - interval '1 day'),
		('c3333333-3333-4333-8333-333333333333', $1, $2, 'false_positive', 'rejected', now()),
		('c4444444-4444-4444-8444-444444444444', $1, $3, 'false_positive', 'pending', now() - interval '20 days')`, tenant, fid, other)

	testdb.Migrate(t, db, dir, testdb.MigrationVersion(t, dir, "finding_approval_decide_by_backfill"), idx, false)

	status := func(id string) string {
		var s string
		if err := db.QueryRow(`SELECT status FROM finding_status_approvals WHERE id = $1`, id).Scan(&s); err != nil {
			t.Fatal(err)
		}
		return s
	}
	for id, want := range map[string]string{
		"c1111111-1111-4111-8111-111111111111": "canceled",
		"c2222222-2222-4222-8222-222222222222": "pending",
		"c3333333-3333-4333-8333-333333333333": "rejected",
		"c4444444-4444-4444-8444-444444444444": "pending",
	} {
		if got := status(id); got != want {
			t.Fatalf("%s: %s, want %s", id, got, want)
		}
	}
	var decideBy sql.NullTime
	if err := db.QueryRow(`SELECT decide_by FROM finding_status_approvals WHERE id = 'c4444444-4444-4444-8444-444444444444'`).Scan(&decideBy); err != nil || !decideBy.Valid {
		t.Fatalf("backfilled decide_by: %v %v", decideBy, err)
	}
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM finding_activities WHERE finding_id = $1 AND changes->>'reason' = 'superseded_by_newer_request'`, fid).Scan(&n); err != nil || n != 1 {
		t.Fatalf("dedupe timeline entries: %d %v", n, err)
	}
	if _, err := db.Exec(`INSERT INTO finding_status_approvals (tenant_id, finding_id, requested_status, status) VALUES ($1, $2, 'accepted', 'pending')`, tenant, fid); err == nil {
		t.Fatal("a second pending request was accepted by the index")
	}
	testdb.Migrate(t, db, dir, v, idx, true)
	testdb.Migrate(t, db, dir, v, idx, false)
}
