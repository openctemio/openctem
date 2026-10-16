package integration

import (
	"context"
	"errors"
	"testing"

	"github.com/openctemio/openctem/api/internal/app/finding"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// failingApprovals refuses to create a request.
type failingApprovals struct {
	vulnerability.ApprovalRepository
}

func (failingApprovals) Create(context.Context, *vulnerability.Approval) error {
	return errors.New("db down")
}

// TestTicketDispositionRequest: a linked ticket closed as "Won't Do" opens a
// pending risk-acceptance request made by the ticket actor (no person), never
// a close (an in-progress finding goes back to confirmed); never twice while one is pending; never for a closed
// finding or across tenants; a person approves it (four-eyes).
func TestTicketDispositionRequest(t *testing.T) {
	db := setupTestDB(t)
	pdb := &postgres.DB{DB: db}
	ctx := context.Background()
	tenant := createTestTenant(t, db, "ticket-req")
	other := createTestTenant(t, db, "ticket-req-other")
	approver := shared.NewID()
	t.Cleanup(func() {
		for _, id := range []shared.ID{tenant, other} {
			_, _ = db.Exec(`DELETE FROM tenants WHERE id = $1`, id.String())
		}
		_, _ = db.Exec(`DELETE FROM users WHERE id = $1`, approver.String())
		_ = db.Close()
	})
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := db.Exec(q, args...); err != nil {
			t.Fatalf("%v\n%s", err, q)
		}
	}
	exec(`INSERT INTO users (id, email, name) VALUES ($1, $2, 'approver')`, approver.String(), approver.String()+"@example.com")
	newFinding := func(status string) shared.ID {
		id := shared.NewID()
		exec(`INSERT INTO findings (id, tenant_id, source, tool_name, message, severity, fingerprint, status)
			VALUES ($1::uuid, $2, 'sast', 'ticket-req', 'm', 'medium', $1::text, $3)`, id.String(), tenant.String(), status)
		return id
	}
	row := func(findingID shared.ID) (n int, actor, requested string, byNull, hasEnd bool) {
		t.Helper()
		if err := db.QueryRow(`SELECT COUNT(*), COALESCE(MAX(requested_by_actor), ''), COALESCE(MAX(requested_status), ''),
				COALESCE(BOOL_AND(requested_by IS NULL), true), COALESCE(BOOL_AND(expires_at IS NOT NULL), false)
			FROM finding_status_approvals WHERE finding_id = $1`, findingID.String()).Scan(&n, &actor, &requested, &byNull, &hasEnd); err != nil {
			t.Fatalf("row: %v", err)
		}
		return
	}
	status := func(findingID shared.ID) string {
		var s string
		if err := db.QueryRow(`SELECT status FROM findings WHERE id = $1`, findingID.String()).Scan(&s); err != nil {
			t.Fatalf("status: %v", err)
		}
		return s
	}

	svc := finding.NewVulnerabilityService(nil, postgres.NewFindingRepository(pdb), logger.NewNop())
	approvals := postgres.NewFindingApprovalRepository(pdb)
	svc.SetApprovalRepository(approvals)

	open := newFinding("in_progress")
	closed := newFinding("resolved")
	out, err := svc.RequestTicketDisposition(ctx, tenant, []shared.ID{open, closed}, vulnerability.FindingStatusAccepted, "jira", "SEC-1", "acct-7")
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Requested) != 1 || out.Requested[0] != open || len(out.Refused) != 1 || out.Refused[0].FindingID != closed.String() {
		t.Fatalf("outcome %+v", out)
	}
	if n, actor, req, byNull, hasEnd := row(open); n != 1 || actor != "ticket" || req != "accepted" || !byNull || !hasEnd {
		t.Fatalf("request row: n=%d actor=%q requested=%q requested_by NULL=%v end=%v", n, actor, req, byNull, hasEnd)
	}
	// The work stopped: the finding is back to confirmed, still open.
	if s := status(open); s != "confirmed" {
		t.Fatalf("after the request the finding is %s, want confirmed", s)
	}
	if n, _, _, _, _ := row(closed); n != 0 {
		t.Fatal("a request was made for a closed finding")
	}

	// A repeated delivery adds nothing: the pending request covers it.
	out, err = svc.RequestTicketDisposition(ctx, tenant, []shared.ID{open}, vulnerability.FindingStatusAccepted, "jira", "SEC-1", "acct-7")
	if err != nil || len(out.Pending) != 1 || len(out.Requested) != 0 {
		t.Fatalf("repeat: %+v %v", out, err)
	}
	if n, _, _, _, _ := row(open); n != 1 {
		t.Fatalf("duplicate rows: %d", n)
	}

	// Another tenant's ticket cannot ask about this tenant's finding.
	out, err = svc.RequestTicketDisposition(ctx, other, []shared.ID{open}, vulnerability.FindingStatusFalsePositive, "jira", "X-1", "")
	if err != nil || len(out.Requested) != 0 || len(out.Refused) != 1 {
		t.Fatalf("cross-tenant: %+v %v", out, err)
	}

	// A ticket only requests; it never asks for a close of another kind.
	if _, err := svc.RequestTicketDisposition(ctx, tenant, []shared.ID{open}, vulnerability.FindingStatusResolved, "jira", "SEC-1", ""); err == nil {
		t.Fatal("a ticket requested a resolve")
	}
	if _, err := svc.RequestTicketDisposition(ctx, tenant, []shared.ID{open}, vulnerability.FindingStatusAccepted, "vex", "SEC-1", ""); err == nil {
		t.Fatal("an unknown integration made a request")
	}

	// An in-progress finding that already has a pending request stays in
	// progress: nothing is requested, so nothing moves.
	busy := newFinding("in_progress")
	if _, err := svc.RequestTicketDisposition(ctx, tenant, []shared.ID{busy}, vulnerability.FindingStatusFalsePositive, "jira", "SEC-2", ""); err != nil {
		t.Fatal(err)
	}
	exec(`UPDATE findings SET status = 'in_progress' WHERE id = $1`, busy.String())
	out, err = svc.RequestTicketDisposition(ctx, tenant, []shared.ID{busy}, vulnerability.FindingStatusAccepted, "jira", "SEC-2", "")
	if err != nil || len(out.Pending) != 1 {
		t.Fatalf("pending: %+v %v", out, err)
	}
	if s := status(busy); s != "in_progress" {
		t.Fatalf("a finding with a pending request moved to %s", s)
	}

	// The request cannot be created: the finding stays in progress.
	failing := newFinding("in_progress")
	svc.SetApprovalRepository(failingApprovals{approvals})
	if _, err := svc.RequestTicketDisposition(ctx, tenant, []shared.ID{failing}, vulnerability.FindingStatusAccepted, "jira", "SEC-3", ""); err == nil {
		t.Fatal("want the create error")
	}
	if s := status(failing); s != "in_progress" {
		t.Fatalf("a finding whose request failed moved to %s", s)
	}
	svc.SetApprovalRepository(approvals)

	// A person approves it (any approver: it was requested by nobody).
	list, err := approvals.ListByFinding(ctx, tenant, open)
	if err != nil || len(list) != 1 {
		t.Fatalf("list: %v %d", err, len(list))
	}
	if _, err := svc.ApproveStatus(ctx, finding.ApproveStatusInput{TenantID: tenant.String(),
		ApprovalID: list[0].ID.String(), ApprovedBy: approver.String()}); err != nil {
		t.Fatalf("approve: %v", err)
	}
	if s := status(open); s != "accepted" {
		t.Fatalf("after approval: %s", s)
	}
}
