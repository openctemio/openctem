package integration

import (
	"context"
	"testing"

	"github.com/openctemio/openctem/api/internal/app/finding"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// TestAIFalsePositiveProposal: AI triage proposes a false positive only for a
// medium or low finding, only as a pending request with no person as
// requester, never twice, never after a person rejected it, never across
// tenants; two distinct people approve it (an actor request needs one more sign-off).
func TestAIFalsePositiveProposal(t *testing.T) {
	db := setupTestDB(t)
	pdb := &postgres.DB{DB: db}
	ctx := context.Background()
	tenant := createTestTenant(t, db, "ai-fp")
	other := createTestTenant(t, db, "ai-fp-other")
	approver, approver2 := shared.NewID(), shared.NewID()
	t.Cleanup(func() {
		for _, id := range []shared.ID{tenant, other} {
			_, _ = db.Exec(`DELETE FROM tenants WHERE id = $1`, id.String())
		}
		for _, id := range []shared.ID{approver, approver2} {
			_, _ = db.Exec(`DELETE FROM users WHERE id = $1`, id.String())
		}
		_ = db.Close()
	})
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := db.Exec(q, args...); err != nil {
			t.Fatalf("%v\n%s", err, q)
		}
	}
	for _, id := range []shared.ID{approver, approver2} {
		exec(`INSERT INTO users (id, email, name) VALUES ($1, $2, 'approver')`, id.String(), id.String()+"@example.com")
	}
	newFinding := func(severity string) shared.ID {
		id := shared.NewID()
		exec(`INSERT INTO findings (id, tenant_id, source, tool_name, message, severity, fingerprint, status)
			VALUES ($1::uuid, $2, 'sast', 'ai-fp', 'm', $3, $1::text, 'confirmed')`, id.String(), tenant.String(), severity)
		return id
	}
	count := func(findingID shared.ID) (n int, actor string, requestedByNull bool) {
		t.Helper()
		if err := db.QueryRow(`SELECT COUNT(*), COALESCE(MAX(requested_by_actor), ''), COALESCE(BOOL_AND(requested_by IS NULL), true)
			FROM finding_status_approvals WHERE finding_id = $1`, findingID.String()).Scan(&n, &actor, &requestedByNull); err != nil {
			t.Fatalf("count: %v", err)
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
	svc.SetApprovalNotifier(staticApprovers{approver, approver2}, nil, nil, "")

	medium := newFinding("medium")
	ok, err := svc.ProposeFalsePositiveFromAI(ctx, tenant, medium, 0.95, "the flagged value is a test fixture")
	if err != nil || !ok {
		t.Fatalf("propose medium: %v %v", ok, err)
	}
	if n, actor, nullBy := count(medium); n != 1 || actor != "ai_triage" || !nullBy {
		t.Fatalf("proposal row: n=%d actor=%q requested_by NULL=%v", n, actor, nullBy)
	}
	if s := status(medium); s != "confirmed" {
		t.Fatalf("a proposal changed the finding: %s", s)
	}
	// Idempotent: a second verdict adds nothing.
	if ok, err := svc.ProposeFalsePositiveFromAI(ctx, tenant, medium, 0.97, "again"); err != nil || ok {
		t.Fatalf("duplicate proposal: %v %v", ok, err)
	}
	if n, _, _ := count(medium); n != 1 {
		t.Fatalf("duplicate rows: %d", n)
	}

	// Never for critical or high, never below the threshold.
	for _, sev := range []string{"critical", "high"} {
		id := newFinding(sev)
		if ok, err := svc.ProposeFalsePositiveFromAI(ctx, tenant, id, 0.99, "x"); err != nil || ok {
			t.Fatalf("%s proposed: %v %v", sev, ok, err)
		}
		if n, _, _ := count(id); n != 0 {
			t.Fatalf("%s has %d proposals", sev, n)
		}
	}
	low := newFinding("low")
	if ok, _ := svc.ProposeFalsePositiveFromAI(ctx, tenant, low, 0.85, "x"); ok {
		t.Fatal("proposed below the threshold")
	}

	// Another tenant cannot propose on, or approve, this tenant's finding.
	if ok, err := svc.ProposeFalsePositiveFromAI(ctx, other, low, 0.99, "x"); err == nil || ok {
		t.Fatalf("cross-tenant proposal: %v %v", ok, err)
	}
	list, err := approvals.ListByFinding(ctx, tenant, medium)
	if err != nil || len(list) != 1 {
		t.Fatalf("list: %v %d", err, len(list))
	}
	if _, err := svc.ApproveStatus(ctx, finding.ApproveStatusInput{TenantID: other.String(),
		ApprovalID: list[0].ID.String(), ApprovedBy: approver.String()}); err == nil {
		t.Fatal("another tenant approved the proposal")
	}

	// A request made by an actor needs one more sign-off than the tier: one
	// approver is not enough, two distinct eligible approvers are.
	requireTwoSignoffs(t, svc, tenant, list[0].ID.String(), approver, approver2,
		func() string { return status(medium) }, "confirmed", "false_positive")

	// Rejected once, never proposed again.
	if ok, err := svc.ProposeFalsePositiveFromAI(ctx, tenant, low, 0.95, "x"); err != nil || !ok {
		t.Fatalf("propose low: %v %v", ok, err)
	}
	list, _ = approvals.ListByFinding(ctx, tenant, low)
	if _, err := svc.RejectApproval(ctx, finding.RejectApprovalInput{TenantID: tenant.String(),
		ApprovalID: list[0].ID.String(), RejectedBy: approver.String(), Reason: "real issue"}); err != nil {
		t.Fatalf("reject: %v", err)
	}
	if ok, err := svc.ProposeFalsePositiveFromAI(ctx, tenant, low, 0.99, "x"); err != nil || ok {
		t.Fatalf("re-proposed after rejection: %v %v", ok, err)
	}
}
