package integration

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/internal/app/finding"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/cirun"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// acceptanceFixture is one tenant with a repository asset, a high finding and
// two people, plus a second tenant for the cross-tenant negatives.
type acceptanceFixture struct {
	db                  *sql.DB
	pdb                 *postgres.DB
	tenant, other       shared.ID
	assetID, findingID  shared.ID
	requester, approver shared.ID
	fingerprint         string
}

func newAcceptanceFixture(t *testing.T) *acceptanceFixture {
	t.Helper()
	db := setupTestDB(t)
	f := &acceptanceFixture{
		db: db, pdb: &postgres.DB{DB: db},
		tenant:    createTestTenant(t, db, "acc-exp"),
		other:     createTestTenant(t, db, "acc-exp-other"),
		assetID:   shared.NewID(),
		findingID: shared.NewID(),
		requester: shared.NewID(),
		approver:  shared.NewID(),
	}
	f.fingerprint = "acc-exp-" + f.findingID.String()
	t.Cleanup(func() {
		for _, id := range []shared.ID{f.tenant, f.other} {
			_, _ = db.Exec(`DELETE FROM tenants WHERE id = $1`, id.String())
		}
		for _, id := range []shared.ID{f.requester, f.approver} {
			_, _ = db.Exec(`DELETE FROM users WHERE id = $1`, id.String())
		}
		_ = db.Close()
	})
	for _, u := range []shared.ID{f.requester, f.approver} {
		f.exec(t, `INSERT INTO users (id, email, name) VALUES ($1, $2, 'acc')`, u.String(), u.String()+"@example.com")
	}
	f.exec(t, `INSERT INTO assets (id, tenant_id, name, asset_type) VALUES ($1, $2, 'acc-repo', 'repository')`,
		f.assetID.String(), f.tenant.String())
	f.exec(t, `INSERT INTO findings (id, tenant_id, asset_id, source, tool_name, message, severity, fingerprint, status)
		VALUES ($1, $2, $3, 'sast', 'acc-tool', 'm', 'high', $4, 'confirmed')`,
		f.findingID.String(), f.tenant.String(), f.assetID.String(), f.fingerprint)
	return f
}

func (f *acceptanceFixture) exec(t *testing.T, q string, args ...any) {
	t.Helper()
	if _, err := f.db.Exec(q, args...); err != nil {
		t.Fatalf("%v\n%s", err, q)
	}
}

func (f *acceptanceFixture) state(t *testing.T) (string, *time.Time) {
	t.Helper()
	var status string
	var end sql.NullTime
	if err := f.db.QueryRow(`SELECT status, acceptance_expires_at FROM findings WHERE id = $1`, f.findingID.String()).
		Scan(&status, &end); err != nil {
		t.Fatalf("read finding: %v", err)
	}
	if !end.Valid {
		return status, nil
	}
	return status, &end.Time
}

func (f *acceptanceFixture) service() *finding.VulnerabilityService {
	svc := finding.NewVulnerabilityService(nil, postgres.NewFindingRepository(f.pdb), logger.NewNop())
	svc.SetApprovalRepository(postgres.NewFindingApprovalRepository(f.pdb))
	return svc
}

// TestFindingAcceptance_EndIsWrittenClearedAndEndsTheGate: approving an
// accepted risk writes findings.acceptance_expires_at; the CI gate honors the
// finding until then and not after; leaving accepted clears the end; another
// tenant can neither approve nor write it.
func TestFindingAcceptance_EndIsWrittenClearedAndEndsTheGate(t *testing.T) {
	f := newAcceptanceFixture(t)
	ctx := context.Background()
	svc := f.service()

	end := time.Now().Add(30 * 24 * time.Hour).UTC().Truncate(time.Second)
	endStr := end.Format(time.RFC3339)
	req, err := svc.RequestApproval(ctx, finding.RequestApprovalInput{
		TenantID: f.tenant.String(), FindingID: f.findingID.String(), RequestedStatus: "accepted", ClosureReason: "risk_accepted",
		Justification: "compensating control", RequestedBy: f.requester.String(), ExpiresAt: &endStr,
	})
	if err != nil {
		t.Fatalf("request: %v", err)
	}

	// The requester cannot approve their own request.
	if _, err := svc.ApproveStatus(ctx, finding.ApproveStatusInput{
		TenantID: f.tenant.String(), ApprovalID: req.ID.String(), ApprovedBy: f.requester.String(),
	}); err == nil {
		t.Fatal("requester approved their own acceptance")
	}
	// Another tenant cannot approve it.
	if _, err := svc.ApproveStatus(ctx, finding.ApproveStatusInput{
		TenantID: f.other.String(), ApprovalID: req.ID.String(), ApprovedBy: f.approver.String(),
	}); err == nil {
		t.Fatal("another tenant approved the acceptance")
	}
	if st, e := f.state(t); st != "confirmed" || e != nil {
		t.Fatalf("finding changed before approval: %s %v", st, e)
	}

	if _, err := svc.ApproveStatus(ctx, finding.ApproveStatusInput{
		TenantID: f.tenant.String(), ApprovalID: req.ID.String(), ApprovedBy: f.approver.String(),
	}); err != nil {
		t.Fatalf("approve: %v", err)
	}
	st, got := f.state(t)
	if st != "accepted" || got == nil || !got.Equal(end) {
		t.Fatalf("after approval: status %s, acceptance end %v, want %v", st, got, end)
	}

	// The CI gate reads the end from the run's findings.
	runID := shared.NewID()
	f.exec(t, `INSERT INTO ci_runs (id, tenant_id, repository_asset_id, provider, issuer, repository)
		VALUES ($1, $2, $3, 'github', 'https://issuer.example.com', 'acme/api')`,
		runID.String(), f.tenant.String(), f.assetID.String())
	f.exec(t, `INSERT INTO ci_run_findings (tenant_id, run_id, fingerprint) VALUES ($1, $2, $3)`,
		f.tenant.String(), runID.String(), f.fingerprint)
	findings, err := postgres.NewCIRunRepository(f.pdb).RunFindings(ctx, f.tenant, runID, f.assetID)
	if err != nil || len(findings) != 1 {
		t.Fatalf("run findings: %v %d", err, len(findings))
	}
	policy := cirun.DefaultGatePolicy()
	policy.NewFindingsOnly = false
	gate := func(now time.Time) string {
		return cirun.Evaluate(cirun.GateInput{Policy: policy, PolicySource: cirun.ScopeDefault,
			Findings: findings, NewFingerprints: map[string]bool{}, BaselineKnown: true,
			BaselineBranch: "main", Now: now}).Verdict
	}
	if v := gate(time.Now()); v != cirun.VerdictPass {
		t.Fatalf("gate before the end: %s, want pass", v)
	}
	if v := gate(end.Add(time.Minute)); v != cirun.VerdictFail {
		t.Fatalf("gate after the end: %s, want fail", v)
	}

	// Another tenant's write path cannot set the end on this finding.
	repo := postgres.NewFindingRepository(f.pdb)
	if err := repo.AcceptUntil(ctx, f.other, f.findingID, end.AddDate(0, 6, 0), nil, vulnerability.ClosureReasonRiskAccepted); err != nil {
		t.Fatalf("cross-tenant AcceptUntil: %v", err)
	}
	if _, e := f.state(t); e == nil || !e.Equal(end) {
		t.Fatalf("another tenant moved the acceptance end: %v", e)
	}

	// Leaving accepted clears the end (any write path).
	f.exec(t, `UPDATE findings SET status = 'confirmed' WHERE id = $1`, f.findingID.String())
	if st, e := f.state(t); st != "confirmed" || e != nil {
		t.Fatalf("after reopen: %s %v, want the end cleared", st, e)
	}
}

// TestFindingAcceptance_SuppressionRuleEnd: a finding an accepted-risk rule
// suppresses takes the rule's expiry; a rule of another tenant writes nothing.
func TestFindingAcceptance_SuppressionRuleEnd(t *testing.T) {
	f := newAcceptanceFixture(t)
	ctx := context.Background()
	f.exec(t, `UPDATE findings SET status = 'accepted', resolution = 'suppressed' WHERE id = $1`, f.findingID.String())

	ruleEnd := time.Now().Add(60 * 24 * time.Hour).UTC().Truncate(time.Second)
	newRule := func(tenant shared.ID) shared.ID {
		id := shared.NewID()
		f.exec(t, `INSERT INTO suppression_rules (id, tenant_id, name, suppression_type, rule_id, status, expires_at, requested_by)
			VALUES ($1, $2, 'r', 'accepted_risk', 'rule-x', 'approved', $3, $4)`,
			id.String(), tenant.String(), ruleEnd, f.requester.String())
		return id
	}
	repo := postgres.NewSuppressionRepository(f.pdb)

	if err := repo.RecordSuppression(ctx, f.findingID, newRule(f.other), "system"); err != nil {
		t.Fatalf("record (other tenant): %v", err)
	}
	if _, e := f.state(t); e != nil {
		t.Fatalf("another tenant's rule set the acceptance end: %v", e)
	}
	if err := repo.RecordSuppression(ctx, f.findingID, newRule(f.tenant), "system"); err != nil {
		t.Fatalf("record: %v", err)
	}
	if _, e := f.state(t); e == nil || !e.Equal(ruleEnd) {
		t.Fatalf("acceptance end %v, want the rule's %v", e, ruleEnd)
	}
}
