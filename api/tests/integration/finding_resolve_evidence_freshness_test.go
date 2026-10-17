package integration

import (
	"context"
	"testing"

	"github.com/openctemio/openctem/api/internal/app/finding"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// Resolve evidence must be newer than the finding's last reopen and last
// sighting. A critical finding that regressed after a confirmed retest, or a
// high one whose checklist was completed before it came back, cannot be
// closed by one person on that old proof; fresh evidence closes it.
func TestResolveEvidence_StaleAfterRegression(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()
	tenant := createTestTenant(t, db, "evidence-fresh")
	verifier, second := shared.NewID(), shared.NewID()
	t.Cleanup(func() {
		_, _ = db.Exec(`DELETE FROM tenants WHERE id = $1`, tenant.String())
		for _, u := range []shared.ID{verifier, second} {
			_, _ = db.Exec(`DELETE FROM users WHERE id = $1`, u.String())
		}
		_ = db.Close()
	})
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := db.Exec(q, args...); err != nil {
			t.Fatalf("%v\n%s", err, q)
		}
	}
	for _, u := range []shared.ID{verifier, second} {
		exec(`INSERT INTO users (id, email, name) VALUES ($1, $2, 'ef')`, u.String(), u.String()+"@example.com")
	}
	asset := shared.NewID()
	exec(`INSERT INTO assets (id, tenant_id, name, asset_type) VALUES ($1, $2, 'ef-host', 'host')`, asset.String(), tenant.String())

	pdb := &postgres.DB{DB: db}
	svc := finding.NewVulnerabilityService(nil, postgres.NewFindingRepository(pdb), logger.NewNop())
	svc.SetOutboxService(db, nil)

	newFinding := func(severity string) shared.ID {
		id := shared.NewID()
		exec(`INSERT INTO findings (id, tenant_id, asset_id, source, tool_name, message, severity, fingerprint, status, last_seen_at)
			VALUES ($1, $2, $3, 'dast', 'ef-tool', 'm', $4, $5, 'fix_applied', NOW() - interval '3 days')`,
			id.String(), tenant.String(), asset.String(), severity, "ef-"+id.String())
		return id
	}
	retest := func(f shared.ID, ago string) {
		exec(`INSERT INTO finding_retests (id, tenant_id, finding_id, trigger, status, outcome, completed_at,
				prior_status, template_id, target, deadline_at)
			VALUES ($1, $2, $3, 'manual', 'completed', 'confirmed_fixed', NOW() - $4::interval,
				'fix_applied', 'tpl', 'https://a.example', NOW())`, shared.NewID().String(), tenant.String(), f.String(), ago)
	}
	checklist := func(f, by shared.ID, ago string) {
		exec(`DELETE FROM finding_verification_checklists WHERE finding_id = $1`, f.String())
		exec(`INSERT INTO finding_verification_checklists (id, tenant_id, finding_id, exposure_cleared, evidence_attached,
				register_updated, monitoring_added, regression_scheduled, completed_by, completed_at)
			VALUES ($1, $2, $3, true, true, true, true, true, $4, NOW() - $5::interval)`,
			shared.NewID().String(), tenant.String(), f.String(), by.String(), ago)
	}
	regress := func(f shared.ID, ago string) {
		exec(`UPDATE findings SET last_reopened_at = NOW() - $2::interval, reopen_count = reopen_count + 1 WHERE id = $1`, f.String(), ago)
	}
	resolve := func(f shared.ID) error {
		_, err := svc.UpdateFindingStatus(ctx, f.String(), tenant.String(), finding.UpdateFindingStatusInput{
			Status: "resolved", Resolution: "verified", ActorID: verifier.String(), HasVerifyPermission: true,
		})
		return err
	}

	// Critical: a confirmed retest from before the regression does not count.
	crit := newFinding("critical")
	retest(crit, "2 days")
	regress(crit, "1 day")
	if err := resolve(crit); err == nil {
		t.Fatal("critical finding resolved on a retest older than its regression")
	}
	// A second verifier's checklist from before the regression does not count either.
	checklist(crit, second, "2 days")
	if err := resolve(crit); err == nil {
		t.Fatal("critical finding resolved on a checklist older than its regression")
	}
	// A retest after the regression does.
	retest(crit, "1 hour")
	if err := resolve(crit); err != nil {
		t.Fatalf("critical finding with a fresh confirming retest: %v", err)
	}

	// High: the checklist must postdate the last sighting too.
	high := newFinding("high")
	checklist(high, verifier, "4 days")
	if err := resolve(high); err == nil {
		t.Fatal("high finding resolved on a checklist older than its last sighting")
	}
	checklist(high, verifier, "1 hour")
	if err := resolve(high); err != nil {
		t.Fatalf("high finding with a fresh checklist: %v", err)
	}
}
