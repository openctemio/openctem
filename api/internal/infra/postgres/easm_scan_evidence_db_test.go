package postgres

import (
	"context"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/attribution"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// tenant_scanned evidence storage against the real schema: one bulk
// statement writes only the tenant's live assets, a re-scan refreshes the row,
// and a step run resolves to its scan only inside its tenant. Requires
// DATABASE_URL.
func TestAttributionRepository_ScanEvidence(t *testing.T) {
	ctx := context.Background()
	db := openTimeoutDB(t)
	repo := NewAttributionRepository(&DB{DB: db})
	tenant := seedTestTenant(ctx, t, db)
	other := seedTestTenant(ctx, t, db)

	mine := seedTestAsset(ctx, t, db, tenant).String()
	deleted := seedTestAsset(ctx, t, db, tenant).String()
	foreign := seedTestAsset(ctx, t, db, other).String()
	mustExec(t, db, `UPDATE assets SET deleted_at = now() WHERE id = $1`, deleted)

	ev := attribution.Evidence{Rule: attribution.RuleTenantScanned, Technique: "subfinder", Source: "sensor:s1",
		Weight: 0.95, Observed: map[string]any{"scan_id": "first"}}
	if err := repo.UpsertEvidenceBulk(ctx, tenant, []string{mine, deleted, foreign}, ev); err != nil {
		t.Fatal(err)
	}
	ev.Observed = map[string]any{"scan_id": "second"}
	if err := repo.UpsertEvidenceBulk(ctx, tenant, []string{mine}, ev); err != nil {
		t.Fatal(err)
	}
	count := func(asset string) int {
		var n int
		_ = db.QueryRowContext(ctx, `SELECT count(*) FROM easm_evidence WHERE asset_id = $1`, asset).Scan(&n)
		return n
	}
	if count(foreign) != 0 || count(deleted) != 0 {
		t.Fatal("evidence written for a foreign tenant's or a deleted asset")
	}
	if count(mine) != 1 {
		t.Fatalf("a re-scan must refresh the row, not add one: %d rows", count(mine))
	}
	var scan string
	_ = db.QueryRowContext(ctx, `SELECT observed->>'scan_id' FROM easm_evidence WHERE asset_id = $1`, mine).Scan(&scan)
	if scan != "second" {
		t.Fatalf("datum not refreshed: %q", scan)
	}

	templateID := seedTimeoutTemplate(ctx, t, db, tenant)
	scanID := shared.NewID()
	mustExec(t, db, `INSERT INTO scans (id, tenant_id, name, scan_type, scan_workflow_id) VALUES ($1, $2, $3, 'workflow', $4)`,
		scanID.String(), tenant.String(), "scan-"+scanID.String(), templateID.String())
	runID := seedRun(ctx, t, db, tenant, templateID, &scanID, "running", 0)
	stepID, stepRunID := shared.NewID(), shared.NewID()
	mustExec(t, db, `INSERT INTO scan_workflow_steps (id, scan_workflow_id, step_key, name, step_order) VALUES ($1, $2, 'recon', 'recon', 1)`,
		stepID.String(), templateID.String())
	mustExec(t, db, `INSERT INTO scan_run_steps (id, scan_run_id, step_id, step_key, step_order, status) VALUES ($1, $2, $3, 'recon', 1, 'running')`,
		stepRunID.String(), runID.String(), stepID.String())

	gotRun, gotScan, err := repo.ScanRunOf(ctx, tenant, stepRunID)
	if err != nil || gotRun != runID.String() || gotScan != scanID.String() {
		t.Fatalf("ScanRunOf = %q %q %v", gotRun, gotScan, err)
	}
	if gotRun, gotScan, err = repo.ScanRunOf(ctx, other, stepRunID); err != nil || gotRun != "" || gotScan != "" {
		t.Fatalf("another tenant resolved the step run: %q %q %v", gotRun, gotScan, err)
	}
}
