package integration

import (
	"context"
	"testing"

	"github.com/openctemio/openctem/api/internal/app/finding"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// A person resolving a finding and moving it straight back (Undo), or
// reopening it by hand, is a correction: it never sets is_regression or
// counts in reopen_count. A scan that sees the finding again after a resolve
// still is a regression.
func TestRegression_UndoIsNotARegression(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()
	tenant := createTestTenant(t, db, "undo-reg")
	t.Cleanup(func() {
		_, _ = db.Exec(`DELETE FROM tenants WHERE id = $1`, tenant.String())
		_ = db.Close()
	})
	pdb := &postgres.DB{DB: db}
	repo := postgres.NewFindingRepository(pdb)
	svc := finding.NewVulnerabilityService(nil, repo, logger.NewNop())
	person := shared.NewID()
	if _, err := db.Exec(`INSERT INTO users (id, email, name) VALUES ($1, $2, 'undo')`, person.String(), person.String()+"@example.com"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = db.Exec(`DELETE FROM users WHERE id = $1`, person.String()) })
	asset := shared.NewID()
	if _, err := db.Exec(`INSERT INTO assets (id, tenant_id, name, asset_type) VALUES ($1, $2, 'undo-host', 'host')`,
		asset.String(), tenant.String()); err != nil {
		t.Fatal(err)
	}
	newFinding := func(fp string) shared.ID {
		id := shared.NewID()
		if _, err := db.Exec(`INSERT INTO findings (id, tenant_id, asset_id, source, tool_name, message, severity, fingerprint, status)
			VALUES ($1, $2, $3, 'sast', 'undo-tool', 'm', 'high', $4, 'confirmed')`,
			id.String(), tenant.String(), asset.String(), fp); err != nil {
			t.Fatal(err)
		}
		return id
	}
	regression := func(id shared.ID) (bool, int) {
		var reg bool
		var n int
		if err := db.QueryRow(`SELECT COALESCE(is_regression, false), COALESCE(reopen_count, 0) FROM findings WHERE id = $1`,
			id.String()).Scan(&reg, &n); err != nil {
			t.Fatal(err)
		}
		return reg, n
	}
	move := func(id shared.ID, status string) {
		t.Helper()
		if _, err := svc.UpdateFindingStatus(ctx, id.String(), tenant.String(), finding.UpdateFindingStatusInput{
			// A resolve without the verification checklist is attested and
			// needs a note.
			Status: status, Resolution: "verified by the owner", ActorID: person.String(), HasVerifyPermission: true,
		}); err != nil {
			t.Fatalf("move to %s: %v", status, err)
		}
	}

	undone := newFinding("undo-1")
	move(undone, "resolved")
	move(undone, "confirmed") // the drawer's Undo, or a person's reopen
	if reg, n := regression(undone); reg || n != 0 {
		t.Errorf("Undo of a resolve: is_regression=%v reopen_count=%d, want false 0", reg, n)
	}

	// The bulk status change is a person's move too.
	bulk := newFinding("undo-2")
	move(bulk, "resolved")
	if _, err := svc.BulkUpdateFindingsStatus(ctx, tenant.String(), finding.BulkUpdateStatusInput{
		FindingIDs: []string{bulk.String()}, Status: "confirmed", ActorID: person.String(), HasVerifyPermission: true,
	}); err != nil {
		t.Fatal(err)
	}
	if reg, n := regression(bulk); reg || n != 0 {
		t.Errorf("bulk reopen: is_regression=%v reopen_count=%d, want false 0", reg, n)
	}

	// Evidence: a scan sees a resolved finding again.
	seen := newFinding("undo-3")
	move(seen, "resolved")
	if _, err := repo.AutoReopenByFingerprintsBatch(ctx, tenant, []string{"undo-3"}); err != nil {
		t.Fatal(err)
	}
	if reg, n := regression(seen); !reg || n != 1 {
		t.Errorf("scan re-detection: is_regression=%v reopen_count=%d, want true 1", reg, n)
	}
}
