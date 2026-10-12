package postgres

import (
	"context"
	"database/sql"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// not_observed (research 18, owner decision O2): feature-branch expiry marks a
// finding not_observed (stale, not fixed), a sighting reopens it, migration
// 000640 relabels only rows whose provenance is certain, and the status CHECK
// refuses unknown values.

func insertBranchFinding(ctx context.Context, t *testing.T, q interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}, tenant, asset shared.ID, branch *shared.ID, status, resolution, lastSeen string) shared.ID {
	t.Helper()
	id := shared.NewID()
	var b any
	if branch != nil {
		b = branch.String()
	}
	if _, err := q.ExecContext(ctx, `INSERT INTO findings (id, tenant_id, asset_id, source, tool_name, message, severity,
		fingerprint, status, resolution, branch_id, last_seen_at)
		VALUES ($1::uuid, $2, $3, 'sast', 'semgrep', 'm', 'high', $1::text, $4, NULLIF($5, ''), $6, `+lastSeen+`)`,
		id.String(), tenant.String(), asset.String(), status, resolution, b); err != nil {
		t.Fatalf("seed finding: %v", err)
	}
	return id
}

func findingStatus(ctx context.Context, t *testing.T, q interface {
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}, id shared.ID) (status string, resolvedAt sql.NullTime, regression bool) {
	t.Helper()
	if err := q.QueryRowContext(ctx, `SELECT status, resolved_at, COALESCE(is_regression, false) FROM findings WHERE id = $1`, id.String()).
		Scan(&status, &resolvedAt, &regression); err != nil {
		t.Fatal(err)
	}
	return status, resolvedAt, regression
}

func TestExpireFeatureBranchFindings_MarksNotObservedAndASightingReopens(t *testing.T) {
	ctx := context.Background()
	db := openGroupsDB(t)
	tenant := seedTestTenant(ctx, t, db)
	asset := shared.NewID()
	if _, err := db.ExecContext(ctx, `INSERT INTO assets (id, tenant_id, name, asset_type) VALUES ($1, $2, $3, 'repository')`,
		asset.String(), tenant.String(), "repo-"+asset.String()); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO asset_repositories (asset_id) VALUES ($1)`, asset.String()); err != nil {
		t.Fatal(err)
	}
	feature, main := shared.NewID(), shared.NewID()
	for id, def := range map[shared.ID]bool{feature: false, main: true} {
		if _, err := db.ExecContext(ctx, `INSERT INTO repository_branches (id, repository_id, name, is_default, keep_when_inactive) VALUES ($1, $2, $3, $4, false)`,
			id.String(), asset.String(), "b-"+id.String(), def); err != nil {
			t.Fatal(err)
		}
	}
	stale := insertBranchFinding(ctx, t, db, tenant, asset, &feature, "new", "", "NOW() - interval '40 days'")
	fresh := insertBranchFinding(ctx, t, db, tenant, asset, &feature, "new", "", "NOW()")
	onMain := insertBranchFinding(ctx, t, db, tenant, asset, &main, "new", "", "NOW() - interval '40 days'")

	repo := NewFindingRepository(&DB{DB: db})
	n, err := repo.ExpireFeatureBranchFindings(ctx, tenant, 30)
	if err != nil || n != 1 {
		t.Fatalf("expired %d (%v), want 1", n, err)
	}
	if st, at, _ := findingStatus(ctx, t, db, stale); st != "not_observed" || at.Valid {
		t.Fatalf("stale feature-branch finding: status %s resolved_at %v, want not_observed and no resolved_at (never fixed)", st, at)
	}
	for _, id := range []shared.ID{fresh, onMain} {
		if st, _, _ := findingStatus(ctx, t, db, id); st != "new" {
			t.Fatalf("finding %s changed to %s", id, st)
		}
	}

	// Seen again: back to an open state, and not counted as a regression.
	var fp string
	_ = db.QueryRowContext(ctx, `SELECT fingerprint FROM findings WHERE id = $1`, stale.String()).Scan(&fp)
	reopened, err := repo.AutoReopenByFingerprintsBatch(ctx, tenant, []string{fp})
	if err != nil || len(reopened) != 1 || reopened[fp].PreviousStatus != "not_observed" {
		t.Fatalf("reopen = %+v (%v)", reopened, err)
	}
	if st, _, reg := findingStatus(ctx, t, db, stale); st != "confirmed" || reg {
		t.Fatalf("after a sighting: status %s regression %v, want confirmed and no regression", st, reg)
	}

	// Another tenant's run touches nothing here (tenant-scoped).
	other := seedTestTenant(ctx, t, db)
	again := insertBranchFinding(ctx, t, db, tenant, asset, &feature, "new", "", "NOW() - interval '40 days'")
	if n, err := repo.ExpireFeatureBranchFindings(ctx, other, 30); err != nil || n != 0 {
		t.Fatalf("another tenant's expiry changed %d rows (%v)", n, err)
	}
	if st, _, _ := findingStatus(ctx, t, db, again); st != "new" {
		t.Fatalf("cross-tenant expiry moved the finding to %s", st)
	}
}
