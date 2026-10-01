package postgres

import (
	"context"
	"database/sql"
	"testing"

	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/domain/vulnerability"
)

// A finding first ingested without branch information is stored with
// branch_id NULL. Auto-resolve joins findings to the repository's DEFAULT
// branch, so such a finding could never be auto-resolved: later default-branch
// scans re-reported it (enrichment) without ever giving it a branch. The same
// was true of a finding first seen on a feature branch and later on the
// default branch. BackfillFindingBranches is the ingest-side repair.

func seedBackfillRepo(ctx context.Context, t *testing.T, db *sql.DB, tenantID shared.ID) shared.ID {
	t.Helper()
	id := shared.NewID()
	if _, err := db.ExecContext(ctx,
		`INSERT INTO assets (id, tenant_id, name, asset_type) VALUES ($1, $2, $3, 'repository')`,
		id.String(), tenantID.String(), "https://github.com/probe/"+id.String()); err != nil {
		t.Fatalf("seed repository asset: %v", err)
	}
	if _, err := db.ExecContext(ctx,
		`INSERT INTO asset_repositories (asset_id) VALUES ($1)`, id.String()); err != nil {
		t.Fatalf("seed asset_repositories: %v", err)
	}
	return id
}

func seedBackfillBranch(ctx context.Context, t *testing.T, db *sql.DB, repoID shared.ID, name string, isDefault bool) shared.ID {
	t.Helper()
	id := shared.NewID()
	if _, err := db.ExecContext(ctx,
		`INSERT INTO repository_branches (id, repository_id, name, is_default) VALUES ($1, $2, $3, $4)`,
		id.String(), repoID.String(), name, isDefault); err != nil {
		t.Fatalf("seed branch %s: %v", name, err)
	}
	return id
}

func seedBackfillFinding(ctx context.Context, t *testing.T, db *sql.DB, tenantID, assetID shared.ID, branchID *shared.ID, scanID string) (shared.ID, string) {
	t.Helper()
	id := shared.NewID()
	fp := "fp-" + id.String()
	var branch any
	if branchID != nil {
		branch = branchID.String()
	}
	if _, err := db.ExecContext(ctx,
		`INSERT INTO findings (id, tenant_id, asset_id, branch_id, title, source, tool_name, message,
		                       fingerprint, severity, status, scan_id)
		 VALUES ($1, $2, $3, $4, 'backfill probe', 'sast', 'semgrep', 'backfill probe', $5, 'high', 'new', $6)`,
		id.String(), tenantID.String(), assetID.String(), branch, fp, scanID); err != nil {
		t.Fatalf("seed finding: %v", err)
	}
	return id, fp
}

func readBranchID(ctx context.Context, t *testing.T, db *sql.DB, id shared.ID) string {
	t.Helper()
	var b sql.NullString
	if err := db.QueryRowContext(ctx, `SELECT branch_id FROM findings WHERE id = $1`, id.String()).Scan(&b); err != nil {
		t.Fatalf("read branch_id: %v", err)
	}
	if !b.Valid {
		return "NULL"
	}
	return b.String
}

func TestBackfillFindingBranches(t *testing.T) {
	db := openRegressionDB(t)
	ctx := context.Background()
	repo := NewFindingRepository(&DB{DB: db})

	tenantID := seedTestTenant(ctx, t, db)
	repoID := seedBackfillRepo(ctx, t, db, tenantID)
	mainID := seedBackfillBranch(ctx, t, db, repoID, "main", true)
	featID := seedBackfillBranch(ctx, t, db, repoID, "feature/x", false)
	otherRepo := seedBackfillRepo(ctx, t, db, tenantID)
	otherMain := seedBackfillBranch(ctx, t, db, otherRepo, "main", true)

	noBranch, fpNoBranch := seedBackfillFinding(ctx, t, db, tenantID, repoID, nil, "scan-1")
	onFeature, fpOnFeature := seedBackfillFinding(ctx, t, db, tenantID, repoID, &featID, "scan-1")
	onMain, fpOnMain := seedBackfillFinding(ctx, t, db, tenantID, repoID, &mainID, "scan-1")
	elsewhere, fpElsewhere := seedBackfillFinding(ctx, t, db, tenantID, otherRepo, nil, "scan-1")

	t.Run("feature-branch scan only fills missing branches", func(t *testing.T) {
		n, err := repo.BackfillFindingBranches(ctx, tenantID, []vulnerability.BranchOccurrenceUpsert{
			{Fingerprint: fpNoBranch, BranchID: featID},
			{Fingerprint: fpOnMain, BranchID: featID},
		})
		if err != nil {
			t.Fatalf("backfill: %v", err)
		}
		if n != 1 {
			t.Errorf("updated %d rows, want 1", n)
		}
		if got := readBranchID(ctx, t, db, noBranch); got != featID.String() {
			t.Errorf("branchless finding: branch_id = %s, want feature", got)
		}
		if got := readBranchID(ctx, t, db, onMain); got != mainID.String() {
			t.Errorf("a feature-branch scan re-pointed a default-branch finding to %s", got)
		}
		// Reset for the next case.
		if _, err := db.ExecContext(ctx, `UPDATE findings SET branch_id = NULL WHERE id = $1`, noBranch.String()); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("default-branch scan fills missing and moves feature findings to the default branch", func(t *testing.T) {
		n, err := repo.BackfillFindingBranches(ctx, tenantID, []vulnerability.BranchOccurrenceUpsert{
			{Fingerprint: fpNoBranch, BranchID: mainID},
			{Fingerprint: fpOnFeature, BranchID: mainID},
			{Fingerprint: fpOnMain, BranchID: mainID},
			// A branch of a DIFFERENT repository must never be attached.
			{Fingerprint: fpElsewhere, BranchID: mainID},
		})
		if err != nil {
			t.Fatalf("backfill: %v", err)
		}
		if n != 2 {
			t.Errorf("updated %d rows, want 2", n)
		}
		for name, id := range map[string]shared.ID{"branchless": noBranch, "feature": onFeature, "main": onMain} {
			if got := readBranchID(ctx, t, db, id); got != mainID.String() {
				t.Errorf("%s finding: branch_id = %s, want main", name, got)
			}
		}
		if got := readBranchID(ctx, t, db, elsewhere); got != "NULL" {
			t.Errorf("finding of another repository got branch %s", got)
		}
	})

	t.Run("another tenant's call touches nothing", func(t *testing.T) {
		other := seedTestTenant(ctx, t, db)
		n, err := repo.BackfillFindingBranches(ctx, other, []vulnerability.BranchOccurrenceUpsert{
			{Fingerprint: fpElsewhere, BranchID: otherMain},
		})
		if err != nil {
			t.Fatalf("backfill: %v", err)
		}
		if n != 0 {
			t.Errorf("cross-tenant backfill updated %d rows", n)
		}
	})

	t.Run("backfilled finding is now auto-resolvable", func(t *testing.T) {
		resolved, err := repo.AutoResolveStaleByAssets(ctx, tenantID, []shared.ID{repoID}, "semgrep", "scan-2", nil)
		if err != nil {
			t.Fatalf("auto-resolve: %v", err)
		}
		got := map[shared.ID]bool{}
		for _, id := range resolved {
			got[id] = true
		}
		if !got[noBranch] {
			t.Error("the finding first ingested without a branch was not auto-resolved")
		}
		if !got[onFeature] {
			t.Error("the finding first seen on a feature branch was not auto-resolved on the default branch")
		}
	})
}
