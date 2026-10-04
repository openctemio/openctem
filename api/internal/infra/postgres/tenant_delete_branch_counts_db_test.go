package postgres

import (
	"context"
	"database/sql"
	"testing"

	_ "github.com/lib/pq"

	"github.com/openctemio/openctem/api/internal/testdb"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// TestDeleteCascade_RepositoryBranchWithFindings guards migration 000238:
// deleting a tenant or a repository asset whose branch has findings used to
// fail, because update_branch_finding_counts() updated a branch row whose
// repository the same cascade had already removed. Since 000378 only a tenant
// delete still cascades findings; an asset delete refuses them.
//
// DB-gated: needs DATABASE_URL pointing at app_test (never the live DB).
func TestDeleteCascade_RepositoryBranchWithFindings(t *testing.T) {
	dbURL := testdb.URL()
	if dbURL == "" {
		t.Skip("DATABASE_URL not set; skipping DB-backed test")
	}
	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer func() { _ = db.Close() }()
	if err := db.Ping(); err != nil {
		t.Skipf("cannot reach test DB: %v", err)
	}
	ctx := context.Background()

	// seed creates, inside tx, a tenant with one repository asset, one branch
	// and one open finding on that branch. Seeding and deleting in the same
	// transaction is what makes the cascade reach the branch after its
	// repository; with the rows committed first the order can differ.
	seed := func(t *testing.T, tx *sql.Tx) (tenantID, assetID, branchID string) {
		t.Helper()
		tenantID = shared.NewID().String()
		mustExecTx(t, tx, `INSERT INTO tenants (id, name, slug) VALUES ($1,$2,$3)`,
			tenantID, "cascade-test", "cascade-"+tenantID[:8])
		if err := tx.QueryRowContext(ctx,
			`INSERT INTO assets (tenant_id, name, asset_type) VALUES ($1,$2,'repository') RETURNING id`,
			tenantID, "repo-"+tenantID[:8]).Scan(&assetID); err != nil {
			t.Fatalf("insert asset: %v", err)
		}
		mustExecTx(t, tx, `INSERT INTO asset_repositories (asset_id) VALUES ($1)`, assetID)
		if err := tx.QueryRowContext(ctx,
			`INSERT INTO repository_branches (repository_id, name) VALUES ($1,'main') RETURNING id`,
			assetID).Scan(&branchID); err != nil {
			t.Fatalf("insert branch: %v", err)
		}
		mustExecTx(t, tx, `INSERT INTO findings (tenant_id, asset_id, branch_id, source, tool_name, message, severity, fingerprint)
			VALUES ($1,$2,$3,'sast','semgrep','x','high',$4)`, tenantID, assetID, branchID, "fp-"+tenantID[:8])

		var total int
		if err := tx.QueryRowContext(ctx, `SELECT findings_total FROM repository_branches WHERE id=$1`, branchID).Scan(&total); err != nil {
			t.Fatalf("read branch counts: %v", err)
		}
		if total != 1 {
			t.Fatalf("branch findings_total = %d, want 1 (counter trigger must still work)", total)
		}
		return tenantID, assetID, branchID
	}

	// inTx runs fn in a transaction that is always rolled back, so nothing
	// is left behind in the test database.
	inTx := func(t *testing.T, fn func(tx *sql.Tx)) {
		t.Helper()
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			t.Fatalf("begin: %v", err)
		}
		defer func() { _ = tx.Rollback() }()
		fn(tx)
	}

	t.Run("delete tenant", func(t *testing.T) {
		inTx(t, func(tx *sql.Tx) {
			tenantID, _, _ := seed(t, tx)
			if _, err := tx.ExecContext(ctx, `DELETE FROM tenants WHERE id=$1`, tenantID); err != nil {
				t.Fatalf("delete tenant: %v", err)
			}
		})
	})

	t.Run("delete repository asset", func(t *testing.T) {
		inTx(t, func(tx *sql.Tx) {
			_, assetID, branchID := seed(t, tx)
			// An asset's findings no longer cascade away with it
			// (findings.asset_id is ON DELETE NO ACTION, migration 000378):
			// the delete fails while the finding exists...
			mustExecTx(t, tx, `SAVEPOINT before_delete`)
			if _, err := tx.ExecContext(ctx, `DELETE FROM assets WHERE id=$1`, assetID); err == nil {
				t.Fatal("deleting an asset that has findings succeeded; findings must not cascade away")
			}
			mustExecTx(t, tx, `ROLLBACK TO SAVEPOINT before_delete`)
			// ...and once they are gone the repository's branches still cascade.
			mustExecTx(t, tx, `DELETE FROM findings WHERE asset_id=$1`, assetID)
			if _, err := tx.ExecContext(ctx, `DELETE FROM assets WHERE id=$1`, assetID); err != nil {
				t.Fatalf("delete asset: %v", err)
			}
			var n int
			if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM repository_branches WHERE id=$1`, branchID).Scan(&n); err != nil {
				t.Fatalf("count branches: %v", err)
			}
			if n != 0 {
				t.Fatalf("branch survived its repository's deletion")
			}
		})
	})

	t.Run("resolving a finding still updates counts", func(t *testing.T) {
		inTx(t, func(tx *sql.Tx) {
			tenantID, _, branchID := seed(t, tx)
			mustExecTx(t, tx, `UPDATE findings SET status='resolved' WHERE tenant_id=$1`, tenantID)
			var total int
			if err := tx.QueryRowContext(ctx, `SELECT findings_total FROM repository_branches WHERE id=$1`, branchID).Scan(&total); err != nil {
				t.Fatalf("read branch counts: %v", err)
			}
			if total != 0 {
				t.Fatalf("findings_total = %d after resolve, want 0", total)
			}
		})
	})
}

func mustExecTx(t *testing.T, tx *sql.Tx, query string, args ...any) {
	t.Helper()
	if _, err := tx.Exec(query, args...); err != nil {
		t.Fatalf("exec %q: %v", query, err)
	}
}
