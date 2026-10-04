package integration

import (
	"context"
	"database/sql"
	"testing"

	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

// BulkUpdateStatusByFilter backs the Pending Review tab: "verify group" moves
// fix_applied findings to resolved, "reject group" moves them back to
// in_progress. The reopen branch used to emit `resolved_by = $4` AND
// `resolved_by = NULL` in one SET list, which PostgreSQL rejects (42601), so
// POST /api/v1/findings/actions/reject-fix failed with a 500 on every call.
func TestBulkUpdateStatusByFilter(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()
	ctx := context.Background()

	reviewer := createTestUser(t, db, "bulk-status-"+shared.NewID().String()+"@example.com", "Reviewer")
	repo := postgres.NewFindingRepository(&postgres.DB{DB: db})

	t.Cleanup(func() {
		_, _ = db.Exec(`DELETE FROM users WHERE id=$1`, reviewer.String())
	})
	// Each case gets its own tenant — the bulk update is tenant-wide, so cases
	// sharing one would see each other's rows.
	newTenant := func(name string) (shared.ID, shared.ID) {
		t.Helper()
		tenant := createTestTenant(t, db, name)
		t.Cleanup(func() {
			_, _ = db.Exec(`DELETE FROM findings WHERE tenant_id=$1`, tenant.String())
			_, _ = db.Exec(`DELETE FROM assets WHERE tenant_id=$1`, tenant.String())
			_, _ = db.Exec(`DELETE FROM tenants WHERE id=$1`, tenant.String())
		})
		return tenant, createTestAsset(t, db, tenant, name)
	}

	insert := func(tenant, asset shared.ID, status string) shared.ID {
		t.Helper()
		id := shared.NewID()
		_, err := db.Exec(`
			INSERT INTO findings (id, tenant_id, asset_id, source, tool_name, message,
				severity, status, fingerprint, resolved_at, resolved_by, created_at, updated_at)
			VALUES ($1,$2,$3,'sast','semgrep','bulk status test','high',$4,$5,NOW(),$6,NOW(),NOW())`,
			id.String(), tenant.String(), asset.String(), status, "fp-"+id.String(), reviewer.String())
		if err != nil {
			t.Fatalf("insert finding: %v", err)
		}
		return id
	}
	read := func(id shared.ID) (status string, resolvedBy, resolvedAt sql.NullString) {
		t.Helper()
		if err := db.QueryRow(`SELECT status, resolved_by::text, resolved_at::text FROM findings WHERE id=$1`,
			id.String()).Scan(&status, &resolvedBy, &resolvedAt); err != nil {
			t.Fatalf("read finding: %v", err)
		}
		return status, resolvedBy, resolvedAt
	}
	fixAppliedIn := func(tenant shared.ID) vulnerability.FindingFilter {
		return vulnerability.FindingFilter{
			TenantID: &tenant,
			Statuses: []vulnerability.FindingStatus{vulnerability.FindingStatusFixApplied},
		}
	}

	t.Run("reopen clears resolution actor and time", func(t *testing.T) {
		tenant, asset := newTenant("bulk-reopen")
		id := insert(tenant, asset, "fix_applied")
		n, err := repo.BulkUpdateStatusByFilter(ctx, tenant, fixAppliedIn(tenant),
			vulnerability.FindingStatusInProgress, "fix did not hold", &reviewer, "")
		if err != nil {
			t.Fatalf("reopen by filter: %v", err)
		}
		if n != 1 {
			t.Fatalf("expected 1 finding reopened, got %d", n)
		}
		status, by, at := read(id)
		if status != "in_progress" || by.Valid || at.Valid {
			t.Fatalf("got status=%s resolved_by=%v resolved_at=%v; want in_progress with both cleared",
				status, by, at)
		}
	})

	t.Run("close records the resolver", func(t *testing.T) {
		tenant, asset := newTenant("bulk-verify")
		id := insert(tenant, asset, "fix_applied")
		if _, err := db.Exec(`UPDATE findings SET resolved_by=NULL, resolved_at=NULL WHERE id=$1`, id.String()); err != nil {
			t.Fatal(err)
		}
		n, err := repo.BulkUpdateStatusByFilter(ctx, tenant, fixAppliedIn(tenant),
			vulnerability.FindingStatusResolved, "verified", &reviewer, vulnerability.ResolutionMethodSecurityReviewed)
		if err != nil {
			t.Fatalf("verify by filter: %v", err)
		}
		var method sql.NullString
		if err := db.QueryRow(`SELECT resolution_method FROM findings WHERE id = $1`, id.String()).Scan(&method); err != nil {
			t.Fatal(err)
		}
		if method.String != "security_reviewed" {
			t.Fatalf("resolution_method = %v, want security_reviewed", method)
		}
		if n != 1 {
			t.Fatalf("expected 1 finding resolved, got %d", n)
		}
		status, by, at := read(id)
		if status != "resolved" || by.String != reviewer.String() || !at.Valid {
			t.Fatalf("got status=%s resolved_by=%v resolved_at=%v; want resolved by %s with a time",
				status, by, at, reviewer)
		}
	})

	t.Run("a close without a resolution method is refused", func(t *testing.T) {
		tenant, asset := newTenant("bulk-nomethod")
		id := insert(tenant, asset, "fix_applied")
		if _, err := repo.BulkUpdateStatusByFilter(ctx, tenant, fixAppliedIn(tenant),
			vulnerability.FindingStatusResolved, "verified", &reviewer, ""); err == nil {
			t.Fatal("resolve by filter with no resolution method succeeded, want refused")
		}
		if status, _, _ := read(id); status != "fix_applied" {
			t.Fatalf("status = %s after a refused close, want fix_applied", status)
		}
	})
}
