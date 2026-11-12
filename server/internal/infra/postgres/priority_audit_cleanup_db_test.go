package postgres

import (
	"context"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/internal/app/finding"
	"github.com/openctemio/openctem/api/internal/testdb"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

func auditCount(t *testing.T, db *DB, where string, args ...any) int {
	t.Helper()
	var n int
	if err := db.QueryRow(`SELECT count(*) FROM priority_class_audit_log WHERE `+where, args...).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// The priority audit never stores a row whose class did not move, the cleanup
// removes the residue and the rows of organizations that are gone (and only
// those), retention deletes in batches, and deleting an organization erases
// its rows.
func TestPriorityAuditCleanup_DB(t *testing.T) {
	sqlDB := testdb.PrivateDatabase(t, "prio_audit", "../../../migrations")
	db := &DB{DB: sqlDB}
	ctx := context.Background()
	repo := NewPriorityAuditRepository(db)

	live, other, gone := shared.NewID(), shared.NewID(), shared.NewID()
	for _, id := range []shared.ID{live, other} {
		if _, err := sqlDB.Exec(`INSERT INTO tenants (id, name, slug) VALUES ($1, $2, $2)`, id.String(), "pa-"+id.String()[24:]); err != nil {
			t.Fatal(err)
		}
	}

	// Writers: a no-op entry is dropped in SQL, a real transition is kept.
	p1, p2 := vulnerability.PriorityClass("P1"), vulnerability.PriorityClass("P2")
	f := shared.NewID()
	if err := repo.LogChange(ctx, finding.PriorityAuditEntry{TenantID: live, FindingID: f, PreviousClass: &p1, NewClass: "P1", Reason: "same", Source: "auto"}); err != nil {
		t.Fatal(err)
	}
	if err := repo.LogChanges(ctx, []finding.PriorityAuditEntry{
		{TenantID: live, FindingID: f, PreviousClass: &p1, NewClass: "P1", Reason: "same", Source: "auto"},
		{TenantID: live, FindingID: f, PreviousClass: &p2, NewClass: "P1", Reason: "moved", Source: "auto"},
		{TenantID: live, FindingID: f, NewClass: "P1", Reason: "first", Source: "auto"},
	}); err != nil {
		t.Fatal(err)
	}
	if n := auditCount(t, db, `tenant_id = $1`, live.String()); n != 2 {
		t.Fatalf("no-op entries must not be stored: %d rows, want 2", n)
	}

	// Residue: 12000 no-op rows (more than one batch), rows of a deleted
	// organization, and real rows of a live one that must survive.
	if _, err := sqlDB.Exec(`INSERT INTO priority_class_audit_log (tenant_id, finding_id, previous_class, new_class, reason, source)
		SELECT $1, gen_random_uuid(), 'P2', 'P2', 'noop', 'auto' FROM generate_series(1, 12000)`, live.String()); err != nil {
		t.Fatal(err)
	}
	if _, err := sqlDB.Exec(`INSERT INTO priority_class_audit_log (tenant_id, finding_id, previous_class, new_class, reason, source)
		SELECT $1, gen_random_uuid(), 'P3', 'P1', 'orphan', 'auto' FROM generate_series(1, 7)`, gone.String()); err != nil {
		t.Fatal(err)
	}
	if _, err := sqlDB.Exec(`INSERT INTO priority_class_audit_log (tenant_id, finding_id, previous_class, new_class, reason, source)
		VALUES ($1, gen_random_uuid(), 'P3', 'P0', 'other', 'auto')`, other.String()); err != nil {
		t.Fatal(err)
	}

	noOp, orphaned, err := repo.PurgeNoOpAndOrphaned(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if noOp != 12000 || orphaned != 7 {
		t.Fatalf("purged no-op=%d orphaned=%d, want 12000 and 7", noOp, orphaned)
	}
	if n := auditCount(t, db, `true`); n != 3 {
		t.Fatalf("%d rows left, want the 2 real rows of the live tenant and 1 of the other", n)
	}
	if n, _, _ := func() (int64, int64, error) { return repo.PurgeNoOpAndOrphaned(ctx) }(); n != 0 {
		t.Fatalf("second purge removed %d rows, want 0", n)
	}

	// Retention: 12000 old rows go in batches, newer ones stay.
	if _, err := sqlDB.Exec(`INSERT INTO priority_class_audit_log (tenant_id, finding_id, previous_class, new_class, reason, source, created_at)
		SELECT $1, gen_random_uuid(), 'P3', 'P2', 'old', 'auto', now() - interval '400 days' FROM generate_series(1, 12000)`, live.String()); err != nil {
		t.Fatal(err)
	}
	deleted, err := repo.DeleteOlderThan(ctx, time.Now().AddDate(0, 0, -180))
	if err != nil || deleted != 12000 {
		t.Fatalf("retention deleted %d (err %v), want 12000", deleted, err)
	}
	if n := auditCount(t, db, `true`); n != 3 {
		t.Fatalf("%d rows left after retention, want 3", n)
	}

	// Organization deletion erases the rows of that organization only.
	if err := NewTenantRepository(db).Delete(ctx, other); err != nil {
		t.Fatal(err)
	}
	if n := auditCount(t, db, `tenant_id = $1`, other.String()); n != 0 {
		t.Fatalf("deleted organization left %d audit rows", n)
	}
	if n := auditCount(t, db, `tenant_id = $1`, live.String()); n != 2 {
		t.Fatalf("another organization lost rows: %d, want 2", n)
	}
}
