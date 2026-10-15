package integration

import (
	"context"
	"database/sql"
	"errors"
	"testing"

	"github.com/openctemio/openctem/api/internal/app/finding"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/internal/testdb"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
	"github.com/openctemio/openctem/api/pkg/logger"
)

type dupFixture struct {
	db            *sql.DB
	tenant, other shared.ID
	asset         shared.ID
}

func newDupFixture(t *testing.T) *dupFixture {
	t.Helper()
	db := setupTestDB(t)
	f := &dupFixture{
		db:     db,
		tenant: createTestTenant(t, db, "dup-int"),
		other:  createTestTenant(t, db, "dup-int-other"),
		asset:  shared.NewID(),
	}
	t.Cleanup(func() {
		for _, id := range []shared.ID{f.tenant, f.other} {
			_, _ = db.Exec(`DELETE FROM tenants WHERE id = $1`, id.String())
		}
		_ = db.Close()
	})
	f.exec(t, `INSERT INTO assets (id, tenant_id, name, asset_type) VALUES ($1, $2, 'dup-host', 'host')`,
		f.asset.String(), f.tenant.String())
	return f
}

func (f *dupFixture) exec(t *testing.T, q string, args ...any) {
	t.Helper()
	if _, err := f.db.Exec(q, args...); err != nil {
		t.Fatalf("%v\n%s", err, q)
	}
}

func (f *dupFixture) finding(t *testing.T, status string) shared.ID {
	t.Helper()
	id := shared.NewID()
	f.exec(t, `INSERT INTO findings (id, tenant_id, asset_id, source, tool_name, message, severity, fingerprint, status)
		VALUES ($1, $2, $3, 'sast', 'dup-tool', 'm', 'high', $4, $5)`,
		id.String(), f.tenant.String(), f.asset.String(), "dup-"+id.String(), status)
	return id
}

func (f *dupFixture) status(t *testing.T, id shared.ID) (string, sql.NullString) {
	t.Helper()
	var st string
	var dupOf sql.NullString
	if err := f.db.QueryRow(`SELECT status, duplicate_of::text FROM findings WHERE id = $1`, id.String()).
		Scan(&st, &dupOf); err != nil {
		t.Fatalf("read finding: %v", err)
	}
	return st, dupOf
}

// The status endpoint (single and bulk, and the workflow action that calls
// it) refuses `duplicate`: a duplicate needs the finding it duplicates and the
// mark-duplicate route's own checks. Nothing is written.
func TestDuplicateIntegrity_StatusChangeRefusesDuplicate(t *testing.T) {
	f := newDupFixture(t)
	ctx := context.Background()
	id := f.finding(t, "confirmed")
	svc := finding.NewVulnerabilityService(nil, postgres.NewFindingRepository(&postgres.DB{DB: f.db}), logger.NewNop())

	_, err := svc.UpdateFindingStatus(ctx, id.String(), f.tenant.String(), finding.UpdateFindingStatusInput{
		Status: "duplicate", ActorID: shared.NewID().String(), HasVerifyPermission: true,
	})
	if !errors.Is(err, vulnerability.ErrDuplicateNeedsCanonical) || !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("PATCH status=duplicate: err = %v, want ErrDuplicateNeedsCanonical (400)", err)
	}
	_, err = svc.BulkUpdateFindingsStatus(ctx, f.tenant.String(), finding.BulkUpdateStatusInput{
		FindingIDs: []string{id.String()}, Status: "duplicate", HasVerifyPermission: true,
	})
	if !errors.Is(err, vulnerability.ErrDuplicateNeedsCanonical) {
		t.Fatalf("bulk status=duplicate: err = %v, want ErrDuplicateNeedsCanonical", err)
	}
	if st, _ := f.status(t, id); st != "confirmed" {
		t.Errorf("status = %s after refused moves, want confirmed", st)
	}
}

// The database refuses a duplicate without a canonical finding, whatever
// path writes it; a duplicate with one is fine. Deleting the canonical
// finding reopens its duplicates (to confirmed, with a timeline entry)
// instead of failing on the constraint.
func TestDuplicateIntegrity_CheckConstraintAndCanonicalDelete(t *testing.T) {
	f := newDupFixture(t)
	canonical := f.finding(t, "confirmed")
	dup := f.finding(t, "confirmed")

	if _, err := f.db.Exec(`UPDATE findings SET status = 'duplicate' WHERE id = $1`, dup.String()); err == nil {
		t.Fatal("orphan duplicate written: the CHECK constraint is missing")
	}
	f.exec(t, `UPDATE findings SET status = 'duplicate', duplicate_of = $2 WHERE id = $1`, dup.String(), canonical.String())

	f.exec(t, `DELETE FROM findings WHERE id = $1`, canonical.String())
	st, dupOf := f.status(t, dup)
	if st != "confirmed" || dupOf.Valid {
		t.Errorf("after canonical delete: status=%s duplicate_of=%v, want confirmed and NULL", st, dupOf)
	}
	var n int
	if err := f.db.QueryRow(`SELECT COUNT(*) FROM finding_activities
		WHERE tenant_id = $1 AND finding_id = $2 AND activity_type = 'status_changed'
		  AND changes->>'old_status' = 'duplicate' AND changes->>'new_status' = 'confirmed'`,
		f.tenant.String(), dup.String()).Scan(&n); err != nil {
		t.Fatalf("count activities: %v", err)
	}
	if n != 1 {
		t.Errorf("timeline entries for the reopen = %d, want 1", n)
	}
}

// The one-time repair in the migration: orphan duplicates of every tenant
// return to confirmed with a timeline entry in their own tenant; a duplicate
// with its canonical finding is untouched; running it again changes nothing.
func TestDuplicateIntegrity_MigrationRepairsOrphans(t *testing.T) {
	const dir = "../../migrations"
	db := testdb.PrivateDatabase(t, "migdupintegrity", dir)
	v := testdb.MigrationVersion(t, dir, "finding_duplicate_has_target")
	testdb.Migrate(t, db, dir, v, v, true) // back to the state before it
	f := &dupFixture{db: db, tenant: createTestTenant(t, db, "dup-mig"), other: createTestTenant(t, db, "dup-mig-other"), asset: shared.NewID()}
	f.exec(t, `INSERT INTO assets (id, tenant_id, name, asset_type) VALUES ($1, $2, 'dup-host', 'host')`,
		f.asset.String(), f.tenant.String())

	canonical := f.finding(t, "confirmed")
	kept := f.finding(t, "confirmed")
	f.exec(t, `UPDATE findings SET status = 'duplicate', duplicate_of = $2 WHERE id = $1`, kept.String(), canonical.String())
	orphan := f.finding(t, "confirmed")
	otherAsset := shared.NewID()
	f.exec(t, `INSERT INTO assets (id, tenant_id, name, asset_type) VALUES ($1, $2, 'dup-other', 'host')`,
		otherAsset.String(), f.other.String())
	otherOrphan := shared.NewID()
	f.exec(t, `INSERT INTO findings (id, tenant_id, asset_id, source, tool_name, message, severity, fingerprint, status)
		VALUES ($1, $2, $3, 'sast', 'dup-tool', 'm', 'high', $4, 'duplicate')`,
		otherOrphan.String(), f.other.String(), otherAsset.String(), "dup-"+otherOrphan.String())
	f.exec(t, `UPDATE findings SET status = 'duplicate' WHERE id = $1`, orphan.String())

	testdb.Migrate(t, db, dir, v, v, false)
	// Idempotent: down and up again repairs nothing more.
	testdb.Migrate(t, db, dir, v, v, true)
	testdb.Migrate(t, db, dir, v, v, false)

	for id, tenant := range map[shared.ID]shared.ID{orphan: f.tenant, otherOrphan: f.other} {
		if st, _ := f.status(t, id); st != "confirmed" {
			t.Errorf("orphan %s status = %s, want confirmed", id, st)
		}
		var n int
		if err := db.QueryRow(`SELECT COUNT(*) FROM finding_activities WHERE tenant_id = $1 AND finding_id = $2
			AND changes->>'reason' = 'duplicate_link_missing'`, tenant.String(), id.String()).Scan(&n); err != nil {
			t.Fatalf("count: %v", err)
		}
		if n != 1 {
			t.Errorf("orphan %s repair entries in its own tenant = %d, want exactly 1", id, n)
		}
	}
	if st, dupOf := f.status(t, kept); st != "duplicate" || !dupOf.Valid {
		t.Errorf("a duplicate with its canonical finding changed: %s %v", st, dupOf)
	}
	if _, err := db.Exec(`UPDATE findings SET status = 'duplicate', duplicate_of = NULL WHERE id = $1`, orphan.String()); err == nil {
		t.Error("orphan duplicate written after the migration: constraint missing")
	}
}
