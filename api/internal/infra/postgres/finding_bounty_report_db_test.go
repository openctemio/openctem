package postgres

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/internal/testdb"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

func newBountyReportFinding(t *testing.T, tenant, asset shared.ID, intake, ref string) *vulnerability.Finding {
	t.Helper()
	f, err := vulnerability.NewFinding(tenant, asset, vulnerability.FindingSourceBugBounty, "bounty-intake",
		vulnerability.SeverityHigh, "Reflected XSS in search "+ref+" "+shared.NewID().String())
	if err != nil {
		t.Fatal(err)
	}
	f.GenerateFingerprint()
	if intake != "" {
		if err := f.SetBountyReport(vulnerability.BountyReport{Intake: intake, Ref: ref, Researcher: "night_owl"}, time.Now()); err != nil {
			t.Fatal(err)
		}
	}
	return f
}

// One finding per report and tenant: the same (intake, ref) twice in a tenant
// is refused with ErrBountyReportExists (a conflict), while another ref, or
// the same ref in another tenant, is a separate row. A finding of another
// source with the same keys in its metadata is outside the index.
func TestBountyReportIdentity_DB(t *testing.T) {
	ctx := context.Background()
	db := openGroupsDB(t)
	repo := NewFindingRepository(&DB{DB: db})
	tenantA := seedTestTenant(ctx, t, db)
	tenantB := seedTestTenant(ctx, t, db)
	assetA := seedOwnedAsset(ctx, t, db, tenantA, nil)
	assetB := seedOwnedAsset(ctx, t, db, tenantB, nil)

	first := newBountyReportFinding(t, tenantA, assetA, "main-program", "R-1")
	if err := repo.Create(ctx, first); err != nil {
		t.Fatalf("create first: %v", err)
	}

	dup := newBountyReportFinding(t, tenantA, assetA, "main-program", "R-1")
	err := repo.Create(ctx, dup)
	if !errors.Is(err, vulnerability.ErrBountyReportExists) || !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("same report twice in a tenant: want ErrBountyReportExists, got %v", err)
	}

	if err := repo.Create(ctx, newBountyReportFinding(t, tenantA, assetA, "main-program", "R-2")); err != nil {
		t.Fatalf("another ref: %v", err)
	}
	if err := repo.Create(ctx, newBountyReportFinding(t, tenantA, assetA, "vdp", "R-1")); err != nil {
		t.Fatalf("same ref on another intake: %v", err)
	}
	other := newBountyReportFinding(t, tenantB, assetB, "main-program", "R-1")
	if err := repo.Create(ctx, other); err != nil {
		t.Fatalf("same report in another tenant: %v", err)
	}

	// A manual finding whose metadata happens to carry the same keys is not
	// a bounty report and never conflicts.
	if _, err := db.ExecContext(ctx, `
		INSERT INTO findings (id, tenant_id, asset_id, source, tool_name, severity, message, fingerprint, metadata)
		VALUES ($1, $2, $3, 'manual', 'm', 'low', 'm', $4, '{"bounty_report": {"intake": "main-program", "ref": "R-1"}}')`,
		shared.NewID().String(), tenantA.String(), assetA.String(), "fp-"+shared.NewID().String()); err != nil {
		t.Fatalf("manual finding with the same keys: %v", err)
	}

	// Lookup is per tenant.
	got, err := repo.FindByBountyReport(ctx, tenantA, "main-program", "R-1")
	if err != nil || got.ID() != first.ID() {
		t.Fatalf("find in tenant A = %v, %v; want %s", got, err, first.ID())
	}
	if r := got.BountyReport(); r == nil || r.Researcher != "night_owl" {
		t.Fatalf("report read back = %+v", r)
	}
	got, err = repo.FindByBountyReport(ctx, tenantB, "main-program", "R-1")
	if err != nil || got.ID() != other.ID() {
		t.Fatalf("find in tenant B = %v, %v; want %s", got, err, other.ID())
	}
	if _, err := repo.FindByBountyReport(ctx, tenantB, "main-program", "R-2"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("tenant A's report from tenant B: want not found, got %v", err)
	}

	// Setting a report on a bug_bounty finding that had none: the same
	// identity as an existing report is refused on update too.
	bare := newBountyReportFinding(t, tenantA, assetA, "", "")
	if err := repo.Create(ctx, bare); err != nil {
		t.Fatalf("create bare: %v", err)
	}
	stored, err := repo.GetByID(ctx, tenantA, bare.ID())
	if err != nil {
		t.Fatal(err)
	}
	if err := stored.SetBountyReport(vulnerability.BountyReport{Intake: "main-program", Ref: "R-2"}, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := repo.Update(ctx, stored); !errors.Is(err, vulnerability.ErrBountyReportExists) {
		t.Fatalf("update to an existing report: want ErrBountyReportExists, got %v", err)
	}
}

// The migration builds a valid unique partial index, and its down step
// removes it (up, down, up). DDL runs as the schema owner.
func TestMigrationFindingsBountyReportRefUnique_DB(t *testing.T) {
	if testdb.URL() == "" {
		testdb.Skipf(t, "DATABASE_URL not set")
	}
	ctx := context.Background()
	db, err := sql.Open("postgres", testdb.MigratorURL())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	read := func(suffix string) string {
		t.Helper()
		files, err := filepath.Glob("../../../migrations/*_findings_bounty_report_ref_unique." + suffix + ".sql")
		if err != nil || len(files) != 1 {
			t.Fatalf("migration file: %v %v", files, err)
		}
		b, err := os.ReadFile(files[0])
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	state := func() (exists, valid, unique bool) {
		t.Helper()
		err := db.QueryRowContext(ctx, `SELECT i.indisvalid, i.indisunique FROM pg_index i
			JOIN pg_class c ON c.oid = i.indexrelid WHERE c.relname = $1`, bountyReportIndex).Scan(&valid, &unique)
		if errors.Is(err, sql.ErrNoRows) {
			return false, false, false
		}
		if err != nil {
			t.Fatal(err)
		}
		return true, valid, unique
	}
	if e, v, u := state(); !e || !v || !u {
		t.Fatalf("after migrate: exists=%v valid=%v unique=%v", e, v, u)
	}
	if _, err := db.ExecContext(ctx, read("down")); err != nil {
		t.Fatalf("down: %v", err)
	}
	if e, _, _ := state(); e {
		t.Fatal("down left the index")
	}
	if _, err := db.ExecContext(ctx, read("up")); err != nil {
		t.Fatalf("up again: %v", err)
	}
	if e, v, u := state(); !e || !v || !u {
		t.Fatalf("after up again: exists=%v valid=%v unique=%v", e, v, u)
	}
}
