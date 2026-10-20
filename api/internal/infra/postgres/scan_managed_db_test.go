package postgres

// Managed scans (scans.managed_by / managed_key): stored and found by key,
// unique per tenant, listed by origin, and backfilled only for ownerless
// platform scans.

import (
	"context"
	"errors"
	"testing"

	"github.com/openctemio/openctem/api/internal/testdb"
	"github.com/openctemio/openctem/api/pkg/domain/scan"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/pagination"
)

func newManagedTestScan(t *testing.T, tenant shared.ID, name string, owner shared.ID) *scan.Scan {
	t.Helper()
	sc, err := scan.NewScan(tenant, name, owner, scan.ScanTypeSingle)
	if err != nil {
		t.Fatal(err)
	}
	sc.SetTargets([]string{"example.com"})
	if err := sc.SetSingleScanner("nuclei", nil, 1); err != nil {
		t.Fatal(err)
	}
	return sc
}

func TestScanManaged_KeyUniqueAndOrigin_DB(t *testing.T) {
	ctx := context.Background()
	db := openScanDB(t)
	repo := NewScanRepository(&DB{DB: db})
	tenant := seedScanTriggerTenant(ctx, t, db)
	other := seedScanTriggerTenant(ctx, t, db)

	person := newManagedTestScan(t, tenant, "Weekly", shared.ID{})
	person.AdHoc = false
	managed := newManagedTestScan(t, tenant, "Continuous coverage: probe.http", shared.ID{})
	managed.AdHoc = true
	managed.ManagedBy, managed.ManagedKey = scan.ManagedByCoverage, "probe.http"
	for _, sc := range []*scan.Scan{person, managed} {
		if err := repo.Create(ctx, sc); err != nil {
			t.Fatal(err)
		}
		id := sc.ID.String()
		t.Cleanup(func() { _, _ = db.ExecContext(context.Background(), `DELETE FROM scans WHERE id = $1`, id) })
	}

	got, err := repo.GetManaged(ctx, tenant, scan.ManagedByCoverage, "probe.http")
	if err != nil || got.ID != managed.ID || got.ManagedBy != scan.ManagedByCoverage || got.ManagedKey != "probe.http" || !got.IsManaged() {
		t.Fatalf("GetManaged = %+v, %v", got, err)
	}
	if byID, err := repo.GetByTenantAndID(ctx, tenant, managed.ID); err != nil || !byID.IsManaged() {
		t.Fatalf("managed fields not read back by id: %+v %v", byID, err)
	}
	if p, err := repo.GetByTenantAndID(ctx, tenant, person.ID); err != nil || p.IsManaged() {
		t.Fatalf("a person's scan reads back as managed: %+v %v", p, err)
	}
	// Another tenant never sees it.
	if _, err := repo.GetManaged(ctx, other, scan.ManagedByCoverage, "probe.http"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cross-tenant GetManaged err = %v, want not found", err)
	}
	if _, err := repo.GetManaged(ctx, tenant, scan.ManagedByEnrichment, "probe.http"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("other owner GetManaged err = %v, want not found", err)
	}

	// Unique per tenant and key, even under another name.
	dup := newManagedTestScan(t, tenant, "Something else", shared.ID{})
	dup.ManagedBy, dup.ManagedKey = scan.ManagedByCoverage, "probe.http"
	if err := repo.Create(ctx, dup); err == nil {
		t.Fatal("a second managed scan with the same key was stored")
	}
	// The same key in another tenant is fine.
	elsewhere := newManagedTestScan(t, other, "Continuous coverage: probe.http", shared.ID{})
	elsewhere.ManagedBy, elsewhere.ManagedKey = scan.ManagedByCoverage, "probe.http"
	if err := repo.Create(ctx, elsewhere); err != nil {
		t.Fatalf("same key in another tenant: %v", err)
	}
	t.Cleanup(func() {
		_, _ = db.ExecContext(context.Background(), `DELETE FROM scans WHERE id = $1`, elsewhere.ID.String())
	})

	// An update never rewrites the owner columns.
	got.Description = "changed"
	if err := repo.Update(ctx, got); err != nil {
		t.Fatal(err)
	}
	if again, _ := repo.GetManaged(ctx, tenant, scan.ManagedByCoverage, "probe.http"); again == nil || again.Description != "changed" {
		t.Fatalf("update lost the managed scan: %+v", again)
	}

	names := func(f scan.Filter) []string {
		t.Helper()
		f.TenantID = &tenant
		res, err := repo.List(ctx, f, pagination.New(1, 50))
		if err != nil {
			t.Fatal(err)
		}
		var out []string
		for _, s := range res.Data {
			out = append(out, s.Name)
		}
		return out
	}
	if n := names(scan.Filter{Origin: scan.OriginSystem, ExcludeAdHoc: true}); len(n) != 1 || n[0] != managed.Name {
		t.Fatalf("origin=system = %v, want only the managed scan", n)
	}
	if n := names(scan.Filter{Origin: scan.OriginUser}); len(n) != 1 || n[0] != person.Name {
		t.Fatalf("origin=user = %v, want only the person's scan", n)
	}
	if n := names(scan.Filter{ExcludeAdHoc: true}); len(n) != 1 || n[0] != person.Name {
		t.Fatalf("default list = %v, want the managed (ad hoc) scan hidden", n)
	}
}

// The migration marks only ownerless platform scans as managed: a person's
// scan that carries the coverage name or tag is theirs, and the down
// migration drops the columns again.
func TestScanManagedMigrationBackfill_DB(t *testing.T) {
	dir := "../../../migrations"
	db := testdb.PrivateDatabase(t, "scan_managed", dir)
	ctx := context.Background()
	repo := NewScanRepository(&DB{DB: db})
	tenant := seedScanTriggerTenant(ctx, t, db)
	member := seedSWUser(ctx, t, db)
	v := testdb.MigrationVersion(t, dir, "scan_managed_by")
	testdb.Migrate(t, db, dir, v, v, true)

	// Written through plain SQL: the columns do not exist right now.
	insert := func(name string, tag string, owner *shared.ID) string {
		t.Helper()
		sc := newManagedTestScan(t, tenant, name, shared.ID{})
		var createdBy any
		if owner != nil {
			createdBy = owner.String()
		}
		if _, err := db.ExecContext(ctx, `
			INSERT INTO scans (id, tenant_id, name, scan_type, scanner_name, scanner_config, targets, tags, status, created_by, ad_hoc)
			VALUES ($1, $2, $3, 'single', 'nuclei', '{}', '{example.com}', $4, 'active', $5, true)`,
			sc.ID.String(), tenant.String(), name, "{"+tag+"}", createdBy); err != nil {
			t.Fatal(err)
		}
		return sc.ID.String()
	}
	cov := insert("Continuous coverage: probe.http", "auto-coverage", nil)
	enr := insert("Automatic enrichment - 20261020-101010", "auto-enrichment", nil)
	userSame := insert("Continuous coverage: scan.ports", "auto-coverage", &member)
	userTag := insert("My scan", "auto-enrichment", &member)

	testdb.Migrate(t, db, dir, v, v, false)

	by := func(id string) (string, string) {
		var b, k string
		if err := db.QueryRowContext(ctx, `SELECT COALESCE(managed_by,''), COALESCE(managed_key,'') FROM scans WHERE id = $1`, id).Scan(&b, &k); err != nil {
			t.Fatal(err)
		}
		return b, k
	}
	if b, k := by(cov); b != "coverage" || k != "probe.http" {
		t.Fatalf("coverage scan backfilled as %q/%q", b, k)
	}
	if b, k := by(enr); b != "enrichment" || k != enr {
		t.Fatalf("enrichment scan backfilled as %q/%q", b, k)
	}
	for _, id := range []string{userSame, userTag} {
		if b, _ := by(id); b != "" {
			t.Fatalf("a person's scan %s was marked managed (%q)", id, b)
		}
	}
	if sc, err := repo.GetManaged(ctx, tenant, scan.ManagedByCoverage, "probe.http"); err != nil || sc.ID.String() != cov {
		t.Fatalf("GetManaged after backfill: %v %v", sc, err)
	}

	testdb.Migrate(t, db, dir, v, v, true)
	var cols int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM information_schema.columns
		WHERE table_name = 'scans' AND column_name IN ('managed_by','managed_key')`).Scan(&cols); err != nil || cols != 0 {
		t.Fatalf("down left %d columns (%v)", cols, err)
	}
}
