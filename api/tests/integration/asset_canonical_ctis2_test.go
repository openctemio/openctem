package integration

import (
	"context"
	"database/sql"
	"errors"
	"testing"

	"github.com/openctemio/openctem/api/internal/app/assetcanon"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// The CTIS 2.0 asset name migration (internal/app/assetcanon): a stored name
// in a non-canonical spelling is renamed (same asset, same findings), or
// merged into the asset of the same type that already holds the canonical
// name (findings follow, their triage is kept, nothing is split or
// duplicated); another type holding the name is a recorded conflict; a dry
// run changes nothing; a second run changes nothing; another tenant is never
// touched; -revert gives renamed assets their old names back.
func TestAssetCanonicalCTIS2(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()
	ctx := context.Background()
	tenant := createTestTenant(t, db, "ctis2canon")
	other := createTestTenant(t, db, "ctis2canon-other")
	defer cleanupTestData(db, tenant, other)

	asset := func(tid shared.ID, typ, sub, name string) shared.ID {
		t.Helper()
		id := shared.NewID()
		var subType any
		if sub != "" {
			subType = sub
		}
		if _, err := db.Exec(`INSERT INTO assets (id, tenant_id, name, asset_type, sub_type, criticality, status, created_at, updated_at)
			VALUES ($1, $2, $3, $4, $5, 'medium', 'active', NOW(), NOW())`, id.String(), tid.String(), name, typ, subType); err != nil {
			t.Fatalf("asset %s: %v", name, err)
		}
		return id
	}
	finding := func(tid, assetID shared.ID, status string) shared.ID {
		t.Helper()
		id := createTestFinding(t, db, tid, assetID, "ctis2 canonical "+status)
		if _, err := db.Exec(`UPDATE findings SET status = $3 WHERE tenant_id = $1 AND id = $2`, tid.String(), id.String(), status); err != nil {
			t.Fatal(err)
		}
		return id
	}
	name := func(id shared.ID) string {
		t.Helper()
		var n string
		if err := db.QueryRow(`SELECT name FROM assets WHERE id = $1`, id.String()).Scan(&n); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return "<deleted>"
			}
			t.Fatal(err)
		}
		return n
	}
	count := func(q string, args ...any) int {
		t.Helper()
		var n int
		if err := db.QueryRow(q, args...).Scan(&n); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
		return n
	}
	findingOf := func(id shared.ID) (assetID, status string) {
		t.Helper()
		if err := db.QueryRow(`SELECT asset_id, status FROM findings WHERE id = $1`, id.String()).Scan(&assetID, &status); err != nil {
			t.Fatal(err)
		}
		return
	}

	// Rename: a Unicode host name, with a confirmed finding.
	renamed := asset(tenant, "subdomain", "", "bücher.example.com")
	rf := finding(tenant, renamed, "confirmed")
	// Merge: the canonical asset exists; the old spelling carries a finding
	// triaged false positive.
	keep := asset(tenant, "subdomain", "", "xn--bcher-kva.shop.example")
	kf := finding(tenant, keep, "new")
	dup := asset(tenant, "subdomain", "", "bücher.shop.example")
	df := finding(tenant, dup, "false_positive")
	// Conflict: the canonical name belongs to another type.
	asset(tenant, "domain", "", "xn--caf-dma.example.com")
	conflict := asset(tenant, "subdomain", "", "café.example.com")
	// Already canonical and an open port: unchanged.
	asset(tenant, "service", "open_port", "203.0.113.5:443:tcp")
	// The other tenant has the same old spelling and the canonical name of
	// the tenant's renamed asset: neither may play any part in its run.
	foreignOld := asset(other, "subdomain", "", "bücher.shop.example")
	foreignCanon := asset(other, "subdomain", "", "xn--bcher-kva.example.com")

	assetsBefore := count(`SELECT count(*) FROM assets WHERE tenant_id = $1`, tenant.String())
	findingsBefore := count(`SELECT count(*) FROM findings WHERE tenant_id = $1`, tenant.String())
	svc := assetcanon.NewService(postgres.NewAssetCanonicalRepository(&postgres.DB{DB: db}))

	dry, err := svc.Run(ctx, tenant, false)
	if err != nil {
		t.Fatal(err)
	}
	if dry.Renamed != 1 || dry.Merged != 1 || dry.Conflicts != 1 {
		t.Fatalf("dry run = %+v", dry)
	}
	if name(renamed) != "bücher.example.com" || name(dup) != "bücher.shop.example" ||
		count(`SELECT count(*) FROM asset_canonical_changes WHERE tenant_id = $1`, tenant.String()) != 0 {
		t.Fatal("the dry run changed something")
	}

	rep, err := svc.Run(ctx, tenant, true)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Renamed != 1 || rep.Merged != 1 || rep.Conflicts != 1 || rep.Raced != 0 {
		t.Fatalf("run = %+v", rep)
	}
	// Same record: the renamed asset keeps its id and its finding.
	if name(renamed) != "xn--bcher-kva.example.com" {
		t.Errorf("renamed asset is %q", name(renamed))
	}
	if a, s := findingOf(rf); a != renamed.String() || s != "confirmed" {
		t.Errorf("finding of the renamed asset: asset %s status %s", a, s)
	}
	// Merge: the duplicate is gone, its finding moved with its triage.
	if name(dup) != "<deleted>" {
		t.Errorf("merged asset still exists as %q", name(dup))
	}
	if a, s := findingOf(df); a != keep.String() || s != "false_positive" {
		t.Errorf("merged finding: asset %s status %s, want on %s and false_positive", a, s, keep)
	}
	if a, _ := findingOf(kf); a != keep.String() {
		t.Errorf("kept asset's finding moved to %s", a)
	}
	// No split, no loss: one asset fewer (the merge), every finding kept.
	if n := count(`SELECT count(*) FROM assets WHERE tenant_id = $1`, tenant.String()); n != assetsBefore-1 {
		t.Errorf("assets %d, want %d", n, assetsBefore-1)
	}
	if n := count(`SELECT count(*) FROM findings WHERE tenant_id = $1`, tenant.String()); n != findingsBefore {
		t.Errorf("findings %d, want %d", n, findingsBefore)
	}
	// Conflict: left as is, recorded once.
	if name(conflict) != "café.example.com" ||
		count(`SELECT count(*) FROM asset_canonical_changes WHERE tenant_id = $1 AND action = 'conflict'`, tenant.String()) != 1 {
		t.Error("conflict not recorded once, or the asset changed")
	}
	// Cross-tenant negative.
	if name(foreignOld) != "bücher.shop.example" || name(foreignCanon) != "xn--bcher-kva.example.com" ||
		count(`SELECT count(*) FROM asset_canonical_changes WHERE tenant_id = $1`, other.String()) != 0 {
		t.Error("the other tenant changed during the tenant's run")
	}

	// Idempotent.
	again, err := svc.Run(ctx, tenant, true)
	if err != nil {
		t.Fatal(err)
	}
	if again.Renamed != 0 || again.Merged != 0 ||
		count(`SELECT count(*) FROM asset_canonical_changes WHERE tenant_id = $1 AND action = 'conflict'`, tenant.String()) != 1 {
		t.Fatalf("second run = %+v", again)
	}

	// Revert gives the renamed asset its old name back; a re-run applies it
	// again.
	reverted, kept, err := svc.Revert(ctx, tenant)
	if err != nil || reverted != 1 || kept != 0 {
		t.Fatalf("revert: %d %d %v", reverted, kept, err)
	}
	if name(renamed) != "bücher.example.com" {
		t.Errorf("after revert the asset is %q", name(renamed))
	}
	if rep, err := svc.Run(ctx, tenant, true); err != nil || rep.Renamed != 1 {
		t.Fatalf("re-apply after revert: %+v %v", rep, err)
	}

	// The other tenant's own run: its old spelling is merged into nothing
	// of the first tenant (it is renamed in its own tenant).
	orep, err := svc.Run(ctx, other, true)
	if err != nil {
		t.Fatal(err)
	}
	if orep.Renamed != 1 || orep.Merged != 0 {
		t.Fatalf("other tenant's run = %+v", orep)
	}
	if got := name(foreignOld); got != "xn--bcher-kva.shop.example" {
		t.Errorf("other tenant's asset is %q", got)
	}
	if name(keep) != "xn--bcher-kva.shop.example" {
		t.Error("the tenant's kept asset changed in the other tenant's run")
	}
}
