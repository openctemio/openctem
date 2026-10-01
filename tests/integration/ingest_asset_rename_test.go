package integration

import (
	"context"
	"database/sql"
	"encoding/json"
	"testing"

	"github.com/openctemio/api/internal/app/ingest"
	"github.com/openctemio/api/internal/infra/postgres"
	"github.com/openctemio/api/pkg/domain/asset"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/logger"
	"github.com/openctemio/ctis"
)

// A host that is renamed while keeping its IP must stay one asset and take
// the new name, and the rename must persist. Before the fix the rename was
// computed in memory and then rejected by the upsert (its conflict key is
// tenant+name, so the row's own id hit assets_pkey), which rolled back every
// asset in the report.

type renameFixture struct {
	db     *sql.DB
	tenant shared.ID
	proc   *ingest.AssetProcessor
}

func newRenameFixture(t *testing.T, tag string) *renameFixture {
	t.Helper()
	db := setupTestDB(t)
	tenant := createTestTenant(t, db, tag)
	t.Cleanup(func() {
		_, _ = db.Exec(`DELETE FROM asset_owners WHERE asset_id IN (SELECT id FROM assets WHERE tenant_id=$1)`, tenant.String())
		_, _ = db.Exec(`DELETE FROM assets WHERE tenant_id=$1`, tenant.String())
		_, _ = db.Exec(`DELETE FROM tenants WHERE id=$1`, tenant.String())
		_ = db.Close()
	})
	log := logger.NewNop()
	repo := postgres.NewAssetRepository(&postgres.DB{DB: db})
	proc := ingest.NewAssetProcessor(repo, log)
	proc.SetCorrelator(ingest.NewAssetCorrelator(repo, log, ingest.CorrelationConfig{StaleAssetDays: 30, MaxIPsPerAsset: 20}))
	return &renameFixture{db: db, tenant: tenant, proc: proc}
}

func (f *renameFixture) ingest(t *testing.T, assets ...ctis.Asset) (map[string]shared.ID, *ingest.Output) {
	t.Helper()
	out := &ingest.Output{}
	m, err := f.proc.ProcessBatch(context.Background(), f.tenant, &ctis.Report{Assets: assets}, out, nil)
	if err != nil {
		t.Fatalf("ProcessBatch: %v", err)
	}
	return m, out
}

type storedAsset struct {
	name        string
	criticality string
	aliases     []string
}

func (f *renameFixture) assets(t *testing.T) map[string]storedAsset {
	t.Helper()
	rows, err := f.db.Query(`SELECT id, name, criticality, COALESCE(properties->'aliases', '[]') FROM assets WHERE tenant_id=$1`, f.tenant.String())
	if err != nil {
		t.Fatalf("query assets: %v", err)
	}
	defer rows.Close()
	out := map[string]storedAsset{}
	for rows.Next() {
		var id, name, crit string
		var raw []byte
		if err := rows.Scan(&id, &name, &crit, &raw); err != nil {
			t.Fatalf("scan: %v", err)
		}
		var aliases []string
		_ = json.Unmarshal(raw, &aliases)
		out[id] = storedAsset{name: name, criticality: crit, aliases: aliases}
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate assets: %v", err)
	}
	return out
}

func hostAsset(ref, name string, props ctis.Properties) ctis.Asset {
	return ctis.Asset{ID: ref, Type: ctis.AssetTypeHost, Value: name, Name: name, Properties: props}
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

func TestIngestRename_IPToHostnamePersistsAndKeepsBatch(t *testing.T) {
	f := newRenameFixture(t, "renameupgrade")

	first, _ := f.ingest(t, hostAsset("h1", "10.77.0.1", nil))
	id := first["h1"]

	// Same host now reported by FQDN, plus a host never seen before.
	second, out := f.ingest(t,
		hostAsset("h1", "web01.corp.example", ctis.Properties{"ip": "10.77.0.1"}),
		hostAsset("h2", "brand-new-host", ctis.Properties{"ip": "10.77.0.2"}),
	)
	if second["h1"] != id {
		t.Fatalf("renamed host mapped to %s, want the existing asset %s", second["h1"], id)
	}
	if out.AssetsCreated != 1 || out.AssetsUpdated != 1 {
		t.Fatalf("created/updated = %d/%d, want 1/1", out.AssetsCreated, out.AssetsUpdated)
	}

	got := f.assets(t)
	if len(got) != 2 {
		t.Fatalf("want 2 assets (renamed + new), got %d: %+v", len(got), got)
	}
	a := got[id.String()]
	if a.name != "web01.corp.example" || !contains(a.aliases, "10.77.0.1") {
		t.Fatalf("existing asset = %+v, want name web01.corp.example with alias 10.77.0.1", a)
	}
	if _, ok := got[second["h2"].String()]; !ok {
		t.Fatalf("new host in the same report was not persisted (the batch rolled back)")
	}
}

func TestIngestRename_SameIPNewHostnameFollowsAndKeepsContext(t *testing.T) {
	f := newRenameFixture(t, "renamelateral")

	first, _ := f.ingest(t, hostAsset("h1", "x-host", ctis.Properties{"ip": "10.77.1.1"}))
	id := first["h1"]
	// What people set on the asset must survive the rename.
	if _, err := f.db.Exec(`UPDATE assets SET criticality='critical' WHERE id=$1`, id.String()); err != nil {
		t.Fatal(err)
	}

	second, _ := f.ingest(t, hostAsset("h1", "y-host", ctis.Properties{"ip": "10.77.1.1"}))
	if second["h1"] != id {
		t.Fatalf("renamed host mapped to %s, want %s", second["h1"], id)
	}
	got := f.assets(t)
	if len(got) != 1 {
		t.Fatalf("want 1 asset, got %d: %+v", len(got), got)
	}
	a := got[id.String()]
	if a.name != "y-host" || !contains(a.aliases, "x-host") || a.criticality != "critical" {
		t.Fatalf("asset = %+v, want name y-host, alias x-host, criticality critical", a)
	}

	// A source still using the old name must not rename it back.
	f.ingest(t, hostAsset("h1", "x-host", ctis.Properties{"ip": "10.77.1.1"}))
	if a := f.assets(t)[id.String()]; a.name != "y-host" {
		t.Fatalf("old name flipped the asset back: %+v", a)
	}

	// A worse name (short after FQDN) is not adopted.
	f.ingest(t, hostAsset("h1", "y-host.corp.example", ctis.Properties{"ip": "10.77.1.1"}))
	f.ingest(t, hostAsset("h1", "z-host", ctis.Properties{"ip": "10.77.1.1"}))
	if a := f.assets(t)[id.String()]; a.name != "y-host.corp.example" {
		t.Fatalf("want FQDN kept, got %+v", a)
	}
}

func TestIngestRename_ScannerShapes(t *testing.T) {
	t.Run("nessus: ip_address as a string", func(t *testing.T) {
		f := newRenameFixture(t, "renamenessus")
		props := func(fqdn string) ctis.Properties {
			return ctis.Properties{"ip_address": "10.77.2.1", "fqdn": fqdn, "mac_address": "00:50:56:aa:bb:01"}
		}
		first, _ := f.ingest(t, hostAsset("h1", "x.corp.example", props("x.corp.example")))
		second, _ := f.ingest(t, hostAsset("h1", "y.corp.example", props("y.corp.example")))
		if second["h1"] != first["h1"] || len(f.assets(t)) != 1 {
			t.Fatalf("renamed Nessus host became a second asset: %+v", f.assets(t))
		}
		if a := f.assets(t)[first["h1"].String()]; a.name != "y.corp.example" {
			t.Fatalf("want y.corp.example, got %+v", a)
		}
	})

	t.Run("vuls: hostname as name, address as value", func(t *testing.T) {
		f := newRenameFixture(t, "renamevuls")
		vuls := func(host string) ctis.Asset {
			return ctis.Asset{ID: "h1", Type: ctis.AssetTypeIPAddress, Value: "10.77.3.1", Name: host,
				Technical: &ctis.AssetTechnical{IPAddress: &ctis.IPAddressTechnical{Version: 4, Hostname: host}}}
		}
		first, _ := f.ingest(t, vuls("x-vuls"))
		second, _ := f.ingest(t, vuls("y-vuls"))
		if second["h1"] != first["h1"] || len(f.assets(t)) != 1 {
			t.Fatalf("renamed Vuls host became a second asset: %+v", f.assets(t))
		}
	})
}

// The repository renames by id inside the upsert transaction; a new name that
// another asset already holds is not forced (the insert merges into that
// asset, as a name match would) and does not fail the batch.
func TestAssetUpsertBatch_RenameByID(t *testing.T) {
	f := newRenameFixture(t, "renamerepo")
	repo := postgres.NewAssetRepository(&postgres.DB{DB: f.db})
	ctx := context.Background()

	mk := func(name string) *asset.Asset {
		a, err := asset.NewAsset(name, asset.AssetTypeHost, asset.CriticalityMedium)
		if err != nil {
			t.Fatal(err)
		}
		a.SetTenantID(f.tenant)
		return a
	}
	a, b := mk("alpha"), mk("bravo")
	if _, _, _, err := repo.UpsertBatch(ctx, []*asset.Asset{a, b}); err != nil {
		t.Fatalf("seed: %v", err)
	}

	if err := a.UpdateName("alpha-renamed"); err != nil {
		t.Fatal(err)
	}
	created, updated, ids, err := repo.UpsertBatch(ctx, []*asset.Asset{a})
	if err != nil {
		t.Fatalf("rename upsert: %v", err)
	}
	if created != 0 || updated != 1 || ids["alpha-renamed"] != a.ID() {
		t.Fatalf("created=%d updated=%d ids=%v, want 0/1 and the same id", created, updated, ids)
	}

	// Rename onto a name another asset holds: no error, bravo absorbs it.
	if err := a.UpdateName("bravo"); err != nil {
		t.Fatal(err)
	}
	if _, _, ids, err = repo.UpsertBatch(ctx, []*asset.Asset{a}); err != nil {
		t.Fatalf("conflicting rename failed the batch: %v", err)
	}
	if ids["bravo"] != b.ID() {
		t.Fatalf("conflicting rename persisted as %s, want bravo's id %s", ids["bravo"], b.ID())
	}
	got := f.assets(t)
	if got[a.ID().String()].name != "alpha-renamed" || got[b.ID().String()].name != "bravo" {
		t.Fatalf("names after conflicting rename: %+v", got)
	}
}
