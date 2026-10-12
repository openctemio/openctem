package integration

import (
	"context"
	"database/sql"
	"testing"

	"github.com/openctemio/ctis"

	"github.com/openctemio/openctem/api/internal/app/ingest"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// Asset identity model: assets are matched on strong identifiers first, then
// the exact name, then a recent hostname, then an unambiguous IP seen within
// the 7-day window. Conflicts become duplicate reviews; nothing auto-merges.

type identityFixture struct {
	db     *sql.DB
	tenant shared.ID
	proc   *ingest.AssetProcessor
	dedup  *postgres.AssetDedupRepository
	ids    *postgres.AssetIdentifierRepository
}

func newIdentityFixture(t *testing.T, tag string) *identityFixture {
	t.Helper()
	db := setupTestDB(t)
	tenant := createTestTenant(t, db, tag)
	t.Cleanup(func() {
		_, _ = db.Exec(`DELETE FROM asset_dedup_review WHERE tenant_id=$1`, tenant.String())
		_, _ = db.Exec(`DELETE FROM asset_identity_backfill WHERE tenant_id=$1`, tenant.String())
		_, _ = db.Exec(`DELETE FROM assets WHERE tenant_id=$1`, tenant.String())
		_, _ = db.Exec(`DELETE FROM tenants WHERE id=$1`, tenant.String())
		_ = db.Close()
	})
	pdb := &postgres.DB{DB: db}
	log := logger.NewNop()
	repo := postgres.NewAssetRepository(pdb)
	f := &identityFixture{
		db: db, tenant: tenant,
		proc:  ingest.NewAssetProcessor(repo, log),
		dedup: postgres.NewAssetDedupRepository(pdb),
		ids:   postgres.NewAssetIdentifierRepository(pdb, repo),
	}
	f.proc.SetCorrelator(ingest.NewAssetCorrelator(repo, log, ingest.CorrelationConfig{}))
	f.proc.SetDedupEnqueuer(f.dedup)
	f.proc.SetIdentityStore(f.ids, f.dedup)
	f.proc.SetStateHistoryRepository(postgres.NewAssetStateHistoryRepository(pdb))
	return f
}

func (f *identityFixture) ingest(t *testing.T, tool string, assets ...ctis.Asset) {
	t.Helper()
	out := &ingest.Output{}
	if _, err := f.proc.ProcessBatch(context.Background(), f.tenant,
		&ctis.Report{Tool: &ctis.Tool{Name: tool}, Assets: assets}, out, nil); err != nil {
		t.Fatalf("ProcessBatch: %v", err)
	}
	if len(out.Errors) > 0 {
		t.Fatalf("ingest errors: %v", out.Errors)
	}
}

func (f *identityFixture) names(t *testing.T) []string {
	t.Helper()
	rows, err := f.db.Query(`SELECT name FROM assets WHERE tenant_id=$1 ORDER BY name`, f.tenant.String())
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var n string
		_ = rows.Scan(&n)
		out = append(out, n)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

func (f *identityFixture) count(t *testing.T, q string, args ...any) int {
	t.Helper()
	var n int
	if err := f.db.QueryRow(q, args...).Scan(&n); err != nil {
		t.Fatalf("%s: %v", q, err)
	}
	return n
}

func (f *identityFixture) reviews(t *testing.T) []postgres.AssetDedupReview {
	t.Helper()
	r, err := f.dedup.ListPendingReviews(context.Background(), f.tenant.String(), nil)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func host(name string, props ctis.Properties, ids *ctis.AssetIdentifiers) ctis.Asset {
	return ctis.Asset{ID: name, Type: ctis.AssetTypeHost, Value: name, Properties: props, Identifiers: ids}
}

func TestAssetIdentity_RenameBySameMACNewIP(t *testing.T) {
	f := newIdentityFixture(t, "ident-mac")
	f.ingest(t, "nessus", host("mac-old.corp.example", ctis.Properties{"ip_addresses": []any{"10.70.0.1"}},
		&ctis.AssetIdentifiers{MACAddresses: []string{"00:1a:2b:3c:4d:5e"}}))
	f.ingest(t, "nessus", host("mac-new.corp.example", ctis.Properties{"ip_addresses": []any{"10.70.0.99"}},
		&ctis.AssetIdentifiers{MACAddresses: []string{"00:1A:2B:3C:4D:5E"}}))

	if got := f.names(t); len(got) != 1 || got[0] != "mac-new.corp.example" {
		t.Fatalf("assets = %v, want one asset renamed to mac-new.corp.example", got)
	}
	if n := f.count(t, `SELECT count(*) FROM asset_state_history WHERE tenant_id=$1 AND change_type='renamed'
		AND old_value='mac-old.corp.example' AND new_value='mac-new.corp.example'`, f.tenant.String()); n != 1 {
		t.Fatalf("renamed history rows = %d, want 1", n)
	}
}

func TestAssetIdentity_NessusMACPropertyMatches(t *testing.T) {
	f := newIdentityFixture(t, "ident-macprop")
	f.ingest(t, "nessus", host("np-old", ctis.Properties{"mac_address": "00:1a:2b:3c:4d:6f"}, nil))
	f.ingest(t, "nessus", host("np-new", ctis.Properties{"mac_address": "00:1a:2b:3c:4d:6f\n02:42:ac:11:00:02"}, nil))
	if got := f.names(t); len(got) != 1 || got[0] != "np-new" {
		t.Fatalf("assets = %v, want one asset np-new", got)
	}
	// The locally administered (Docker) MAC is not an identifier.
	if n := f.count(t, `SELECT count(*) FROM asset_identifiers WHERE tenant_id=$1 AND kind='mac'`, f.tenant.String()); n != 1 {
		t.Fatalf("mac identifiers = %d, want 1", n)
	}
}

func TestAssetIdentity_DHCPReuseAfterWindow(t *testing.T) {
	f := newIdentityFixture(t, "ident-dhcp")
	f.ingest(t, "nessus", host("dhcp-a", ctis.Properties{"ip_addresses": []any{"10.70.1.5"}}, nil))
	// The IP was last seen on dhcp-a 8 days ago, though the asset itself was
	// seen today: the IP no longer counts.
	if _, err := f.db.Exec(`UPDATE asset_identifiers SET last_seen = NOW() - INTERVAL '8 days'
		WHERE tenant_id=$1 AND kind='ip'`, f.tenant.String()); err != nil {
		t.Fatal(err)
	}
	f.ingest(t, "nessus", host("dhcp-b", ctis.Properties{"ip_addresses": []any{"10.70.1.5"}}, nil))
	if got := f.names(t); len(got) != 2 {
		t.Fatalf("assets = %v, want dhcp-a and dhcp-b kept apart", got)
	}
}

func TestAssetIdentity_TwoScannersOneHost(t *testing.T) {
	f := newIdentityFixture(t, "ident-2scan")
	f.ingest(t, "nessus", host("web01.corp.example", ctis.Properties{"ip_address": "10.70.2.10"}, nil))
	// Vuls names the host by short name and sends the IP as the value.
	f.ingest(t, "vuls", ctis.Asset{ID: "v", Type: ctis.AssetTypeHost, Name: "web01", Value: "10.70.2.10"})
	// Later it reports from a new IP: matched by the hostname it was seen with.
	f.ingest(t, "vuls", ctis.Asset{ID: "v", Type: ctis.AssetTypeHost, Name: "web01", Value: "10.70.2.11"})
	if got := f.names(t); len(got) != 1 || got[0] != "web01.corp.example" {
		t.Fatalf("assets = %v, want one asset keeping its FQDN", got)
	}
}

func TestAssetIdentity_ConflictGoesToReview(t *testing.T) {
	f := newIdentityFixture(t, "ident-conflict")
	f.ingest(t, "nessus", host("conf-a", nil, &ctis.AssetIdentifiers{MACAddresses: []string{"00:1a:2b:00:00:01"}}))
	f.ingest(t, "nessus", host("conf-b", nil, &ctis.AssetIdentifiers{BIOSUUID: "4c4c4544-0042-3510-8051-b4c04f4e4d32"}))
	// MAC says conf-a, BIOS UUID (ranked higher) says conf-b.
	f.ingest(t, "nessus", host("conf-c", nil, &ctis.AssetIdentifiers{
		MACAddresses: []string{"00:1a:2b:00:00:01"}, BIOSUUID: "4C4C4544-0042-3510-8051-B4C04F4E4D32",
	}))
	if got := f.names(t); len(got) != 2 {
		t.Fatalf("assets = %v, want two assets (no merge)", got)
	}
	revs := f.reviews(t)
	if len(revs) != 1 || revs[0].Reason == nil || *revs[0].Reason != "identifier_conflict" {
		t.Fatalf("reviews = %+v, want one identifier_conflict review", revs)
	}
	if revs[0].Evidence["kind"] != "mac" {
		t.Fatalf("evidence = %v, want the shared MAC", revs[0].Evidence)
	}
}

func TestAssetIdentity_HigherRankedConflictVetoes(t *testing.T) {
	f := newIdentityFixture(t, "ident-veto")
	f.ingest(t, "sensor", host("veto-a", nil, &ctis.AssetIdentifiers{MachineID: "aaaa1111", MACAddresses: []string{"00:1a:2b:00:00:09"}}))
	f.ingest(t, "sensor", host("veto-b", nil, &ctis.AssetIdentifiers{MachineID: "bbbb2222", MACAddresses: []string{"00:1a:2b:00:00:09"}}))
	if got := f.names(t); len(got) != 2 {
		t.Fatalf("assets = %v, want a new asset: a different host ID vetoes the MAC match", got)
	}
	if revs := f.reviews(t); len(revs) != 1 {
		t.Fatalf("reviews = %d, want 1 for the shared MAC", len(revs))
	}
}

func TestAssetIdentity_RepositoryRenamedSameSCMID(t *testing.T) {
	f := newIdentityFixture(t, "ident-repo")
	repo := func(name string) ctis.Asset {
		return ctis.Asset{ID: name, Type: ctis.AssetTypeRepository, Value: name,
			Identifiers: &ctis.AssetIdentifiers{SCMRepoID: "123456"}}
	}
	f.ingest(t, "github", repo("github.com/acme/old-repo"))
	f.ingest(t, "github", repo("github.com/acme/new-repo"))
	if got := f.names(t); len(got) != 1 || got[0] != "github.com/acme/new-repo" {
		t.Fatalf("assets = %v, want the repository renamed", got)
	}
	if n := f.count(t, `SELECT count(*) FROM asset_identifiers WHERE tenant_id=$1 AND kind='scm_repo_id' AND value='github.com:123456'`,
		f.tenant.String()); n != 1 {
		t.Fatalf("scm_repo_id identifiers = %d, want 1", n)
	}
}

func TestAssetIdentity_BackfillQueuesReviewsWithoutMerging(t *testing.T) {
	f := newIdentityFixture(t, "ident-backfill")
	seed := func(name, tool, props string) {
		if _, err := f.db.Exec(`INSERT INTO assets (id, tenant_id, name, asset_type, criticality, status, properties,
			discovery_tool, last_seen, created_at, updated_at)
			VALUES ($1,$2,$3,'host','medium','active',$4::jsonb,$5, NOW(), NOW(), NOW())`,
			shared.NewID().String(), f.tenant.String(), name, props, tool); err != nil {
			t.Fatalf("seed %s: %v", name, err)
		}
	}
	// Two assets carrying one MAC.
	seed("dup-mac-1", "qualys", `{"mac_address":"00:1a:2b:3c:00:01"}`)
	seed("dup-mac-2", "qualys", `{"mac_address":"00:1a:2b:3c:00:01"}`)
	// A Nessus host renamed before the Nessus IP shape was matched.
	seed("old-name.corp", "nessus", `{"ip_address":"10.70.9.9"}`)
	seed("new-name.corp", "nessus", `{"ip_address":"10.70.9.9"}`)
	// Unrelated host.
	seed("lonely", "nessus", `{"ip_address":"10.70.9.10"}`)

	pdb := &postgres.DB{DB: f.db}
	b := ingest.NewIdentityBackfill(postgres.NewAssetIdentityBackfillRepository(pdb), f.ids, f.dedup, logger.NewNop())
	stats, err := b.RunTenant(context.Background(), f.tenant)
	if err != nil {
		t.Fatal(err)
	}
	if stats.AssetsScanned != 5 {
		t.Fatalf("scanned %d assets, want 5", stats.AssetsScanned)
	}
	if got := f.names(t); len(got) != 5 {
		t.Fatalf("assets = %v, backfill must not merge", got)
	}
	reasons := map[string]int{}
	for _, r := range f.reviews(t) {
		if r.Reason != nil {
			reasons[*r.Reason]++
		}
	}
	if reasons["shared_identifier"] != 1 || reasons["renamed_host"] != 1 {
		t.Fatalf("review reasons = %v, want one shared_identifier and one renamed_host", reasons)
	}

	// A second run is idempotent: no new reviews.
	if _, err := b.RunTenant(context.Background(), f.tenant); err != nil {
		t.Fatal(err)
	}
	if n := len(f.reviews(t)); n != 2 {
		t.Fatalf("reviews after rerun = %d, want 2", n)
	}
}
