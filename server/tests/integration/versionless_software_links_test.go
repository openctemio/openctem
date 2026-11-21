package integration

// Version-hidden technologies of curated public products become software
// links (docs/architecture/vulnerability-matching.md, "Version hidden"), at
// ingest and through the backfill of stored technologies, on the shape that
// started it: 109 nginx hosts, 103 of them hiding the version. The
// possibly-affected tier of an emerging-threat alert then lists them; another
// organization's hosts never show; a private name never reaches the catalog;
// a version learned later replaces the version-less link.

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/openctemio/ctis/v2"

	assettechapp "github.com/openctemio/openctem/server/internal/app/assettech"
	"github.com/openctemio/openctem/server/internal/infra/postgres"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
	"github.com/openctemio/openctem/server/pkg/domain/threatalert"
	"github.com/openctemio/openctem/server/pkg/logger"
)

// versionlessLinks counts the tenant's current links of product name by
// whether the version is known.
func versionlessLinks(t *testing.T, g *setRig, tenant shared.ID, product string) (blind, known int) {
	t.Helper()
	if err := g.r.db.QueryRowContext(context.Background(), `
		SELECT COUNT(*) FILTER (WHERE v.raw = ''), COUNT(*) FILTER (WHERE v.raw <> '')
		FROM asset_software s
		JOIN software_versions v ON v.id = s.software_version_id
		JOIN software_products p ON p.id = s.product_id
		WHERE s.tenant_id = $1 AND p.tenant_id IS NULL AND p.cpe_vendor = 'f5' AND p.cpe_product = $2
		  AND s.superseded_at IS NULL AND s.version_state = 'established'`, tenant.String(), product).Scan(&blind, &known); err != nil {
		t.Fatal(err)
	}
	return blind, known
}

type countingSink struct{ assets map[shared.ID]int }

func (c *countingSink) SoftwareChanged(tenant shared.ID, ids []shared.ID) {
	c.assets[tenant] += len(ids)
}

func TestVersionlessSoftwareLinks(t *testing.T) {
	g := newTechRig(t)
	other := g.r.newTenant("httpx")
	ctx := context.Background()
	at := time.Now().UTC().Add(-time.Hour)
	name := func(i int) string { return fmt.Sprintf("web%03d.nginx.example.com", i) }

	// Ingest: 103 hosts say only "nginx", 6 give the version; another
	// organization has 3 version-less nginx hosts; one host also runs a
	// private product without a version.
	for i := 0; i < 109; i++ {
		tech := "nginx"
		if i >= 103 {
			tech = "nginx:1.25.3"
		}
		g.send(g.tn, "httpx", at, "", ctis.Asset{ID: "d", Type: ctis.AssetTypeDomainName, Value: name(i), Technologies: techsOf(tech)})
	}
	g.send(g.tn, "httpx", at, "", ctis.Asset{ID: "d", Type: ctis.AssetTypeDomainName, Value: "portal.example.com",
		Technologies: techsOf("Acme Portal")})
	for i := 0; i < 3; i++ {
		g.send(other, "httpx", at, "", ctis.Asset{ID: "d", Type: ctis.AssetTypeDomainName,
			Value: fmt.Sprintf("other%d.example.org", i), Technologies: techsOf("nginx")})
	}
	if blind, known := versionlessLinks(t, g, g.tn.tenant, "nginx"); blind != 103 || known != 6 {
		t.Fatalf("after ingest: %d version-less and %d versioned nginx links, want 103 and 6", blind, known)
	}
	var private int
	if err := g.r.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM software_products WHERE lower(name) = 'acme portal'`).Scan(&private); err != nil {
		t.Fatal(err)
	}
	if private != 0 {
		t.Fatalf("a private name without a version created %d catalog rows", private)
	}

	// The state before this change: technologies stored, no version-less
	// links. The backfill links them again.
	for _, tn := range []shared.ID{g.tn.tenant, other.tenant} {
		if _, err := g.r.db.ExecContext(ctx, `
			DELETE FROM asset_software s USING software_versions v
			WHERE v.id = s.software_version_id AND v.raw = '' AND s.tenant_id = $1`, tn.String()); err != nil {
			t.Fatal(err)
		}
	}
	pdb := &postgres.DB{DB: g.r.db}
	store := postgres.NewAssetTechnologyBackfillRepository(pdb)
	sink := &countingSink{assets: map[shared.ID]int{}}
	job := assettechapp.NewSoftwareLinkBackfill(store, postgres.NewSoftwareRepository(pdb), sink, logger.NewNop())
	if _, err := job.Run(ctx); err != nil {
		t.Fatal(err)
	}
	if blind, known := versionlessLinks(t, g, g.tn.tenant, "nginx"); blind != 103 || known != 6 {
		t.Fatalf("after the backfill: %d version-less and %d versioned links, want 103 and 6", blind, known)
	}
	if blind, _ := versionlessLinks(t, g, other.tenant, "nginx"); blind != 3 {
		t.Fatalf("other organization: %d version-less links, want 3", blind)
	}
	if sink.assets[g.tn.tenant] != 103 || sink.assets[other.tenant] != 3 {
		t.Fatalf("matcher queued %v assets, want 103 and 3", sink.assets)
	}
	if err := g.r.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM software_products WHERE lower(name) = 'acme portal'`).Scan(&private); err != nil {
		t.Fatal(err)
	}
	if private != 0 {
		t.Fatal("the backfill created a catalog row for a private name")
	}

	// Done once: a second run finds nothing pending; running a tenant again
	// from the start changes nothing (idempotent).
	var sightings int
	sum := func() int {
		var n int
		if err := g.r.db.QueryRowContext(ctx, `SELECT COALESCE(SUM(sightings), 0) FROM asset_software WHERE tenant_id = $1`,
			g.tn.tenant.String()).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	sightings = sum()
	pending, err := store.PendingSoftwareLinkTenants(ctx, assettechapp.SoftwareLinkVersion)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range pending {
		if id == g.tn.tenant || id == other.tenant {
			t.Fatal("a finished tenant is pending again")
		}
	}
	if _, err := g.r.db.ExecContext(ctx, `DELETE FROM asset_software_versionless_backfill WHERE tenant_id = $1`, g.tn.tenant.String()); err != nil {
		t.Fatal(err)
	}
	if _, err := job.RunTenant(ctx, g.tn.tenant); err != nil {
		t.Fatal(err)
	}
	if blind, _ := versionlessLinks(t, g, g.tn.tenant, "nginx"); blind != 103 || sum() != sightings {
		t.Fatalf("re-run: %d version-less links, sightings %d -> %d", blind, sightings, sum())
	}

	// The possibly-affected tier of an alert for an nginx CVE lists the 103
	// hosts of this organization and none of the other's.
	cve := fmt.Sprintf("CVE-2026-%d", 1_000_000+time.Now().UnixNano()%1_000_000_000) // unique per run
	var pid string
	if err := g.r.db.QueryRowContext(ctx, `SELECT id FROM software_products WHERE tenant_id IS NULL AND cpe_vendor = 'f5' AND cpe_product = 'nginx'`).Scan(&pid); err != nil {
		t.Fatal(err)
	}
	if _, err := g.r.db.ExecContext(ctx, `INSERT INTO cve_records (cve_id, severity, cvss_score) VALUES ($1, 'critical', 9.8)`, cve); err != nil {
		t.Fatal(err)
	}
	if _, err := g.r.db.ExecContext(ctx, `INSERT INTO vulnerability_affected (cve_id, product_id, v_start, v_start_incl, v_end, v_end_incl)
		VALUES ($1, $2, '1.25.0', true, '1.29.3', true)`, cve, pid); err != nil {
		t.Fatal(err)
	}
	alerts := postgres.NewThreatAlertRepository(pdb)
	possible := func(tn shared.ID) map[shared.ID]bool {
		list, err := alerts.AffectedAssets(ctx, tn, cve)
		if err != nil {
			t.Fatal(err)
		}
		out := map[shared.ID]bool{}
		for _, a := range list {
			if a.Kind == threatalert.MatchPossible {
				out[a.AssetID] = true
			}
		}
		return out
	}
	if got := possible(g.tn.tenant); len(got) != 103 {
		t.Fatalf("possibly affected: %d assets, want 103", len(got))
	}
	for i := 0; i < 3; i++ {
		if possible(g.tn.tenant)[g.assetID(other, fmt.Sprintf("other%d.example.org", i))] {
			t.Fatal("another organization's host is listed")
		}
	}

	// A version read later replaces the version-less link of that host: it
	// leaves the possibly-affected tier.
	g.send(g.tn, "httpx", time.Now().UTC(), "", ctis.Asset{ID: "d", Type: ctis.AssetTypeDomainName, Value: name(0),
		Technologies: techsOf("nginx:1.30.0")})
	if blind, known := versionlessLinks(t, g, g.tn.tenant, "nginx"); blind != 102 || known != 7 {
		t.Fatalf("after a version was read: %d version-less, %d versioned, want 102 and 7", blind, known)
	}
	if got := possible(g.tn.tenant); len(got) != 102 || got[g.assetID(g.tn, name(0))] {
		t.Fatalf("possibly affected after a version was read: %d assets", len(got))
	}
}
