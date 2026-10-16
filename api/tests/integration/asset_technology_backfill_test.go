package integration

// The asset technology backfill (RFC-112 §3.7) on a migrated database: the
// copy migration fills asset_technologies from properties.technologies; the
// controller classifies the rows and removes the component links ingest no
// longer creates; a real component stays; another tenant is never touched;
// a tenant is done once.

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/ctis"

	assettechapp "github.com/openctemio/openctem/api/internal/app/assettech"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/internal/testdb"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// insertTechLink adds a component link as the old ingest made it: a
// tenant-private product named name, version raw, source technology.
func insertTechLink(t *testing.T, g *setRig, tenant, assetID shared.ID, name, version string) {
	t.Helper()
	ctx := context.Background()
	var pid, vid string
	if err := g.r.db.QueryRowContext(ctx, `
		SELECT id FROM software_products WHERE tenant_id = $1 AND lower(name) = lower($2) AND cpe_vendor IS NULL`,
		tenant.String(), name).Scan(&pid); err != nil {
		if err := g.r.db.QueryRowContext(ctx, `
			INSERT INTO software_products (tenant_id, part, name, source) VALUES ($1, 'a', $2, 'observed') RETURNING id`,
			tenant.String(), name).Scan(&pid); err != nil {
			t.Fatal(err)
		}
	}
	if err := g.r.db.QueryRowContext(ctx, `
		INSERT INTO software_versions (product_id, tenant_id, raw) VALUES ($1, $2, $3) RETURNING id`,
		pid, tenant.String(), version).Scan(&vid); err != nil {
		t.Fatal(err)
	}
	if _, err := g.r.db.ExecContext(ctx, `
		INSERT INTO asset_software (tenant_id, asset_id, product_id, software_version_id, source, confidence)
		VALUES ($1, $2, $3, $4, 'technology', 50)`, tenant.String(), assetID.String(), pid, vid); err != nil {
		t.Fatal(err)
	}
}

func techLinkNames(t *testing.T, g *setRig, tenant shared.ID) map[string]bool {
	t.Helper()
	rows, err := g.r.db.QueryContext(context.Background(), `
		SELECT p.name FROM asset_software s JOIN software_products p ON p.id = s.product_id
		 WHERE s.tenant_id = $1`, tenant.String())
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	out := map[string]bool{}
	for rows.Next() {
		var n string
		_ = rows.Scan(&n)
		out[n] = true
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestAssetTechnologyBackfill(t *testing.T) {
	g := newTechRig(t)
	other := g.r.newTenant("httpx")
	ctx := context.Background()
	const name, otherName = "old.tech.example.com", "old.other.example.com"
	at := time.Now().UTC().Add(-time.Hour)
	g.send(g.tn, "httpx", at, "", ctis.Asset{ID: "d", Type: ctis.AssetTypeDomain, Value: name,
		Properties: ctis.Properties{"technologies": []any{"HSTS", "Vercel", "nginx", "Next.js:13.4.1"}}})
	g.send(other, "httpx", at, "", ctis.Asset{ID: "d", Type: ctis.AssetTypeDomain, Value: otherName,
		Properties: ctis.Properties{"technologies": []any{"HSTS"}}})
	a, b := g.assetID(g.tn, name), g.assetID(other, otherName)

	// The state before asset_technologies: no rows, and the old ingest's
	// links for every detection.
	for _, tn := range []shared.ID{g.tn.tenant, other.tenant} {
		if _, err := g.r.db.ExecContext(ctx, `DELETE FROM asset_technologies WHERE tenant_id = $1`, tn.String()); err != nil {
			t.Fatal(err)
		}
		if _, err := g.r.db.ExecContext(ctx, `DELETE FROM asset_software WHERE tenant_id = $1`, tn.String()); err != nil {
			t.Fatal(err)
		}
	}
	// ...and the retired property the copy migration reads.
	// Tags a person may have set, some with the text of a technology.
	for id, list := range map[shared.ID]string{a: `["HSTS", "Vercel", "nginx", "Next.js:13.4.1"]`, b: `["HSTS"]`} {
		if _, err := g.r.db.ExecContext(ctx, `UPDATE assets SET properties = jsonb_set(COALESCE(properties, '{}'), '{technologies}', $2::jsonb),
		       tags = ARRAY['prod', 'HSTS', 'Next.js:13.4.1', 'vercel'] WHERE id = $1`,
			id.String(), list); err != nil {
			t.Fatal(err)
		}
	}
	insertTechLink(t, g, g.tn.tenant, a, "hsts", "")
	insertTechLink(t, g, g.tn.tenant, a, "vercel", "")
	insertTechLink(t, g, g.tn.tenant, a, "nginx", "")
	insertTechLink(t, g, g.tn.tenant, a, "cloudflare", "2")
	insertTechLink(t, g, g.tn.tenant, a, "next.js", "13.4.1")
	insertTechLink(t, g, other.tenant, b, "hsts", "")

	// The copy migration's statement, run again on this data.
	version := testdb.MigrationVersion(t, filepath.Join("..", "..", "migrations"), "asset_technologies_backfill")
	body, err := os.ReadFile(filepath.Join("..", "..", "migrations", fmt.Sprintf("%06d_asset_technologies_backfill.up.sql", version)))
	if err != nil {
		t.Fatal(err)
	}
	copySQL, _, _ := strings.Cut(string(body), "-- Tenants the asset-technology-backfill")
	if _, err := g.r.db.ExecContext(ctx, copySQL); err != nil {
		t.Fatalf("copy: %v", err)
	}
	if got := g.technologies(g.tn, name); len(got) != 4 || got["next.js"].Version != "13.4.1" || got["hsts"].Category != "other" {
		t.Fatalf("copied = %+v", got)
	}

	db := &postgres.DB{DB: g.r.db}
	bf := assettechapp.NewBackfill(postgres.NewAssetTechnologyBackfillRepository(db), logger.NewNop(), false)
	stats, err := bf.RunTenant(ctx, g.tn.tenant)
	if err != nil {
		t.Fatal(err)
	}
	if stats.LinksRemoved != 3 || stats.Technologies != 4 || stats.Classified != 4 {
		t.Fatalf("stats = %+v, want 4 technologies classified, 3 links removed", stats)
	}
	if stats.PropertiesDropped != 1 {
		t.Fatalf("properties dropped = %d, want 1", stats.PropertiesDropped)
	}
	var left int
	if err := g.r.db.QueryRowContext(ctx, `SELECT count(*) FROM assets WHERE tenant_id = $1 AND properties ? 'technologies'`,
		g.tn.tenant.String()).Scan(&left); err != nil || left != 0 {
		t.Fatalf("assets still holding the retired key: %d %v", left, err)
	}
	// Tags are never removed: a person's tag with the same text as a
	// technology ("HSTS", "Next.js:13.4.1", "vercel") survives untouched.
	var tags string
	if err := g.r.db.QueryRowContext(ctx, `SELECT array_to_string(tags, ',') FROM assets WHERE id = $1`, a.String()).Scan(&tags); err != nil {
		t.Fatal(err)
	}
	if tags != "prod,HSTS,Next.js:13.4.1,vercel" {
		t.Fatalf("tags = %q, want them all kept", tags)
	}
	// Only the three versionless, CPE-less links go; a versioned link stays
	// whatever its category (cloudflare:2 is a CDN).
	if got := techLinkNames(t, g, g.tn.tenant); len(got) != 2 || !got["next.js"] || !got["cloudflare"] {
		t.Fatalf("links left = %v, want next.js and cloudflare", got)
	}
	var recorded int
	if err := g.r.db.QueryRowContext(ctx, `SELECT count(*) FROM asset_technology_backfill_removed WHERE tenant_id = $1 AND asset_id = $2`,
		g.tn.tenant.String(), a.String()).Scan(&recorded); err != nil || recorded != 3 {
		t.Fatalf("recorded removals = %d (%v), want 3", recorded, err)
	}
	if got := g.technologies(g.tn, name); len(got) != 4 || got["vercel"].Category != "hosting" ||
		got["hsts"].Category != "security_header" || got["nginx"].Category != "web_server" {
		t.Fatalf("technologies = %+v", got)
	}
	// Tenant B is untouched by tenant A's run.
	if got := techLinkNames(t, g, other.tenant); !got["hsts"] {
		t.Fatalf("tenant B's links changed: %v", got)
	}
	if got := g.technologies(other, otherName); len(got) != 1 || got["hsts"].Category != "other" {
		t.Fatalf("tenant A's run changed tenant B's rows: %+v", got)
	}

	// Run marks each tenant; a second run finds nothing pending for them.
	if _, err := bf.Run(ctx); err != nil {
		t.Fatal(err)
	}
	pending, err := postgres.NewAssetTechnologyBackfillRepository(db).PendingTenants(ctx, assettechapp.BackfillVersion, true)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range pending {
		if p == g.tn.tenant || p == other.tenant {
			t.Fatalf("tenant still pending after a run: %s", p)
		}
	}
	if got := techLinkNames(t, g, other.tenant); got["hsts"] {
		t.Fatalf("tenant B's junk link survived its own run: %v", got)
	}
}

// Report-only (the default first run) deletes nothing: it counts the
// removable links, leaves every row, and the tenant is picked up again once
// removal is enabled. The delete statement itself refuses a versioned or
// CPE-backed link even when asked for it, and records what it deletes.
func TestAssetTechnologyBackfill_ReportOnlyAndGuards(t *testing.T) {
	g := newTechRig(t)
	ctx := context.Background()
	const name = "report.tech.example.com"
	g.send(g.tn, "httpx", time.Now().UTC().Add(-time.Hour), "", ctis.Asset{ID: "d", Type: ctis.AssetTypeDomain, Value: name,
		Properties: ctis.Properties{"technologies": []any{"nginx"}}})
	a := g.assetID(g.tn, name)
	if _, err := g.r.db.ExecContext(ctx, `DELETE FROM asset_software WHERE tenant_id = $1`, g.tn.tenant.String()); err != nil {
		t.Fatal(err)
	}
	insertTechLink(t, g, g.tn.tenant, a, "hsts", "")
	insertTechLink(t, g, g.tn.tenant, a, "vercel", "")
	insertTechLink(t, g, g.tn.tenant, a, "cloudflare", "2")
	insertTechLink(t, g, g.tn.tenant, a, "openssl", "")
	// openssl has a CPE: a versionless link of a CPE-backed product stays.
	if _, err := g.r.db.ExecContext(ctx, `UPDATE software_products SET cpe_vendor = 'openssl', cpe_product = 'openssl' WHERE tenant_id = $1 AND name = 'openssl'`,
		g.tn.tenant.String()); err != nil {
		t.Fatal(err)
	}

	db := &postgres.DB{DB: g.r.db}
	repo := postgres.NewAssetTechnologyBackfillRepository(db)
	report := assettechapp.NewBackfill(repo, logger.NewNop(), true)
	stats, err := report.RunTenant(ctx, g.tn.tenant)
	if err != nil {
		t.Fatal(err)
	}
	if stats.LinksReported != 2 || stats.LinksRemoved != 0 {
		t.Fatalf("report-only stats = %+v, want 2 reported, 0 removed", stats)
	}
	if got := techLinkNames(t, g, g.tn.tenant); len(got) != 4 {
		t.Fatalf("report-only changed the links: %v", got)
	}

	// A report-only Run marks the tenant as reported; only an enforcing run
	// sees it pending again.
	if _, err := report.Run(ctx); err != nil {
		t.Fatal(err)
	}
	has := func(enforce bool) bool {
		p, err := repo.PendingTenants(ctx, assettechapp.BackfillVersion, enforce)
		if err != nil {
			t.Fatal(err)
		}
		for _, id := range p {
			if id == g.tn.tenant {
				return true
			}
		}
		return false
	}
	if has(false) || !has(true) {
		t.Fatalf("pending after a report-only run: report=%v enforce=%v, want false/true", has(false), has(true))
	}

	// The delete statement refuses versioned and CPE-backed links.
	rows, err := g.r.db.QueryContext(ctx, `
		SELECT s.id FROM asset_software s JOIN software_products p ON p.id = s.product_id
		 WHERE s.tenant_id = $1 AND p.name IN ('cloudflare', 'openssl')`, g.tn.tenant.String())
	if err != nil {
		t.Fatal(err)
	}
	var protected []shared.ID
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			t.Fatal(err)
		}
		id, _ := shared.IDFromString(s)
		protected = append(protected, id)
	}
	rows.Close()
	if n, err := repo.DeleteLinks(ctx, g.tn.tenant, protected); err != nil || n != 0 {
		t.Fatalf("DeleteLinks of a versioned and a CPE-backed link = %d, %v; want 0", n, err)
	}

	enforce := assettechapp.NewBackfill(repo, logger.NewNop(), false)
	if _, err := enforce.Run(ctx); err != nil {
		t.Fatal(err)
	}
	if got := techLinkNames(t, g, g.tn.tenant); len(got) != 2 || !got["cloudflare"] || !got["openssl"] {
		t.Fatalf("links after enforcing = %v, want cloudflare and openssl", got)
	}
	var recorded int
	if err := g.r.db.QueryRowContext(ctx, `SELECT count(*) FROM asset_technology_backfill_removed WHERE tenant_id = $1`,
		g.tn.tenant.String()).Scan(&recorded); err != nil || recorded != 2 {
		t.Fatalf("recorded removals = %d (%v), want 2", recorded, err)
	}
}
