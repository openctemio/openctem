package integration

// The asset technology backfill (RFC-112 §3.7) on a migrated database: the
// copy migration fills asset_technologies from properties.technologies; the
// controller classifies the rows and removes the component links ingest no
// longer creates; a real component stays; another tenant is never touched;
// a tenant is done once.

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/ctis"

	assettechapp "github.com/openctemio/openctem/api/internal/app/assettech"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
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
	insertTechLink(t, g, g.tn.tenant, a, "hsts", "")
	insertTechLink(t, g, g.tn.tenant, a, "vercel", "")
	insertTechLink(t, g, g.tn.tenant, a, "nginx", "")
	insertTechLink(t, g, g.tn.tenant, a, "cloudflare", "2")
	insertTechLink(t, g, g.tn.tenant, a, "next.js", "13.4.1")
	insertTechLink(t, g, other.tenant, b, "hsts", "")

	// The copy migration's statement, run again on this data.
	files, _ := filepath.Glob("../../migrations/*_asset_technologies_backfill.up.sql")
	if len(files) != 1 {
		t.Fatalf("copy migration: %v", files)
	}
	body, err := os.ReadFile(files[0])
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
	bf := assettechapp.NewBackfill(postgres.NewAssetTechnologyBackfillRepository(db), logger.NewNop())
	stats, err := bf.RunTenant(ctx, g.tn.tenant)
	if err != nil {
		t.Fatal(err)
	}
	if stats.LinksRemoved != 4 || stats.Technologies != 4 || stats.Classified != 4 {
		t.Fatalf("stats = %+v, want 4 technologies classified, 4 links removed", stats)
	}
	if got := techLinkNames(t, g, g.tn.tenant); len(got) != 1 || !got["next.js"] {
		t.Fatalf("links left = %v, want only next.js", got)
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
	pending, err := postgres.NewAssetTechnologyBackfillRepository(db).PendingTenants(ctx, assettechapp.BackfillVersion)
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
