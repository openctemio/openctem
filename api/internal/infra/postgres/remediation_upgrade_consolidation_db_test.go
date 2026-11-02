package postgres_test

// One package version, many advisories, one remediation group: the key
// applier reads the fixed versions from an upgrade advice when the scanner
// gave no list, and gives every open finding of the same installed package
// version the highest upgrade target any of them needs. Another tenant's
// findings of the same shared package version are never read or rekeyed.

import (
	"context"
	"database/sql"
	"testing"

	_ "github.com/lib/pq"

	"github.com/openctemio/openctem/api/internal/app/remediation"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/internal/testdb"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

func TestRemediationUpgradeConsolidation_DB(t *testing.T) {
	dbURL := testdb.URL()
	if dbURL == "" {
		t.Skip("DATABASE_URL not set to a test database")
	}
	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	ctx := context.Background()
	if err := db.PingContext(ctx); err != nil {
		testdb.Skipf(t, "cannot reach DATABASE_URL: %v", err)
	}
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := db.ExecContext(ctx, q, args...); err != nil {
			t.Fatalf("%.60s: %v", q, err)
		}
	}
	tenantA, tenantB := shared.NewID(), shared.NewID()
	product, version := shared.NewID(), shared.NewID()
	for _, tid := range []shared.ID{tenantA, tenantB} {
		exec(`INSERT INTO tenants (id, name, slug) VALUES ($1::uuid, 'consolidate', 'consolidate-' || $1::text)`, tid.String())
	}
	exec(`INSERT INTO software_products (id, part, name, source, purl_type, purl_namespace, purl_name)
		VALUES ($1, 'a', 'Django', 'osv', 'pypi', '', 'django')`, product.String())
	exec(`INSERT INTO software_versions (id, product_id, raw) VALUES ($1, $2, '1.8.3')`, version.String(), product.String())
	t.Cleanup(func() {
		for _, tid := range []shared.ID{tenantA, tenantB} {
			_, _ = db.ExecContext(ctx, `DELETE FROM finding_remediation_keys WHERE tenant_id = $1`, tid.String())
			_, _ = db.ExecContext(ctx, `DELETE FROM findings WHERE tenant_id = $1`, tid.String())
			_, _ = db.ExecContext(ctx, `DELETE FROM assets WHERE tenant_id = $1`, tid.String())
			_, _ = db.ExecContext(ctx, `DELETE FROM tenants WHERE id = $1`, tid.String())
		}
		_, _ = db.ExecContext(ctx, `DELETE FROM software_versions WHERE id = $1`, version.String())
		_, _ = db.ExecContext(ctx, `DELETE FROM software_products WHERE id = $1`, product.String())
	})

	seed := func(tid shared.ID, advice string) shared.ID {
		asset := shared.NewID()
		exec(`INSERT INTO assets (id, tenant_id, name, asset_type) VALUES ($1, $2, $3, 'repository')`,
			asset.String(), tid.String(), "repo-"+asset.String())
		id := shared.NewID()
		exec(`INSERT INTO findings (id, tenant_id, asset_id, source, tool_name, message, severity, fingerprint, status, component_id, remediation)
			VALUES ($1::uuid, $2, $3, 'sca', 'trivy', 'django advisory', 'high', $1::text, 'new', $4, jsonb_build_object('recommendation', $5::text))`,
			id.String(), tid.String(), asset.String(), version.String(), advice)
		return id
	}
	a1 := seed(tenantA, "Upgrade Django to 1.11.28, 2.2.10, 3.0.3")
	a2 := seed(tenantA, "Upgrade Django to 1.11.29, 2.2.13, 3.0.7")
	b1 := seed(tenantB, "Upgrade Django to 1.11.28, 2.2.10, 3.0.3")

	repo := postgres.NewFindingRemediationKeyRepository(&postgres.DB{DB: db})
	applier := remediation.NewKeyApplier(repo, logger.NewNop())
	key := func(id, tid shared.ID) string {
		var k sql.NullString
		_ = db.QueryRowContext(ctx, `SELECT remediation_key FROM finding_remediation_keys WHERE tenant_id = $1 AND finding_id = $2`,
			tid.String(), id.String()).Scan(&k)
		return k.String
	}

	// Tenant B first: its own target.
	if _, err := applier.ApplyIDs(ctx, tenantB, []shared.ID{b1}, true); err != nil {
		t.Fatal(err)
	}
	// Tenant A's first finding alone: 1.11.28.
	if _, err := applier.ApplyIDs(ctx, tenantA, []shared.ID{a1}, true); err != nil {
		t.Fatal(err)
	}
	// A newer advisory on the same version arrives: it alone is applied, and
	// its open sibling moves to the shared, higher target.
	a3 := seed(tenantA, "Upgrade Django to 5.2.8, 5.1.14, 4.2.26")
	if _, err := applier.ApplyIDs(ctx, tenantA, []shared.ID{a3}, true); err != nil {
		t.Fatal(err)
	}
	want := "upgrade:pypi:django:4.2.26"
	if got := key(a1, tenantA); got != want {
		t.Errorf("a1 key %q, want %q (moved with its sibling)", got, want)
	}
	if got := key(a3, tenantA); got != want {
		t.Errorf("a3 key %q, want %q", got, want)
	}
	if got := key(a2, tenantA); got != want {
		t.Errorf("a2 key %q (never applied itself), want %q", got, want)
	}
	// Another tenant's finding of the same shared package version is untouched.
	if got := key(b1, tenantB); got != "upgrade:pypi:django:1.11.28" {
		t.Errorf("tenant B key %q, want its own target", got)
	}

	groups, err := repo.ListGroups(ctx, tenantA, []string{"resolved", "false_positive", "accepted", "duplicate"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(groups) != 1 || groups[0].FindingCount != 3 || groups[0].Title != "Upgrade Django to 4.2.26" {
		t.Fatalf("groups %+v: want one group of 3 findings", groups)
	}
}
