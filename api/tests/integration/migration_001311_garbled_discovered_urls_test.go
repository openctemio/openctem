package integration

// Migration 001311 (RFC-056 WS2, RFC-043 §10): the discovered-URL assets
// v0.8.0 stored under a garbled name ("https:::host:path") become GET web
// endpoints under their origin, like 001288 does for URL-named ones. Their
// findings move to the origin, pending duplicate reviews naming them go, and
// every lookup stays inside the URL's own tenant. Runs as the schema owner in
// a rolled-back transaction.

import (
	"context"
	"database/sql"
	"os"
	"sort"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/internal/testdb"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func TestMigration001311ConvertsGarbledDiscoveredURLs(t *testing.T) {
	appDB := openLifecycleDB(t)
	ctx := context.Background()
	tenantA := seedLifecycleTenant(ctx, t, appDB)
	tenantB := seedLifecycleTenant(ctx, t, appDB)

	up, err := os.ReadFile("../../migrations/001311_garbled_discovered_url_assets.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	var code []string
	for _, l := range strings.Split(string(up), "\n") {
		if !strings.HasPrefix(strings.TrimSpace(l), "--") {
			code = append(code, l)
		}
	}
	if strings.Contains(strings.ToLower(strings.Join(code, "\n")), "audit_log") {
		t.Fatal("001311 writes audit rows from SQL")
	}

	db, err := sql.Open("postgres", testdb.MigratorURL())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback() }()
	asset := func(tenant shared.ID, name, typ, sub string, deleted bool) string {
		t.Helper()
		id := shared.NewID().String()
		del := "NULL"
		if deleted {
			del = "now()"
		}
		var subArg any
		if sub != "" {
			subArg = sub
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO assets (id, tenant_id, name, asset_type, sub_type, deleted_at)
			VALUES ($1, $2, $3, $4, $5, `+del+`)`, id, tenant.String(), name, typ, subArg); err != nil {
			t.Fatalf("seed asset %s: %v", name, err)
		}
		return id
	}
	finding := func(tenant shared.ID, assetID, title string) {
		t.Helper()
		if _, err := tx.ExecContext(ctx, `INSERT INTO findings (tenant_id, asset_id, source, tool_name, message, title, severity, fingerprint)
			VALUES ($1, $2, 'dast', 'nuclei', $3::text, $3::text, 'high', $4)`,
			tenant.String(), assetID, title, "fp-"+shared.NewID().String()); err != nil {
			t.Fatalf("seed finding: %v", err)
		}
	}
	url := func(tenant shared.ID, name string) string {
		return asset(tenant, name, "service", "discovered_url", false)
	}

	// Tenant A, as v0.8.0 stored it.
	shopA := asset(tenantA, "https:::shop.example.test", "service", "http", false) // garbled origin
	adminA := asset(tenantA, "http:::admin.example.test:8080", "service", "http", false)
	wwwA := asset(tenantA, "https://www.example.test", "application", "website", false) // canonical origin
	asset(tenantA, "https://gone.example.test", "service", "http", true)                // deleted origin

	checkout := url(tenantA, "https:::shop.example.test:cart:checkout?step=2&coupon=x#top")
	finding(tenantA, checkout, "xss in checkout")
	url(tenantA, "https:::shop.example.test:orders:12345:invoice")
	url(tenantA, "https:::shop.example.test:2024:report") // a number that is a path, not a port
	adminLogin := url(tenantA, "http:::admin.example.test:8080:login")
	finding(tenantA, adminLogin, "exposed panel")
	url(tenantA, "https:::www.example.test:443:about") // explicit default port
	url(tenantA, "https:::api.example.test:v1:users")  // no origin asset yet
	url(tenantA, "https:::[2001:db8::1]:8443:status")  // IPv6 host
	goneURL := url(tenantA, "https:::gone.example.test:old")
	if _, err := tx.ExecContext(ctx, `INSERT INTO asset_dedup_review (tenant_id, normalized_name, asset_type,
			keep_asset_id, keep_asset_name, merge_asset_ids, merge_asset_names, status, reason)
		VALUES ($1, 'http://admin.example.test:8080', 'service', $2, 'http:::admin.example.test:8080:login',
			ARRAY[$3]::uuid[], ARRAY['http:::admin.example.test:8080'], 'pending', 'normalization_garbled')`,
		tenantA.String(), adminLogin, adminA); err != nil {
		t.Fatal(err)
	}

	// Tenant B holds the same names: its URLs land on its own origin.
	shopB := asset(tenantB, "https:::shop.example.test", "service", "http", false)
	cartB := url(tenantB, "https:::shop.example.test:cart:checkout")
	finding(tenantB, cartB, "tenant b finding")

	runSQL(ctx, t, tx, string(up))

	endpoints := func(tenant shared.ID) []string {
		t.Helper()
		rows, err := tx.QueryContext(ctx, `SELECT o.name || ' ' || e.method || ' ' || e.path_template || ' ' || e.param_count
			FROM web_endpoints e JOIN assets o ON o.id = e.origin_asset_id AND o.tenant_id = e.tenant_id
			WHERE e.tenant_id = $1`, tenant.String())
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = rows.Close() }()
		var out []string
		for rows.Next() {
			var s string
			if err := rows.Scan(&s); err != nil {
				t.Fatal(err)
			}
			out = append(out, s)
		}
		if err := rows.Err(); err != nil {
			t.Fatal(err)
		}
		sort.Strings(out)
		return out
	}
	wantA := []string{
		"http:::admin.example.test:8080 GET /login 0",
		"https://[2001:db8::1]:8443 GET /status 0",
		"https://api.example.test GET /v1/users 0",
		"https://www.example.test GET /about 0",
		"https:::shop.example.test GET /cart/checkout 2",
		"https:::shop.example.test GET /orders/{int}/invoice 0",
		"https:::shop.example.test GET /{int}/report 0",
	}
	sort.Strings(wantA)
	if got := endpoints(tenantA); strings.Join(got, "\n") != strings.Join(wantA, "\n") {
		t.Errorf("tenant A endpoints:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(wantA, "\n"))
	}
	if got := endpoints(tenantB); len(got) != 1 || got[0] != "https:::shop.example.test GET /cart/checkout 0" {
		t.Errorf("tenant B endpoints: %v", got)
	}

	var n int
	q := func(query string, args ...any) int {
		t.Helper()
		if err := tx.QueryRowContext(ctx, query, args...).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	// Converted URL assets are gone; the one under a deleted origin stays.
	if c := q(`SELECT count(*) FROM assets WHERE tenant_id = $1 AND sub_type = 'discovered_url'`, tenantA.String()); c != 1 {
		t.Errorf("tenant A: %d discovered_url assets left, want 1 (under a deleted origin)", c)
	}
	if c := q(`SELECT count(*) FROM assets WHERE id = $1`, goneURL); c != 1 {
		t.Error("the URL under a deleted origin was removed")
	}
	if c := q(`SELECT count(*) FROM assets WHERE tenant_id = $1 AND sub_type = 'discovered_url'`, tenantB.String()); c != 0 {
		t.Errorf("tenant B: %d discovered_url assets left", c)
	}
	// Findings moved to their origin, inside their tenant.
	if c := q(`SELECT count(*) FROM findings WHERE tenant_id = $1 AND asset_id = $2 AND title = 'xss in checkout'`, tenantA.String(), shopA); c != 1 {
		t.Error("tenant A checkout finding not on the shop origin")
	}
	if c := q(`SELECT count(*) FROM findings WHERE tenant_id = $1 AND asset_id = $2 AND title = 'exposed panel'`, tenantA.String(), adminA); c != 1 {
		t.Error("tenant A admin finding not on the admin origin")
	}
	if c := q(`SELECT count(*) FROM findings WHERE tenant_id = $1 AND asset_id = $2`, tenantB.String(), shopB); c != 1 {
		t.Error("tenant B finding not on tenant B's origin")
	}
	// No new origin for a URL whose canonical origin exists; one for api.
	if c := q(`SELECT count(*) FROM assets WHERE tenant_id = $1 AND name = 'https://www.example.test'`, tenantA.String()); c != 1 {
		t.Errorf("tenant A has %d https://www.example.test assets", c)
	}
	if c := q(`SELECT count(*) FROM web_endpoints WHERE tenant_id = $1 AND origin_asset_id = $2`, tenantA.String(), wwwA); c != 1 {
		t.Error("tenant A: /about is not under the existing www origin")
	}
	if c := q(`SELECT count(*) FROM assets WHERE tenant_id = $1 AND name = 'https://api.example.test' AND asset_type = 'service' AND sub_type = 'http'`, tenantA.String()); c != 1 {
		t.Error("tenant A: origin https://api.example.test not created")
	}
	if c := q(`SELECT count(*) FROM assets WHERE tenant_id = $1 AND name = 'https://shop.example.test'`, tenantB.String()); c != 0 {
		t.Error("tenant B: a canonical shop origin was created next to its garbled one")
	}
	// The review that named a converted URL is gone.
	if c := q(`SELECT count(*) FROM asset_dedup_review WHERE tenant_id = $1 AND status = 'pending'`, tenantA.String()); c != 0 {
		t.Errorf("tenant A: %d pending reviews left", c)
	}
}
