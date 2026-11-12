package postgres

import (
	"context"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Metrics count the attributed inventory unless the request asks for
// discovered assets (research/124, RFC-054 §15.6), and the toggle never
// reaches another tenant's assets. Requires DATABASE_URL.
func TestMetricsPopulation(t *testing.T) {
	db := openSensorDB(t)
	ctx := context.Background()
	repo := NewEASMSummaryRepository(&DB{DB: db})
	tenant := seedTestTenant(ctx, t, db)
	other := seedTestTenant(ctx, t, db)
	add := func(tid shared.ID, name, state string) {
		t.Helper()
		id := shared.NewID().String()
		if _, err := db.ExecContext(ctx, `INSERT INTO assets (id, tenant_id, name, asset_type, status) VALUES ($1, $2, $3, 'subdomain', 'active')`, id, tid.String(), name); err != nil {
			t.Fatal(err)
		}
		if state != "" {
			if _, err := db.ExecContext(ctx, `INSERT INTO asset_attributions (asset_id, tenant_id, state, confidence) VALUES ($1, $2, $3, 60)`, id, tid.String(), state); err != nil {
				t.Fatal(err)
			}
		}
	}
	add(tenant, "ours.example.com", "confirmed")
	add(tenant, "legacy.example.com", "")
	add(tenant, "found.example.net", "discovered")
	add(tenant, "held.example.net", "needs_review")
	add(tenant, "no.example.net", "rejected")
	add(other, "theirs.example.org", "discovered")

	count := func(c context.Context) int {
		t.Helper()
		d, err := repo.Summary(c, tenant, nil, time.Now(), 5)
		if err != nil {
			t.Fatal(err)
		}
		return d.AssetsByType["subdomain"]
	}
	if n := count(ctx); n != 2 {
		t.Fatalf("default population = %d, want 2 (attributed only)", n)
	}
	if n := count(shared.WithDiscoveredAssets(ctx)); n != 3 {
		t.Fatalf("include_discovered population = %d, want 3 (never review, rejected or another tenant)", n)
	}
}
