package postgres

import (
	"context"
	"testing"
	"time"

	"github.com/openctemio/openctem/server/pkg/domain/asset"
	"github.com/openctemio/openctem/server/pkg/domain/coverage"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
)

// A web service whose page changed has its screenshot pair moved to due now,
// only inside the tenant, only when the pair waits for its cadence, and not
// again within a day of the last attempt. Requires DATABASE_URL.
func TestAssetCoveragePagesChanged(t *testing.T) {
	db := openHopDB(t)
	repo := NewAssetCoverageRepository(&DB{DB: db})
	ctx := context.Background()
	h, other := newHopTenant(t, db, 0), newHopTenant(t, db, 0)

	service := func(tenant shared.ID, name string) shared.ID {
		t.Helper()
		id := shared.NewID()
		hopExec(t, db, `INSERT INTO assets (id, tenant_id, name, asset_type, sub_type, properties)
			VALUES ($1, $2, $3, 'service', 'http', '{"port": 443}'::jsonb)`, id, tenant, name)
		return id
	}
	changed := service(h.tenant, "https://changed.example.com")
	recent := service(h.tenant, "https://recent.example.com")
	paused := service(h.tenant, "https://paused.example.com")
	foreign := service(other.tenant, "https://foreign.example.net")

	var rules []coverage.Rule
	for _, r := range coverage.RulesFor(asset.AssetTypeService, "http") {
		if r.Capability == "capture.screenshot" {
			rules = append(rules, r)
		}
	}
	if len(rules) != 1 || rules[0].Every != 30*24*time.Hour {
		t.Fatalf("http service capture.screenshot rule: %+v", rules)
	}
	for _, tn := range []shared.ID{h.tenant, other.tenant} {
		if _, _, err := repo.Reconcile(ctx, tn, rules); err != nil {
			t.Fatal(err)
		}
	}
	// All pairs covered a week ago with a month to go; one attempted an hour
	// ago; one paused (screenshots off).
	hopExec(t, db, `UPDATE asset_coverage SET state = 'covered', next_due_at = now() + interval '23 days',
		last_attempt_at = now() - interval '7 days' WHERE capability = 'capture.screenshot' AND tenant_id IN ($1, $2)`,
		h.tenant.String(), other.tenant.String())
	hopExec(t, db, `UPDATE asset_coverage SET last_attempt_at = now() - interval '1 hour'
		WHERE tenant_id = $1 AND asset_id = $2 AND capability = 'capture.screenshot'`, h.tenant.String(), recent.String())
	hopExec(t, db, `UPDATE asset_coverage SET state = 'paused', reason = 'feature_off'
		WHERE tenant_id = $1 AND asset_id = $2 AND capability = 'capture.screenshot'`, h.tenant.String(), paused.String())

	due := func(tenant, id shared.ID) bool {
		t.Helper()
		var ok bool
		if err := db.QueryRowContext(ctx, `SELECT next_due_at <= now() FROM asset_coverage
			WHERE tenant_id = $1 AND asset_id = $2 AND capability = 'capture.screenshot'`, tenant.String(), id.String()).Scan(&ok); err != nil {
			t.Fatal(err)
		}
		return ok
	}
	// Tenant h reports its own three assets and tenant other's asset id.
	if err := repo.PagesChanged(ctx, h.tenant, []shared.ID{changed, recent, paused, foreign}); err != nil {
		t.Fatal(err)
	}
	if !due(h.tenant, changed) {
		t.Fatal("a changed page is due now")
	}
	if due(h.tenant, recent) {
		t.Fatal("a pair attempted within a day does not move")
	}
	if due(h.tenant, paused) {
		t.Fatal("a paused pair keeps its state")
	}
	if due(other.tenant, foreign) {
		t.Fatal("another organization's pair moved")
	}
	if err := repo.PagesChanged(ctx, h.tenant, nil); err != nil {
		t.Fatal(err)
	}
}
