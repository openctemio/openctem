package asset_test

// The stale pass of the asset lifecycle worker against a migrated database.
// The worker used to require an asset_sources row before demoting an asset;
// nothing writes that table, so no asset ingest created was ever demoted.
// These tests pin the replacement: provenance from assets.discovery_source,
// the clock from assets.last_seen, and the run scoped to one tenant.

import (
	"context"
	"database/sql"
	"testing"

	_ "github.com/lib/pq"

	assetapp "github.com/openctemio/openctem/api/internal/app/asset"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/internal/testdb"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

type lifecycleHarness struct {
	t  *testing.T
	db *sql.DB
	w  *assetapp.AssetLifecycleWorker
}

func newLifecycleHarness(t *testing.T) *lifecycleHarness {
	t.Helper()
	dbURL := testdb.URL()
	if dbURL == "" {
		testdb.Skipf(t, "DATABASE_URL not set; skipping asset lifecycle DB test")
		return nil
	}
	sqldb, err := sql.Open("postgres", dbURL)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { _ = sqldb.Close() })
	if err := sqldb.PingContext(context.Background()); err != nil {
		testdb.Skipf(t, "cannot reach DATABASE_URL: %v", err)
		return nil
	}
	repo := postgres.NewTenantRepository(&postgres.DB{DB: sqldb})
	return &lifecycleHarness{t: t, db: sqldb, w: assetapp.NewAssetLifecycleWorker(sqldb, repo, logger.NewNop())}
}

func (h *lifecycleHarness) exec(q string, args ...any) {
	h.t.Helper()
	if _, err := h.db.ExecContext(context.Background(), q, args...); err != nil {
		h.t.Fatalf("%s: %v", q, err)
	}
}

// tenant creates a tenant with the lifecycle worker enabled: 14-day threshold,
// no grace period, the default exclusions (manual, import) unless excluded is
// given, and no ingest-silence pause.
func (h *lifecycleHarness) tenant(excluded string) shared.ID {
	h.t.Helper()
	id := shared.NewID()
	if excluded == "" {
		excluded = `["manual", "import"]`
	}
	h.exec(`INSERT INTO tenants (id, name, slug, settings) VALUES ($1, 'lifecycle IT', $2,
		jsonb_build_object('asset_lifecycle', jsonb_build_object(
			'enabled', true, 'stale_threshold_days', 14, 'grace_period_days', 0,
			'excluded_source_types', $3::jsonb, 'pause_on_integration_failure', false)))`,
		id.String(), "lc-"+id.String(), excluded)
	h.t.Cleanup(func() {
		ctx := context.Background()
		_, _ = h.db.ExecContext(ctx, `DELETE FROM asset_state_history WHERE tenant_id = $1`, id.String())
		_, _ = h.db.ExecContext(ctx, `DELETE FROM assets WHERE tenant_id = $1`, id.String())
		_, _ = h.db.ExecContext(ctx, `DELETE FROM tenants WHERE id = $1`, id.String())
	})
	return id
}

// asset inserts an active asset whose last sighting was lastSeenDaysAgo days
// ago. source is assets.discovery_source ("" stores NULL).
func (h *lifecycleHarness) asset(tenantID shared.ID, name, source string, lastSeenDaysAgo int) shared.ID {
	h.t.Helper()
	id := shared.NewID()
	h.exec(`INSERT INTO assets (id, tenant_id, name, asset_type, status, discovery_source,
			discovered_at, first_seen, last_seen, created_at, updated_at)
		VALUES ($1, $2, $3, 'domain', 'active', NULLIF($4, ''),
			NOW() - interval '90 days', NOW() - interval '90 days',
			NOW() - make_interval(days => $5), NOW() - interval '90 days', NOW() - make_interval(days => $5))`,
		id.String(), tenantID.String(), name, source, lastSeenDaysAgo)
	return id
}

func (h *lifecycleHarness) status(id shared.ID) string {
	h.t.Helper()
	var s string
	if err := h.db.QueryRowContext(context.Background(), `SELECT status FROM assets WHERE id = $1`, id.String()).Scan(&s); err != nil {
		h.t.Fatalf("status of %s: %v", id, err)
	}
	return s
}

func TestLifecycleWorker_DemotesIngestedAssetsNotSeenWithinThreshold(t *testing.T) {
	h := newLifecycleHarness(t)
	if h == nil {
		return
	}
	ctx := context.Background()
	tenantID := h.tenant("")

	// No asset_sources rows anywhere: the provenance comes from the asset.
	sensorOld := h.asset(tenantID, "old.sensor.example", "sensor", 30)
	ctOld := h.asset(tenantID, "old.ct.example", "cert_transparency", 30)
	sensorFresh := h.asset(tenantID, "fresh.sensor.example", "sensor", 2)
	manualOld := h.asset(tenantID, "old.manual.example", "manual", 30)
	unknownOld := h.asset(tenantID, "old.unknown.example", "", 30)
	importOld := h.asset(tenantID, "old.import.example", "nessus", 30)

	// Another tenant's stale-looking ingested asset is never touched.
	otherTenant := h.tenant("")
	otherOld := h.asset(otherTenant, "old.other.example", "sensor", 30)

	dry, err := h.w.Run(ctx, tenantID, true)
	if err != nil {
		t.Fatalf("dry run: %v", err)
	}
	if dry.TransitionedToStale != 2 {
		t.Fatalf("dry run counted %d candidates, want 2 (sensor + cert_transparency)", dry.TransitionedToStale)
	}
	if got := h.status(sensorOld); got != "active" {
		t.Fatalf("dry run changed status to %q", got)
	}

	rep, err := h.w.Run(ctx, tenantID, false)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if rep.Skipped || rep.TransitionedToStale != 2 {
		t.Fatalf("run: skipped=%v (%s) transitioned=%d, want 2", rep.Skipped, rep.SkipReason, rep.TransitionedToStale)
	}
	for _, c := range []struct {
		name string
		id   shared.ID
		want string
	}{
		{"sensor-discovered, not seen for 30 days", sensorOld, "stale"},
		{"cert transparency, not seen for 30 days", ctOld, "stale"},
		{"sensor-discovered, seen 2 days ago", sensorFresh, "active"},
		{"manual (excluded by default)", manualOld, "active"},
		{"no discovery source = manual", unknownOld, "active"},
		{"file import (excluded by default)", importOld, "active"},
		{"other tenant", otherOld, "active"},
	} {
		if got := h.status(c.id); got != c.want {
			t.Errorf("%s: status %q, want %q", c.name, got, c.want)
		}
	}
}

func TestLifecycleWorker_ExcludedSourceTypes(t *testing.T) {
	h := newLifecycleHarness(t)
	if h == nil {
		return
	}
	ctx := context.Background()

	// Excluding the scanner category protects every ingest-discovered asset.
	scannerExcluded := h.tenant(`["manual", "import", "scanner"]`)
	protected := h.asset(scannerExcluded, "old.sensor.example", "sensor", 30)
	if rep, err := h.w.Run(ctx, scannerExcluded, false); err != nil || rep.TransitionedToStale != 0 {
		t.Fatalf("scanner excluded: transitioned=%v err=%v, want 0", rep, err)
	}
	if got := h.status(protected); got != "active" {
		t.Errorf("scanner excluded: status %q, want active", got)
	}

	// A raw discovery_source value can be excluded on its own.
	rawExcluded := h.tenant(`["manual", "import", "cert_transparency"]`)
	ct := h.asset(rawExcluded, "old.ct.example", "cert_transparency", 30)
	sensor := h.asset(rawExcluded, "old.sensor.example", "sensor", 30)
	if _, err := h.w.Run(ctx, rawExcluded, false); err != nil {
		t.Fatalf("raw excluded: %v", err)
	}
	if got := h.status(ct); got != "active" {
		t.Errorf("excluded cert_transparency asset: status %q, want active", got)
	}
	if got := h.status(sensor); got != "stale" {
		t.Errorf("sensor asset next to an excluded source: status %q, want stale", got)
	}

	// With nothing excluded, a manually created asset not touched for 30 days
	// is demoted too.
	nothingExcluded := h.tenant(`["collector"]`)
	manual := h.asset(nothingExcluded, "old.manual.example", "", 30)
	if _, err := h.w.Run(ctx, nothingExcluded, false); err != nil {
		t.Fatalf("nothing excluded: %v", err)
	}
	if got := h.status(manual); got != "stale" {
		t.Errorf("manual asset with no exclusions: status %q, want stale", got)
	}
}
