package integration

// Asset change timeline (RFC-069 §11) through the real ingest on a migrated
// database: an event only when the shown value or its deciding source
// changes; re-sightings refresh in place at most hourly; late and replayed
// reports are ignored; flapping folds into one event; locks, releases and
// TTL expiry say why; a sensor's clock cannot future- or back-date data; the
// timeline is tenant- and data-scope-isolated; retention drops whole months.

import (
	"context"
	"testing"
	"time"

	"github.com/openctemio/ctis"

	"github.com/openctemio/openctem/api/internal/app/ingest"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

type timelineEvent struct {
	old, new, kind, name, run, reason string
	flaps                             int
	actor                             *string
	at                                time.Time
}

func (g *reconcileRig) events(name, attribute string) []timelineEvent {
	g.t.Helper()
	rows, err := g.r.db.QueryContext(context.Background(), `
		SELECT old_value, new_value, source_kind, source_name, source_run, reason, flap_count, actor_id, at
		  FROM asset_change_events
		 WHERE tenant_id = $1 AND asset_id = $2 AND attribute = $3
		 ORDER BY at, created_at`, g.tn.tenant.String(), g.assetID(name), attribute)
	if err != nil {
		g.t.Fatal(err)
	}
	defer rows.Close()
	var out []timelineEvent
	for rows.Next() {
		var e timelineEvent
		if err := rows.Scan(&e.old, &e.new, &e.kind, &e.name, &e.run, &e.reason, &e.flaps, &e.actor, &e.at); err != nil {
			g.t.Fatal(err)
		}
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		g.t.Fatal(err)
	}
	return out
}

// importReport sends a server-side import with a run id.
func (g *reconcileRig) importReport(kind asset.SourceKind, run string, observed time.Time, a ctis.Asset) {
	g.t.Helper()
	tid := g.tn.tenant
	rep := &ctis.Report{Version: "1.0", Tool: &ctis.Tool{Name: "feed"}, Assets: []ctis.Asset{a},
		Metadata: ctis.ReportMetadata{Timestamp: observed}}
	agt := &sensor.Sensor{TenantID: &tid, Status: sensor.SensorStatusActive}
	opts := ingest.Options{SourceKind: kind, SourceName: string(kind) + "-feed", SourceRun: run}
	if out, err := g.r.svc.Ingest(context.Background(), agt, ingest.Input{Report: rep, Options: opts}); err != nil || len(out.Errors) > 0 {
		g.t.Fatalf("Ingest: %v %v", err, out.Errors)
	}
}

func (g *reconcileRig) sourceObservedAt(name string, attr asset.TrackedAttribute, kind asset.SourceKind) time.Time {
	g.t.Helper()
	var at time.Time
	if err := g.r.db.QueryRowContext(context.Background(), `
		SELECT observed_at FROM asset_attribute_sources
		 WHERE tenant_id = $1 AND asset_id = $2 AND attribute = $3 AND source_kind = $4`,
		g.tn.tenant.String(), g.assetID(name), string(attr), string(kind)).Scan(&at); err != nil {
		g.t.Fatalf("observed_at: %v", err)
	}
	return at
}

func TestAssetTimeline_EventOnlyWhenTheValueChanges(t *testing.T) {
	g := newReconcileRig(t)
	const name = "tl-1.example.com"
	t0 := time.Now().UTC().Add(-6 * time.Hour).Truncate(time.Second)

	g.importReport(asset.SourceKindImport, "batch-1", t0, withClaims(reconHost(name), "high", "", ""))
	if ev := g.events(name, "criticality"); len(ev) != 0 {
		t.Fatalf("creating the asset with the source's value is not a change: %+v", ev)
	}

	// Re-sighting within the hour: nothing written, observed_at unchanged.
	g.importReport(asset.SourceKindImport, "batch-2", t0.Add(10*time.Minute), withClaims(reconHost(name), "high", "", ""))
	if at := g.sourceObservedAt(name, asset.AttrCriticality, asset.SourceKindImport); !at.Equal(t0) {
		t.Fatalf("a re-sighting within the hour rewrote observed_at: %s", at)
	}
	// After the hour: observed_at refreshed in place, still no event.
	g.importReport(asset.SourceKindImport, "batch-3", t0.Add(2*time.Hour), withClaims(reconHost(name), "high", "", ""))
	if at := g.sourceObservedAt(name, asset.AttrCriticality, asset.SourceKindImport); !at.Equal(t0.Add(2 * time.Hour)) {
		t.Fatalf("a re-sighting after the hour did not refresh observed_at: %s", at)
	}
	if ev := g.events(name, "criticality"); len(ev) != 0 {
		t.Fatalf("re-sightings wrote events: %+v", ev)
	}

	// A new value is one event with old -> new, source, run, reason, time.
	g.importReport(asset.SourceKindImport, "batch-4", t0.Add(3*time.Hour), withClaims(reconHost(name), "critical", "", ""))
	ev := g.events(name, "criticality")
	if len(ev) != 1 {
		t.Fatalf("events = %+v, want one", ev)
	}
	e := ev[0]
	if e.old != "high" || e.new != "critical" || e.kind != "import" || e.name != "import-feed" || e.run != "batch-4" ||
		e.reason != string(asset.ChangeReasonNewerObservation) || !e.at.Equal(t0.Add(3*time.Hour)) || e.actor != nil {
		t.Fatalf("event = %+v", e)
	}

	// Late (older) and replayed (same time) reports change nothing.
	g.importReport(asset.SourceKindImport, "late", t0.Add(time.Hour), withClaims(reconHost(name), "low", "", ""))
	g.importReport(asset.SourceKindImport, "replay", t0.Add(3*time.Hour), withClaims(reconHost(name), "low", "", ""))
	if crit, _, _, _ := g.attrs(name); crit != "critical" {
		t.Fatalf("a late or replayed report changed the asset: %s", crit)
	}
	if ev := g.events(name, "criticality"); len(ev) != 1 {
		t.Fatalf("a late or replayed report wrote an event: %+v", ev)
	}
}

func TestAssetTimeline_FlappingFoldsIntoOneEvent(t *testing.T) {
	g := newReconcileRig(t)
	const name = "tl-flap.example.com"
	t0 := time.Now().UTC().Add(-time.Hour)
	g.importReport(asset.SourceKindIntegration, "", t0, withClaims(reconHost(name), "high", "", ""))
	for i, v := range []string{"critical", "high", "critical"} {
		g.importReport(asset.SourceKindIntegration, "", t0.Add(time.Duration(i+1)*time.Minute), withClaims(reconHost(name), v, "", ""))
	}
	ev := g.events(name, "criticality")
	if len(ev) != 1 || ev[0].flaps != 3 || ev[0].old != "high" || ev[0].new != "critical" {
		t.Fatalf("flapping: %+v, want one event high -> critical with 3 flips", ev)
	}
	// A different value after the flapping is a real change, also folded
	// while it keeps flapping (the event says where it started and ended).
	if crit, _, _, _ := g.attrs(name); crit != "critical" {
		t.Fatalf("asset shows %s", crit)
	}
}

func TestAssetTimeline_LockReleaseSourceChangeAndTTL(t *testing.T) {
	g := newReconcileRig(t)
	const name = "tl-lock.example.com"
	ctx := context.Background()
	now := time.Now().UTC()

	g.importReport(asset.SourceKindImport, "", now.Add(-3*time.Hour), withClaims(reconHost(name), "high", "", ""))
	// The same value from a more trusted source: the deciding source
	// changes, the value does not; that is an event too.
	g.importReport(asset.SourceKindIntegration, "sync-9", now.Add(-2*time.Hour), withClaims(reconHost(name), "high", "", ""))
	ev := g.events(name, "criticality")
	if len(ev) != 1 || ev[0].old != "high" || ev[0].new != "high" || ev[0].kind != "integration" || ev[0].run != "sync-9" {
		t.Fatalf("source change: %+v", ev)
	}

	id := g.assetID(name)
	actor := shared.NewID()
	if _, err := g.assets.LockAttribute(ctx, g.tn.tenant.String(), id, "criticality", "low", actor.String()); err != nil {
		t.Fatal(err)
	}
	if _, err := g.assets.ReleaseAttributeLock(ctx, g.tn.tenant.String(), id, "criticality", actor.String()); err != nil {
		t.Fatal(err)
	}
	ev = g.events(name, "criticality")
	if len(ev) != 3 {
		t.Fatalf("events after lock and release: %+v", ev)
	}
	lock, rel := ev[1], ev[2]
	if lock.reason != "manual_lock" || lock.new != "low" || lock.actor == nil || *lock.actor != actor.String() {
		t.Fatalf("lock event: %+v", lock)
	}
	// A person's release is its own entry, even right after the lock.
	if rel.reason != "lock_released" || rel.old != "low" || rel.new != "high" || rel.kind != "integration" ||
		rel.actor == nil || *rel.actor != actor.String() {
		t.Fatalf("release event: %+v", rel)
	}
}

func TestAssetTimeline_TTLExpiryMovesToTheNextSource(t *testing.T) {
	g := newReconcileRig(t)
	const name = "tl-ttl.example.com"
	ctx := context.Background()
	now := time.Now().UTC()

	g.importReport(asset.SourceKindImport, "", now.Add(-2*time.Hour), withClaims(reconHost(name), "medium", "", ""))
	g.importReport(asset.SourceKindIntegration, "", now.Add(-time.Hour), withClaims(reconHost(name), "critical", "", ""))
	if crit, _, _, _ := g.attrs(name); crit != "critical" {
		t.Fatalf("integration should decide: %s", crit)
	}
	// The integration stops reporting: age its record past the 30-day TTL.
	if _, err := g.r.db.ExecContext(ctx, `
		UPDATE asset_attribute_sources SET observed_at = now() - interval '40 days', ingested_at = now() - interval '40 days'
		 WHERE tenant_id = $1 AND asset_id = $2 AND source_kind = 'integration'`, g.tn.tenant.String(), g.assetID(name)); err != nil {
		t.Fatal(err)
	}
	aid, _ := shared.IDFromString(g.assetID(name))
	n, err := g.assets.ResolveAttributes(ctx, g.tn.tenant, []shared.ID{aid}, "")
	if err != nil || n != 1 {
		t.Fatalf("ResolveAttributes = %d, %v", n, err)
	}
	if crit, _, _, _ := g.attrs(name); crit != "medium" {
		t.Fatalf("after TTL expiry: %s, want the import's medium", crit)
	}
	ev := g.events(name, "criticality")
	last := ev[len(ev)-1]
	if last.reason != string(asset.ChangeReasonTTLExpiry) || last.old != "critical" || last.new != "medium" {
		t.Fatalf("ttl event: %+v", last)
	}
	// Resolving again changes nothing and writes nothing.
	if n, _ := g.assets.ResolveAttributes(ctx, g.tn.tenant, []shared.ID{aid}, ""); n != 0 || len(g.events(name, "criticality")) != len(ev) {
		t.Fatalf("a second resolve changed %d values", n)
	}
}

func TestAssetTimeline_SensorClockIsClamped(t *testing.T) {
	g := newReconcileRig(t)
	const name = "tl-clock.example.com"
	tid := g.tn.tenant
	dispatched := time.Now().UTC().Add(-time.Hour).Truncate(time.Millisecond)
	a := reconHost(name)
	a.IsInternetAccessible = true
	rep := &ctis.Report{Version: "1.0", Tool: &ctis.Tool{Name: "nmap"}, Assets: []ctis.Asset{a},
		// The sensor claims it saw this two days ago, before it was given the job.
		Metadata: ctis.ReportMetadata{Timestamp: dispatched.Add(-48 * time.Hour)}}
	agt := &sensor.Sensor{ID: g.tn.sensor, TenantID: &tid, Type: sensor.SensorTypeWorker, Status: sensor.SensorStatusActive}
	cmdID := shared.NewID()
	opts := ingest.Options{Binding: ingest.Binding{Kind: ingest.BindingCommand, CommandID: &cmdID, Targets: []string{name}, DispatchedAt: dispatched}}
	if out, err := g.r.svc.Ingest(context.Background(), agt, ingest.Input{Report: rep, Options: opts}); err != nil || len(out.Errors) > 0 {
		t.Fatalf("Ingest: %v %v", err, out.Errors)
	}
	if at := g.sourceObservedAt(name, asset.AttrExposure, asset.SourceKindScan); !at.Equal(dispatched) {
		t.Fatalf("observed_at = %s, want the dispatch time %s", at, dispatched)
	}
	var run string
	_ = g.r.db.QueryRowContext(context.Background(), `SELECT source_run FROM asset_attribute_sources WHERE tenant_id = $1 AND asset_id = $2 AND attribute = 'exposure'`,
		tid.String(), g.assetID(name)).Scan(&run)
	if run != cmdID.String() {
		t.Fatalf("source_run = %q, want the command id", run)
	}
}

func TestAssetTimeline_ListIsTenantAndScopeIsolated(t *testing.T) {
	g := newReconcileRig(t)
	ctx := context.Background()
	repo := postgres.NewAssetChangeEventRepository(&postgres.DB{DB: g.r.db})
	const name = "tl-list.example.com"
	t0 := time.Now().UTC().Add(-time.Hour)
	g.importReport(asset.SourceKindIntegration, "", t0, withClaims(reconHost(name), "low", "", ""))
	g.importReport(asset.SourceKindIntegration, "", t0.Add(time.Minute), withClaims(reconHost(name), "high", "a@example.com", "internal"))

	all, more, err := repo.ListChanges(ctx, g.tn.tenant, asset.ChangeQuery{Limit: 50})
	if err != nil || more || len(all) < 2 {
		t.Fatalf("feed: %d events more=%v err=%v", len(all), more, err)
	}
	if all[0].AssetName != name {
		t.Fatalf("feed carries the asset name: %+v", all[0])
	}
	// Keyset pages: one at a time, newest first, no repeats.
	first, more, err := repo.ListChanges(ctx, g.tn.tenant, asset.ChangeQuery{Limit: 1})
	if err != nil || !more || len(first) != 1 {
		t.Fatalf("page 1: %v %v %v", first, more, err)
	}
	second, _, err := repo.ListChanges(ctx, g.tn.tenant, asset.ChangeQuery{Limit: 1, BeforeAt: &first[0].At, BeforeID: &first[0].ID})
	if err != nil || len(second) != 1 || second[0].ID == first[0].ID || second[0].At.After(first[0].At) {
		t.Fatalf("page 2: %+v after %+v (%v)", second, first, err)
	}
	// Filters.
	only, _, _ := repo.ListChanges(ctx, g.tn.tenant, asset.ChangeQuery{Attributes: []string{"owner_ref"}, Limit: 50})
	for _, e := range only {
		if e.Attribute != "owner_ref" {
			t.Fatalf("attribute filter returned %s", e.Attribute)
		}
	}
	if none, _, _ := repo.ListChanges(ctx, g.tn.tenant, asset.ChangeQuery{SourceKinds: []asset.SourceKind{asset.SourceKindScan}, Limit: 50}); len(none) != 0 {
		t.Fatalf("source filter: %d scan events", len(none))
	}

	// Another tenant sees nothing of it, by feed or by asset id.
	other := g.r.newTenant("nmap")
	aid, _ := shared.IDFromString(g.assetID(name))
	if ev, _, _ := repo.ListChanges(ctx, other.tenant, asset.ChangeQuery{Limit: 50}); len(ev) != 0 {
		t.Fatalf("another tenant's feed shows %d events", len(ev))
	}
	if ev, _, _ := repo.ListChanges(ctx, other.tenant, asset.ChangeQuery{AssetID: &aid, Limit: 50}); len(ev) != 0 {
		t.Fatalf("another tenant read the asset's timeline: %d events", len(ev))
	}
	// A member with no data scope row sees nothing in the feed.
	member := shared.NewID()
	if ev, _, _ := repo.ListChanges(ctx, g.tn.tenant, asset.ChangeQuery{ScopeUserID: &member, Limit: 50}); len(ev) != 0 {
		t.Fatalf("an out-of-scope member sees %d events", len(ev))
	}

	// Erasure: deleting the tenant removes its timeline (cascade).
	if _, err := g.r.db.ExecContext(ctx, `DELETE FROM tenants WHERE id = $1`, g.tn.tenant.String()); err != nil {
		t.Fatal(err)
	}
	var left int
	_ = g.r.db.QueryRowContext(ctx, `SELECT count(*) FROM asset_change_events WHERE tenant_id = $1`, g.tn.tenant.String()).Scan(&left)
	if left != 0 {
		t.Fatalf("%d events outlived their tenant", left)
	}
}

func TestAssetTimeline_PartitionsAndRetention(t *testing.T) {
	g := newReconcileRig(t)
	ctx := context.Background()
	repo := postgres.NewAssetChangeEventRepository(&postgres.DB{DB: g.r.db})
	const name = "tl-retention.example.com"
	g.importReport(asset.SourceKindImport, "", time.Now().UTC().Add(-time.Hour), withClaims(reconHost(name), "low", "", ""))
	aid := g.assetID(name)
	insert := func(at time.Time) {
		if _, err := g.r.db.ExecContext(ctx, `
			INSERT INTO asset_change_events (id, tenant_id, asset_id, at, attribute, old_value, new_value, source_kind, reason)
			VALUES ($1, $2, $3, $4, 'criticality', 'low', 'high', 'import', 'newer_observation')`,
			shared.NewID().String(), g.tn.tenant.String(), aid, at); err != nil {
			t.Fatal(err)
		}
	}
	old := time.Date(2019, 3, 1, 0, 0, 0, 0, time.UTC) // before every monthly partition: default partition
	insert(old)
	insert(time.Now().UTC()) // this month's partition
	// The migration created this month and the next two years.
	var months int
	_ = g.r.db.QueryRowContext(ctx, `SELECT count(*) FROM pg_inherits WHERE inhparent = 'asset_change_events'::regclass`).Scan(&months)
	if months < 25 {
		t.Fatalf("partitions = %d, want the default plus at least two years of months", months)
	}
	n, err := repo.DeleteBefore(ctx, time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC))
	if err != nil || n < 1 {
		t.Fatalf("DeleteBefore = %d, %v", n, err)
	}
	var left int
	_ = g.r.db.QueryRowContext(ctx, `SELECT count(*) FROM asset_change_events WHERE tenant_id = $1 AND asset_id = $2`,
		g.tn.tenant.String(), aid).Scan(&left)
	if left != 1 {
		t.Fatalf("events left = %d, want the recent one", left)
	}
}

// A feed (program feed, passive data) is its own source kind: by default it
// decides network exposure but never ownership or business context.
func TestAssetTimeline_FeedSourceKind(t *testing.T) {
	g := newReconcileRig(t)
	const name = "tl-feed.example.com"
	now := time.Now().UTC()
	g.importReport(asset.SourceKindImport, "", now.Add(-time.Hour), withClaims(reconHost(name), "low", "", ""))
	a := withClaims(reconHost(name), "critical", "", "")
	a.IsInternetAccessible = true
	g.importReport(asset.SourceKindFeed, "seq-42", now, a)
	crit, _, exp, _ := g.attrs(name)
	if crit != "low" || exp != "public" {
		t.Fatalf("feed: criticality %s (must stay the import's), exposure %s", crit, exp)
	}
	var kind, run string
	if err := g.r.db.QueryRowContext(context.Background(), `SELECT source_kind, source_run FROM asset_attribute_sources
		WHERE tenant_id = $1 AND asset_id = $2 AND attribute = 'exposure'`, g.tn.tenant.String(), g.assetID(name)).Scan(&kind, &run); err != nil {
		t.Fatal(err)
	}
	if kind != "feed" || run != "seq-42" {
		t.Fatalf("recorded %s / %s", kind, run)
	}
}
