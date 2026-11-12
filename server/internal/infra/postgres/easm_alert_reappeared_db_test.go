package postgres

import (
	"context"
	"testing"

	"github.com/openctemio/openctem/api/internal/app/easmdns"
	"github.com/openctemio/openctem/api/pkg/domain/exposure"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// An active exposure that is not seen for longer than the tenant's alert
// fingerprint lifetime and then seen again is announced as "reappeared"
// (default 30 days, per tenant). Requires DATABASE_URL.
func TestEASMAlerts_Reappeared(t *testing.T) {
	sqlDB := openSensorDB(t)
	ctx := context.Background()
	db := &DB{DB: sqlDB}
	alerts := NewEASMAlerter(db)
	writer := NewEASMExposureWriter(db, alerts)
	dnsRepo := NewEASMDNSRepository(db).WithAlerts(alerts)

	tenantA := seedTestTenant(ctx, t, sqlDB)
	tenantB := seedTestTenant(ctx, t, sqlDB)

	event := func(tn shared.ID, assetID shared.ID, title string) *exposure.ExposureEvent {
		t.Helper()
		ev, err := exposure.NewExposureEvent(tn, exposure.EventTypeDanglingCNAME, exposure.SeverityMedium, title, easmdns.Source, map[string]any{"domain": title})
		if err != nil {
			t.Fatal(err)
		}
		ev.SetAssetID(&assetID)
		return ev
	}
	asset := func(tn shared.ID, name string) shared.ID {
		t.Helper()
		id := seedNamedAsset(ctx, t, dnsRepo, tn, name, "subdomain", "active")
		if _, err := sqlDB.ExecContext(ctx, `INSERT INTO asset_attributions (asset_id, tenant_id, state, confidence) VALUES ($1, $2, 'confirmed', 90)`,
			id.String(), tn.String()); err != nil {
			t.Fatal(err)
		}
		return id
	}
	// alertsOf returns the reasons of the tenant's immediate exposure alerts.
	alertsOf := func(tn shared.ID) []string {
		t.Helper()
		rows, err := sqlDB.QueryContext(ctx, `SELECT metadata->>'reason' FROM notification_outbox
			WHERE tenant_id = $1 AND event_type = 'new_exposure' AND aggregate_type = 'exposure' ORDER BY created_at, id`, tn.String())
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		var out []string
		for rows.Next() {
			var r string
			if err := rows.Scan(&r); err != nil {
				t.Fatal(err)
			}
			out = append(out, r)
		}
		if err := rows.Err(); err != nil {
			t.Fatal(err)
		}
		return out
	}
	ageSighting := func(ev *exposure.ExposureEvent, days int) {
		t.Helper()
		if _, err := sqlDB.ExecContext(ctx, `UPDATE exposure_events SET last_seen_at = now() - make_interval(days => $3)
			WHERE tenant_id = $1 AND fingerprint = $2`, ev.TenantID().String(), ev.Fingerprint(), days); err != nil {
			t.Fatal(err)
		}
	}
	setReappear := func(tn shared.ID, days int) {
		t.Helper()
		if _, err := sqlDB.ExecContext(ctx, `UPDATE tenants SET settings = jsonb_set(COALESCE(settings, '{}'::jsonb), '{easm}', jsonb_build_object('reappear_after_days', $2::int)) WHERE id = $1`,
			tn.String(), days); err != nil {
			t.Fatal(err)
		}
	}
	seed := func(ev *exposure.ExposureEvent) {
		t.Helper()
		if err := writer.BulkUpsert(ctx, []*exposure.ExposureEvent{ev}); err != nil {
			t.Fatal(err)
		}
	}
	// sight records the same exposure seen again.
	sight := func(tn, assetID shared.ID, title string) {
		t.Helper()
		seed(event(tn, assetID, title))
	}

	a1 := asset(tenantA, "one.reappear.example.com")
	first := event(tenantA, a1, "Dangling CNAME: one.reappear.example.com")
	seed(first)
	if got := alertsOf(tenantA); len(got) != 1 || got[0] != "new" {
		t.Fatalf("first sighting alerts = %v, want [new]", got)
	}

	t.Run("seen again within the window announces nothing", func(t *testing.T) {
		ageSighting(first, 29)
		sight(tenantA, a1, "Dangling CNAME: one.reappear.example.com")
		if got := alertsOf(tenantA); len(got) != 1 {
			t.Fatalf("alerts = %v, want only the first", got)
		}
	})

	t.Run("unseen past the default window then seen again: reappeared", func(t *testing.T) {
		ageSighting(first, 31)
		sight(tenantA, a1, "Dangling CNAME: one.reappear.example.com")
		got := alertsOf(tenantA)
		if len(got) != 2 || got[1] != "reappeared" {
			t.Fatalf("alerts = %v, want [new reappeared]", got)
		}
		// The sighting moved last_seen_at: an immediate re-sighting is quiet.
		sight(tenantA, a1, "Dangling CNAME: one.reappear.example.com")
		if got := alertsOf(tenantA); len(got) != 2 {
			t.Fatalf("alerts = %v after an immediate re-sighting, want 2", got)
		}
	})

	t.Run("a resolved exposure does not announce a reappearance", func(t *testing.T) {
		ageSighting(first, 90)
		if n, err := dnsRepo.ResolveAuto(ctx, tenantA, easmdns.Source, []string{first.Fingerprint()}, easmdns.AutoResolveNote); err != nil || n != 1 {
			t.Fatalf("resolve: %d %v", n, err)
		}
		ageSighting(first, 90)
		before := len(alertsOf(tenantA))
		sight(tenantA, a1, "Dangling CNAME: one.reappear.example.com")
		if got := alertsOf(tenantA); len(got) != before {
			t.Fatalf("alerts = %v, a resolved exposure must stay quiet", got)
		}
	})

	t.Run("the window is per tenant", func(t *testing.T) {
		const title = "Dangling CNAME: shared.reappear.example.com"
		aA, aB := asset(tenantA, "shared.reappear.example.com"), asset(tenantB, "shared.reappear.example.com")
		evA, evB := event(tenantA, aA, title), event(tenantB, aB, title)
		seed(evA)
		seed(evB)
		ageSighting(evA, 10)
		ageSighting(evB, 10)
		setReappear(tenantB, 7)
		beforeA, beforeB := len(alertsOf(tenantA)), len(alertsOf(tenantB))
		sight(tenantA, aA, title)
		sight(tenantB, aB, title)
		if got := len(alertsOf(tenantA)); got != beforeA {
			t.Fatalf("tenant A (default 30 days) alerted on a 10 day gap: %v", alertsOf(tenantA))
		}
		gotB := alertsOf(tenantB)
		if len(gotB) != beforeB+1 || gotB[len(gotB)-1] != "reappeared" {
			t.Fatalf("tenant B (7 days) alerts = %v, want a reappeared alert", gotB)
		}
	})
}
