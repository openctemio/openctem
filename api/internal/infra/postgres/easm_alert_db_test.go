package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"testing"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/internal/app/easmdns"
	"github.com/openctemio/openctem/api/pkg/domain/easmalert"
	"github.com/openctemio/openctem/api/pkg/domain/exposure"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// EASM alerts through the notification outbox against the real schema
// (migration 000980; research/22 P0-7 acceptance tests). Requires
// DATABASE_URL.
func TestEASMAlerts(t *testing.T) {
	sqlDB := openSensorDB(t)
	ctx := context.Background()
	db := &DB{DB: sqlDB}
	alerts := NewEASMAlerter(db)
	writer := NewEASMExposureWriter(db, alerts)
	dnsRepo := NewEASMDNSRepository(db).WithAlerts(alerts)

	tenant := seedTestTenant(ctx, t, sqlDB)
	other := seedTestTenant(ctx, t, sqlDB)

	asset := func(tn shared.ID, name, state string) shared.ID {
		t.Helper()
		id := seedNamedAsset(ctx, t, dnsRepo, tn, name, "subdomain", "active")
		if state != "" {
			if _, err := sqlDB.ExecContext(ctx, `INSERT INTO asset_attributions (asset_id, tenant_id, state, confidence) VALUES ($1, $2, $3, 90)`,
				id.String(), tn.String(), state); err != nil {
				t.Fatal(err)
			}
		}
		return id
	}
	event := func(tn shared.ID, assetID *shared.ID, typ exposure.EventType, sev exposure.Severity, title string) *exposure.ExposureEvent {
		t.Helper()
		ev, err := exposure.NewExposureEvent(tn, typ, sev, title, easmdns.Source, map[string]any{"domain": title})
		if err != nil {
			t.Fatal(err)
		}
		if assetID != nil {
			ev.SetAssetID(assetID)
		}
		return ev
	}
	immediate := func(tn shared.ID) int {
		t.Helper()
		var n int
		if err := sqlDB.QueryRowContext(ctx, `SELECT count(*) FROM notification_outbox
			WHERE tenant_id = $1 AND event_type = 'new_exposure' AND aggregate_type = 'exposure'`, tn.String()).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	digest := func(tn shared.ID) (int, easmDigest) {
		t.Helper()
		var rows int
		var d easmDigest
		if err := sqlDB.QueryRowContext(ctx, `SELECT count(*) FROM notification_outbox
			WHERE tenant_id = $1 AND aggregate_type = 'easm_digest'`, tn.String()).Scan(&rows); err != nil {
			t.Fatal(err)
		}
		if rows == 0 {
			return 0, d
		}
		var raw []byte
		if err := sqlDB.QueryRowContext(ctx, `SELECT metadata FROM notification_outbox
			WHERE tenant_id = $1 AND aggregate_type = 'easm_digest' AND status = 'pending'`, tn.String()).Scan(&raw); err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(raw, &d); err != nil {
			t.Fatal(err)
		}
		return rows, d
	}

	confirmed := asset(tenant, "shop.alerts.example.com", "confirmed")
	unrecorded := asset(tenant, "legacy.alerts.example.com", "")
	review := asset(tenant, "new.alerts.example.com", "needs_review")
	rejected := asset(tenant, "notours.alerts.example.com", "rejected")

	dangling := event(tenant, &confirmed, exposure.EventTypeDanglingCNAME, exposure.SeverityMedium, "Dangling CNAME: shop.alerts.example.com")

	t.Run("new medium exposure on a confirmed asset: one immediate alert", func(t *testing.T) {
		if err := writer.BulkUpsert(ctx, []*exposure.ExposureEvent{dangling}); err != nil {
			t.Fatal(err)
		}
		if got := immediate(tenant); got != 1 {
			t.Fatalf("immediate alerts = %d, want 1", got)
		}
		var title, url, sev string
		var raw []byte
		if err := sqlDB.QueryRowContext(ctx, `SELECT title, url, severity, metadata FROM notification_outbox
			WHERE tenant_id = $1 AND aggregate_type = 'exposure'`, tenant.String()).Scan(&title, &url, &sev, &raw); err != nil {
			t.Fatal(err)
		}
		var meta map[string]any
		_ = json.Unmarshal(raw, &meta)
		if sev != "medium" || meta["source"] != easmdns.Source || meta["attribution"] != "confirmed" || meta["reason"] != "new" ||
			meta["channel"] != "easm" || url == "" || title == "" {
			t.Fatalf("alert = %q %q %q %v", title, url, sev, meta)
		}
	})

	t.Run("re-sighting announces nothing", func(t *testing.T) {
		again := event(tenant, &confirmed, exposure.EventTypeDanglingCNAME, exposure.SeverityMedium, "Dangling CNAME: shop.alerts.example.com")
		if again.Fingerprint() != dangling.Fingerprint() {
			t.Fatal("fixture: fingerprints differ")
		}
		if err := writer.BulkUpsert(ctx, []*exposure.ExposureEvent{again}); err != nil {
			t.Fatal(err)
		}
		if got := immediate(tenant); got != 1 {
			t.Fatalf("immediate alerts = %d after a re-sighting, want 1", got)
		}
	})

	t.Run("resolved by the check, then found again: one more alert", func(t *testing.T) {
		fps := []string{dangling.Fingerprint()}
		if n, err := dnsRepo.ResolveAuto(ctx, tenant, easmdns.Source, fps, easmdns.AutoResolveNote); err != nil || n != 1 {
			t.Fatalf("resolve: %d %v", n, err)
		}
		if got := immediate(tenant); got != 1 {
			t.Fatalf("resolving alerted: %d", got)
		}
		if n, err := dnsRepo.ReopenAuto(ctx, tenant, easmdns.Source, fps, easmdns.AutoResolveNote); err != nil || n != 1 {
			t.Fatalf("reopen: %d %v", n, err)
		}
		if got := immediate(tenant); got != 2 {
			t.Fatalf("immediate alerts = %d after a reopen, want 2", got)
		}
		var reason string
		_ = sqlDB.QueryRowContext(ctx, `SELECT metadata->>'reason' FROM notification_outbox
			WHERE tenant_id = $1 AND aggregate_type = 'exposure' ORDER BY created_at DESC LIMIT 1`, tenant.String()).Scan(&reason)
		if reason != "reopened" {
			t.Fatalf("reason = %q", reason)
		}
	})

	t.Run("rejected asset: never; deleted asset: never", func(t *testing.T) {
		gone := asset(tenant, "gone.alerts.example.com", "confirmed")
		if _, err := sqlDB.ExecContext(ctx, `UPDATE assets SET deleted_at = now() WHERE id = $1`, gone.String()); err != nil {
			t.Fatal(err)
		}
		evs := []*exposure.ExposureEvent{
			event(tenant, &rejected, exposure.EventTypeDanglingCNAME, exposure.SeverityHigh, "Dangling CNAME: notours.alerts.example.com"),
			event(tenant, &gone, exposure.EventTypeDanglingCNAME, exposure.SeverityHigh, "Dangling CNAME: gone.alerts.example.com"),
		}
		if err := writer.BulkUpsert(ctx, evs); err != nil {
			t.Fatal(err)
		}
		if got := immediate(tenant); got != 2 {
			t.Fatalf("immediate alerts = %d, want still 2", got)
		}
		if n, _ := digest(tenant); n != 0 {
			t.Fatalf("a rejected or deleted asset reached the digest")
		}
	})

	t.Run("unverified, low and unlinked go to one digest; unrecorded medium is immediate", func(t *testing.T) {
		evs := []*exposure.ExposureEvent{
			event(tenant, &review, exposure.EventTypeDanglingCNAME, exposure.SeverityHigh, "Dangling CNAME: new.alerts.example.com"),
			event(tenant, &confirmed, exposure.EventTypeEmailSecurityWeak, exposure.SeverityLow, "Weak email: shop.alerts.example.com"),
			event(tenant, nil, exposure.EventTypeSubdomainDiscovered, exposure.SeverityInfo, "New subdomain: x.alerts.example.com"),
			event(tenant, &unrecorded, exposure.EventTypeDanglingCNAME, exposure.SeverityMedium, "Dangling CNAME: legacy.alerts.example.com"),
		}
		if err := writer.BulkUpsert(ctx, evs); err != nil {
			t.Fatal(err)
		}
		if got := immediate(tenant); got != 3 {
			t.Fatalf("immediate alerts = %d, want 3", got)
		}
		rows, d := digest(tenant)
		if rows != 1 || d.Count != 3 || d.BySeverity["high"] != 1 || d.ByLabel[easmalert.LabelUnverified] != 1 ||
			d.ByLabel[easmalert.LabelUnlinked] != 1 || len(d.Items) != 3 {
			t.Fatalf("digest rows=%d %+v", rows, d)
		}
		var sev string
		var scheduled sql.NullTime
		_ = sqlDB.QueryRowContext(ctx, `SELECT severity, scheduled_at FROM notification_outbox
			WHERE tenant_id = $1 AND aggregate_type = 'easm_digest'`, tenant.String()).Scan(&sev, &scheduled)
		if sev != "high" || !scheduled.Valid || scheduled.Time.UTC().Hour() != easmalert.DigestHourUTC {
			t.Fatalf("digest severity %q scheduled %v", sev, scheduled)
		}

		// A second batch merges into the same pending digest.
		more := event(tenant, &review, exposure.EventTypeEmailSecurityWeak, exposure.SeverityLow, "Weak email: new.alerts.example.com")
		if err := writer.BulkUpsert(ctx, []*exposure.ExposureEvent{more}); err != nil {
			t.Fatal(err)
		}
		if rows, d := digest(tenant); rows != 1 || d.Count != 4 {
			t.Fatalf("after a second batch: rows=%d count=%d", rows, d.Count)
		}
	})

	t.Run("tenant isolation", func(t *testing.T) {
		if got := immediate(other); got != 0 {
			t.Fatalf("tenant B has %d alerts from tenant A's writes", got)
		}
		if n, _ := digest(other); n != 0 {
			t.Fatal("tenant B has a digest from tenant A's writes")
		}
		// Asking to announce tenant A's exposure ids as tenant B matches nothing.
		var ids []string
		if err := sqlDB.QueryRowContext(ctx, `SELECT array_agg(id::text) FROM exposure_events WHERE tenant_id = $1`,
			tenant.String()).Scan(pq.Array(&ids)); err != nil || len(ids) == 0 {
			t.Fatalf("tenant A exposure ids: %v %v", ids, err)
		}
		tx, err := sqlDB.BeginTx(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		if err := alerts.EnqueueInTx(ctx, tx, other, ids, easmalert.ReasonNew); err != nil {
			t.Fatal(err)
		}
		if err := tx.Commit(); err != nil {
			t.Fatal(err)
		}
		if got := immediate(other); got != 0 {
			t.Fatalf("foreign ids produced %d alerts for tenant B", got)
		}
		// Tenant B's own exposure on the same name alerts only tenant B.
		theirs := asset(other, "shop.alerts.example.com", "confirmed")
		if err := writer.BulkUpsert(ctx, []*exposure.ExposureEvent{
			event(other, &theirs, exposure.EventTypeDanglingCNAME, exposure.SeverityMedium, "Dangling CNAME: shop.alerts.example.com"),
		}); err != nil {
			t.Fatal(err)
		}
		if immediate(other) != 1 || immediate(tenant) != 3 {
			t.Fatalf("A=%d B=%d", immediate(tenant), immediate(other))
		}
	})

	t.Run("rollback leaves neither the exposure nor the alert", func(t *testing.T) {
		before := immediate(tenant)
		ev := event(tenant, &confirmed, exposure.EventTypeDanglingNS, exposure.SeverityHigh, "Dangling delegation: shop.alerts.example.com")
		tx, err := sqlDB.BeginTx(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		written, err := writer.exposures.BulkUpsertInTx(ctx, tx, []*exposure.ExposureEvent{ev})
		if err != nil || len(written) != 1 || !written[0].Inserted {
			t.Fatalf("upsert in tx: %+v %v", written, err)
		}
		if err := alerts.EnqueueInTx(ctx, tx, tenant, []string{written[0].ID}, easmalert.ReasonNew); err != nil {
			t.Fatal(err)
		}
		_ = tx.Rollback()
		if got := immediate(tenant); got != before {
			t.Fatalf("alerts = %d after rollback, want %d", got, before)
		}
		var n int
		_ = sqlDB.QueryRowContext(ctx, `SELECT count(*) FROM exposure_events WHERE tenant_id = $1 AND fingerprint = $2`,
			tenant.String(), ev.Fingerprint()).Scan(&n)
		if n != 0 {
			t.Fatal("exposure survived the rollback")
		}
	})
}

// The per-tenant hourly budget: alerts over it go to the digest, the most
// severe first, and other tenants keep their own budget.
func TestEASMAlerts_Throttle(t *testing.T) {
	sqlDB := openSensorDB(t)
	ctx := context.Background()
	db := &DB{DB: sqlDB}
	alerts := NewEASMAlerter(db).WithHourlyBudget(2)
	writer := NewEASMExposureWriter(db, alerts)
	repo := NewEASMDNSRepository(db)
	tenant := seedTestTenant(ctx, t, sqlDB)
	other := seedTestTenant(ctx, t, sqlDB)

	batch := func(tn shared.ID, sevs ...exposure.Severity) {
		t.Helper()
		evs := make([]*exposure.ExposureEvent, 0, len(sevs))
		for i, sev := range sevs {
			id := seedNamedAsset(ctx, t, repo, tn, shared.NewID().String()[24:]+".throttle.example.com", "subdomain", "active")
			ev, err := exposure.NewExposureEvent(tn, exposure.EventTypeDanglingCNAME, sev,
				"Dangling CNAME "+string(rune('a'+i))+id.String(), easmdns.Source, nil)
			if err != nil {
				t.Fatal(err)
			}
			ev.SetAssetID(&id)
			evs = append(evs, ev)
		}
		if err := writer.BulkUpsert(ctx, evs); err != nil {
			t.Fatal(err)
		}
	}
	batch(tenant, exposure.SeverityMedium, exposure.SeverityCritical, exposure.SeverityHigh)
	batch(other, exposure.SeverityMedium)

	sevs := func(tn shared.ID) map[string]int {
		rows, err := sqlDB.QueryContext(ctx, `SELECT severity FROM notification_outbox WHERE tenant_id = $1 AND aggregate_type = 'exposure'`, tn.String())
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		out := map[string]int{}
		for rows.Next() {
			var s string
			_ = rows.Scan(&s)
			out[s]++
		}
		if err := rows.Err(); err != nil {
			t.Fatal(err)
		}
		return out
	}
	if got := sevs(tenant); got["critical"] != 1 || got["high"] != 1 || got["medium"] != 0 {
		t.Fatalf("immediate = %v, want the critical and the high", got)
	}
	var raw []byte
	if err := sqlDB.QueryRowContext(ctx, `SELECT metadata FROM notification_outbox WHERE tenant_id = $1 AND aggregate_type = 'easm_digest'`,
		tenant.String()).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	var d easmDigest
	_ = json.Unmarshal(raw, &d)
	if d.Count != 1 || d.Throttled != 1 {
		t.Fatalf("digest = %+v, want the throttled medium", d)
	}
	if got := sevs(other); got["medium"] != 1 {
		t.Fatalf("tenant B's budget was spent by tenant A: %v", got)
	}
}
