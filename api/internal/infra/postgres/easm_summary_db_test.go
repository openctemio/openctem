package postgres

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func seedSurfaceAsset(ctx context.Context, t *testing.T, db *sql.DB, tenant shared.ID, name, typ string, firstSeen time.Time) string {
	t.Helper()
	id := shared.NewID().String()
	if _, err := db.ExecContext(ctx,
		`INSERT INTO assets (id, tenant_id, name, asset_type, first_seen) VALUES ($1, $2, $3, $4, $5)`,
		id, tenant.String(), name, typ, firstSeen); err != nil {
		t.Fatalf("seed asset %s: %v", name, err)
	}
	return id
}

func seedExposure(ctx context.Context, t *testing.T, db *sql.DB, tenant shared.ID, assetID any, typ, sev, state string) {
	t.Helper()
	id := shared.NewID().String()
	if _, err := db.ExecContext(ctx, `
		INSERT INTO exposure_events (id, tenant_id, asset_id, event_type, severity, state, title, fingerprint, source)
		VALUES ($1::uuid, $2, $3, $4, $5, $6, $7, $1::text, 'test')`,
		id, tenant.String(), assetID, typ, sev, state, typ+" "+sev); err != nil {
		t.Fatalf("seed exposure: %v", err)
	}
}

// The EASM overview against the real schema: counts by type and attribution
// state (no record = legacy confirmed), new-asset windows and the CTEM cycle,
// open external exposures only, top risks ordered by severity, CT freshness,
// tenant isolation and data-scope narrowing.
func TestEASMSummaryRepository(t *testing.T) {
	db := openSensorDB(t)
	ctx := context.Background()
	repo := NewEASMSummaryRepository(&DB{DB: db})
	tenant := seedTestTenant(ctx, t, db)
	other := seedTestTenant(ctx, t, db)
	now := time.Now().UTC()

	old := now.Add(-90 * 24 * time.Hour)
	root := seedSurfaceAsset(ctx, t, db, tenant, "acme.com", "domain", old)
	www := seedSurfaceAsset(ctx, t, db, tenant, "www.acme.com", "subdomain", now.Add(-2*24*time.Hour))
	api := seedSurfaceAsset(ctx, t, db, tenant, "api.acme.com", "subdomain", now.Add(-20*24*time.Hour))
	_ = seedSurfaceAsset(ctx, t, db, tenant, "203.0.113.7", "ip_address", old)
	_ = seedSurfaceAsset(ctx, t, db, tenant, "laptop-1", "host", now) // not surface
	_ = seedSurfaceAsset(ctx, t, db, other, "evil.example", "domain", now)
	// A person marked this one as not ours: counted as rejected, nowhere else.
	notOurs := seedSurfaceAsset(ctx, t, db, tenant, "notours.acme.com", "subdomain", now.Add(-24*time.Hour))
	if _, err := db.ExecContext(ctx, `INSERT INTO asset_attributions (asset_id, tenant_id, state, confidence, decided_at)
		VALUES ($1, $2, 'rejected', 0, now())`, notOurs, tenant.String()); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `
		INSERT INTO asset_attributions (asset_id, tenant_id, state, confidence, reason, created_at)
		VALUES ($1, $3, 'needs_review', 85, 'fqdn_under_asserted_root', now() - interval '3 days'),
		       ($2, $3, 'confirmed', 99, 'fqdn_under_verified_root', now())`, api, www, tenant.String()); err != nil {
		t.Fatal(err)
	}
	seedExposure(ctx, t, db, tenant, www, "certificate_expiring", "high", "active")
	seedExposure(ctx, t, db, tenant, api, "subdomain_discovered", "info", "active")
	seedExposure(ctx, t, db, tenant, nil, "subdomain_discovered", "info", "active") // verified domain without an asset
	seedExposure(ctx, t, db, tenant, root, "certificate_expired", "medium", "resolved")
	seedExposure(ctx, t, db, tenant, root, "credential_leaked", "critical", "active")      // not an EASM type
	seedExposure(ctx, t, db, tenant, notOurs, "certificate_expired", "critical", "active") // rejected asset
	seedExposure(ctx, t, db, other, nil, "certificate_expiring", "critical", "active")
	if _, err := db.ExecContext(ctx, `
		INSERT INTO ct_monitor_state (tenant_id, domain, last_success_at, consecutive_failures)
		VALUES ($1, 'acme.com', now() - interval '5 hours', 0), ($1, 'acme.io', NULL, 2)`, tenant.String()); err != nil {
		t.Fatal(err)
	}
	user := shared.NewID()
	if _, err := db.ExecContext(ctx, `INSERT INTO users (id, email, name) VALUES ($1, $2, 'scoped')`, user.String(), user.String()+"@easm.test"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = db.ExecContext(context.Background(), `DELETE FROM users WHERE id = $1`, user.String()) })
	if _, err := db.ExecContext(ctx, `
		INSERT INTO ctem_cycles (id, tenant_id, name, status, activated_at, created_by)
		VALUES ($1, $2, 'Q4', 'active', now() - interval '10 days', $3)`, shared.NewID().String(), tenant.String(), user.String()); err != nil {
		t.Fatal(err)
	}

	d, err := repo.Summary(ctx, tenant, nil, now, 10)
	if err != nil {
		t.Fatal(err)
	}
	// The surface is the inventory (RFC-054 §4.4): api.acme.com waits for
	// review and is not counted; it shows in the attribution counts.
	if d.AssetsByType["domain"] != 1 || d.AssetsByType["subdomain"] != 1 || d.AssetsByType["ip_address"] != 1 || d.AssetsByType["host"] != 0 {
		t.Errorf("by type = %v", d.AssetsByType)
	}
	if d.ReviewByReason["fqdn_under_asserted_root"] != 1 || len(d.ReviewByReason) != 1 {
		t.Errorf("review by reason = %v", d.ReviewByReason)
	}
	if d.AttributionByState[""] != 2 || d.AttributionByState["needs_review"] != 1 || d.AttributionByState["confirmed"] != 1 || d.AttributionByState["rejected"] != 1 {
		t.Errorf("attribution = %v", d.AttributionByState)
	}
	if d.OldestReviewSince == nil || now.Sub(*d.OldestReviewSince) < 70*time.Hour {
		t.Errorf("review age = %v", d.OldestReviewSince)
	}
	if d.NewSince7d != 1 || d.NewSince30d != 1 || d.NewSinceCycle != 1 || d.CycleStart == nil {
		t.Errorf("new = 7d %d 30d %d cycle %d (%v)", d.NewSince7d, d.NewSince30d, d.NewSinceCycle, d.CycleStart)
	}
	if d.OpenBySeverity["high"] != 1 || d.OpenBySeverity["info"] != 2 || d.OpenBySeverity["critical"] != 0 || d.OpenBySeverity["medium"] != 0 {
		t.Errorf("open by severity = %v (resolved, non-EASM and other-tenant rows must not count)", d.OpenBySeverity)
	}
	if len(d.TopRisks) != 1 || d.TopRisks[0].Type != "certificate_expiring" || d.TopRisks[0].AssetName == nil || *d.TopRisks[0].AssetName != "www.acme.com" {
		t.Errorf("top risks = %+v", d.TopRisks)
	}
	if d.CTWatched != 2 || d.CTFailing != 1 || d.CTNeverSucceeded != 1 || d.CTOldestSuccess == nil {
		t.Errorf("ct = %d/%d/%d %v", d.CTWatched, d.CTFailing, d.CTNeverSucceeded, d.CTOldestSuccess)
	}

	// A member scoped to www.acme.com sees only that asset and its exposure.
	if _, err := db.ExecContext(ctx, `INSERT INTO user_accessible_assets (user_id, tenant_id, asset_id) VALUES ($1, $2, $3)`,
		user.String(), tenant.String(), www); err != nil {
		t.Fatal(err)
	}
	s, err := repo.Summary(ctx, tenant, &user, now, 10)
	if err != nil {
		t.Fatal(err)
	}
	if s.AssetsByType["subdomain"] != 1 || s.AssetsByType["domain"] != 0 || s.OpenBySeverity["info"] != 0 || s.OpenBySeverity["high"] != 1 || s.OldestReviewSince != nil {
		t.Errorf("scoped summary leaks: types %v sev %v review %v", s.AssetsByType, s.OpenBySeverity, s.OldestReviewSince)
	}
}
