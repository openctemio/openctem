package postgres

import (
	"context"
	"testing"
	"time"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/pkg/domain/easmchange"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Typed attack-surface changes against the real schema. Requires DATABASE_URL.
func TestEASMChanges(t *testing.T) {
	sqlDB := openSensorDB(t)
	ctx := context.Background()
	db := &DB{DB: sqlDB}
	repo := NewEASMChangeRepository(db)
	dnsRepo := NewEASMDNSRepository(db)

	tenant := seedTestTenant(ctx, t, sqlDB)
	other := seedTestTenant(ctx, t, sqlDB)
	now := time.Now().UTC()
	at := now.Add(-24 * time.Hour)

	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := sqlDB.ExecContext(ctx, q, args...); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	history := func(tn, asset shared.ID, change string) {
		exec(`INSERT INTO asset_state_history (tenant_id, asset_id, change_type, source, changed_at) VALUES ($1, $2, $3, 'scan', $4)`,
			tn.String(), asset.String(), change, at)
	}
	timeline := func(tn, asset shared.ID, attr string, added, removed []string) {
		exec(`INSERT INTO asset_change_events (id, tenant_id, asset_id, at, attribute, added, removed, source_kind, reason)
			VALUES ($1, $2, $3, $4, $5, $6, $7, 'scan', 'newer_observation')`,
			shared.NewID().String(), tn.String(), asset.String(), at, attr, pq.Array(added), pq.Array(removed))
	}
	exposureRow := func(tn shared.ID, asset *shared.ID, typ, sev, state string) {
		var aid any
		if asset != nil {
			aid = asset.String()
		}
		exec(`INSERT INTO exposure_events (tenant_id, asset_id, event_type, severity, state, title, fingerprint, source, first_seen_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7, 'easm_dns', $8)`,
			tn.String(), aid, typ, sev, state, typ+" title", shared.NewID().String(), at)
	}

	host := seedNamedAsset(ctx, t, dnsRepo, tenant, "new.example.com", "subdomain", "active")
	gone := seedNamedAsset(ctx, t, dnsRepo, tenant, "old.example.com", "subdomain", "inactive")
	cert := seedNamedAsset(ctx, t, dnsRepo, tenant, "cert-sha", "certificate", "active")
	internal := seedNamedAsset(ctx, t, dnsRepo, tenant, "db01.corp", "host", "active") // not on the surface
	pending := seedNamedAsset(ctx, t, dnsRepo, tenant, "maybe.example.net", "subdomain", "active")
	exec(`INSERT INTO asset_attributions (asset_id, tenant_id, state, confidence) VALUES ($1, $2, 'needs_review', 50)`, pending.String(), tenant.String())
	rejected := seedNamedAsset(ctx, t, dnsRepo, tenant, "notours.example.org", "subdomain", "active")
	exec(`INSERT INTO asset_attributions (asset_id, tenant_id, state, confidence) VALUES ($1, $2, 'rejected', 10)`, rejected.String(), tenant.String())

	service := seedNamedAsset(ctx, t, dnsRepo, tenant, "new.example.com:8080", "service", "active")
	exec(`UPDATE assets SET exposure = 'public' WHERE id = $1`, service.String())
	history(tenant, service, "appeared") // an internet-facing service: a port opened
	history(tenant, host, "appeared")
	history(tenant, gone, "disappeared")
	history(tenant, cert, "appeared")
	history(tenant, internal, "appeared")
	history(tenant, pending, "appeared")
	timeline(tenant, host, "ip_addresses", []string{"203.0.113.9"}, []string{"203.0.113.8"})
	timeline(tenant, host, "technologies", []string{"nginx"}, nil)
	timeline(tenant, host, "open_ports", []string{"8443/tcp"}, []string{"21/tcp"})
	timeline(tenant, host, "criticality", nil, nil) // not a surface change
	exposureRow(tenant, &host, "dangling_cname", "medium", "active")
	exposureRow(tenant, &host, "certificate_expiring", "low", "active")
	exposureRow(tenant, &host, "email_security_weak", "low", "resolved")
	exposureRow(tenant, &host, "port_open", "info", "active")        // skipped: the asset carries it
	exposureRow(tenant, &host, "ssl_issue", "low", "false_positive") // skipped
	exposureRow(tenant, &rejected, "dangling_ns", "high", "active")  // skipped: not ours
	exposureRow(tenant, nil, "subdomain_takeover", "high", "active") // unlinked

	// The other tenant's rows never show.
	foreign := seedNamedAsset(ctx, t, dnsRepo, other, "foreign.example.com", "subdomain", "active")
	history(other, foreign, "appeared")
	exposureRow(other, &foreign, "dangling_cname", "high", "active")

	q := easmchange.Query{From: now.Add(-7 * 24 * time.Hour), To: now, Limit: 100}
	page, err := repo.ListChanges(ctx, tenant, nil, q)
	if err != nil {
		t.Fatal(err)
	}
	want := map[easmchange.Kind]int{
		easmchange.KindHostAdded: 1, easmchange.KindHostRemoved: 1, easmchange.KindCertChanged: 1,
		easmchange.KindDNSChanged: 1, easmchange.KindTechChanged: 1, easmchange.KindPortOpened: 2,
		easmchange.KindPortClosed: 1, easmchange.KindDNSDangling: 2, easmchange.KindCertExpiring: 1,
		easmchange.KindExposureNew: 1,
	}
	for k, n := range want {
		if page.Counts[k] != n {
			t.Errorf("count %s = %d, want %d (all: %v)", k, page.Counts[k], n, page.Counts)
		}
	}
	if page.Total != 12 || len(page.Items) != 12 {
		t.Fatalf("total %d items %d, want 12", page.Total, len(page.Items))
	}
	for _, c := range page.Items {
		if c.AssetName == "foreign.example.com" || c.AssetName == "db01.corp" || c.AssetName == "maybe.example.net" || c.AssetName == "notours.example.org" {
			t.Errorf("change of an excluded asset listed: %+v", c)
		}
	}

	// Kind filter and keyset pages.
	q.Kinds = []easmchange.Kind{easmchange.KindDNSDangling}
	page, err = repo.ListChanges(ctx, tenant, nil, q)
	if err != nil || len(page.Items) != 2 || page.Total != 12 {
		t.Fatalf("kind filter: %v %+v", err, page)
	}
	q.Kinds, q.Limit = nil, 4
	seen := map[string]bool{}
	for pages := 0; ; pages++ {
		page, err = repo.ListChanges(ctx, tenant, nil, q)
		if err != nil {
			t.Fatal(err)
		}
		for _, c := range page.Items {
			key := c.ID + string(c.Kind)
			if seen[key] {
				t.Fatalf("change repeated across pages: %s", key)
			}
			seen[key] = true
		}
		if page.NextCursor == "" {
			break
		}
		q.Cursor = page.NextCursor
		if pages > 5 {
			t.Fatal("pagination does not end")
		}
	}
	if len(seen) != 12 {
		t.Fatalf("paged %d changes, want 12", len(seen))
	}
	q.Cursor = "garbage"
	if _, err := repo.ListChanges(ctx, tenant, nil, q); err == nil {
		t.Fatal("bad cursor accepted")
	}
	q.Cursor = ""

	// A restricted member sees only the assets in their scope, and no
	// asset-less exposure.
	user := seedUser(ctx, t, db)
	scope := &shared.DataScope{TenantID: tenant, UserID: user}
	page, err = repo.ListChanges(ctx, tenant, scope, easmchange.Query{From: q.From, To: q.To, Limit: 100})
	if err != nil || page.Total != 0 || len(page.Items) != 0 {
		t.Fatalf("member without scope rows sees changes: %v %+v", err, page)
	}
	exec(`INSERT INTO user_accessible_assets (user_id, tenant_id, asset_id, ownership_type) VALUES ($1, $2, $3, 'secondary')`,
		user.String(), tenant.String(), cert.String())
	page, err = repo.ListChanges(ctx, tenant, scope, easmchange.Query{From: q.From, To: q.To, Limit: 100})
	if err != nil || page.Total != 1 || len(page.Items) != 1 || page.Items[0].Kind != easmchange.KindCertChanged {
		t.Fatalf("scoped member: %v %+v", err, page)
	}

	// Outside the window nothing counts.
	counts, total, err := repo.CountChanges(ctx, tenant, nil, now.Add(-30*24*time.Hour), now.Add(-20*24*time.Hour))
	if err != nil || total != 0 || counts[easmchange.KindHostAdded] != 0 {
		t.Fatalf("old window: %v %d %v", err, total, counts)
	}

	// The digest claim is once per tenant and slot.
	slot, from := easmchange.DigestSlot(now, time.Monday)
	ok, err := repo.ClaimDigest(ctx, tenant, slot, from, want, 11)
	if err != nil || !ok {
		t.Fatalf("first claim: %v %v", ok, err)
	}
	if ok, err = repo.ClaimDigest(ctx, tenant, slot, from, want, 11); err != nil || ok {
		t.Fatalf("second claim of the same slot: %v %v", ok, err)
	}
	if ok, err = repo.ClaimDigest(ctx, other, slot, from, nil, 0); err != nil || !ok {
		t.Fatalf("other tenant claim: %v %v", ok, err)
	}
	last, err := repo.LastDigestAt(ctx, tenant)
	if err != nil || last == nil {
		t.Fatalf("last digest: %v %v", last, err)
	}
	if err := repo.ReleaseDigest(ctx, tenant, slot); err != nil {
		t.Fatal(err)
	}
	if ok, err = repo.ClaimDigest(ctx, tenant, slot, from, want, 11); err != nil || !ok {
		t.Fatalf("claim after release: %v %v", ok, err)
	}
}
