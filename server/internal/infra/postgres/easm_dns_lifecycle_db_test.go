package postgres

import (
	"context"
	"testing"

	"github.com/openctemio/openctem/server/internal/app/easmdns"
	"github.com/openctemio/openctem/server/pkg/domain/exposure"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
)

// The dangling lifecycle's reads and writes against the real schema, each
// scoped to the tenant: ownership facts, certificate trouble on a name, the
// dangling tag and sighted asset names. The same names and addresses in
// another tenant prove nothing and are never changed. Requires DATABASE_URL.
func TestEASMDNSRepository_Lifecycle(t *testing.T) {
	sqlDB := openSensorDB(t)
	ctx := context.Background()
	db := &DB{DB: sqlDB}
	r := NewEASMDNSRepository(db)
	tenant := seedTestTenant(ctx, t, sqlDB)
	other := seedTestTenant(ctx, t, sqlDB)

	root := seedNamedAsset(ctx, t, r, tenant, "acme-cdn.example", "domain", "active")
	pending := seedNamedAsset(ctx, t, r, tenant, "maybe.example", "domain", "active")
	addr := seedNamedAsset(ctx, t, r, tenant, "198.51.100.7", "ip_address", "active")
	seedNamedAsset(ctx, t, r, other, "theirs-cdn.example", "domain", "active")
	seedNamedAsset(ctx, t, r, other, "198.51.100.8", "ip_address", "active")
	sub := seedNamedAsset(ctx, t, r, tenant, "Promo.Acme.Example.", "subdomain", "active")
	theirSub := seedNamedAsset(ctx, t, r, other, "promo.acme.example", "subdomain", "active")
	if _, err := sqlDB.ExecContext(ctx, `INSERT INTO asset_attributions (asset_id, tenant_id, state, confidence) VALUES ($1, $2, 'needs_review', 50)`,
		pending.String(), tenant.String()); err != nil {
		t.Fatal(err)
	}
	if _, err := sqlDB.ExecContext(ctx, `UPDATE assets SET properties = '{"asn_org":"Example Net"}' WHERE id = $1`, addr.String()); err != nil {
		t.Fatal(err)
	}
	_ = root

	own, err := r.Ownership(ctx, tenant, "acme-cdn.example", []string{"198.51.100.7", "198.51.100.8"})
	if err != nil {
		t.Fatal(err)
	}
	if !own.RootOwned || !own.Addresses["198.51.100.7"].Confirmed || own.Addresses["198.51.100.7"].ASNOrg != "Example Net" {
		t.Fatalf("own = %+v", own)
	}
	if _, ok := own.Addresses["198.51.100.8"]; ok {
		t.Fatal("another tenant's address counted as ours")
	}
	if o, _ := r.Ownership(ctx, tenant, "theirs-cdn.example", nil); o.RootOwned {
		t.Fatal("another tenant's root counted as ours")
	}
	if o, _ := r.Ownership(ctx, tenant, "maybe.example", nil); o.RootOwned {
		t.Fatal("a root awaiting review counted as confirmed")
	}

	// Certificate trouble: ours on the name, a resolved one, another tenant's.
	exp := NewExposureRepository(db)
	mk := func(tn shared.ID, asset shared.ID, typ exposure.EventType, title string, details map[string]any) *exposure.ExposureEvent {
		ev, err := exposure.NewExposureEvent(tn, typ, exposure.SeverityHigh, title, "recon_scan", details)
		if err != nil {
			t.Fatal(err)
		}
		ev.SetAssetID(&asset)
		return ev
	}
	expired := mk(tenant, sub, exposure.EventTypeCertificateExpired, "Expired TLS certificate on promo.acme.example",
		map[string]any{"domain": "promo.acme.example", "not_after": "2025-11-08T00:00:00Z", "issuer_cn": "R10"})
	mismatch := mk(tenant, sub, exposure.EventTypeSSLIssue, "TLS certificate does not cover promo.acme.example",
		map[string]any{"domain": "promo.acme.example", "issue": "name_mismatch"})
	theirs := mk(other, theirSub, exposure.EventTypeSSLIssue, "promo.acme.example serves another site's TLS certificate",
		map[string]any{"domain": "promo.acme.example", "issue": "foreign_certificate"})
	if err := exp.BulkUpsert(ctx, []*exposure.ExposureEvent{expired, mismatch, theirs}); err != nil {
		t.Fatal(err)
	}
	if _, err := sqlDB.ExecContext(ctx, `UPDATE exposure_events SET state = 'resolved' WHERE tenant_id = $1 AND fingerprint = $2`,
		tenant.String(), mismatch.Fingerprint()); err != nil {
		t.Fatal(err)
	}
	tr, err := r.HostCertificateTrouble(ctx, tenant, "promo.acme.example.")
	if err != nil || len(tr) != 1 || tr[0].Kind != "expired" || tr[0].Issuer != "R10" {
		t.Fatalf("trouble = %+v %v", tr, err)
	}
	if tr, _ := r.HostCertificateTrouble(ctx, other, "promo.acme.example"); len(tr) != 1 || tr[0].Kind != "foreign_certificate" {
		t.Fatalf("other tenant trouble = %+v", tr)
	}

	// Tag: on twice keeps one, the other tenant's asset is untouched, off removes.
	tags := func(id shared.ID) []string {
		var out []string
		rows, err := sqlDB.QueryContext(ctx, `SELECT unnest(tags) FROM assets WHERE id = $1`, id.String())
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		for rows.Next() {
			var s string
			_ = rows.Scan(&s)
			out = append(out, s)
		}
		if err := rows.Err(); err != nil {
			t.Fatal(err)
		}
		return out
	}
	for range 2 {
		if err := r.SetDanglingTag(ctx, tenant, sub, true); err != nil {
			t.Fatal(err)
		}
	}
	if err := r.SetDanglingTag(ctx, tenant, theirSub, true); err != nil {
		t.Fatal(err)
	}
	if got := tags(sub); len(got) != 1 || got[0] != easmdns.TagDanglingCNAME {
		t.Fatalf("tags = %v", got)
	}
	if got := tags(theirSub); len(got) != 0 {
		t.Fatalf("another tenant's asset tagged: %v", got)
	}
	if err := r.SetDanglingTag(ctx, tenant, sub, false); err != nil || len(tags(sub)) != 0 {
		t.Fatalf("tag not removed: %v %v", tags(sub), err)
	}

	names, err := r.AssetNames(ctx, tenant, []shared.ID{sub, theirSub, addr})
	if err != nil || len(names) != 1 || names[sub] != "promo.acme.example" {
		t.Fatalf("names = %v %v", names, err)
	}

	// The open dangling read carries the response class.
	dc, _ := exposure.NewExposureEvent(tenant, exposure.EventTypeDanglingCNAME, exposure.SeverityHigh, "Dangling CNAME: promo.acme.example",
		easmdns.Source, map[string]any{"domain": "promo.acme.example", "target": "dns.ladipage.com", "response_class": easmdns.ClassProviderRefuses})
	dc.SetAssetID(&sub)
	if err := exp.BulkUpsert(ctx, []*exposure.ExposureEvent{dc}); err != nil {
		t.Fatal(err)
	}
	open, err := r.OpenDanglingCNAMEs(ctx, tenant, []shared.ID{sub})
	if err != nil || len(open) != 1 || open[0].ResponseClass != easmdns.ClassProviderRefuses {
		t.Fatalf("open = %+v %v", open, err)
	}
	if open, _ := r.OpenDanglingCNAMEs(ctx, other, []shared.ID{sub}); len(open) != 0 {
		t.Fatal("another tenant read our dangling exposure")
	}
}
