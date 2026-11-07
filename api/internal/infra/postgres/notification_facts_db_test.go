package postgres

import (
	"context"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// The facts a channel message names are read inside the event's tenant
// only, joins included. Requires DATABASE_URL.
func TestNotificationFacts_TenantScoped(t *testing.T) {
	sqlDB := openSensorDB(t)
	ctx := context.Background()
	db := &DB{DB: sqlDB}
	dnsRepo := NewEASMDNSRepository(db)
	facts := NewNotificationFactsRepository(db)

	tenant := seedTestTenant(ctx, t, sqlDB)
	other := seedTestTenant(ctx, t, sqlDB)

	host := seedNamedAsset(ctx, t, dnsRepo, tenant, "www.facts.example.com", "subdomain", "active")
	addr := seedNamedAsset(ctx, t, dnsRepo, tenant, "2603:1000:4::5e1", "ip_address", "active")
	if _, err := sqlDB.ExecContext(ctx, `INSERT INTO asset_relationships (tenant_id, source_asset_id, target_asset_id, relationship_type)
		VALUES ($1, $2, $3, 'resolves_to')`, tenant.String(), host.String(), addr.String()); err != nil {
		t.Fatal(err)
	}
	expID := shared.NewID()
	if _, err := sqlDB.ExecContext(ctx, `INSERT INTO exposure_events (id, tenant_id, asset_id, event_type, severity, title, fingerprint, source)
		VALUES ($1, $2, $3, 'web_interface_exposed', 'high', 'Admin panel', $4, 'test')`,
		expID.String(), tenant.String(), host.String(), "fp-"+expID.String()); err != nil {
		t.Fatal(err)
	}

	f, err := facts.Exposure(ctx, tenant, expID)
	if err != nil || f == nil || f.AssetName != "www.facts.example.com" || f.Class != "web_interface_exposed" || f.Title != "Admin panel" {
		t.Fatalf("own exposure: %+v, %v", f, err)
	}
	if f, err := facts.Exposure(ctx, other, expID); err != nil || f != nil {
		t.Fatalf("another tenant read the exposure: %+v, %v", f, err)
	}

	refs, err := facts.AssetSources(ctx, tenant, []string{addr.String()})
	if err != nil || len(refs) != 1 || refs[0].From != "www.facts.example.com" || refs[0].Name != "2603:1000:4::5e1" {
		t.Fatalf("own assets: %+v, %v", refs, err)
	}
	if refs, err := facts.AssetSources(ctx, other, []string{addr.String(), host.String()}); err != nil || len(refs) != 0 {
		t.Fatalf("another tenant read the assets: %+v, %v", refs, err)
	}

	// A relationship planted under another tenant never names a source.
	foreign := seedNamedAsset(ctx, t, dnsRepo, other, "evil.example.net", "subdomain", "active")
	if _, err := sqlDB.ExecContext(ctx, `INSERT INTO asset_relationships (tenant_id, source_asset_id, target_asset_id, relationship_type)
		VALUES ($1, $2, $3, 'resolves_to')`, other.String(), foreign.String(), addr.String()); err == nil {
		refs, err := facts.AssetSources(ctx, tenant, []string{addr.String()})
		if err != nil || len(refs) != 1 || refs[0].From != "www.facts.example.com" {
			t.Fatalf("cross-tenant relationship used: %+v, %v", refs, err)
		}
	}

	if name, _, err := facts.Organization(ctx, tenant); err != nil || name == "" {
		t.Fatalf("organization: %q, %v", name, err)
	}
}
