package postgres

import (
	"context"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/exposure"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// research/22 P0-9: rejecting a name resolves its EASM exposures and those
// under it (CT and DNS, active only, never another tenant's or another
// source's), and relinking moves CT rows only onto the tenant's own assets.
func TestEASMExposureHygiene(t *testing.T) {
	sqlDB := openSensorDB(t)
	ctx := context.Background()
	db := &DB{DB: sqlDB}
	exp := NewExposureRepository(db)
	dns := NewEASMDNSRepository(db)
	tenant := seedTestTenant(ctx, t, sqlDB)
	other := seedTestTenant(ctx, t, sqlDB)

	sub := seedNamedAsset(ctx, t, dns, tenant, "old.hyg.example.com", "subdomain", "active")
	root := seedNamedAsset(ctx, t, dns, tenant, "hyg.example.com", "domain", "active")
	theirs := seedNamedAsset(ctx, t, dns, other, "old.hyg.example.com", "subdomain", "active")

	mk := func(tn shared.ID, assetID *shared.ID, source, host string, typ exposure.EventType) *exposure.ExposureEvent {
		t.Helper()
		ev, err := exposure.NewExposureEvent(tn, typ, exposure.SeverityHigh, string(typ)+": "+host, source, map[string]any{"domain": host})
		if err != nil {
			t.Fatal(err)
		}
		if assetID != nil {
			ev.SetAssetID(assetID)
		}
		return ev
	}
	onRoot := mk(tenant, &root, "cert_transparency", "old.hyg.example.com", exposure.EventTypeCertificateExpiring)
	under := mk(tenant, nil, "cert_transparency", "api.old.hyg.example.com", exposure.EventTypeSubdomainDiscovered)
	dnsEv := mk(tenant, &sub, "easm_dns", "old.hyg.example.com", exposure.EventTypeDanglingCNAME)
	sibling := mk(tenant, &root, "cert_transparency", "www.hyg.example.com", exposure.EventTypeSubdomainDiscovered)
	lookalike := mk(tenant, nil, "cert_transparency", "bold.hyg.example.com", exposure.EventTypeSubdomainDiscovered)
	scan := mk(tenant, &sub, "scan", "old.hyg.example.com", exposure.EventTypePortOpen)
	foreign := mk(other, &theirs, "cert_transparency", "old.hyg.example.com", exposure.EventTypeCertificateExpiring)
	all := []*exposure.ExposureEvent{onRoot, under, dnsEv, sibling, lookalike, scan, foreign}
	if err := exp.BulkUpsert(ctx, all); err != nil {
		t.Fatal(err)
	}
	state := func(ev *exposure.ExposureEvent) string {
		var s string
		if err := sqlDB.QueryRowContext(ctx, `SELECT state FROM exposure_events WHERE tenant_id = $1 AND fingerprint = $2`,
			ev.TenantID().String(), ev.Fingerprint()).Scan(&s); err != nil {
			t.Fatal(err)
		}
		return s
	}

	// Another tenant's asset id resolves nothing here.
	if n, err := exp.ResolveRejectedNames(ctx, tenant, []shared.ID{theirs}); err != nil || n != 0 {
		t.Fatalf("foreign asset id: %d %v", n, err)
	}
	n, err := exp.ResolveRejectedNames(ctx, tenant, []shared.ID{sub})
	if err != nil || n != 3 {
		t.Fatalf("resolved %d (%v), want 3", n, err)
	}
	for _, ev := range []*exposure.ExposureEvent{onRoot, under, dnsEv} {
		if state(ev) != "resolved" {
			t.Errorf("%s not resolved", ev.Title())
		}
	}
	for _, ev := range []*exposure.ExposureEvent{sibling, lookalike, scan, foreign} {
		if state(ev) != "active" {
			t.Errorf("%s resolved but is not under the rejected name", ev.Title())
		}
	}
	var hist int
	_ = sqlDB.QueryRowContext(ctx, `SELECT count(*) FROM exposure_state_history h JOIN exposure_events e ON e.id = h.exposure_event_id
		WHERE e.tenant_id = $1 AND h.reason = $2`, tenant.String(), RejectedResolutionNote).Scan(&hist)
	if hist != 3 {
		t.Fatalf("state history rows = %d, want 3", hist)
	}

	// Relink: onto the tenant's own asset only.
	if n, err := exp.RelinkExposures(ctx, tenant, "cert_transparency", map[string]shared.ID{lookalike.Fingerprint(): theirs}); err != nil || n != 0 {
		t.Fatalf("relinked onto another tenant's asset: %d %v", n, err)
	}
	if n, err := exp.RelinkExposures(ctx, tenant, "cert_transparency", map[string]shared.ID{sibling.Fingerprint(): sub}); err != nil || n != 1 {
		t.Fatalf("relink: %d %v", n, err)
	}
	if n, _ := exp.RelinkExposures(ctx, tenant, "cert_transparency", map[string]shared.ID{sibling.Fingerprint(): sub}); n != 0 {
		t.Fatal("an unchanged link was rewritten")
	}
	if n, _ := exp.RelinkExposures(ctx, tenant, "easm_dns", map[string]shared.ID{sibling.Fingerprint(): root}); n != 0 {
		t.Fatal("relink crossed sources")
	}
}
