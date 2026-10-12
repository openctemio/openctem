package integration

// The property schema through the real ingest on a migrated database
// (RFC-042 §6.3.9): a report that spells one concept six ways stores it once
// (ip_addresses), a port reported on a domain becomes the domain's
// host:port service with an `exposes` edge instead of a domain property, the
// domain resolves_to each address (an IP asset per address, last_verified
// refreshed on the next sighting), and another tenant's asset of the same
// name is never touched.

import (
	"context"
	"encoding/json"
	"slices"
	"sort"
	"testing"
	"time"

	"github.com/openctemio/ctis"

	"github.com/openctemio/openctem/api/internal/app/ingest"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

func TestIngest_PropertySchemaNormalised(t *testing.T) {
	r := newV2Rig(t, ingest.DefaultBlindingGuard())
	tn := r.newTenant("dnsx")
	other := r.newTenant("dnsx")
	db := &postgres.DB{DB: r.db}
	ctx := context.Background()
	svc := ingest.NewService(
		postgres.NewAssetRepository(db), postgres.NewFindingRepository(db),
		postgres.NewVulnerabilityRepository(db), postgres.NewComponentRepository(db),
		postgres.NewSensorRepository(db), postgres.NewBranchRepository(db), postgres.NewTenantRepository(db),
		postgres.NewAuditRepository(db), logger.NewNop())
	svc.SetRelationshipRepository(postgres.NewAssetRelationshipRepository(db))
	tid, oid := tn.tenant, other.tenant
	agt := &sensor.Sensor{ID: tn.sensor, TenantID: &tid, Type: sensor.SensorTypeWorker, Status: sensor.SensorStatusActive}

	const domain = "props.example.com"
	// The other tenant has a domain of the same name, with a legacy key.
	otherID := shared.NewID()
	if _, err := r.db.ExecContext(ctx, `INSERT INTO assets (id, tenant_id, name, asset_type, status, properties)
		VALUES ($1, $2, $3, 'domain', 'active', '{"ip": "192.0.2.99"}')`, otherID.String(), oid.String(), domain); err != nil {
		t.Fatal(err)
	}

	report := func(tool string, bind ingest.Binding, assets ...ctis.Asset) {
		t.Helper()
		rep := &ctis.Report{Version: "1.0", Tool: &ctis.Tool{Name: tool}, Assets: assets,
			Metadata: ctis.ReportMetadata{ID: "rep-" + shared.NewID().String(), Timestamp: time.Now().UTC()}}
		out, err := svc.Ingest(ctx, agt, ingest.Input{Report: rep, Options: ingest.Options{Binding: bind}})
		if err != nil || len(out.Errors) > 0 {
			t.Fatalf("Ingest: %v %v", err, out.Errors)
		}
	}
	props := func(tenant shared.ID, name string) map[string]any {
		t.Helper()
		var raw []byte
		if err := r.db.QueryRowContext(ctx, `SELECT properties FROM assets WHERE tenant_id = $1 AND name = $2 AND deleted_at IS NULL`,
			tenant.String(), name).Scan(&raw); err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		m := map[string]any{}
		if err := json.Unmarshal(raw, &m); err != nil {
			t.Fatal(err)
		}
		return m
	}
	strs := func(v any) []string {
		var out []string
		xs, _ := v.([]any)
		for _, e := range xs {
			out = append(out, e.(string))
		}
		sort.Strings(out)
		return out
	}
	edgeTargets := func(relType string) []string {
		t.Helper()
		rows, err := r.db.QueryContext(ctx, `SELECT t.name FROM asset_relationships rel
			JOIN assets s ON s.id = rel.source_asset_id JOIN assets t ON t.id = rel.target_asset_id
			WHERE rel.tenant_id = $1 AND s.name = $2 AND rel.relationship_type = $3`, tid.String(), domain, relType)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		var out []string
		for rows.Next() {
			var n string
			if err := rows.Scan(&n); err != nil {
				t.Fatal(err)
			}
			out = append(out, n)
		}
		if err := rows.Err(); err != nil {
			t.Fatal(err)
		}
		sort.Strings(out)
		return out
	}

	// One report, every spelling: ip, a plain ip_address string, ips,
	// resolved_ips as a comma-separated string, plus a port on the domain.
	report("dnsx", ingest.Binding{},
		ctis.Asset{ID: "d", Type: ctis.AssetTypeDomain, Value: domain, Properties: ctis.Properties{
			"ip": "203.0.113.10", "ip_address": "203.0.113.11", "ips": []any{"203.0.113.12"},
			"resolved_ips": "203.0.113.13, 203.0.113.10", "port": "443",
		}},
		ctis.Asset{ID: "h", Type: ctis.AssetTypeHost, Value: "web-1.example.com", Properties: ctis.Properties{
			"ip": "198.51.100.7", "addresses": []any{"198.51.100.8", "not-an-address"},
		}},
	)

	want := []string{"203.0.113.10", "203.0.113.11", "203.0.113.12", "203.0.113.13"}
	d := props(tid, domain)
	if got := strs(d["ip_addresses"]); !slices.Equal(got, want) {
		t.Errorf("domain ip_addresses = %v, want %v", got, want)
	}
	for _, k := range []string{"ip", "ip_address", "ips", "resolved_ips", "port"} {
		if _, ok := d[k]; ok {
			t.Errorf("domain still holds %q: %v", k, d)
		}
	}
	h := props(tid, "web-1.example.com")
	if got := strs(h["ip_addresses"]); !slices.Equal(got, []string{"198.51.100.7", "198.51.100.8"}) {
		t.Errorf("host ip_addresses = %v", got)
	}
	if _, ok := h["addresses"]; ok {
		t.Errorf("host still holds addresses: %v", h)
	}

	// The port went to the domain's service, which the domain exposes.
	var svcType, svcSub string
	var svcPort float64
	if err := r.db.QueryRowContext(ctx, `SELECT asset_type, sub_type, (properties->>'port')::float FROM assets
		WHERE tenant_id = $1 AND properties->>'host' = $2 AND deleted_at IS NULL`, tid.String(), domain).
		Scan(&svcType, &svcSub, &svcPort); err != nil {
		t.Fatalf("routed service: %v", err)
	}
	if svcType != "service" || svcSub != "open_port" || svcPort != 443 {
		t.Errorf("routed service = %s/%s port %v", svcType, svcSub, svcPort)
	}
	if got := edgeTargets("exposes"); len(got) != 1 {
		t.Errorf("exposes edges = %v, want the one service", got)
	}
	// The domain resolves to each address, an IP asset per address.
	if got := edgeTargets("resolves_to"); !slices.Equal(got, want) {
		t.Errorf("resolves_to = %v, want %v", got, want)
	}

	// The owner's case: a nuclei result, an ip_address asset named by the
	// host it reached, with ip and port, run for a command on that host.
	var before time.Time
	if err := r.db.QueryRowContext(ctx, `SELECT max(rel.last_verified) FROM asset_relationships rel
		JOIN assets s ON s.id = rel.source_asset_id WHERE rel.tenant_id = $1 AND s.name = $2 AND rel.relationship_type = 'resolves_to'`,
		tid.String(), domain).Scan(&before); err != nil {
		t.Fatalf("last_verified: %v", err)
	}
	cmd := shared.NewID()
	report("nuclei", ingest.Binding{Kind: ingest.BindingCommand, CommandID: &cmd, Targets: []string{domain}, Tool: "nuclei"},
		ctis.Asset{ID: "n", Type: ctis.AssetTypeIPAddress, Value: "203.0.113.10", Name: domain,
			Properties: ctis.Properties{"ip": "203.0.113.10", "port": "8443"}})
	d = props(tid, domain)
	if _, ok := d["port"]; ok {
		t.Errorf("a nuclei port landed on the domain: %v", d)
	}
	if _, ok := d["ip"]; ok {
		t.Errorf("a nuclei ip landed on the domain: %v", d)
	}
	if got := edgeTargets("exposes"); len(got) != 2 {
		t.Errorf("exposes edges after the nuclei port = %v, want the 443 and 8443 services", got)
	}
	var after time.Time
	if err := r.db.QueryRowContext(ctx, `SELECT rel.last_verified FROM asset_relationships rel
		JOIN assets s ON s.id = rel.source_asset_id JOIN assets t ON t.id = rel.target_asset_id
		WHERE rel.tenant_id = $1 AND s.name = $2 AND t.name = '203.0.113.10' AND rel.relationship_type = 'resolves_to'`,
		tid.String(), domain).Scan(&after); err != nil {
		t.Fatalf("last_verified after: %v", err)
	}
	if after.Before(before) || after.Equal(before) {
		t.Errorf("resolves_to last_verified not refreshed: %v then %v", before, after)
	}

	// Tenant isolation: the other tenant's same-named domain is untouched.
	o := props(oid, domain)
	if o["ip"] != "192.0.2.99" || o["ip_addresses"] != nil {
		t.Errorf("other tenant's domain changed: %v", o)
	}
	var otherEdges int
	if err := r.db.QueryRowContext(ctx, `SELECT count(*) FROM asset_relationships WHERE source_asset_id = $1 OR target_asset_id = $1`,
		otherID.String()).Scan(&otherEdges); err != nil {
		t.Fatal(err)
	}
	if otherEdges != 0 {
		t.Errorf("other tenant's domain got %d edges", otherEdges)
	}
}
