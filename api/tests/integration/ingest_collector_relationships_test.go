package integration

import (
	"context"
	"testing"
	"time"

	"github.com/openctemio/ctis"

	"github.com/openctemio/openctem/api/internal/app/ingest"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/sensor"
)

// vcenterReport is what the vCenter collector sends: an ESXi host and a
// virtual machine that names it in esxi_host, with its address, plus the
// same placement as a typed relationship.
func vcenterReport(vm string) *ctis.Report {
	return &ctis.Report{
		Version:  "1.0",
		Tool:     &ctis.Tool{Name: "vcenter"},
		Metadata: ctis.ReportMetadata{Timestamp: time.Now().UTC(), SourceType: "collector", CoverageType: "full"},
		Assets: []ctis.Asset{
			{ID: "esx", Type: ctis.AssetTypeHost, Value: "esx01.example.com", Name: "esx01.example.com",
				Properties: ctis.Properties{"cluster": "prod", "is_virtual": false}},
			{ID: "vm", Type: ctis.AssetTypeHost, Value: vm, Name: vm,
				Properties: ctis.Properties{"esxi_host": "ESX01.example.com", "cluster": "prod", "ip_addresses": []any{"192.0.2.10"}}},
		},
		Relationships: []ctis.Relationship{{Type: ctis.RelHostedBy, FromRef: "vm", ToRef: "esx"}},
	}
}

// A collector's placement becomes relationships inside the tenant: the
// virtual machine runs_on its hypervisor host and contains its existing
// address asset. Writing it again adds nothing; another tenant's identical
// assets are never linked; an existing asset an unsolicited report may not
// change gets no edge.
func TestIngest_CollectorRelationships(t *testing.T) {
	r := newV2Rig(t, ingest.DefaultBlindingGuard())
	db := &postgres.DB{DB: r.db}
	r.svc.SetRelationshipRepository(postgres.NewAssetRelationshipRepository(db))
	ctx := context.Background()

	trusted := func(tn v2Tenant, rep *ctis.Report) {
		t.Helper()
		tid := tn.tenant
		agt := &sensor.Sensor{TenantID: &tid, Status: sensor.SensorStatusActive}
		out, err := r.svc.Ingest(ctx, agt, ingest.Input{Report: rep})
		if err != nil {
			t.Fatalf("trusted ingest: %v", err)
		}
		if len(out.Errors) > 0 {
			t.Fatalf("trusted ingest: %v", out.Errors)
		}
	}
	collect := func(tn v2Tenant, rep *ctis.Report) {
		t.Helper()
		tid := tn.tenant
		agt := &sensor.Sensor{ID: tn.sensor, TenantID: &tid, Type: sensor.SensorTypeCollector, Status: sensor.SensorStatusActive}
		out, err := r.svc.Ingest(ctx, agt, ingest.Input{Report: rep, Options: ingest.Options{Admitted: true}})
		if err != nil {
			t.Fatalf("collector ingest: %v", err)
		}
		if len(out.Errors) > 0 {
			t.Fatalf("collector ingest: %v", out.Errors)
		}
	}
	address := func(tn v2Tenant) {
		t.Helper()
		trusted(tn, &ctis.Report{Version: "1.0", Tool: &ctis.Tool{Name: "import"}, Metadata: ctis.ReportMetadata{Timestamp: time.Now().UTC()},
			Assets: []ctis.Asset{{ID: "ip", Type: ctis.AssetTypeIPAddress, Value: "192.0.2.10", Name: "192.0.2.10"}}})
	}
	type edge struct{ src, rel, dst string }
	edges := func(tn v2Tenant) []edge {
		t.Helper()
		rows, err := r.db.QueryContext(ctx, `
			SELECT s.name, rel.relationship_type, d.name FROM asset_relationships rel
			JOIN assets s ON s.id = rel.source_asset_id
			JOIN assets d ON d.id = rel.target_asset_id
			WHERE rel.tenant_id = $1 AND s.tenant_id = $1 AND d.tenant_id = $1
			ORDER BY 1, 2, 3`, tn.tenant.String())
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		var out []edge
		for rows.Next() {
			var e edge
			if err := rows.Scan(&e.src, &e.rel, &e.dst); err != nil {
				t.Fatal(err)
			}
			out = append(out, e)
		}
		if err := rows.Err(); err != nil {
			t.Fatal(err)
		}
		return out
	}
	crossTenant := func() int {
		t.Helper()
		var n int
		if err := r.db.QueryRowContext(ctx, `
			SELECT count(*) FROM asset_relationships rel
			JOIN assets s ON s.id = rel.source_asset_id
			JOIN assets d ON d.id = rel.target_asset_id
			WHERE s.tenant_id <> rel.tenant_id OR d.tenant_id <> rel.tenant_id`).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}

	a := r.newTenant("vcenter")
	b := r.newTenant("vcenter")
	address(a)
	address(b)
	// Tenant B holds an identically named hypervisor host.
	trusted(b, &ctis.Report{Version: "1.0", Tool: &ctis.Tool{Name: "import"}, Metadata: ctis.ReportMetadata{Timestamp: time.Now().UTC()},
		Assets: []ctis.Asset{{ID: "esx", Type: ctis.AssetTypeHost, Value: "esx01.example.com", Name: "esx01.example.com"}}})

	collect(a, vcenterReport("vm01.example.com"))
	want := []edge{
		{"vm01.example.com", "contains", "192.0.2.10"},
		{"vm01.example.com", "runs_on", "esx01.example.com"},
	}
	got := edges(a)
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("tenant A edges = %v, want %v", got, want)
	}

	// Idempotent: the same report again adds no edge.
	collect(a, vcenterReport("vm01.example.com"))
	if got := edges(a); len(got) != len(want) {
		t.Fatalf("after a second report: %d edges, want %d (%v)", len(got), len(want), got)
	}

	// Tenant B's assets were never linked from tenant A's report.
	if got := edges(b); len(got) != 0 {
		t.Fatalf("tenant B edges = %v, want none", got)
	}
	if n := crossTenant(); n != 0 {
		t.Fatalf("%d relationships cross a tenant boundary", n)
	}

	// An existing virtual machine an unsolicited report may not change gets
	// no edge from that report.
	c := r.newTenant("vcenter")
	address(c)
	trusted(c, &ctis.Report{Version: "1.0", Tool: &ctis.Tool{Name: "import"}, Metadata: ctis.ReportMetadata{Timestamp: time.Now().UTC()},
		Assets: []ctis.Asset{{ID: "vm", Type: ctis.AssetTypeHost, Value: "vm02.example.com", Name: "vm02.example.com"}}})
	collect(c, vcenterReport("vm02.example.com"))
	for _, e := range edges(c) {
		if e.src == "vm02.example.com" {
			t.Fatalf("unsolicited report added %v to an existing asset it may not change", e)
		}
	}
}
