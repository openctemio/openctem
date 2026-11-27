package integration

import (
	"context"
	"testing"
	"time"

	"github.com/openctemio/ctis/v2"

	"github.com/openctemio/openctem/server/internal/app/ingest"
	"github.com/openctemio/openctem/server/internal/infra/postgres"
	"github.com/openctemio/openctem/server/pkg/domain/sensor"
	"github.com/openctemio/openctem/server/pkg/logger"
)

// A named host linked to an address the tenant already records as an
// ip_address asset is its own host asset that contains the address: it is
// never merged into the address asset, which has no place for the host's
// name (the name was lost, and the scanner's findings landed on the
// address). The address asset stays as it was, and another tenant's asset
// with the same address is untouched.
func TestIngest_HostKeptBesideItsAddress(t *testing.T) {
	r := newV2RigWith(t, ingest.DefaultBlindingGuard(), func(svc *ingest.Service, db *postgres.DB) {
		svc.SetCorrelator(ingest.NewAssetCorrelator(postgres.NewAssetRepository(db), logger.NewNop(), ingest.CorrelationConfig{}))
		svc.SetRelationshipRepository(postgres.NewAssetRelationshipRepository(db))
	})
	ctx := context.Background()
	const ip, host = "192.0.2.17", "srv-web-00.corp.example.net"

	send := func(tn v2Tenant, tool string, assets []ctis.Asset, rels []ctis.Relationship, findings []ctis.Finding) {
		t.Helper()
		tid := tn.tenant
		agt := &sensor.Sensor{ID: tn.sensor, TenantID: &tid, Type: sensor.SensorTypeWorker, Status: sensor.SensorStatusActive}
		rep := &ctis.Report{Version: ctis.SchemaVersion, Tool: &ctis.Tool{Name: tool},
			Metadata: ctis.ReportMetadata{ID: ctis.NewReportID(), GeneratedAt: time.Now().UTC()},
			Assets:   assets, Relationships: rels, Findings: findings}
		out, err := r.svc.Ingest(ctx, agt, ingest.Input{Report: rep})
		if err != nil {
			t.Fatal(err)
		}
		if len(out.Errors) > 0 {
			t.Fatal(out.Errors)
		}
	}
	address := ctis.Asset{ID: "ipn-1", Type: ctis.AssetTypeIPAddress, Value: ip}

	a, b := r.newTenant(), r.newTenant()
	// The inventory knows the address first (both tenants).
	send(a, "inventory", []ctis.Asset{address}, nil, nil)
	send(b, "inventory", []ctis.Asset{address}, nil, nil)

	// The network scanner reports the host by name, with the address it has.
	send(a, "nessus",
		[]ctis.Asset{{ID: "h-1", Type: ctis.AssetTypeHost, Value: host, Name: "srv-web-00"}, address},
		[]ctis.Relationship{{Type: ctis.RelHasAddress, FromRef: "h-1", ToRef: "ipn-1"}},
		[]ctis.Finding{{Type: ctis.FindingTypeVulnerability, Title: "OpenSSH flaw", Severity: ctis.SeverityHigh,
			RuleID: "nessus-100001", AssetRef: "h-1"}})

	typeOf := func(tn v2Tenant, name string) string {
		t.Helper()
		var typ string
		err := r.db.QueryRowContext(ctx, `SELECT asset_type FROM assets WHERE tenant_id = $1 AND name = $2`,
			tn.tenant.String(), name).Scan(&typ)
		if err != nil {
			return ""
		}
		return typ
	}
	if got := typeOf(a, host); got != "host" {
		t.Fatalf("host %q stored as %q, want its own host asset (its name was dropped)", host, got)
	}
	if got := typeOf(a, ip); got != "ip_address" {
		t.Fatalf("address %q stored as %q, want the ip_address asset unchanged", ip, got)
	}

	// The host contains its address.
	var edges int
	if err := r.db.QueryRowContext(ctx, `SELECT count(*) FROM asset_relationships rel
		JOIN assets s ON s.id = rel.source_asset_id JOIN assets d ON d.id = rel.target_asset_id
		WHERE rel.tenant_id = $1 AND s.name = $2 AND d.name = $3 AND rel.relationship_type = 'contains'`,
		a.tenant.String(), host, ip).Scan(&edges); err != nil {
		t.Fatal(err)
	}
	if edges != 1 {
		t.Fatalf("host contains address edges = %d, want 1", edges)
	}

	// The scanner's finding is on the host, not on the address.
	var onHost int
	if err := r.db.QueryRowContext(ctx, `SELECT count(*) FROM findings f JOIN assets s ON s.id = f.asset_id
		WHERE f.tenant_id = $1 AND s.name = $2 AND f.rule_id = 'nessus-100001'`, a.tenant.String(), host).Scan(&onHost); err != nil {
		t.Fatal(err)
	}
	if onHost != 1 {
		t.Fatalf("findings on the host = %d, want 1", onHost)
	}

	// Tenant B: only its address asset, no host, no finding.
	var bAssets int
	if err := r.db.QueryRowContext(ctx, `SELECT count(*) FROM assets WHERE tenant_id = $1`, b.tenant.String()).Scan(&bAssets); err != nil {
		t.Fatal(err)
	}
	if bAssets != 1 || typeOf(b, ip) != "ip_address" {
		t.Fatalf("tenant B assets = %d (address type %q), want its one ip_address asset", bAssets, typeOf(b, ip))
	}

	// A second report of the same host lands on the same host asset.
	send(a, "nessus",
		[]ctis.Asset{{ID: "h-1", Type: ctis.AssetTypeHost, Value: host, Name: "srv-web-00"}, address},
		[]ctis.Relationship{{Type: ctis.RelHasAddress, FromRef: "h-1", ToRef: "ipn-1"}}, nil)
	var aAssets int
	if err := r.db.QueryRowContext(ctx, `SELECT count(*) FROM assets WHERE tenant_id = $1`, a.tenant.String()).Scan(&aAssets); err != nil {
		t.Fatal(err)
	}
	if aAssets != 2 {
		t.Fatalf("tenant A assets = %d, want 2 (one host, one address)", aAssets)
	}
}
