package integration

import (
	"context"
	"testing"
	"time"

	"github.com/openctemio/ctis"

	"github.com/openctemio/openctem/api/internal/app/ingest"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// Host normalisation moves properties.ip into ip_addresses and deletes ip,
// and inferAssetExposure only read ip: a host with a public IP was never
// inferred internet-exposed, so the reachability-gated priority rules never
// fired for it. Checked here on a migrated database, through the real ingest.
func TestIngest_HostExposureInferredFromNormalisedIP(t *testing.T) {
	r := newV2Rig(t, ingest.DefaultBlindingGuard())
	tn := r.newTenant("nmap")
	db := &postgres.DB{DB: r.db}
	svc := ingest.NewService(
		postgres.NewAssetRepository(db), postgres.NewFindingRepository(db),
		postgres.NewVulnerabilityRepository(db), postgres.NewComponentRepository(db),
		postgres.NewSensorRepository(db), postgres.NewBranchRepository(db), postgres.NewTenantRepository(db),
		postgres.NewAuditRepository(db), logger.NewNop())
	tid := tn.tenant
	agt := &sensor.Sensor{ID: tn.sensor, TenantID: &tid, Type: sensor.SensorTypeWorker, Status: sensor.SensorStatusActive}
	ingestHosts := func(bind ingest.Binding, hosts ...ctis.Asset) {
		t.Helper()
		rep := &ctis.Report{Version: "1.0", Tool: &ctis.Tool{Name: "nmap"}, Assets: hosts,
			Metadata: ctis.ReportMetadata{Timestamp: time.Now().UTC()}}
		out, err := svc.Ingest(context.Background(), agt, ingest.Input{Report: rep, Options: ingest.Options{Binding: bind}})
		if err != nil || len(out.Errors) > 0 {
			t.Fatalf("Ingest: %v %v", err, out.Errors)
		}
	}
	exposure := func(name string) string {
		t.Helper()
		var e string
		if err := r.db.QueryRowContext(context.Background(),
			`SELECT exposure FROM assets WHERE tenant_id = $1 AND name = $2`, tn.tenant.String(), name).Scan(&e); err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		return e
	}

	ingestHosts(ingest.Binding{},
		ctis.Asset{ID: "pub", Type: ctis.AssetTypeHost, Value: "edge-1.example.com", Properties: ctis.Properties{"ip": "8.8.8.8"}},
		ctis.Asset{ID: "priv", Type: ctis.AssetTypeHost, Value: "db-1.corp.example", Properties: ctis.Properties{"ip": "10.0.0.5"}},
		ctis.Asset{ID: "later", Type: ctis.AssetTypeHost, Value: "app-1.example.com"},
	)
	if got := exposure("edge-1.example.com"); got != "public" {
		t.Errorf("host with a public IP: exposure = %q, want public", got)
	}
	if got := exposure("db-1.corp.example"); got != "unknown" {
		t.Errorf("host with a private IP: exposure = %q, want unknown", got)
	}
	if got := exposure("app-1.example.com"); got != "unknown" {
		t.Errorf("host without an IP: exposure = %q, want unknown", got)
	}

	// A re-scan that learns the public IP of a known host backfills it, when
	// a command covering the host stands behind it (RFC-040 §5.3).
	later := ctis.Asset{ID: "later", Type: ctis.AssetTypeHost, Value: "app-1.example.com", Properties: ctis.Properties{"ip": "1.1.1.1"}}
	ingestHosts(ingest.Binding{}, later)
	if got := exposure("app-1.example.com"); got != "unknown" {
		t.Errorf("a re-scan without a command changed the exposure of an existing host: %q", got)
	}
	ingestHosts(ingest.Binding{Kind: ingest.BindingCommand, Targets: []string{"app-1.example.com"}}, later)
	if got := exposure("app-1.example.com"); got != "public" {
		t.Errorf("re-scanned host with a public IP: exposure = %q, want public", got)
	}
}
