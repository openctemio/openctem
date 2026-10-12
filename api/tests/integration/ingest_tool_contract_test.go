package integration

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/ctis"

	"github.com/openctemio/openctem/api/internal/app/ingest"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/sensorresult"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// Tool contracts (sdk-go docs/rfcs/sensor-sdk-v2.md) through the real
// repository and ingest: a sensor's manifest keeps each tool's contract,
// read back only under the sensor's own tenant, and a bound report of a
// ported tool keeps only the output types the tool declares. Two tenants run
// a tool of the same name with different contracts; neither sees or uses the
// other's.
func TestIngest_ToolContractProduces(t *testing.T) {
	r := newV2Rig(t, ingest.DefaultBlindingGuard())
	a := r.newTenant("acme-probe")
	b := r.newTenant("acme-probe")
	db := &postgres.DB{DB: r.db}
	ctx := context.Background()
	sensors := postgres.NewSensorRepository(db)
	results := postgres.NewSensorResultRepository(db)
	svc := ingest.NewService(
		postgres.NewAssetRepository(db), postgres.NewFindingRepository(db),
		postgres.NewVulnerabilityRepository(db), postgres.NewComponentRepository(db),
		sensors, postgres.NewBranchRepository(db), postgres.NewTenantRepository(db),
		postgres.NewAuditRepository(db), logger.NewNop())
	svc.SetResultQuarantine(results, sensorresult.DefaultLimits())
	svc.SetToolContractSource(sensors)

	save := func(tn v2Tenant, digestChar string, produces ...string) {
		t.Helper()
		tid := tn.tenant
		m := sensor.Manifest{Schema: sensor.ManifestSchema, Tools: []sensor.ManifestTool{{Name: "acme-probe", Installed: true,
			Contract: &sensor.ToolContract{APIVersion: sensor.ToolContractAPIVersion, Digest: "sha256:" + strings.Repeat(digestChar, 64),
				Version: "1.0.0", Class: "target-scan", Tier: "T1", Network: "targets", Produces: produces}}}}
		d, err := m.Digest()
		if err != nil {
			t.Fatal(err)
		}
		saved, err := sensors.SaveManifest(ctx, sensor.ManifestVersion{SensorID: tn.sensor, TenantID: &tid, Digest: d,
			Source: sensor.ManifestSourceSensor, Manifest: m, Ignored: []sensor.ManifestIgnored{}}, nil, time.Now().UTC())
		if err != nil || !saved {
			t.Fatalf("SaveManifest: %v saved=%v", err, saved)
		}
	}
	save(a, "a", "asset:domain")
	save(b, "b", "asset:domain", "asset:repository")

	// Stored and read back under the owning tenant only.
	aTID, bTID := a.tenant, b.tenant
	got, err := sensors.CurrentManifest(ctx, &aTID, a.sensor)
	if err != nil || got.Manifest.ToolContract("acme-probe") == nil || got.Manifest.ToolContract("acme-probe").Digest != "sha256:"+strings.Repeat("a", 64) {
		t.Fatalf("tenant A contract: %+v %v", got, err)
	}
	if _, err := sensors.CurrentManifest(ctx, &bTID, a.sensor); err == nil {
		t.Fatal("tenant B read tenant A's sensor manifest")
	}
	if _, err := sensors.CurrentManifest(ctx, nil, a.sensor); err == nil {
		t.Fatal("a platform-scoped read returned a tenant sensor's manifest")
	}

	ingestProbe := func(tn v2Tenant, domain, repo string) {
		t.Helper()
		tid := tn.tenant
		agt := &sensor.Sensor{ID: tn.sensor, TenantID: &tid, Type: sensor.SensorTypeWorker, Status: sensor.SensorStatusActive}
		cmd := shared.NewID()
		rep := &ctis.Report{Version: "1.0", Tool: &ctis.Tool{Name: "acme-probe"},
			Metadata: ctis.ReportMetadata{ID: "rep-" + cmd.String(), Timestamp: time.Now().UTC()},
			Assets: []ctis.Asset{
				{ID: "d", Type: ctis.AssetTypeDomain, Value: domain},
				{ID: "r", Type: ctis.AssetTypeRepository, Value: repo},
			}}
		bind := ingest.Binding{Kind: ingest.BindingCommand, CommandID: &cmd, Tool: "acme-probe", Targets: []string{domain}}
		out, err := svc.Ingest(ctx, agt, ingest.Input{Report: rep, Options: ingest.Options{Binding: bind, Route: "ctis"}})
		if err != nil || len(out.Errors) > 0 {
			t.Fatalf("Ingest: %v %v", err, out.Errors)
		}
	}
	exists := func(tn v2Tenant, name string) bool {
		t.Helper()
		var n int
		if err := r.db.QueryRowContext(ctx, `SELECT count(*) FROM assets WHERE tenant_id = $1 AND name = $2`, tn.tenant.String(), name).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n > 0
	}
	quarantined := func(tn v2Tenant) int {
		t.Helper()
		var n int
		if err := r.db.QueryRowContext(ctx, `SELECT count(*) FROM sensor_result_quarantine WHERE tenant_id = $1 AND reason = $2`,
			tn.tenant.String(), string(sensorresult.ReasonOutOfContract)).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}

	// Tenant A declares domains only: the repository is held, never written.
	ingestProbe(a, "contract-a.example.org", "github.com/evil/planted-a")
	if !exists(a, "contract-a.example.org") || exists(a, "github.com/evil/planted-a") || quarantined(a) != 1 {
		t.Fatalf("tenant A: domain=%v repo=%v quarantined=%d", exists(a, "contract-a.example.org"), exists(a, "github.com/evil/planted-a"), quarantined(a))
	}
	// Tenant B declares repositories too (the catalog does not know the
	// tool): applied whole, and tenant A's narrower contract is not used.
	ingestProbe(b, "contract-b.example.org", "github.com/acme/legit-b")
	if !exists(b, "contract-b.example.org") || !exists(b, "github.com/acme/legit-b") || quarantined(b) != 0 {
		t.Fatalf("tenant B: repo=%v quarantined=%d", exists(b, "github.com/acme/legit-b"), quarantined(b))
	}
}
