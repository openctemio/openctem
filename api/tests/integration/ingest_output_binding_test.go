package integration

import (
	"context"
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

// research/27 P0-4 (G12) through the real ingest: a dnsx task's report that
// carries a repository has the repository held in the quarantine (reason
// out_of_contract), never written; its in-contract assets are written. In
// warn mode the same report is applied whole. Nothing crosses tenants.
func TestIngest_OutputTypeBinding(t *testing.T) {
	r := newV2Rig(t, ingest.DefaultBlindingGuard())
	tn := r.newTenant("dnsx")
	db := &postgres.DB{DB: r.db}
	ctx := context.Background()
	results := postgres.NewSensorResultRepository(db)
	svc := ingest.NewService(
		postgres.NewAssetRepository(db), postgres.NewFindingRepository(db),
		postgres.NewVulnerabilityRepository(db), postgres.NewComponentRepository(db),
		postgres.NewSensorRepository(db), postgres.NewBranchRepository(db), postgres.NewTenantRepository(db),
		postgres.NewAuditRepository(db), logger.NewNop())
	svc.SetResultQuarantine(results, sensorresult.DefaultLimits())
	tid := tn.tenant
	agt := &sensor.Sensor{ID: tn.sensor, TenantID: &tid, Type: sensor.SensorTypeWorker, Status: sensor.SensorStatusActive}

	ingestDNSX := func(domain, repo string) {
		t.Helper()
		cmd := shared.NewID()
		rep := &ctis.Report{Version: "1.0", Tool: &ctis.Tool{Name: "dnsx"},
			Metadata: ctis.ReportMetadata{ID: "rep-" + cmd.String(), Timestamp: time.Now().UTC()},
			Assets: []ctis.Asset{
				{ID: "d", Type: ctis.AssetTypeDomain, Value: domain},
				{ID: "r", Type: ctis.AssetTypeRepository, Value: repo},
			}}
		bind := ingest.Binding{Kind: ingest.BindingCommand, CommandID: &cmd, Tool: "dnsx", Targets: []string{domain}}
		out, err := svc.Ingest(ctx, agt, ingest.Input{Report: rep, Options: ingest.Options{Binding: bind, Route: "ctis"}})
		if err != nil || len(out.Errors) > 0 {
			t.Fatalf("Ingest: %v %v", err, out.Errors)
		}
	}
	exists := func(name string) bool {
		t.Helper()
		var n int
		if err := r.db.QueryRowContext(ctx, `SELECT count(*) FROM assets WHERE tenant_id = $1 AND name = $2`, tid.String(), name).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n > 0
	}

	// No stored policy: the default (quarantine).
	ingestDNSX("bind.example.org", "github.com/evil/planted")
	if !exists("bind.example.org") {
		t.Fatal("the in-contract domain was not written")
	}
	if exists("github.com/evil/planted") {
		t.Fatal("a dnsx report planted a repository")
	}
	var reason string
	var assets int
	if err := r.db.QueryRowContext(ctx, `SELECT reason, assets_count FROM sensor_result_quarantine WHERE tenant_id = $1`, tid.String()).Scan(&reason, &assets); err != nil {
		t.Fatalf("no quarantine row: %v", err)
	}
	if reason != string(sensorresult.ReasonOutOfContract) || assets != 1 {
		t.Fatalf("quarantine row = %s/%d", reason, assets)
	}

	// Warn mode: applied whole.
	if err := results.SavePolicy(ctx, &sensorresult.Policy{TenantID: tid, Mode: sensorresult.ModeWarn}); err != nil {
		t.Fatal(err)
	}
	ingestDNSX("warn.example.org", "github.com/acme/legit")
	if !exists("warn.example.org") || !exists("github.com/acme/legit") {
		t.Fatal("warn mode did not apply the report whole")
	}
}
