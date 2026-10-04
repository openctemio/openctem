package integration

import (
	"context"
	"database/sql"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/lib/pq"
	"github.com/openctemio/ctis"

	"github.com/openctemio/openctem/api/internal/app/ingest"
	"github.com/openctemio/openctem/api/internal/app/tenablesc"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/command"
	"github.com/openctemio/openctem/api/pkg/domain/integration"
	"github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// The Tenable.sc connector flow on a migrated database
// (docs/rfcs/RFC-047-tenable-sc-sensor-connector.md): an integration's sync
// queues a connector_sync command that only its own sensor reporting the
// tenable_sc tool can claim; the sensor's CTIS reports (the sensor repo's
// golden output) ingest bound to the command; a mitigated row resolves the
// open finding; completion moves the integration's cursor.
func TestTenableSCConnector_Flow(t *testing.T) {
	sqldb := setupTestDB(t)
	t.Cleanup(func() { _ = sqldb.Close() })
	db := &postgres.DB{DB: sqldb}
	ctx := context.Background()

	sensorRepo := postgres.NewSensorRepository(db)
	known, _, err := sensorRepo.KnownCapabilityNames(ctx, nil, []string{tenablesc.ToolName}, nil)
	if err != nil || !known[tenablesc.ToolName] {
		t.Fatalf("tenable_sc must be in the tool catalog (a sensor's report of it would be dropped): %v %v", known, err)
	}

	tenant, other := seedTenant(t, sqldb), seedTenant(t, sqldb)
	connSensor := seedReportingSensor(t, sqldb, tenant, tenablesc.ToolName)
	nucleiSensor := seedReportingSensor(t, sqldb, tenant, "nuclei")
	otherSensor := seedReportingSensor(t, sqldb, other, tenablesc.ToolName)

	intRepo := postgres.NewIntegrationRepository(db)
	intg := integration.NewIntegration(shared.NewID(), tenant, "Tenable.sc", integration.CategorySecurity,
		integration.ProviderTenable, integration.AuthTypeAPIKey)
	intg.SetConfig(map[string]any{"engine": "tenable_sc", "execution_mode": "sensor",
		"sensor_id": connSensor.String(), "instance": "sc-prod"})
	if err := intRepo.Create(ctx, intg); err != nil {
		t.Fatalf("create integration: %v", err)
	}

	cmdRepo := postgres.NewCommandRepository(db)
	svc := tenablesc.NewService(intRepo, sensorRepo, cmdRepo, postgres.NewFindingRepository(db), nil, logger.NewNop())
	svc.SetSyncClaimer(intRepo)

	// Another tenant cannot sync it.
	if _, err := svc.RequestSync(ctx, other, intg.ID(), tenablesc.TriggerManual, nil); err == nil {
		t.Fatal("another tenant synced the integration")
	}
	res, err := svc.RequestSync(ctx, tenant, intg.ID(), tenablesc.TriggerManual, nil)
	if err != nil {
		t.Fatalf("request sync: %v", err)
	}

	// Routing: pinned to the connector sensor, which must report the tool.
	for name, c := range map[string]struct {
		tenant shared.ID
		sensor shared.ID
	}{
		"same tenant, no tenable_sc tool": {tenant, nucleiSensor},
		"other tenant's sensor":           {other, otherSensor},
	} {
		ok, err := cmdRepo.ClaimForSensor(ctx, c.tenant, res.CommandID, c.sensor.String())
		if err == nil && ok {
			t.Fatalf("%s claimed the connector_sync command", name)
		}
	}
	ok, err := cmdRepo.ClaimForSensor(ctx, tenant, res.CommandID, connSensor.String())
	if err != nil || !ok {
		t.Fatalf("connector sensor could not claim: %v %v", ok, err)
	}

	// Ingest the sensor's golden reports, bound to the command.
	raw, err := os.ReadFile("testdata/tenablesc/sensor_golden_reports.json")
	if err != nil {
		t.Fatal(err)
	}
	var reports []*ctis.Report
	if err := json.Unmarshal(raw, &reports); err != nil {
		t.Fatalf("golden reports: %v", err)
	}
	ing := ingest.NewService(
		postgres.NewAssetRepository(db), postgres.NewFindingRepository(db),
		postgres.NewVulnerabilityRepository(db), postgres.NewComponentRepository(db),
		sensorRepo, postgres.NewBranchRepository(db), postgres.NewTenantRepository(db),
		postgres.NewAuditRepository(db), logger.NewNop())
	ing.SetSourceResolveMode(ingest.SourceResolveEnforce)
	tid := tenant
	agt := &sensor.Sensor{ID: connSensor, TenantID: &tid, Type: sensor.SensorTypeWorker, Status: sensor.SensorStatusActive}
	cmdID := res.CommandID
	bind := ingest.Binding{Kind: ingest.BindingCommand, CommandID: &cmdID, Tool: tenablesc.ToolName}
	for _, rep := range reports {
		out, err := ing.Ingest(ctx, agt, ingest.Input{Report: rep, Options: ingest.Options{Binding: bind}})
		if err != nil || len(out.Errors) > 0 {
			t.Fatalf("ingest %s: %v %v", rep.Metadata.ID, err, out.Errors)
		}
		if rep.Metadata.ID == "cmd-1-0" && out.FindingsSourceMitigated == 0 {
			t.Fatal("the golden mitigated row was not recognized")
		}
	}
	count := func(q string, args ...any) int {
		t.Helper()
		var n int
		if err := sqldb.QueryRowContext(ctx, q, args...).Scan(&n); err != nil {
			t.Fatalf("%v: %s", err, q)
		}
		return n
	}
	// 156860 (3 CVEs → 3 findings), 51192 and 10287 open; 97833 mitigated → none.
	if n := count(`SELECT COUNT(*) FROM findings WHERE tenant_id = $1 AND tool_name = 'tenable_sc'`, tenant.String()); n != 5 {
		t.Fatalf("findings %d, want 5 (no finding from a mitigated row)", n)
	}
	if n := count(`SELECT COUNT(*) FROM findings WHERE tenant_id = $1 AND rule_id = '97833'`, tenant.String()); n != 0 {
		t.Fatal("a mitigated row created a finding")
	}

	// A later sync reports 51192 mitigated: the open finding is resolved.
	var again []*ctis.Report
	if err := json.Unmarshal(raw, &again); err != nil {
		t.Fatal(err)
	}
	mitigated := again[0]
	var keep []ctis.Finding
	for _, f := range mitigated.Findings {
		if f.RuleID == "51192" {
			f.Status = ctis.FindingStatusResolved
			f.Properties["tenable_state"] = "mitigated"
			// Tenable reports seconds; a mitigation after the open sighting.
			f.Properties["tenable_last_mitigated"] = time.Now().Add(2 * time.Second).UTC().Format(time.RFC3339)
			keep = append(keep, f)
		}
	}
	mitigated.Findings = keep
	mitigated.Metadata.ID = "cmd-2-0"
	out, err := ing.Ingest(ctx, agt, ingest.Input{Report: mitigated, Options: ingest.Options{Binding: bind}})
	if err != nil || out.FindingsSourceResolved != 1 {
		t.Fatalf("mitigated ingest: resolved %d, err %v, errors %v", out.FindingsSourceResolved, err, out.Errors)
	}
	if n := count(`SELECT COUNT(*) FROM findings WHERE tenant_id = $1 AND rule_id = '51192' AND status = 'resolved'
		AND resolution_method = 'source_mitigated'`, tenant.String()); n != 1 {
		t.Fatal("the mitigated finding was not resolved")
	}
	if n := count(`SELECT COUNT(*) FROM audit_logs WHERE tenant_id = $1 AND action = 'ingest.source_resolved'
		AND resource_id = $2 AND metadata->>'count' = '1'`, tenant.String(), cmdID.String()); n != 1 {
		t.Fatalf("source-asserted resolve audit entries: %d, want 1", n)
	}

	// Completion moves the cursor.
	result, _ := json.Marshal(map[string]any{"status": "completed", "metadata": map[string]any{
		"tenable_version": "6.4.0", "licensed_ips": 1000, "active_ips": 400, "hosts": 3, "open": 5, "mitigated": 1, "plugins": 4}})
	if _, err := sqldb.ExecContext(ctx, `UPDATE commands SET status = 'completed', started_at = NOW() - interval '5 minutes',
		completed_at = NOW(), result = $3 WHERE tenant_id = $1 AND id = $2`, tenant.String(), cmdID.String(), result); err != nil {
		t.Fatal(err)
	}
	stored, err := intRepo.GetByTenantAndID(ctx, tenant, intg.ID())
	if err != nil {
		t.Fatal(err)
	}
	if changed, err := svc.Reconcile(ctx, stored); err != nil || !changed {
		t.Fatalf("reconcile: %v %v", changed, err)
	}
	stored, _ = intRepo.GetByTenantAndID(ctx, tenant, intg.ID())
	st := tenablesc.State(stored)
	if st.LastSuccessfulSync == nil || st.LastOutcome != tenablesc.OutcomeCompleted || st.ActiveIPs != 400 ||
		stored.Status() != integration.StatusConnected || stored.LastSyncAt() == nil {
		t.Fatalf("after completion: state %+v status %s", st, stored.Status())
	}

	// The scheduled claim is compare-and-set: of two replicas, one wins.
	exp := stored.NextSyncAt()
	next := time.Now().Add(time.Hour)
	first, err1 := intRepo.ClaimSyncDue(ctx, tenant, intg.ID(), exp, next)
	second, err2 := intRepo.ClaimSyncDue(ctx, tenant, intg.ID(), exp, next)
	if err1 != nil || err2 != nil || !first || second {
		t.Fatalf("claim: %v %v (%v %v)", first, second, err1, err2)
	}
	if ok, _ := intRepo.ClaimSyncDue(ctx, other, intg.ID(), nil, next); ok {
		t.Fatal("another tenant claimed the integration's sync")
	}
	var ctype string
	_ = sqldb.QueryRowContext(ctx, `SELECT type FROM commands WHERE id = $1`, cmdID.String()).Scan(&ctype)
	if ctype != string(command.CommandTypeConnectorSync) {
		t.Fatalf("command type %q", ctype)
	}
}

func seedTenant(t *testing.T, db *sql.DB) shared.ID {
	t.Helper()
	id := shared.NewID()
	if _, err := db.ExecContext(context.Background(), `INSERT INTO tenants (id, name, slug) VALUES ($1, $2, $2)`,
		id.String(), "tsc-"+id.String()); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	t.Cleanup(func() {
		_, _ = db.ExecContext(context.Background(), `DELETE FROM ingest_reports WHERE tenant_id = $1`, id.String())
		_, _ = db.ExecContext(context.Background(), `DELETE FROM tenants WHERE id = $1`, id.String())
	})
	return id
}

// seedReportingSensor inserts an active sensor that reported the given tools
// installed (what a heartbeat stores after sanitizing against the catalog).
func seedReportingSensor(t *testing.T, db *sql.DB, tenant shared.ID, tools ...string) shared.ID {
	t.Helper()
	id := shared.NewID()
	type tool struct {
		Name      string `json:"name"`
		Installed bool   `json:"installed"`
	}
	reported := make([]tool, 0, len(tools))
	for _, n := range tools {
		reported = append(reported, tool{Name: n, Installed: true})
	}
	rt, _ := json.Marshal(reported)
	if _, err := db.ExecContext(context.Background(), `INSERT INTO sensors (id, tenant_id, name, api_key_hash, api_key_prefix,
		status, type, reported_tools, reported_tool_names, reported_at)
		VALUES ($1, $2, $3, $4, 'octs_t', 'active', 'worker', $5, $6, NOW())`,
		id.String(), tenant.String(), "tsc-"+id.String()[:8], "h-"+id.String(), rt, pq.Array(tools)); err != nil {
		t.Fatalf("seed sensor: %v", err)
	}
	return id
}
