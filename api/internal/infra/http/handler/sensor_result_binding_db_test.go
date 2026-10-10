package handler

// Result binding and quarantine (docs/rfcs/RFC-040-platform-sensor-mutual-distrust.md
// §5.3, owner decision Q6 (a)): real sensors, the command check every sensor
// report goes through (ingest.OpenCommand), the ingest service and a migrated
// database. The protocol v2 wire around it is covered by
// tests/integration/ingest_v2_binding_test.go.

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/lib/pq"
	"github.com/openctemio/ctis"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/internal/app/ingest"
	"github.com/openctemio/openctem/api/internal/app/sensor"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/internal/testdb"
	sensordom "github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/sensorresult"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

type bindingRig struct {
	t       *testing.T
	db      *sql.DB
	svc     *ingest.Service
	cmds    *postgres.CommandRepository
	results *postgres.SensorResultRepository
	tenant  shared.ID
	sensors map[string]*sensordom.Sensor // sensor name -> sensor
	ids     map[string]shared.ID         // sensor name -> id
}

// newBindingRig builds a tenant with a worker, a second worker
// and a collector. mode "" leaves the tenant without a policy row (a new
// tenant: quarantine).
func newBindingRig(t *testing.T, mode sensorresult.Mode) *bindingRig {
	t.Helper()
	dbURL := testdb.URL()
	if dbURL == "" {
		t.Skip("DATABASE_URL not set; skipping result binding DB test")
	}
	sqldb, err := sql.Open("postgres", dbURL)
	if err != nil {
		t.Skipf("open db: %v", err)
	}
	t.Cleanup(func() { _ = sqldb.Close() })
	if err := sqldb.PingContext(context.Background()); err != nil {
		t.Skipf("cannot reach DATABASE_URL: %v", err)
	}
	db := &postgres.DB{DB: sqldb}
	log := logger.NewNop()

	sensorRepo := postgres.NewSensorRepository(db)
	sensorSvc := sensor.NewSensorService(sensorRepo, nil, log)
	sensorSvc.SetAPIKeyRepository(postgres.NewSensorAPIKeyRepository(db))
	svc := ingest.NewService(
		postgres.NewAssetRepository(db), postgres.NewFindingRepository(db),
		postgres.NewVulnerabilityRepository(db), postgres.NewComponentRepository(db),
		sensorRepo, postgres.NewBranchRepository(db), postgres.NewTenantRepository(db),
		postgres.NewAuditRepository(db), log)
	results := postgres.NewSensorResultRepository(db)
	cmds := postgres.NewCommandRepository(db)
	svc.SetCommandReader(cmds)
	svc.SetResultQuarantine(results, sensorresult.DefaultLimits())

	ctx := context.Background()
	rig := &bindingRig{t: t, db: sqldb, svc: svc, cmds: cmds, results: results, tenant: shared.NewID(),
		sensors: map[string]*sensordom.Sensor{}, ids: map[string]shared.ID{}}
	if _, err := sqldb.ExecContext(ctx, `INSERT INTO tenants (id, name, slug) VALUES ($1, $2, $3)`,
		rig.tenant.String(), "result binding", "result-binding-"+rig.tenant.String()); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	t.Cleanup(func() {
		_, _ = sqldb.ExecContext(context.Background(), `DELETE FROM tenants WHERE id = $1`, rig.tenant.String())
	})
	if mode != "" {
		p := sensorresult.Policy{TenantID: rig.tenant, Mode: mode}
		if err := results.SavePolicy(ctx, &p); err != nil {
			t.Fatalf("save policy: %v", err)
		}
	}
	for _, s := range []struct{ name, typ, mode string }{
		{"worker", "worker", "daemon"}, {"other-worker", "worker", "daemon"},
		{"collector", "collector", "daemon"},
	} {
		out, err := sensorSvc.CreateSensor(ctx, sensor.CreateSensorInput{
			TenantID: rig.tenant.String(), Name: s.name, Type: s.typ, ExecutionMode: s.mode,
			Capabilities: []string{"infra"},
		})
		if err != nil {
			t.Fatalf("create sensor %s: %v", s.name, err)
		}
		rig.sensors[s.name] = out.Sensor
		rig.ids[s.name] = out.Sensor.ID
	}
	return rig
}

// push ingests a CTIS report as the named sensor, bound to commandID when set,
// the way a sensor report is admitted: the command must be open on this
// sensor (ingest.OpenCommand), then the binding decides what the report may
// change. It answers the HTTP status and body the sensor would see.
func (r *bindingRig) push(sensorName string, report *ctis.Report, commandID string) (int, map[string]any) {
	r.t.Helper()
	ctx := context.Background()
	agt := r.sensors[sensorName]
	var binding ingest.Binding
	if commandID != "" {
		cmd, err := ingest.OpenCommand(ctx, r.cmds, agt, commandID, time.Now())
		if err != nil {
			return http.StatusNotFound, map[string]any{"code": ingest.CodeCommandNotFound}
		}
		binding = ingest.CommandBinding(cmd)
	}
	out, err := r.svc.Ingest(ctx, agt, ingest.Input{Report: report, Options: ingest.Options{Binding: binding, Route: "ctis"}})
	if err != nil {
		var (
			de *shared.DomainError
			qe *ingest.QuarantinedError
		)
		switch {
		case errors.As(err, &qe):
			return http.StatusUnprocessableEntity, map[string]any{"code": ingest.CodeResultsQuarantined}
		case errors.Is(err, sensorresult.ErrFull):
			return http.StatusUnprocessableEntity, map[string]any{"code": "RESULTS_QUARANTINE_FULL"}
		case errors.As(err, &de) && de.Code == ingest.CodeCommandNotFound:
			return http.StatusNotFound, map[string]any{"code": de.Code}
		case errors.As(err, &de) && de.Code == ingest.CodeToolNotPermitted:
			return http.StatusUnprocessableEntity, map[string]any{"code": de.Code}
		}
		r.t.Fatalf("push: %v", err)
	}
	raw, _ := json.Marshal(out)
	var body map[string]any
	_ = json.Unmarshal(raw, &body)
	return http.StatusCreated, body
}

// trusted ingests a report server-side (a tenant upload, zero sensor id):
// the baseline the tests start from.
func (r *bindingRig) trusted(report *ctis.Report) {
	r.t.Helper()
	tid := r.tenant
	agt := &sensordom.Sensor{TenantID: &tid, Status: sensordom.SensorStatusActive}
	if _, err := r.svc.Ingest(context.Background(), agt, ingest.Input{Report: report}); err != nil {
		r.t.Fatalf("trusted ingest: %v", err)
	}
}

// command seeds a command assigned to the named sensor.
func (r *bindingRig) command(sensorName, status string, payload map[string]any, completedAgo time.Duration) string {
	r.t.Helper()
	id := shared.NewID().String()
	raw, _ := json.Marshal(payload)
	var completed any
	if completedAgo > 0 {
		completed = time.Now().Add(-completedAgo)
	}
	if _, err := r.db.ExecContext(context.Background(), `
		INSERT INTO commands (id, tenant_id, sensor_id, type, priority, payload, status, created_at, expires_at, completed_at)
		VALUES ($1, $2, $3, 'scan', 'normal', $4, $5, NOW(), NOW() + interval '1 hour', $6)`,
		id, r.tenant.String(), r.ids[sensorName].String(), string(raw), status, completed); err != nil {
		r.t.Fatalf("seed command: %v", err)
	}
	return id
}

type assetRow struct {
	status, exposure, classification string
	internet, pii                    bool
	compliance                       []string
}

func (r *bindingRig) asset(name string) assetRow {
	r.t.Helper()
	var (
		a     assetRow
		class sql.NullString
	)
	if err := r.db.QueryRowContext(context.Background(), `
		SELECT status, exposure, data_classification, COALESCE(is_internet_accessible, false),
		       COALESCE(pii_data_exposed, false), COALESCE(compliance_scope, '{}')
		FROM assets WHERE tenant_id = $1 AND name = $2`, r.tenant.String(), name).
		Scan(&a.status, &a.exposure, &class, &a.internet, &a.pii, pq.Array(&a.compliance)); err != nil {
		r.t.Fatalf("read asset %s: %v", name, err)
	}
	a.classification = class.String
	return a
}

func (r *bindingRig) count(q string, args ...any) int {
	r.t.Helper()
	var n int
	if err := r.db.QueryRowContext(context.Background(), q, args...).Scan(&n); err != nil {
		r.t.Fatalf("count: %v", err)
	}
	return n
}

func (r *bindingRig) findingStatus(rule string) string {
	r.t.Helper()
	var st string
	if err := r.db.QueryRowContext(context.Background(),
		`SELECT status FROM findings WHERE tenant_id = $1 AND rule_id = $2`, r.tenant.String(), rule).Scan(&st); err != nil {
		r.t.Fatalf("read finding %s: %v", rule, err)
	}
	return st
}

// hostReport is a report about hosts, with the flags a sensor could try to
// plant on them.
func hostReport(tool string, flags bool, hosts ...string) *ctis.Report {
	rep := &ctis.Report{Version: "1.0", Tool: &ctis.Tool{Name: tool},
		Metadata: ctis.ReportMetadata{ID: "rep-" + shared.NewID().String(), Timestamp: time.Now().UTC()}}
	for i, h := range hosts {
		a := ctis.Asset{ID: "h" + string(rune('a'+i)), Type: ctis.AssetTypeHost, Value: h}
		if flags {
			a.IsInternetAccessible = true
			a.Compliance = &ctis.AssetCompliance{Frameworks: []string{"pci-dss"}, DataClassification: "restricted", PIIExposed: true}
		}
		rep.Assets = append(rep.Assets, a)
	}
	return rep
}

func withFindings(rep *ctis.Report, rules ...string) *ctis.Report {
	for _, rule := range rules {
		rep.Findings = append(rep.Findings, ctis.Finding{Type: ctis.FindingTypeVulnerability, Title: "finding " + rule,
			Severity: ctis.SeverityHigh, RuleID: rule, AssetRef: rep.Assets[0].ID})
	}
	return rep
}

// A sensor without a command cannot alter an existing asset: no exposure,
// compliance, classification or PII flag, and no reactivation. Collector and
// reports are limited the same way. Before RFC-040 the worker's
// report re-applied every flag and reactivated the inactive host.
func TestResultBinding_UnsolicitedCannotAlterExistingAsset(t *testing.T) {
	r := newBindingRig(t, sensorresult.ModeWarn)
	r.trusted(hostReport("nmap", false, "db-1.corp.example", "old-1.corp.example"))
	if _, err := r.db.Exec(`UPDATE assets SET status = 'inactive' WHERE tenant_id = $1 AND name = 'old-1.corp.example'`, r.tenant.String()); err != nil {
		t.Fatal(err)
	}
	before := r.asset("db-1.corp.example")

	for _, sensorName := range []string{"worker", "collector"} {
		code, body := r.push(sensorName, hostReport("nmap", true, "db-1.corp.example", "old-1.corp.example", "new-"+sensorName+".corp.example"), "")
		if code != http.StatusCreated {
			t.Fatalf("%s: status %d %v", sensorName, code, body)
		}
		if body["binding"] != "unsolicited" || body["assets_limited"] != float64(2) {
			t.Fatalf("%s: response %v, want binding unsolicited and 2 limited assets", sensorName, body)
		}
		if got := r.asset("db-1.corp.example"); got.exposure != before.exposure || got.internet || got.pii ||
			got.classification != "" || len(got.compliance) != 0 {
			t.Fatalf("%s altered an existing asset without a command: %+v", sensorName, got)
		}
		if got := r.asset("old-1.corp.example"); got.status != "inactive" {
			t.Fatalf("%s reactivated an inactive asset without a command: %s", sensorName, got.status)
		}
		// New assets are still created, with the report's flags.
		if got := r.asset("new-" + sensorName + ".corp.example"); !got.internet || !got.pii {
			t.Fatalf("%s: a new asset did not keep the report's flags: %+v", sensorName, got)
		}
	}
	// The worker's report was applied only because the tenant is on warn:
	// the response and the audit say so.
	if _, body := r.push("worker", hostReport("nmap", false, "db-1.corp.example"), ""); body["unsolicited_warned"] != true {
		t.Fatalf("warn-mode response does not say so: %v", body)
	}
}

// A sensor cannot reopen a finding a person resolved without a command
// covering its asset. A finding the scanner auto-resolved still reopens, and
// a report bound to a covering command reopens both.
func TestResultBinding_UnsolicitedCannotReopenHumanResolved(t *testing.T) {
	r := newBindingRig(t, sensorresult.ModeWarn)
	r.trusted(withFindings(hostReport("nmap", false, "app-1.corp.example"), "human", "machine"))
	if _, err := r.db.Exec(`UPDATE findings SET status = 'resolved', resolution = 'fixed', resolution_method = 'security_reviewed'
		WHERE tenant_id = $1 AND rule_id = 'human'`, r.tenant.String()); err != nil {
		t.Fatal(err)
	}
	if _, err := r.db.Exec(`UPDATE findings SET status = 'resolved', resolution = 'auto_fixed', resolution_method = 'scan_verified'
		WHERE tenant_id = $1 AND rule_id = 'machine'`, r.tenant.String()); err != nil {
		t.Fatal(err)
	}

	code, body := r.push("worker", withFindings(hostReport("nmap", false, "app-1.corp.example"), "human", "machine"), "")
	if code != http.StatusCreated || body["reopens_withheld"] != float64(1) {
		t.Fatalf("status %d %v, want 201 with one reopen withheld", code, body)
	}
	if got := r.findingStatus("human"); got != "resolved" {
		t.Fatalf("a report without a command reopened a human-resolved finding: %s", got)
	}
	if got := r.findingStatus("machine"); got != "confirmed" {
		t.Fatalf("an auto-resolved finding seen again was not reopened: %s", got)
	}

	cmd := r.command("worker", "running", map[string]any{"scanner": "nmap", "targets": []string{"app-1.corp.example"}}, 0)
	code, body = r.push("worker", withFindings(hostReport("nmap", false, "app-1.corp.example"), "human"), cmd)
	if code != http.StatusCreated || body["binding"] != "command" {
		t.Fatalf("bound push: %d %v", code, body)
	}
	if got := r.findingStatus("human"); got != "confirmed" {
		t.Fatalf("a report bound to a covering command did not reopen the regression: %s", got)
	}
}

// Collector uploads keep working on a new tenant (quarantine mode), while the same report from a worker is quarantined with 422
// RESULTS_QUARANTINED, applies nothing, and can be accepted or discarded.
func TestResultBinding_CollectorUploadsWorkWorkerQuarantined(t *testing.T) {
	r := newBindingRig(t, "")
	if p := r.svc.ResultPolicy(context.Background(), r.tenant); p.Mode != sensorresult.ModeQuarantine || p.Stored {
		t.Fatalf("a new tenant's policy is %+v, want the quarantine default", p)
	}
	for _, name := range []string{"collector"} {
		code, body := r.push(name, withFindings(hostReport("nuclei", false, name+".corp.example"), name+"-rule"), "")
		if code != http.StatusCreated || body["findings_created"] != float64(1) {
			t.Fatalf("%s upload: %d %v", name, code, body)
		}
	}

	code, body := r.push("worker", withFindings(hostReport("nuclei", false, "w.corp.example"), "w-rule"), "")
	if code != http.StatusUnprocessableEntity || body["code"] != ingest.CodeResultsQuarantined {
		t.Fatalf("worker without a command: %d %v, want 422 RESULTS_QUARANTINED", code, body)
	}
	if n := r.count(`SELECT COUNT(*) FROM assets WHERE tenant_id = $1 AND name = 'w.corp.example'`, r.tenant.String()); n != 0 {
		t.Fatal("a quarantined report wrote an asset")
	}
	items, total, err := r.svc.ListQuarantined(context.Background(), r.tenant, sensorresult.ListFilter{Status: sensorresult.StatusPending})
	if err != nil || total != 1 || items[0].SensorID != r.ids["worker"] || items[0].FindingsCount != 1 || items[0].Route != "ctis" {
		t.Fatalf("quarantine: %v %d %+v", err, total, items)
	}
	if n := r.count(`SELECT COUNT(*) FROM sensor_result_quarantine WHERE tenant_id = $1 AND sensor_id <> $2`,
		r.tenant.String(), r.ids["worker"].String()); n != 0 {
		t.Fatalf("CI or collector uploads were quarantined: %d", n)
	}

	reviewer := r.seedUser()
	out, err := r.svc.AcceptQuarantined(context.Background(), auditapp.AuditContext{}, r.tenant, items[0].ID, reviewer)
	if err != nil || out.FindingsCreated != 1 {
		t.Fatalf("accept: %v %+v", err, out)
	}
	if n := r.count(`SELECT COUNT(*) FROM assets WHERE tenant_id = $1 AND name = 'w.corp.example'`, r.tenant.String()); n != 1 {
		t.Fatal("an accepted report was not applied")
	}
	if _, err := r.svc.AcceptQuarantined(context.Background(), auditapp.AuditContext{}, r.tenant, items[0].ID, reviewer); !errors.Is(err, sensorresult.ErrAlreadyReviewed) {
		t.Fatalf("second accept: %v, want ErrAlreadyReviewed", err)
	}

	// Discard: nothing applied, payload dropped.
	_, _ = r.push("worker", withFindings(hostReport("nuclei", false, "x.corp.example"), "x-rule"), "")
	items, _, _ = r.svc.ListQuarantined(context.Background(), r.tenant, sensorresult.ListFilter{Status: sensorresult.StatusPending})
	if len(items) != 1 {
		t.Fatalf("pending after second push: %d", len(items))
	}
	if err := r.svc.DiscardQuarantined(context.Background(), auditapp.AuditContext{}, r.tenant, items[0].ID, reviewer); err != nil {
		t.Fatal(err)
	}
	if n := r.count(`SELECT COUNT(*) FROM sensor_result_quarantine WHERE id = $1 AND status = 'discarded' AND payload IS NULL`, items[0].ID.String()); n != 1 {
		t.Fatal("discarded item kept its payload")
	}
	if n := r.count(`SELECT COUNT(*) FROM assets WHERE tenant_id = $1 AND name = 'x.corp.example'`, r.tenant.String()); n != 0 {
		t.Fatal("a discarded report was applied")
	}
}

// Results bound to a command assigned to the submitting sensor behave as
// before, also on a quarantine-mode tenant: they change the existing assets
// the command covers. An existing asset outside its targets is left alone,
// and a report from another tool than the command's is refused.
func TestResultBinding_BoundResultsStillApply(t *testing.T) {
	r := newBindingRig(t, "")
	r.trusted(hostReport("nmap", false, "db-1.corp.example", "elsewhere.corp.example"))
	cmd := r.command("worker", "running", map[string]any{"scanner": "nmap", "targets": []string{"db-1.corp.example"}}, 0)

	code, body := r.push("worker", hostReport("nmap", true, "db-1.corp.example", "elsewhere.corp.example"), cmd)
	if code != http.StatusCreated || body["binding"] != "command" || body["assets_limited"] != float64(1) {
		t.Fatalf("bound push: %d %v", code, body)
	}
	// Its scanner signals apply; the data classification it claims does not:
	// scanners are not trusted for it by default (RFC-069).
	if got := r.asset("db-1.corp.example"); !got.internet || !got.pii || got.classification != "" {
		t.Fatalf("a bound report did not update the asset its command covers: %+v", got)
	}
	if got := r.asset("elsewhere.corp.example"); got.internet || got.pii {
		t.Fatalf("a bound report altered an asset outside its command's targets: %+v", got)
	}
	if n := r.count(`SELECT COUNT(*) FROM sensor_result_quarantine WHERE tenant_id = $1`, r.tenant.String()); n != 0 {
		t.Fatal("a bound report was quarantined")
	}

	// A command finished a moment ago still binds (RFC-026 grace window).
	done := r.command("worker", "completed", map[string]any{"scanner": "nmap", "targets": []string{"db-1.corp.example"}}, time.Minute)
	if code, body := r.push("worker", hostReport("nmap", false, "db-1.corp.example"), done); code != http.StatusCreated {
		t.Fatalf("bound to a just-finished command: %d %v", code, body)
	}
	// Another tool than the command's is refused.
	if code, body := r.push("worker", hostReport("nuclei", false, "db-1.corp.example"), cmd); code != http.StatusUnprocessableEntity || body["code"] != ingest.CodeToolNotPermitted {
		t.Fatalf("other tool: %d %v, want 422 TOOL_NOT_PERMITTED", code, body)
	}
}

// A report that names another sensor's command, a command finished long
// ago, or one that does not exist is refused with 404 COMMAND_NOT_FOUND and
// writes nothing. Before RFC-040 v1 ignored the header and applied it.
func TestResultBinding_CrossSensorCommandRefused(t *testing.T) {
	r := newBindingRig(t, sensorresult.ModeWarn)
	others := r.command("other-worker", "running", map[string]any{"scanner": "nmap", "targets": []string{"victim.corp.example"}}, 0)
	stale := r.command("worker", "completed", map[string]any{"scanner": "nmap", "targets": []string{"victim.corp.example"}}, time.Hour)
	for name, id := range map[string]string{"another sensor's command": others, "finished an hour ago": stale, "unknown": shared.NewID().String(), "not an id": "x"} {
		code, body := r.push("worker", hostReport("nmap", true, "victim.corp.example"), id)
		if code != http.StatusNotFound || body["code"] != ingest.CodeCommandNotFound {
			t.Fatalf("%s: %d %v, want 404 COMMAND_NOT_FOUND", name, code, body)
		}
	}
	if n := r.count(`SELECT COUNT(*) FROM assets WHERE tenant_id = $1`, r.tenant.String()); n != 0 {
		t.Fatalf("a refused report wrote %d assets", n)
	}
}

func (r *bindingRig) seedUser() shared.ID {
	r.t.Helper()
	id := shared.NewID()
	if _, err := r.db.Exec(`INSERT INTO users (id, email, name, status) VALUES ($1, $2, 'reviewer', 'active')`,
		id.String(), "reviewer-"+id.String()+"@openctem-test.local"); err != nil {
		r.t.Fatalf("seed user: %v", err)
	}
	r.t.Cleanup(func() { _, _ = r.db.Exec(`DELETE FROM users WHERE id = $1`, id.String()) })
	return id
}
