package integration

// Marking things out of scope, end to end (docs/rfcs/RFC-054-scope-model.md
// §6.5, api/docs/guides/out-of-scope.md): exclusions of a name, of an
// address inside a range, and of a path, then real scans on a migrated
// database. The stored command payloads never carry an excluded target;
// the range job carries its exclusions and the web job its deny paths; the
// run records which targets were left out and by which rule; and ingest
// drops a result outside the job's assignment.

import (
	"context"
	"database/sql"
	"encoding/json"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/ctis"

	"github.com/openctemio/openctem/api/internal/app/ingest"
	scansvc "github.com/openctemio/openctem/api/internal/app/scan"
	"github.com/openctemio/openctem/api/internal/app/scanrun"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	commanddom "github.com/openctemio/openctem/api/pkg/domain/command"
	"github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// exclusionScanService is scanServiceOver with the real exclusion filter
// (the scope service), as production wires it.
func exclusionScanService(db *sql.DB, cmds commanddom.Repository) *scansvc.Service {
	pg := &postgres.DB{DB: db}
	svc := scansvc.NewService(
		postgres.NewScanRepository(pg), postgres.NewScanWorkflowRepository(pg), nil,
		postgres.NewScanRunRepository(pg), postgres.NewScanWorkflowStepRepository(pg),
		postgres.NewStepRunRepository(pg), cmds, nil, nil,
		postgres.NewToolRepository(pg), nil, tenantSensors{}, nil,
		logger.New(logger.Config{Level: "error"}),
		allowAllTargetChecks(scansvc.WithScopeExclusionFilter(scopeService(db)))...,
	)
	svc.SetStepQueuer(scanrun.NewService(
		postgres.NewScanWorkflowRepository(pg), postgres.NewScanWorkflowStepRepository(pg),
		postgres.NewScanRunRepository(pg), postgres.NewStepRunRepository(pg),
		postgres.NewSensorRepository(pg), cmds, nil, logger.New(logger.Config{Level: "error"}),
		scanrun.WithTargetGate(svc), scanrun.WithToolFacts(integrationTools),
	))
	return svc
}

func payloadTargets(p map[string]any) []string {
	var out []string
	list, _ := p["targets"].([]any)
	for _, v := range list {
		s, _ := v.(string)
		out = append(out, s)
	}
	return out
}

func runExcluded(t *testing.T, db *sql.DB, runID string) []scansvc.ExcludedTarget {
	t.Helper()
	var raw []byte
	if err := db.QueryRowContext(context.Background(), `SELECT context FROM scan_runs WHERE id = $1`, runID).Scan(&raw); err != nil {
		t.Fatalf("read run: %v", err)
	}
	var rc struct {
		Excluded []scansvc.ExcludedTarget `json:"excluded_targets"`
		Count    int                      `json:"excluded_target_count"`
	}
	if err := json.Unmarshal(raw, &rc); err != nil {
		t.Fatal(err)
	}
	return rc.Excluded
}

func TestExclusions_EndToEnd(t *testing.T) {
	db := openLifecycleDB(t)
	ctx := context.Background()
	tenant := seedLifecycleTenant(ctx, t, db)
	other := seedLifecycleTenant(ctx, t, db)

	const (
		excludedName = "legacy.e2e-excl.example"
		excludedAddr = "198.51.100.5"
		rangeTarget  = "198.51.100.0/29"
		webHostE2E   = "app.e2e-excl.example"
	)
	seedApprovedExclusion(t, db, tenant, "domain", excludedName)
	seedApprovedExclusion(t, db, tenant, "ip_address", excludedAddr)
	seedPathExclusion(t, db, tenant, webHostE2E, "/admin")
	// Another tenant's exclusion never applies here, nor is it named.
	seedApprovedExclusion(t, db, other, "ip_address", "198.51.100.3")

	svc := exclusionScanService(db, guardedCommands(db, scopeService(db)))

	// A port scan of a range with an excluded address and an excluded name.
	portRun, err := svc.QuickScan(ctx, scansvc.QuickScanInput{TenantID: tenant.String(), ScannerName: "naabu",
		Targets: []string{rangeTarget, excludedName}})
	if err != nil {
		t.Fatalf("port scan: %v", err)
	}
	// A web scan of a host with an excluded path.
	if _, err := svc.QuickScan(ctx, scansvc.QuickScanInput{TenantID: tenant.String(), ScannerName: "nuclei",
		Targets: []string{"https://" + webHostE2E}}); err != nil {
		t.Fatalf("web scan: %v", err)
	}

	payloads := commandPayloads(t, db, tenant, "scan")
	if len(payloads) != 2 {
		t.Fatalf("%d scan commands, want 2", len(payloads))
	}
	var portJob, webJob map[string]any
	for _, p := range payloads {
		raw, _ := json.Marshal(p)
		if strings.Contains(string(raw), excludedName) {
			t.Fatalf("a payload carries the excluded name: %s", raw)
		}
		for _, tg := range payloadTargets(p) {
			if tg == excludedAddr || tg == rangeTarget {
				t.Fatalf("a payload targets the excluded address or the whole range: %v", payloadTargets(p))
			}
		}
		if slices.Contains(payloadTargets(p), "https://"+webHostE2E) {
			webJob = p
		} else {
			portJob = p
		}
	}
	if portJob == nil || webJob == nil {
		t.Fatalf("jobs: %v", payloads)
	}
	// The range job carries the exclusion so the sensor cuts around it
	// again; the other tenant's exclusion is not there.
	excl, _ := portJob[scansvc.PayloadKeyExclusions].([]any)
	if len(excl) != 1 || excl[0] != excludedAddr+"/32" {
		t.Fatalf("range job exclusions = %v", portJob[scansvc.PayloadKeyExclusions])
	}
	if got := webDenyPaths(webJob); !slices.Equal(got, []string{"/admin"}) {
		t.Fatalf("web job deny paths = %v", got)
	}

	// The run records what was left out and by which rule.
	left := runExcluded(t, db, portRun.ScanRunID)
	byTarget := map[string]scansvc.ExcludedTarget{}
	for _, e := range left {
		byTarget[e.Target] = e
	}
	if e := byTarget[excludedName]; len(e.Rules) != 1 || e.Rules[0].Pattern != excludedName {
		t.Fatalf("excluded name: %+v (all %+v)", e, left)
	}
	if e := byTarget[rangeTarget]; !e.Cut || e.RemovedAddresses != 1 || len(e.Rules) != 1 || e.Rules[0].Pattern != excludedAddr {
		t.Fatalf("cut range: %+v (all %+v)", e, left)
	}

	// Ingest drops a result outside the job's assignment (the excluded
	// address, which the pieces leave out) and keeps one inside.
	pieces := payloadTargets(portJob)
	pg := &postgres.DB{DB: db}
	ing := ingest.NewService(
		postgres.NewAssetRepository(pg), postgres.NewFindingRepository(pg),
		postgres.NewVulnerabilityRepository(pg), postgres.NewComponentRepository(pg),
		postgres.NewSensorRepository(pg), postgres.NewBranchRepository(pg), postgres.NewTenantRepository(pg),
		postgres.NewAuditRepository(pg), logger.NewNop())
	ing.SetToolFacts(integrationTools)
	tid := tenant
	sensorID := shared.NewID()
	agt := &sensor.Sensor{ID: sensorID, TenantID: &tid, Type: sensor.SensorTypeWorker, Status: sensor.SensorStatusActive}
	cmdID := shared.NewID()
	rep := &ctis.Report{Version: "1.0", Tool: &ctis.Tool{Name: "naabu"},
		Metadata: ctis.ReportMetadata{ID: "rep-" + cmdID.String(), Timestamp: time.Now().UTC()},
		Assets: []ctis.Asset{
			{ID: "in", Type: ctis.AssetTypeIPAddress, Value: "198.51.100.2"},
			{ID: "out", Type: ctis.AssetTypeIPAddress, Value: excludedAddr},
		}}
	bind := ingest.Binding{Kind: ingest.BindingCommand, CommandID: &cmdID, CommandType: commanddom.CommandTypeScan, Tool: "naabu", Targets: pieces}
	out, err := ing.Ingest(ctx, agt, ingest.Input{Report: rep, Options: ingest.Options{Binding: bind, Route: "ctis"}})
	if err != nil {
		t.Fatalf("ingest: %v", err)
	}
	if out.AssetsOutsideChunk != 1 {
		t.Fatalf("assets outside the assignment = %d, want 1", out.AssetsOutsideChunk)
	}
	if n := countRows(t, db, `SELECT count(*) FROM assets WHERE tenant_id = $1 AND name = '`+excludedAddr+`'`, tenant); n != 0 {
		t.Fatal("ingest wrote the excluded address")
	}
	if n := countRows(t, db, `SELECT count(*) FROM assets WHERE tenant_id = $1 AND name = '198.51.100.2'`, tenant); n != 1 {
		t.Fatal("ingest dropped an address inside the assignment")
	}
}
