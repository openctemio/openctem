package tenablesc

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/openctemio/openctem/api/internal/app/scancoverage"
	"github.com/openctemio/openctem/api/pkg/domain/command"
	"github.com/openctemio/openctem/api/pkg/domain/ingestreport"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	protov2 "github.com/openctemio/openctem/api/pkg/sensorproto/v2"
)

func coverageEnv(t *testing.T, extra map[string]any) *env {
	t.Helper()
	e := newEnv(t)
	cfg := map[string]any{"coverage_enabled": true, "coverage_policy_id": float64(1000003), "coverage_repository_id": float64(5),
		"safety_margin": float64(2)}
	for k, v := range extra {
		cfg[k] = v
	}
	e.intg.SetConfig(connectorIntegration(e.tenant, e.sensorID, cfg).Config())
	st := readState(e.intg)
	st.LicensedIPs, st.ActiveIPs = 100, 40
	writeState(e.intg, st)
	return e
}

func TestCoverageStatus(t *testing.T) {
	ctx := context.Background()

	e := coverageEnv(t, nil)
	st, err := e.svc.CoverageStatus(ctx, e.intg)
	if err != nil || !st.Ready || st.ActiveIPs != 40 || st.Policy.Mode != scancoverage.LicenseActiveIPCap ||
		st.Policy.Cap != 100 || st.Policy.SafetyMargin != 2 {
		t.Fatalf("%+v %v", st, err)
	}
	if h := st.Policy.Headroom(st.ActiveIPs, st.DefaultBatch); h != 58 {
		t.Fatalf("headroom %d, want 100-40-2", h)
	}

	e = coverageEnv(t, map[string]any{"license_cap": float64(50)})
	if st, _ := e.svc.CoverageStatus(ctx, e.intg); st.Policy.Cap != 50 {
		t.Fatalf("a lower configured cap wins: %+v", st)
	}

	for name, mut := range map[string]func(e *env){
		"coverage off": func(e *env) { e.intg.SetConfig(connectorIntegration(e.tenant, e.sensorID, nil).Config()) },
		"no coverage policy": func(e *env) {
			e.intg.SetConfig(connectorIntegration(e.tenant, e.sensorID, map[string]any{"coverage_enabled": true}).Config())
		},
		"no license numbers yet": func(e *env) {
			st := readState(e.intg)
			st.LicensedIPs = 0
			writeState(e.intg, st)
		},
		"disabled": func(e *env) { e.intg.SetStatus("disabled") },
	} {
		e := coverageEnv(t, nil)
		mut(e)
		if st, err := e.svc.CoverageStatus(ctx, e.intg); err != nil || st.Ready || st.Reason == "" {
			t.Errorf("%s: %+v %v", name, st, err)
		}
	}
}

func TestCoverageBatchLifecycle(t *testing.T) {
	ctx := context.Background()
	e := coverageEnv(t, nil)

	id, err := e.svc.DispatchCoverageBatch(ctx, e.tenant, e.intg.ID(), []string{"10.0.0.1", "10.0.0.2"}, "sess-1")
	if err != nil {
		t.Fatal(err)
	}
	cmd := e.cmds.rows[id]
	if cmd.Type != command.CommandTypeConnectorScan || *cmd.SensorID != e.sensorID {
		t.Fatalf("command %+v", cmd)
	}
	var p ScanPayload
	_ = json.Unmarshal(cmd.Payload, &p)
	if p.PolicyID != 1000003 || p.RepositoryID != 5 || p.RunID != "sess-1" || len(p.Targets) != 2 {
		t.Fatalf("payload %+v", p)
	}
	if State(e.intg).CoverageCommandID != id.String() {
		t.Fatal("open batch not recorded")
	}

	// While it is open: no second batch, and not ready.
	if _, err := e.svc.DispatchCoverageBatch(ctx, e.tenant, e.intg.ID(), []string{"10.0.0.3"}, "sess-2"); !errors.Is(err, ErrCoverageBusy) {
		t.Fatalf("second batch: %v", err)
	}
	if st, _ := e.svc.CoverageStatus(ctx, e.intg); st.Ready {
		t.Fatal("ready while the previous batch is open")
	}

	// Completed but its report is still being ingested: still not ready.
	cmd.Status = command.CommandStatusCompleted
	cmd.Result, _ = json.Marshal(map[string]any{"metadata": map[string]any{"licensed_ips": 100, "active_ips": 42}})
	e.reports.reports[id] = []ingestreport.CoverageReport{{State: protov2.StateProcessing, ToolName: ToolName}}
	if st, _ := e.svc.CoverageStatus(ctx, e.intg); st.Ready {
		t.Fatal("ready before the batch's report was ingested")
	}

	// Ingested: ready, sized with Tenable.sc's new active count.
	e.reports.reports[id][0].State = protov2.StateCompleted
	st, err := e.svc.CoverageStatus(ctx, e.intg)
	if err != nil || !st.Ready || st.ActiveIPs != 42 {
		t.Fatalf("%+v %v", st, err)
	}
	if s := State(e.intg); s.CoverageCommandID != "" || s.LastCoverageOutcome != "completed" {
		t.Fatalf("state %+v", s)
	}

	// Another tenant cannot dispatch on it.
	if _, err := e.svc.DispatchCoverageBatch(ctx, shared.NewID(), e.intg.ID(), []string{"10.0.0.1"}, "x"); err == nil {
		t.Fatal("cross-tenant dispatch")
	}
}

func TestValidateConnector_CoverageNeedsPolicy(t *testing.T) {
	e := newEnv(t)
	cfg := connectorIntegration(e.tenant, e.sensorID, map[string]any{"coverage_enabled": true}).Config()
	if err := e.svc.ValidateConnector(context.Background(), e.tenant, cfg); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("coverage without a policy: %v", err)
	}
	cfg["coverage_policy_id"], cfg["coverage_repository_id"] = float64(1), float64(2)
	if err := e.svc.ValidateConnector(context.Background(), e.tenant, cfg); err != nil {
		t.Fatalf("complete coverage config: %v", err)
	}
}
