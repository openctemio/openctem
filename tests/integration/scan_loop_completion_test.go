package integration

import (
	"context"
	"database/sql"
	"encoding/json"
	"strings"
	"testing"

	_ "github.com/lib/pq"

	pipelinesvc "github.com/openctemio/api/internal/app/pipeline"
	scansvc "github.com/openctemio/api/internal/app/scan"
	"github.com/openctemio/api/internal/infra/postgres"
	pipelinedom "github.com/openctemio/api/pkg/domain/pipeline"
	"github.com/openctemio/api/pkg/logger"
)

// The second half of the scan loop had no test at all.
//
// TestTriggerSingleScan_ProducesAReportableRun covers the outbound half: a
// trigger produces a run, a step run, and a command carrying the routing keys.
// Nothing covered what happens when that command comes back — which is precisely
// where the defect lived. The dispatcher wrote `run_id`, the reader wanted
// `pipeline_run_id`, and so every finished command was discarded in silence: the
// run was never advanced, never completed, never failed, and no error was raised
// anywhere. Seven runs over the product's history, none completed.
//
// A test of the outbound half alone would still have passed throughout. These
// tests close the loop: they take the command exactly as the command handler
// does — decoding the stored payload through the shared contract type — and drive
// the same service call the handler makes, then assert the run actually reaches a
// terminal state.
//
// Deliberately driven through pipelinesvc rather than an HTTP request: the
// handler's own job (decode, check routable, dispatch) is pinned by
// TestStepCommandPayloadKeysMatchHandlerContract in pkg/domain/pipeline. Between
// the two, every link from dispatch to terminal state is covered without standing
// up a server.

// newPipelineService builds the pipeline service with the real repositories.
// agentRepo and securityValidator are unused on the completion path.
func newPipelineService(db *sql.DB) *pipelinesvc.Service {
	pg := &postgres.DB{DB: db}
	return pipelinesvc.NewService(
		postgres.NewPipelineTemplateRepository(pg),
		postgres.NewPipelineStepRepository(pg),
		postgres.NewPipelineRunRepository(pg),
		postgres.NewStepRunRepository(pg),
		nil, // agentRepo
		postgres.NewCommandRepository(pg),
		nil, // securityValidator
		logger.New(logger.Config{Level: "error"}),
	)
}

// routingFromCommand reads the stored command payload the way the command
// handler does — through the shared contract type — and fails the test if it is
// not routable. Decoding here rather than reading columns is the point: if the
// dispatcher stops emitting the keys, this is where it shows.
func routingFromCommand(ctx context.Context, t *testing.T, db *sql.DB, tenantID string) pipelinedom.StepCommandPayload {
	t.Helper()

	var raw []byte
	if err := db.QueryRowContext(ctx,
		`SELECT payload FROM commands WHERE tenant_id = $1 ORDER BY created_at DESC LIMIT 1`,
		tenantID).Scan(&raw); err != nil {
		t.Fatalf("read command payload: %v", err)
	}

	var p pipelinedom.StepCommandPayload
	if err := json.Unmarshal(raw, &p); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	if !p.IsRoutable() {
		t.Fatalf("the dispatched command is not routable (pipeline_run_id=%q step_key=%q) — "+
			"the command handler would treat it as 'not a pipeline command' and discard the result",
			p.PipelineRunID, p.StepKey)
	}
	return p
}

func runState(ctx context.Context, t *testing.T, db *sql.DB, runID string) (status string, errMsg sql.NullString, completedSteps int) {
	t.Helper()
	if err := db.QueryRowContext(ctx,
		`SELECT status, error_message, completed_steps FROM pipeline_runs WHERE id = $1`, runID).
		Scan(&status, &errMsg, &completedSteps); err != nil {
		t.Fatalf("read run state: %v", err)
	}
	return status, errMsg, completedSteps
}

// The success path, which has never once happened on the production database.
func TestScanLoop_CompletedCommandCompletesTheRun(t *testing.T) {
	db := openLifecycleDB(t)
	ctx := context.Background()
	svc := newTriggerService(db)
	pipeSvc := newPipelineService(db)

	tenantID := seedLifecycleTenant(ctx, t, db)
	scanID := seedLifecycleScan(ctx, t, db, tenantID)

	run, err := svc.TriggerScan(ctx, scansvc.TriggerScanExecInput{
		TenantID: tenantID.String(),
		ScanID:   scanID.String(),
	})
	if err != nil {
		t.Fatalf("TriggerScan: %v", err)
	}

	// Before the agent reports, the run must NOT be terminal — otherwise the
	// assertion afterwards proves nothing.
	if status, _, _ := runState(ctx, t, db, run.ID.String()); status == "completed" {
		t.Fatal("precondition failed: the run was already completed before anything reported back")
	}

	p := routingFromCommand(ctx, t, db, tenantID.String())

	// Exactly what CommandHandler.Complete does with a finished command.
	if err := pipeSvc.OnStepCompleted(ctx, p.PipelineRunID, p.StepKey, 3,
		map[string]any{"probe": true}); err != nil {
		t.Fatalf("OnStepCompleted: %v", err)
	}

	status, _, completedSteps := runState(ctx, t, db, run.ID.String())
	if status != "completed" {
		t.Errorf("run status = %q, want completed — a scan that finished must reach a terminal "+
			"state, not sit until a reaper stamps it as a timeout", status)
	}
	if completedSteps != 1 {
		t.Errorf("completed_steps = %d, want 1; completion is decided by comparing this to total_steps",
			completedSteps)
	}
}

// The failure path, and the reason the whole loop mattered: users were told their
// scan timed out when the scanner had in fact failed in seconds with a specific,
// fixable error. This asserts the real error reaches the run.
func TestScanLoop_FailedCommandSurfacesTheRealError(t *testing.T) {
	db := openLifecycleDB(t)
	ctx := context.Background()
	svc := newTriggerService(db)
	pipeSvc := newPipelineService(db)

	tenantID := seedLifecycleTenant(ctx, t, db)
	scanID := seedLifecycleScan(ctx, t, db, tenantID)

	run, err := svc.TriggerScan(ctx, scansvc.TriggerScanExecInput{
		TenantID: tenantID.String(),
		ScanID:   scanID.String(),
	})
	if err != nil {
		t.Fatalf("TriggerScan: %v", err)
	}

	p := routingFromCommand(ctx, t, db, tenantID.String())

	// The exact error five production runs actually hit.
	const realErr = "scanner not found: nuclei"
	if err := pipeSvc.OnStepFailed(ctx, p.PipelineRunID, p.StepKey, realErr, "COMMAND_FAILED"); err != nil {
		t.Fatalf("OnStepFailed: %v", err)
	}

	status, errMsg, _ := runState(ctx, t, db, run.ID.String())
	if status != "failed" {
		t.Errorf("run status = %q, want failed", status)
	}
	if !strings.Contains(errMsg.String, realErr) {
		t.Errorf("run error_message = %q, want it to contain %q — losing the scanner's own error is "+
			"what made users see 'scan exceeded configured timeout' for a scanner that was simply "+
			"not installed", errMsg.String, realErr)
	}
	if strings.Contains(errMsg.String, "exceeded configured timeout") {
		t.Error("the run must not claim it timed out when the command reported a specific failure")
	}
}

// A command that carries no routing keys must be recognized as unroutable rather
// than half-processed. This is the shape every production command had before the
// fix, so it is worth keeping as an explicit case.
func TestScanLoop_LegacyPayloadIsNotRoutable(t *testing.T) {
	var p pipelinedom.StepCommandPayload
	if err := json.Unmarshal([]byte(`{"run_id":"r-1","scan_id":"s-1","scanner":"nuclei"}`), &p); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if p.IsRoutable() {
		t.Error("a payload carrying only run_id must not be routable; treating it as routable would " +
			"dispatch an empty run id into the pipeline service")
	}
}
