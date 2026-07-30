package integration

import (
	"context"
	"database/sql"
	"encoding/json"
	"os"
	"testing"

	_ "github.com/lib/pq"

	scansvc "github.com/openctemio/api/internal/app/scan"
	"github.com/openctemio/api/internal/infra/postgres"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/logger"
)

// A single-scanner scan is the shape essentially every real scan takes, and
// nothing covered it end to end. On the live database it had a 0% success rate:
// seven runs over the feature's whole history, none completed. Two independent
// defects combined —
//
//  1. the run was created with total_steps=1 and no step_runs at all, so
//     OnStepCompleted/OnStepFailed looked the step up by key, found nothing, and
//     could never advance the run; and
//  2. the command payload carried `run_id`, while the command handler routes on
//     `pipeline_run_id` + `step_key` and silently returns for anything else. Not
//     one command in the production database carried the key the reader wanted.
//
// Either alone is enough to make a finished scan never reach its run. The
// scanner's real error ("scanner not found: nuclei") was dropped, and the run sat
// untouched until the reaper stamped it "scan exceeded configured timeout" — so
// users were told their scan timed out when in fact it had failed in seconds for
// a specific, fixable reason.
//
// These tests assert on what actually lands in the database, because the
// database is what the handler reads later.

const quickScanStepKey = "quick_scan"

// availableAgents is the minimum AgentSelector that lets a trigger proceed.
// TriggerScan calls CheckAgentAvailability without a nil guard, and refusing
// here would abort before the code under test runs.
type availableAgents struct{}

func (availableAgents) CheckAgentAvailability(context.Context, shared.ID, string, bool) *scansvc.AgentAvailability {
	return &scansvc.AgentAvailability{HasTenantAgent: true, Available: true}
}

func (availableAgents) CanUsePlatformAgents(context.Context, shared.ID) (bool, string) {
	return false, "test"
}

func (availableAgents) SelectAgent(context.Context, scansvc.SelectAgentRequest) (*scansvc.SelectAgentResult, error) {
	return nil, nil
}

func openLifecycleDB(t *testing.T) *sql.DB {
	t.Helper()

	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		t.Skip("DATABASE_URL not set; skipping single-scan lifecycle tests")
	}

	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		t.Skipf("open db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	if err := db.PingContext(context.Background()); err != nil {
		t.Skipf("cannot reach DATABASE_URL: %v", err)
	}
	return db
}

// newTriggerService wires the real repositories the trigger path touches. The
// collaborators left nil are all nil-guarded on this path; keeping them nil
// keeps the test about the lifecycle rather than about wiring.
func newTriggerService(db *sql.DB) *scansvc.Service {
	pg := &postgres.DB{DB: db}
	return scansvc.NewService(
		postgres.NewScanRepository(pg),
		postgres.NewPipelineTemplateRepository(pg),
		nil, // assetGroupRepo — unused without targetMappingRepo
		postgres.NewPipelineRunRepository(pg),
		postgres.NewPipelineStepRepository(pg),
		postgres.NewStepRunRepository(pg),
		postgres.NewCommandRepository(pg),
		nil, // scannerTemplateRepo
		nil, // templateSourceRepo
		postgres.NewToolRepository(pg),
		nil, // templateSyncer
		availableAgents{},
		nil, // securityValidator
		logger.New(logger.Config{Level: "error"}),
	)
}

func seedLifecycleTenant(ctx context.Context, t *testing.T, db *sql.DB) shared.ID {
	t.Helper()

	id := shared.NewID()
	if _, err := db.ExecContext(ctx,
		`INSERT INTO tenants (id, name, slug) VALUES ($1, $2, $3)`,
		id.String(), "single scan lifecycle", "test-"+id.String()); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	t.Cleanup(func() {
		_, _ = db.ExecContext(context.Background(), `DELETE FROM tenants WHERE id = $1`, id.String())
	})
	return id
}

// seedLifecycleScan inserts an active single-scanner scan naming a real seeded
// tool, so validateToolsAtTriggerTime passes. Returns the scan id.
//
// The tool is looked up rather than invented: the migrations seed the builtin
// catalog, and a hand-inserted row would have to reproduce every column
// scanTool reads. Picking the lowest active name keeps it deterministic.
func seedLifecycleScan(ctx context.Context, t *testing.T, db *sql.DB, tenantID shared.ID) shared.ID {
	t.Helper()

	var toolName string
	if err := db.QueryRowContext(ctx,
		`SELECT name FROM tools WHERE is_active ORDER BY name LIMIT 1`).Scan(&toolName); err != nil {
		t.Skipf("no active tool seeded in this database, cannot trigger a scan: %v", err)
	}

	scanID := shared.NewID()
	if _, err := db.ExecContext(ctx,
		`INSERT INTO scans (id, tenant_id, name, scan_type, scanner_name, targets,
		                    status, schedule_type, agent_preference, timeout_seconds)
		 VALUES ($1, $2, $3, 'single', $4, ARRAY['example.test'],
		         'active', 'manual', 'tenant', 3600)`,
		scanID.String(), tenantID.String(), "probe scan "+scanID.String(), toolName); err != nil {
		t.Fatalf("seed scan: %v", err)
	}
	return scanID
}

// routingProbe mirrors what both sides of the contract care about, including the
// legacy key, so one decode asserts the new keys arrived AND the old one stayed.
type routingProbe struct {
	PipelineRunID string `json:"pipeline_run_id"`
	StepKey       string `json:"step_key"`
	StepRunID     string `json:"step_run_id"`
	RunID         string `json:"run_id"`
}

// The whole fix in one test: triggering a single scan must leave behind a run
// with a step to report against, and a command a handler can route back to it.
func TestTriggerSingleScan_ProducesAReportableRun(t *testing.T) {
	db := openLifecycleDB(t)
	ctx := context.Background()
	svc := newTriggerService(db)

	tenantID := seedLifecycleTenant(ctx, t, db)
	scanID := seedLifecycleScan(ctx, t, db, tenantID)

	run, err := svc.TriggerScan(ctx, scansvc.TriggerScanExecInput{
		TenantID: tenantID.String(),
		ScanID:   scanID.String(),
	})
	if err != nil {
		t.Fatalf("TriggerScan: %v", err)
	}

	// 1. A step row must exist. Without one the run can only ever be reaped.
	var stepCount int
	var stepKey, stepStatus sql.NullString
	var stepCommandID sql.NullString
	if err := db.QueryRowContext(ctx,
		`SELECT count(*), min(step_key), min(status), min(command_id::text)
		 FROM step_runs WHERE pipeline_run_id = $1`,
		run.ID.String()).Scan(&stepCount, &stepKey, &stepStatus, &stepCommandID); err != nil {
		t.Fatalf("query step runs: %v", err)
	}

	if stepCount != 1 {
		t.Fatalf("a single scan needs exactly one step run to report against, got %d — "+
			"with none, OnStepCompleted has no step to complete and the run hangs until reaped", stepCount)
	}
	if stepKey.String != quickScanStepKey {
		t.Errorf("step_key = %q, want %q (the seeded quick-scan step)", stepKey.String, quickScanStepKey)
	}

	// total_steps must agree with the number of step rows, or the
	// `completed+failed+skipped >= TotalSteps` test in OnStepCompleted never trips.
	if run.TotalSteps != stepCount {
		t.Errorf("run.TotalSteps = %d but %d step rows exist; completion compares exactly these two",
			run.TotalSteps, stepCount)
	}

	// 2. The step must be linked to its command and queued, or the UI shows a
	// step stuck 'pending' after the work was already dispatched.
	if !stepCommandID.Valid || stepCommandID.String == "" {
		t.Error("step run has no command_id; nothing ties the step to the work it waits on")
	}
	if stepStatus.String != "queued" {
		t.Errorf("step run status = %q, want queued once the command exists", stepStatus.String)
	}

	// 3. The payload must be routable. This is the assertion that would have
	// caught the original defect outright.
	var raw []byte
	if err := db.QueryRowContext(ctx,
		`SELECT payload FROM commands WHERE tenant_id = $1 ORDER BY created_at DESC LIMIT 1`,
		tenantID.String()).Scan(&raw); err != nil {
		t.Fatalf("read command payload: %v", err)
	}

	var routed routingProbe
	if err := json.Unmarshal(raw, &routed); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}

	if routed.PipelineRunID != run.ID.String() {
		t.Errorf("payload pipeline_run_id = %q, want the run id %q — without it the handler "+
			"treats the command as 'not a pipeline command' and throws the result away",
			routed.PipelineRunID, run.ID.String())
	}
	if routed.StepKey != quickScanStepKey {
		t.Errorf("payload step_key = %q, want %q", routed.StepKey, quickScanStepKey)
	}
	if routed.StepRunID == "" {
		t.Error("payload step_run_id is empty")
	}
	// The legacy key must survive: the agent SDK reads it.
	if routed.RunID != run.ID.String() {
		t.Errorf("payload run_id = %q, want %q — the agent SDK still reads this key",
			routed.RunID, run.ID.String())
	}
	// And the command the step points at must be the one we just read.
	var payloadCommandID string
	if err := db.QueryRowContext(ctx,
		`SELECT id::text FROM commands WHERE tenant_id = $1 ORDER BY created_at DESC LIMIT 1`,
		tenantID.String()).Scan(&payloadCommandID); err != nil {
		t.Fatalf("read command id: %v", err)
	}
	if stepCommandID.String != payloadCommandID {
		t.Errorf("step run points at command %s but the scan created %s",
			stepCommandID.String, payloadCommandID)
	}
}
