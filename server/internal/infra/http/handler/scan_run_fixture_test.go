package handler

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/scanrun"
	"github.com/openctemio/openctem/api/pkg/domain/scanworkflow"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// webRunFixture is the run the web renders its run sheet from. It is written
// by this test from the handler's own response, so the web reads what the
// API really sends: a field the API renames (the run's step runs are
// `scan_run_steps`) changes this file and breaks the web test that reads it.
var webRunFixture = filepath.Join("..", "..", "..", "..", "..", "web", "src", "features", "scans",
	"components", "__tests__", "fixtures", "scan-run.api.json")

func fixtureID(t *testing.T, s string) shared.ID {
	t.Helper()
	id, err := shared.IDFromString(s)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// TestRunResponse_WebFixture keeps the web fixture equal to GET
// /scan-runs/{id}'s body for a run with step runs. UPDATE_GOLDEN=1 rewrites it.
func TestRunResponse_WebFixture(t *testing.T) {
	started := time.Date(2026, 10, 8, 9, 0, 0, 0, time.UTC)
	done := started.Add(90 * time.Second)
	runID := fixtureID(t, "11111111-1111-4111-8111-111111111111")
	run := &scanrun.Run{
		ID:             runID,
		TenantID:       fixtureID(t, "22222222-2222-4222-8222-222222222222"),
		ScanWorkflowID: fixtureID(t, "33333333-3333-4333-8333-333333333333"),
		Kind:           scanrun.RunKindScan,
		TriggerType:    scanworkflow.TriggerTypeManual,
		Status:         scanrun.RunStatusRunning,
		StartedAt:      &started,
		TotalSteps:     2,
		CompletedSteps: 1,
		TotalFindings:  3,
		CreatedAt:      started,
		StepRuns: []*scanrun.StepRun{
			{
				ID: fixtureID(t, "44444444-4444-4444-8444-444444444444"), ScanRunID: runID,
				StepID:  fixtureID(t, "55555555-5555-4555-8555-555555555555"),
				StepKey: "ports", StepName: "Port scan", Tool: "naabu", Capability: "scan.ports@1",
				Status: scanrun.StepRunStatusCompleted, StartedAt: &started, CompletedAt: &done,
				Attempt: 1, MaxAttempts: 3, FindingsCount: 3,
			},
			{
				ID: fixtureID(t, "66666666-6666-4666-8666-666666666666"), ScanRunID: runID,
				StepID:  fixtureID(t, "77777777-7777-4777-8777-777777777777"),
				StepKey: "vulns", StepName: "Vulnerability scan", Tool: "nuclei",
				Status: scanrun.StepRunStatusRunning, StartedAt: &done, Attempt: 1, MaxAttempts: 3,
			},
		},
	}

	got, err := json.MarshalIndent(toRunResponse(run), "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	got = append(got, '\n')
	if os.Getenv("UPDATE_GOLDEN") == "1" {
		if err := os.WriteFile(webRunFixture, got, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(webRunFixture)
	if err != nil {
		t.Fatalf("read the web fixture (UPDATE_GOLDEN=1 writes it): %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("the run response changed; rerun with UPDATE_GOLDEN=1 and fix the web readers of %s.\ngot:\n%s", webRunFixture, got)
	}
}
