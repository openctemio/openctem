package unit

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/domain/tool"
)

// RFC-030 B4: outside zones, a scanner that reads one target per job
// (betterleaks, trivy, semgrep) used to get every target in one command and
// scan only the first. Each target now gets its own command, created as
// batches of the run's one step so the step completes with the last one.

func TestPerTargetDispatch_SingleTargetScannerFansOutWithoutZones(t *testing.T) {
	tenant := shared.NewID()
	svc, deps := newZonedScanService(&fakeZoneDir{}, nil, nil) // tenant has no zones
	repos := make([]string, 20)
	for i := range repos {
		repos[i] = fmt.Sprintf("https://github.com/example/repo-%02d", i)
	}
	sc := singleScan(t, deps, tenant, "betterleaks", 1, nil, repos...)
	run, err := trigger(t, svc, sc)
	if err != nil {
		t.Fatalf("trigger: %v", err)
	}
	if got := len(deps.commandRepo.commands); got != len(repos) {
		t.Fatalf("commands = %d, want one per repository (%d)", got, len(repos))
	}
	byTarget := commandsByTarget(t, deps) // also fails on a target dispatched twice
	for _, r := range repos {
		c := byTarget[r]
		if c == nil {
			t.Errorf("%s was not dispatched", r)
			continue
		}
		var p struct {
			Target  string   `json:"target"`
			Targets []string `json:"targets"`
			Scanner string   `json:"scanner"`
		}
		if err := json.Unmarshal(c.Payload, &p); err != nil {
			t.Fatal(err)
		}
		if p.Target != r || len(p.Targets) != 1 || p.Scanner != "betterleaks" {
			t.Errorf("%s: payload target=%q targets=%v scanner=%q; want the one repository", r, p.Target, p.Targets, p.Scanner)
		}
		if c.ScanZoneID != nil || c.SensorID != nil {
			t.Errorf("%s: unzoned job was zoned (%v) or pinned (%v)", r, c.ScanZoneID, c.SensorID)
		}
	}
	if hasWarning(warningsOf(run), "takes one target per job") {
		t.Errorf("single-target caveat kept although every target got its own job: %v", warningsOf(run))
	}
	pt, ok := run.Context["per_target_dispatch"].(map[string]any)
	if !ok || pt["jobs"] != len(repos) {
		t.Errorf("per_target_dispatch = %v, want jobs=%d", run.Context["per_target_dispatch"], len(repos))
	}
}

func TestPerTargetDispatch_ListScannerStaysOneCommand(t *testing.T) {
	tenant := shared.NewID()
	svc, deps := newZonedScanService(&fakeZoneDir{}, nil, nil)
	sc := singleScan(t, deps, tenant, "nuclei", 1, nil, "8.8.8.8", "app.example.com", "1.1.1.1")
	run, err := trigger(t, svc, sc)
	if err != nil {
		t.Fatal(err)
	}
	if len(deps.commandRepo.commands) != 1 {
		t.Fatalf("commands = %d, want nuclei's single list command", len(deps.commandRepo.commands))
	}
	if run.Context["per_target_dispatch"] != nil {
		t.Error("a list scanner was fanned out")
	}
}

func TestPerTargetDispatch_OneTargetIsOneCommand(t *testing.T) {
	tenant := shared.NewID()
	svc, deps := newZonedScanService(&fakeZoneDir{}, nil, nil)
	sc := singleScan(t, deps, tenant, "betterleaks", 1, nil, "https://github.com/example/only")
	run, err := trigger(t, svc, sc)
	if err != nil {
		t.Fatal(err)
	}
	if len(deps.commandRepo.commands) != 1 || run.Context["per_target_dispatch"] != nil {
		t.Fatalf("commands = %d, per_target_dispatch = %v; want one plain command",
			len(deps.commandRepo.commands), run.Context["per_target_dispatch"])
	}
	for _, c := range deps.commandRepo.commands {
		if c.StepRunID != nil {
			t.Error("a one-command run was created as a batch")
		}
	}
}

func TestPerTargetDispatch_RefusesMoreJobsThanThePerRunCap(t *testing.T) {
	tenant := shared.NewID()
	svc, deps := newZonedScanService(&fakeZoneDir{}, nil, nil)
	deps.toolRepo.tools["trivy"] = &tool.Tool{ID: shared.NewID(), Name: "trivy", IsActive: true, SupportedTargets: []string{"repository", "container"}}
	targets := make([]string, 1001)
	for i := range targets {
		targets[i] = fmt.Sprintf("registry.example.com/app-%04d:latest", i)
	}
	sc := singleScan(t, deps, tenant, "trivy", 1, nil, targets...)
	_, err := trigger(t, svc, sc)
	if err == nil || !strings.Contains(err.Error(), "1001 jobs") || !strings.Contains(err.Error(), "one target per job") {
		t.Fatalf("err = %v; want TOO_MANY_JOBS naming the 1001 jobs and the one-target-per-job reason", err)
	}
	if len(deps.commandRepo.commands) != 0 {
		t.Errorf("%d commands created for a refused run", len(deps.commandRepo.commands))
	}

	// Exactly at the cap is accepted.
	sc = singleScan(t, deps, tenant, "trivy", 1, nil, targets[:1000]...)
	if _, err := trigger(t, svc, sc); err != nil {
		t.Fatalf("1000 targets (the cap): %v", err)
	}
	if got := len(deps.commandRepo.commands); got != 1000 {
		t.Errorf("commands = %d, want 1000", got)
	}
}
