package scan

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/command"
	"github.com/openctemio/openctem/api/pkg/domain/scan"
	"github.com/openctemio/openctem/api/pkg/domain/scanrun"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func TestReachesNoTargetHost(t *testing.T) {
	for name, tc := range map[string]struct {
		tool string
		cfg  map[string]any
		want bool
	}{
		"dns resolution":           {"dnsx", nil, true},
		"subdomain discovery":      {"subfinder", nil, true},
		"asn lookup":               {"asn", nil, true},
		"rdap lookup":              {"rdap", nil, true},
		"custom resolvers":         {"dnsx", map[string]any{"resolvers": []any{"198.51.100.53"}}, false},
		"template scan":            {"nuclei", nil, false},
		"http probe":               {"httpx", nil, false},
		"port scan":                {"naabu", nil, false},
		"unknown tool fails close": {"something-new", nil, false},
		"no tool":                  {"", nil, false},
	} {
		if got := reachesNoTargetHost(tc.tool, tc.cfg); got != tc.want {
			t.Errorf("%s: reachesNoTargetHost(%q) = %v, want %v", name, tc.tool, got, tc.want)
		}
	}
}

// commandHostKeys runs the repository's key assignment on a created command,
// as CommandRepository.Create does, and returns the column and payload keys.
func commandHostKeys(t *testing.T, c *command.Command) (column []string, payload []string, inPayload bool) {
	t.Helper()
	if err := command.AssignHostKeys(c); err != nil {
		t.Fatal(err)
	}
	var p map[string]json.RawMessage
	if err := json.Unmarshal(c.Payload, &p); err != nil {
		t.Fatal(err)
	}
	raw, ok := p["host_keys"]
	if ok {
		if err := json.Unmarshal(raw, &payload); err != nil {
			t.Fatal(err)
		}
	}
	return c.HostKeys, payload, ok
}

// A passive single-scanner command (continuous coverage DNS resolution)
// holds no host and is held back by none; an active one keeps the keys of
// its targets. Before, the DNS resolution got the keys of its names and
// waited behind every port, HTTP and template scan of them.
func TestSingleScannerCommand_PassiveToolHoldsNoHosts(t *testing.T) {
	tenant := shared.NewID()
	targets := []string{"app.example.com", "api.example.com"}
	for _, tc := range []struct {
		tool     string
		wantKeys bool
	}{{"dnsx", false}, {"subfinder", false}, {"httpx", true}, {"nuclei", true}} {
		svc := splitGate(&tenantExclusionRepo{}, nil)
		cmds := &createdCommands{}
		svc.commandRepo = cmds
		sc := &scan.Scan{ID: shared.NewID(), TenantID: tenant, ScannerName: tc.tool}
		run := &scanrun.Run{ID: shared.NewID(), TenantID: tenant, Context: map[string]any{}}
		if err := svc.createScannerCommand(context.Background(), sc, run, nil, targets, false); err != nil {
			t.Fatalf("%s: %v", tc.tool, err)
		}
		column, payload, inPayload := commandHostKeys(t, cmds.cmds[0])
		if !inPayload {
			t.Fatalf("%s: payload carries no host_keys", tc.tool)
		}
		if got := len(column) > 0; got != tc.wantKeys {
			t.Errorf("%s: host keys = %v, want keys: %v", tc.tool, column, tc.wantKeys)
		}
		if len(payload) != len(column) {
			t.Errorf("%s: payload keys %v differ from held keys %v", tc.tool, payload, column)
		}
		if !tc.wantKeys && column == nil {
			t.Errorf("%s: keys must be an empty list (marks the command as keyless), got nil", tc.tool)
		}
	}
}

// The zone and fan-out batches follow the same rule.
func TestZoneCommands_PassiveToolHoldsNoHosts(t *testing.T) {
	tenant := shared.NewID()
	for _, tc := range []struct {
		tool     string
		wantKeys bool
	}{{"dnsx", false}, {"naabu", true}} {
		svc := splitGate(&tenantExclusionRepo{}, nil)
		cmds := &createdCommands{}
		svc.commandRepo = cmds
		sc := &scan.Scan{ID: shared.NewID(), TenantID: tenant, ScannerName: tc.tool, TargetsPerJob: 1}
		run := &scanrun.Run{ID: shared.NewID(), TenantID: tenant, Context: map[string]any{}}
		plan := &zonePlan{Batches: []zoneBatch{{Targets: []string{"a.example.com"}}, {Targets: []string{"b.example.com"}}}}
		if err := svc.createZoneCommands(context.Background(), sc, run, nil, plan, false); err != nil {
			t.Fatalf("%s: %v", tc.tool, err)
		}
		if len(cmds.cmds) != 2 {
			t.Fatalf("%s: %d commands, want 2", tc.tool, len(cmds.cmds))
		}
		for _, c := range cmds.cmds {
			column, _, _ := commandHostKeys(t, c)
			if got := len(column) > 0; got != tc.wantKeys {
				t.Errorf("%s: host keys = %v, want keys: %v", tc.tool, column, tc.wantKeys)
			}
		}
	}
}

func TestUnzonedJobPlan(t *testing.T) {
	targets := func(n int) []string {
		out := make([]string, n)
		for i := range out {
			out[i] = "h" + string(rune('a'+i%26)) + ".example.com"
		}
		return out
	}
	for name, tc := range map[string]struct {
		scanner string
		perJob  int
		n       int
		jobs    int // 0: no plan (one command)
		size    int
	}{
		"list scanner, 50 targets of 25 per job": {"nuclei", 25, 50, 2, 25},
		"list scanner, remainder in a last job":  {"nuclei", 25, 51, 3, 25},
		"list scanner, fits one job":             {"nuclei", 25, 25, 0, 0},
		"list scanner, default 1 per job":        {"httpx", 1, 50, 0, 0},
		"list scanner, unset per job":            {"httpx", 0, 50, 0, 0},
		"one-target scanner, one job per target": {"semgrep", 0, 3, 3, 1},
		"one-target scanner, one target":         {"semgrep", 0, 1, 0, 0},
		"list scanner, one target":               {"nuclei", 25, 1, 0, 0},
	} {
		sc := &scan.Scan{ScannerName: tc.scanner, TargetsPerJob: tc.perJob}
		plan, err := unzonedJobPlan(sc, targets(tc.n))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if tc.jobs == 0 {
			if plan != nil {
				t.Errorf("%s: %d jobs, want one command", name, len(plan.Batches))
			}
			continue
		}
		if plan == nil || len(plan.Batches) != tc.jobs {
			t.Fatalf("%s: plan = %+v, want %d jobs", name, plan, tc.jobs)
		}
		total := 0
		for _, b := range plan.Batches {
			if len(b.Targets) > tc.size || b.Zone != nil || b.SensorID != nil {
				t.Errorf("%s: batch %+v exceeds %d targets or is pinned", name, b, tc.size)
			}
			total += len(b.Targets)
		}
		if total != tc.n {
			t.Errorf("%s: batches carry %d targets, want %d", name, total, tc.n)
		}
		ctx := map[string]any{}
		recordUnzonedJobPlan(plan, ctx)
		rec, _ := ctx[runContextKeyPerTarget].(map[string]any)
		if rec["jobs"] != tc.jobs || rec["targets_per_job"] != tc.size {
			t.Errorf("%s: recorded %v", name, rec)
		}
	}

	// The per-run job cap still applies.
	sc := &scan.Scan{ScannerName: "nuclei", TargetsPerJob: 2}
	if _, err := unzonedJobPlan(sc, targets(2*maxZoneJobsPerRun+2)); err == nil {
		t.Fatal("a fan-out above the job cap must be refused")
	}
}
