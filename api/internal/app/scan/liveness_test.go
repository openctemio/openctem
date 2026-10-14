package scan

import (
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/scan"
	"github.com/openctemio/openctem/api/pkg/domain/scanrun"
	"github.com/openctemio/openctem/api/pkg/domain/scanworkflow"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/stage"
)

// workflowSteps answers fixed steps per workflow.
type workflowSteps struct {
	scanworkflow.StepRepository
	by  map[shared.ID][]*scanworkflow.Step
	err error
}

func (w workflowSteps) GetByScanWorkflowID(_ context.Context, id shared.ID) ([]*scanworkflow.Step, error) {
	return w.by[id], w.err
}

func rangeScan(t *testing.T, targets ...string) *scan.Scan {
	t.Helper()
	sc, err := scan.NewScanWithTargets(shared.NewID(), "net", targets, scan.ScanTypeSingle)
	if err != nil {
		t.Fatal(err)
	}
	return sc
}

func workflowScan(t *testing.T, wf shared.ID, targets ...string) *scan.Scan {
	t.Helper()
	sc := rangeScan(t, targets...)
	sc.ScanType = scan.ScanTypeWorkflow
	sc.ScanWorkflowID = &wf
	return sc
}

// A new scan with a range finds live hosts first when its scan can (a
// single scanner, or a workflow with Host discovery); a workflow without
// it keeps sweeping; an explicit choice is kept, and an explicit liveness
// that cannot run is refused.
func TestApplyCIDRMode(t *testing.T) {
	network, plain := shared.NewID(), shared.NewID()
	s := &Service{tools: testTools, stepRepo: workflowSteps{by: map[shared.ID][]*scanworkflow.Step{
		network: {{StepKey: "hosts", Capabilities: []string{"discover.hosts"}}, {StepKey: "ports", Capabilities: []string{"scan.ports"}}},
		plain:   {{StepKey: "ports", Tool: "naabu"}},
	}}}
	ctx := context.Background()

	cases := []struct {
		name     string
		sc       *scan.Scan
		explicit scan.CIDRMode
		want     scan.CIDRMode
		err      string
	}{
		{"single scanner with a range", rangeScan(t, "198.51.100.0/24"), "", scan.CIDRModeLiveness, ""},
		{"workflow with host discovery", workflowScan(t, network, "198.51.100.0/24"), "", scan.CIDRModeLiveness, ""},
		{"workflow without host discovery", workflowScan(t, plain, "198.51.100.0/24"), "", "", ""},
		{"explicit liveness without host discovery", workflowScan(t, plain, "198.51.100.0/24"), scan.CIDRModeLiveness, "", CodeLivenessNeedsHostDiscovery},
		{"explicit sweep", rangeScan(t, "198.51.100.0/24"), scan.CIDRModeSweep, scan.CIDRModeSweep, ""},
		{"explicit inventory", rangeScan(t, "198.51.100.0/24"), scan.CIDRModeInventory, scan.CIDRModeInventory, ""},
		{"no range", rangeScan(t, "198.51.100.7", "app.example.com"), "", "", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if err := c.sc.SetTargetOptions(scan.TargetOptions{CIDRMode: c.explicit}); err != nil {
				t.Fatal(err)
			}
			err := s.applyCIDRMode(ctx, c.sc, c.explicit != "")
			var de *shared.DomainError
			if c.err != "" {
				if !errors.As(err, &de) || de.Code != c.err {
					t.Fatalf("err = %v, want %s", err, c.err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got := c.sc.TargetOptions.CIDRMode; got != c.want {
				t.Fatalf("cidr_mode = %q, want %q", got, c.want)
			}
		})
	}

	// A step lookup that fails refuses the save (never a silent default).
	s.stepRepo = workflowSteps{err: errors.New("db down")}
	if err := s.applyCIDRMode(ctx, workflowScan(t, network, "198.51.100.0/24"), false); err == nil {
		t.Fatal("a failed step lookup was ignored")
	}
}

// Live hosts first keeps the range for host discovery and adds the
// inventory's addresses inside it, read for the scan's own tenant.
func TestExpandSelectors_Liveness(t *testing.T) {
	sel := &recordingSelector{}
	s := &Service{tools: testTools, selectorAssets: sel}
	sc := rangeScan(t, "198.51.100.0/24", "app.example.com")
	if err := sc.SetTargetOptions(scan.TargetOptions{CIDRMode: scan.CIDRModeLiveness}); err != nil {
		t.Fatal(err)
	}
	exp, err := s.expandSelectors(context.Background(), sc)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(exp.Literal, []string{"198.51.100.0/24", "app.example.com"}) {
		t.Fatalf("literal = %v, want the range kept", exp.Literal)
	}
	if len(sel.queries) != 1 || sel.queries[0].InCIDR != "198.51.100.0/24" || sel.queries[0].TenantID != sc.TenantID {
		t.Fatalf("queries = %+v, want the range's inventory addresses of the scan's tenant", sel.queries)
	}
	if len(exp.Members) != 1 {
		t.Fatalf("members = %+v", exp.Members)
	}

	// Sweep (a scan saved before liveness) asks the inventory nothing.
	sel.queries = nil
	sweep := rangeScan(t, "198.51.100.0/24")
	if _, err := s.expandSelectors(context.Background(), sweep); err != nil || len(sel.queries) != 0 {
		t.Fatalf("sweep: %v %+v", err, sel.queries)
	}
}

func stepToolOf(t *testing.T, key stage.Key) StepTool {
	t.Helper()
	st, ok := stage.Lookup(key)
	if !ok {
		t.Fatalf("no stage %s", key)
	}
	return StepTool{Name: st.DefaultTool(), Stage: st, HasStage: true}
}

// In a liveness run only host discovery and passive stages take ranges.
func TestLivenessSeeds(t *testing.T) {
	ctx := map[string]any{RunContextKeyCIDRMode: "liveness", "targets": []any{"198.51.100.0/24", "198.51.100.7", "app.example.com"}}
	all := []string{"198.51.100.0/24", "198.51.100.7", "app.example.com"}
	for _, c := range []struct {
		key  stage.Key
		want []string
	}{
		{stage.DiscoverHosts, all},
		{stage.LookupASN, all},
		{stage.ScanPorts, []string{"198.51.100.7", "app.example.com"}},
		{stage.VulnTemplates, []string{"198.51.100.7", "app.example.com"}},
	} {
		got := LivenessSeeds(testCat, ctx, stepToolOf(t, c.key), nil)
		var targets []string
		if got != nil {
			targets = got.Targets
		} else {
			targets = all
		}
		if !slices.Equal(targets, c.want) {
			t.Errorf("%s: targets = %v, want %v", c.key, targets, c.want)
		}
	}
	// A tool the catalog does not know is not trusted to be passive.
	if got := LivenessSeeds(testCat, ctx, StepTool{Name: "acme-scanner"}, &StepTargets{Targets: all}); slices.Contains(got.Targets, "198.51.100.0/24") {
		t.Errorf("an unknown tool got the range: %v", got.Targets)
	}
	// Another mode is unchanged.
	sweep := map[string]any{"targets": all}
	if got := LivenessSeeds(testCat, sweep, stepToolOf(t, stage.ScanPorts), nil); got != nil {
		t.Errorf("sweep run changed: %+v", got)
	}
}

// The platform names the probe ports of every host discovery job; a step's
// own ports are kept; a port scan is not touched.
func TestStepCommandPayload_HostProbePorts(t *testing.T) {
	run := &scanrun.Run{ID: shared.NewID(), Context: map[string]any{}}
	payload := func(caps []string, cfg map[string]any) map[string]any {
		t.Helper()
		step := &scanworkflow.Step{ID: shared.NewID(), StepKey: "s", Capabilities: caps, Config: cfg}
		p, err := StepCommandPayload(testCat, run, step, "naabu", shared.NewID().String(), nil)
		if err != nil {
			t.Fatal(err)
		}
		c, _ := p[scanworkflow.PayloadKeyConfig].(map[string]any)
		return c
	}
	if got := payload([]string{"discover.hosts"}, nil); got["ports"] != stage.HostProbePorts {
		t.Fatalf("host discovery config = %v, want the platform's probe ports", got)
	}
	if got := payload([]string{"discover.hosts"}, map[string]any{"ports": "22"}); got["ports"] != "22" {
		t.Fatalf("host discovery config = %v, want the step's ports", got)
	}
	if got := payload([]string{"scan.ports"}, nil); got["ports"] != nil {
		t.Fatalf("port scan config = %v, want no ports added", got)
	}
}
