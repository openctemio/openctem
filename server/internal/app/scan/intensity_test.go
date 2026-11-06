package scan

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/attribution"
	"github.com/openctemio/openctem/api/pkg/domain/scan"
	"github.com/openctemio/openctem/api/pkg/domain/scanworkflow"
	scopedom "github.com/openctemio/openctem/api/pkg/domain/scope"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

func intensityScan(t *testing.T, scanType scan.ScanType) *scan.Scan {
	t.Helper()
	sc, err := scan.NewScanWithTargets(shared.NewID(), "s", []string{"example.com"}, scanType)
	if err != nil {
		t.Fatal(err)
	}
	return sc
}

// A workflow with a step above the chosen intensity is refused when it is
// saved, naming the step; one within it is saved with that intensity.
func TestApplyIntensity_WorkflowStepAboveCeilingRefused(t *testing.T) {
	steps := stubSteps{steps: []*scanworkflow.Step{
		{StepKey: "subdomains", Capabilities: []string{"discover.subdomains"}},
		{StepKey: "dns", Capabilities: []string{"resolve.dns"}},
		{StepKey: "http", Capabilities: []string{"probe.http"}},
	}}
	s := &Service{stepRepo: steps, logger: logger.NewNop()}
	sc := intensityScan(t, scan.ScanTypeWorkflow)
	wf := shared.NewID()
	sc.ScanWorkflowID = &wf

	err := s.applyIntensity(context.Background(), sc, "passive")
	if domainCode(err) != scan.CodeIntensityExceeded {
		t.Fatalf("passive scan of a workflow with an HTTP probe: err = %v, want %s", err, scan.CodeIntensityExceeded)
	}
	if err := s.applyIntensity(context.Background(), sc, "active"); err != nil {
		t.Fatalf("active: %v", err)
	}
	if sc.Intensity != scan.IntensityActive {
		t.Fatalf("intensity = %q", sc.Intensity)
	}
	// Omitted: the tier the workflow probes at.
	if err := s.applyIntensity(context.Background(), sc, ""); err != nil || sc.Intensity != scan.IntensityActive {
		t.Fatalf("omitted: %v / %q", err, sc.Intensity)
	}

	passiveOnly := &Service{stepRepo: stubSteps{steps: steps.steps[:2]}, logger: logger.NewNop()}
	if err := passiveOnly.applyIntensity(context.Background(), sc, ""); err != nil || sc.Intensity != scan.IntensityPassive {
		t.Fatalf("passive workflow, omitted intensity: %v / %q (want passive)", err, sc.Intensity)
	}
}

func TestApplyIntensity_SingleScanner(t *testing.T) {
	s := &Service{logger: logger.NewNop()}
	sc := intensityScan(t, scan.ScanTypeSingle)
	sc.ScannerName = "zap"
	if err := s.applyIntensity(context.Background(), sc, "active"); domainCode(err) != scan.CodeIntensityExceeded {
		t.Fatalf("zap at active: %v", err)
	}
	if err := s.applyIntensity(context.Background(), sc, "intrusive"); err != nil {
		t.Fatal(err)
	}
	sc.ScannerName = "dnsx"
	sc.ScannerConfig = map[string]any{"resolvers": "203.0.113.53"}
	if err := s.applyIntensity(context.Background(), sc, "passive"); domainCode(err) != scan.CodeIntensityExceeded {
		t.Fatalf("dnsx with custom resolvers at passive: %v", err)
	}
	if err := s.applyIntensity(context.Background(), sc, "loud"); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("unknown intensity: %v", err)
	}
}

// A single-scanner run whose tool is above the scan's intensity (the row
// was changed behind the service) is refused before anything is queued.
func TestRefuseRunAboveIntensity(t *testing.T) {
	sc := intensityScan(t, scan.ScanTypeSingle)
	sc.ScannerName = "nuclei"
	sc.Intensity = scan.IntensityPassive
	if err := refuseRunAboveIntensity(sc); domainCode(err) != scan.CodeIntensityExceeded {
		t.Fatalf("nuclei in a passive scan: %v", err)
	}
	sc.ScannerName = "subfinder"
	if err := refuseRunAboveIntensity(sc); err != nil {
		t.Fatal(err)
	}
}

// A passive dispatch takes only names in the organization's scope: a name
// no scope target, seed or verified domain covers is refused (no_entry),
// even when nobody rejected it; the active gate is unchanged.
func TestResolveDispatchTargets_PassiveRefusesOutOfScope(t *testing.T) {
	review := shared.NewID()
	gate := &stubGate{
		blocked:   map[string]attribution.State{review.String(): attribution.StateNeedsReview},
		uncovered: map[string]bool{"victim.example.org": true, "far.example.net": true},
	}
	svc := &Service{scopeExclusions: &stubExclusions{values: map[string]bool{}}, attributionGate: gate, logger: logger.NewNop()}
	in := DispatchTargetsInput{
		TenantID:    shared.NewID(),
		Targets:     []string{"new.example.com", "victim.example.org", "far.example.net"},
		Assets:      map[string]DispatchAsset{"new.example.com": {IDs: []string{review.String()}}, "far.example.net": {IDs: []string{shared.NewID().String()}}},
		PassiveOnly: true,
	}
	out, err := svc.ResolveDispatchTargets(context.Background(), in)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"new.example.com"}; !reflect.DeepEqual(out.Allowed, want) {
		t.Fatalf("allowed = %v, want %v", out.Allowed, want)
	}
	got := map[string]string{}
	for _, r := range out.Refused {
		got[r.Target] = r.Code
	}
	for _, name := range []string{"victim.example.org", "far.example.net"} {
		if got[name] != scopedom.RefusalNoEntry {
			t.Errorf("%s: refused = %v, want %s", name, got, scopedom.RefusalNoEntry)
		}
	}

	gate.err = errors.New("db down")
	if _, err := svc.ResolveDispatchTargets(context.Background(), in); err == nil {
		t.Fatal("a failed scope read must refuse the passive dispatch")
	}
}
