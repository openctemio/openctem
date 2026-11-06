package scan

import (
	"context"
	"reflect"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/attribution"
	"github.com/openctemio/openctem/api/pkg/domain/scan"
	"github.com/openctemio/openctem/api/pkg/domain/scanworkflow"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// A passive scan only looks names up: its run takes names nobody confirmed
// yet and names that resolve only through a wildcard record, as its steps'
// derived targets do. A rejected name stays refused, and a name outside the
// organization's scope too.
func TestResolveScanTargets_PassiveRunTakesUnconfirmedNames(t *testing.T) {
	gate := &stubGate{
		blockedTyped: map[string]attribution.State{
			"new.example.com":      attribution.StateUnattributed,
			"guess.example.com":    attribution.StateWildcardOnly,
			"rejected.example.com": attribution.StateRejected,
		},
		uncovered: map[string]bool{"elsewhere.net": true},
	}
	svc := allowAllChecks(&Service{attributionGate: gate, logger: logger.NewNop()})
	targets := []string{"new.example.com", "guess.example.com", "rejected.example.com", "elsewhere.net", "ok.example.com"}

	sc := &scan.Scan{ScanType: scan.ScanTypeWorkflow, Targets: targets}
	sc.TenantID = testScan("").TenantID
	if err := sc.SetIntensity(scan.IntensityPassive); err != nil {
		t.Fatal(err)
	}
	got, err := svc.resolveScanTargets(context.Background(), sc)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"new.example.com", "guess.example.com", "ok.example.com"}; !reflect.DeepEqual(got.Targets, want) {
		t.Fatalf("passive run targets = %v, want %v", got.Targets, want)
	}
	if got.Unconfirmed != 1 || got.OutOfScope != 1 || got.WildcardOnly != 0 {
		t.Fatalf("unconfirmed=%d out_of_scope=%d wildcard=%d, want 1 (rejected), 1 (outside scope), 0",
			got.Unconfirmed, got.OutOfScope, got.WildcardOnly)
	}

	// The same scan at active intensity gets the active gate; a
	// wildcard-only name is its own skip reason, not "ownership".
	if err := sc.SetIntensity(scan.IntensityActive); err != nil {
		t.Fatal(err)
	}
	got, err = svc.resolveScanTargets(context.Background(), sc)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"elsewhere.net", "ok.example.com"}; !reflect.DeepEqual(got.Targets, want) {
		t.Fatalf("active run targets = %v, want %v", got.Targets, want)
	}
	if got.Unconfirmed != 2 || got.WildcardOnly != 1 {
		t.Fatalf("unconfirmed=%d wildcard=%d, want 2 and 1", got.Unconfirmed, got.WildcardOnly)
	}
	if names := got.SkippedNames[SkipWildcardOnly]; !reflect.DeepEqual(names, []string{"guess.example.com"}) {
		t.Fatalf("wildcard-only names = %v", names)
	}
	// A workflow whose every step is passive marks its context: the same
	// active-intensity scan then gets the passive gate.
	if got, err := svc.resolveScanTargets(withPassiveRun(context.Background(), true), sc); err != nil ||
		!reflect.DeepEqual(got.Targets, []string{"new.example.com", "guess.example.com", "ok.example.com"}) {
		t.Fatalf("passive-steps run targets = %v (%v)", got, err)
	}
	groups := skipGroups(maxRunSkipSamples, nil, got, nil, nil)
	var wildcard *SkipGroup
	for i := range groups {
		if groups[i].Reason == SkipWildcardOnly {
			wildcard = &groups[i]
		}
	}
	if wildcard == nil || wildcard.Count != 1 || wildcard.Tone != SkipToneInfo {
		t.Fatalf("wildcard-only group = %+v, want one info group", wildcard)
	}
}

// A workflow whose every step is passive runs passive whatever its
// intensity; one active step is enough to keep the active gate.
func TestStepsPassiveOnly(t *testing.T) {
	passive := &scanworkflow.Step{StepKey: "dns", Tool: "dnsx"}
	active := &scanworkflow.Step{StepKey: "http", Tool: "httpx"}
	if !stepsPassiveOnly([]*scanworkflow.Step{passive}) {
		t.Error("all-passive workflow not passive")
	}
	if stepsPassiveOnly([]*scanworkflow.Step{passive, active}) {
		t.Error("workflow with an active step counted passive")
	}
	if stepsPassiveOnly(nil) {
		t.Error("no steps counted passive")
	}
}
