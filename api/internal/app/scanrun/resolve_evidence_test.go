package scanrun

import (
	"context"
	"testing"
	"time"

	scanapp "github.com/openctemio/openctem/api/internal/app/scan"
	freshdom "github.com/openctemio/openctem/api/pkg/domain/assetfreshness"
	"github.com/openctemio/openctem/api/pkg/domain/assetresolution"
	"github.com/openctemio/openctem/api/pkg/domain/scanrun"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// staleNames: names with old resolution evidence, any tenant.
type staleNames map[string]time.Time

func (s staleNames) FreshestByName(_ context.Context, _ shared.ID, names []string, _ []freshdom.Class) ([]freshdom.NameEvidence, error) {
	var out []freshdom.NameEvidence
	for _, n := range names {
		if at, ok := s[n]; ok {
			out = append(out, freshdom.NameEvidence{AssetID: shared.NewID(), Name: n, ObservedAt: at})
		}
	}
	return out, nil
}

// Resolve before active: a passive stage (DNS) still takes a name that has
// not resolved for a week, so it can find out whether it resolves again; an
// active stage (the port scan) does not.
func TestResolveBeforeActive_StaleNameSkipsActiveStages(t *testing.T) {
	f := newChainFixture(t)
	f.run.Context["targets"] = []string{"acme.com", "dead.acme.com"}
	f.s.targetGate.(*scanapp.Service).SetResolveEvidence(staleNames{"dead.acme.com": time.Now().Add(-30 * 24 * time.Hour)}, nil)
	// subs and dns first: subs is a root, dns follows it.
	f.settle("subs", scanrun.StepRunStatusCompleted)
	f.schedule(t)
	if dns := f.commandTargets(t, 0); !contains(dns, "dead.acme.com") {
		t.Fatalf("dnsx targets = %v: a passive stage must still take the stale name", dns)
	}
	f.settle("dns", scanrun.StepRunStatusCompleted)
	f.schedule(t)
	ports := f.commandTargets(t, 1)
	if contains(ports, "dead.acme.com") || !contains(ports, "acme.com") {
		t.Fatalf("naabu targets = %v: a name without recent resolution evidence reached an active stage", ports)
	}
}

// An active step whose every seed is stale settles without a command.
func TestResolveBeforeActive_AllStaleSettles(t *testing.T) {
	f := newChainFixture(t)
	f.run.Context["targets"] = []string{"dead.acme.com"}
	f.s.targetGate.(*scanapp.Service).SetResolveEvidence(staleNames{"dead.acme.com": time.Now().Add(-30 * 24 * time.Hour)}, nil)
	f.tpl.Steps = f.tpl.Steps[2:3] // ports alone
	f.tpl.Steps[0].DependsOn = nil
	n := len(f.cmds.created)
	f.schedule(t)
	if r := f.store.rows["ports"]; r.Status != scanrun.StepRunStatusCompleted || len(f.cmds.created) != n {
		t.Fatalf("ports = %s with %d new command(s)", r.Status, len(f.cmds.created)-n)
	}
}

// deadNames is a resolution state: the names it holds are not_resolving.
type deadNames map[string]bool

func (d deadNames) RecordResolved(context.Context, shared.ID, []shared.ID, time.Time) error {
	return nil
}
func (d deadNames) RecordFailed(context.Context, shared.ID, []shared.ID, time.Time, string) error {
	return nil
}
func (d deadNames) RecordFailedNames(context.Context, shared.ID, []string, time.Time, string) error {
	return nil
}
func (d deadNames) NotResolving(_ context.Context, _ shared.ID, names []string) (map[string]bool, error) {
	out := map[string]bool{}
	for _, n := range names {
		if d[n] {
			out[n] = true
		}
	}
	return out, nil
}
func (d deadNames) Get(context.Context, shared.ID, shared.ID) (*assetresolution.Resolution, error) {
	return nil, nil
}

// A name the platform knows does not resolve (not_resolving) reaches the
// passive DNS step, which can find out it resolves again, and no active
// step; the active step records how many names it left out, for the run
// map. The scan's include-unresolved option only lets a name without
// evidence through (never one known to be dead), so no evidence is given
// here for the dead name at all.
func TestResolveBeforeActive_NotResolvingNameSkipsActiveStages(t *testing.T) {
	f := newChainFixture(t)
	f.run.Context["targets"] = []string{"acme.com", "dead.acme.com", "other.acme.com"}
	gate := f.s.targetGate.(*scanapp.Service)
	gate.SetResolutionStore(deadNames{"dead.acme.com": true})
	f.settle("subs", scanrun.StepRunStatusCompleted)
	f.schedule(t)
	if dns := f.commandTargets(t, 0); !contains(dns, "dead.acme.com") {
		t.Fatalf("dnsx targets = %v: the passive DNS step must still take a not_resolving name", dns)
	}
	f.settle("dns", scanrun.StepRunStatusCompleted)
	f.schedule(t)
	ports := f.commandTargets(t, 1)
	if contains(ports, "dead.acme.com") || !contains(ports, "acme.com") || !contains(ports, "other.acme.com") {
		t.Fatalf("naabu targets = %v: a not_resolving name reached an active step", ports)
	}
	if n := outputCount(f.store.rows["ports"].Output, StepOutputNotResolvingSkipped); n != 1 {
		t.Fatalf("ports output %v: not_resolving_skipped_count = %d, want 1", f.store.rows["ports"].Output, n)
	}
	if n := outputCount(f.store.rows["dns"].Output, StepOutputNotResolvingSkipped); n != 0 {
		t.Fatalf("the passive step recorded %d names left out", n)
	}
}
