package scanrun

import (
	"context"
	"testing"
	"time"

	scanapp "github.com/openctemio/openctem/api/internal/app/scan"
	freshdom "github.com/openctemio/openctem/api/pkg/domain/assetfreshness"
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
