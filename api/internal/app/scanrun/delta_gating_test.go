package scanrun

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/scanrun"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/stage"
)

// deltaHops is memHops with a delta baseline: done are the assets the
// previous run already handled.
type deltaHops struct {
	*memHops
	done  map[shared.ID]bool
	err   error
	asked struct {
		prev       shared.ID
		step, cap  string
		ids        int
		maxAge     time.Duration
		tenantSeen shared.ID
	}
}

func (d *deltaHops) UnchangedSince(_ context.Context, tenantID, prev shared.ID, stepKey, capability string, ids []shared.ID, maxAge time.Duration) (map[shared.ID]bool, error) {
	d.asked.prev, d.asked.step, d.asked.cap, d.asked.ids, d.asked.maxAge, d.asked.tenantSeen = prev, stepKey, capability, len(ids), maxAge, tenantID
	return d.done, d.err
}

// gatingDeltaFixture: subs -> dns -> templates (nuclei, a heavy stage) with dns
// finished and three names it produced; the workflow gates heavy stages.
func gatingDeltaFixture(t *testing.T, gating bool) (*chainFixture, *deltaHops, []shared.ID) {
	t.Helper()
	f := newChainFixture(t)
	f.tpl.Steps = f.tpl.Steps[:2]
	tpl := f.tpl.Steps[1].Clone()
	tpl.StepKey, tpl.Tool, tpl.DependsOn, tpl.StepOrder = "templates", "nuclei", []string{"dns"}, 3
	f.tpl.Steps = append(f.tpl.Steps, tpl)
	sr := scanrun.NewStepRun(f.run.ID, tpl.ID, "templates", 3, 0)
	f.sr["templates"] = sr.ID
	f.store.rows["templates"] = *sr
	cp := *sr
	f.run.StepRuns = []*scanrun.StepRun{f.run.GetStepRun("subs"), f.run.GetStepRun("dns"), &cp}
	delete(f.store.rows, "ports")
	delete(f.store.rows, "http")
	f.run.TotalSteps = 3
	f.run.Context["targets"] = []string{}
	f.tpl.Settings.DeltaGating = gating
	f.s.toolRepo = platformTools{names: map[string]bool{"subfinder": true, "dnsx": true, "nuclei": true}}
	dh := &deltaHops{memHops: f.hops, done: map[shared.ID]bool{}}
	f.s.hops = dh
	f.seed("subs", "acme.com", 0, nil)
	f.settle("subs", scanrun.StepRunStatusCompleted)
	f.settle("dns", scanrun.StepRunStatusCompleted)
	ids := []shared.ID{
		f.output("dns", "a.acme.com", "subdomain", "", ""),
		f.output("dns", "b.acme.com", "subdomain", "", ""),
		f.output("dns", "c.acme.com", "subdomain", "", ""),
	}
	return f, dh, ids
}

// With delta gating, a heavy stage takes only what is not done since the
// previous run; the rest are recorded unchanged.
func TestDeltaGating_HeavyStageTakesOnlyTheDelta(t *testing.T) {
	f, dh, ids := gatingDeltaFixture(t, true)
	f.hops.previous = shared.NewID()
	dh.done[ids[0]], dh.done[ids[1]] = true, true

	f.schedule(t)
	got := f.allCommandTargets(t)
	if len(got) != 1 || got[0] != "c.acme.com" {
		t.Fatalf("templates targets = %v, want only the changed name", got)
	}
	p := f.hops.plan(t, f.run.ID, "templates")
	if p.Skipped[scanrun.ReasonUnchanged] != 2 {
		t.Fatalf("plan skipped = %v", p.Skipped)
	}
	if dh.asked.prev != f.hops.previous || dh.asked.step != "templates" || dh.asked.cap != string(stage.VulnTemplates) ||
		dh.asked.maxAge != stage.HeavyMaxAge(stage.VulnTemplates) || dh.asked.tenantSeen != f.run.TenantID {
		t.Fatalf("baseline asked %+v", dh.asked)
	}
	unchanged := 0
	for _, r := range f.hops.targets {
		if r.StageKey == "templates" && r.Reason == scanrun.ReasonUnchanged && r.Decision == scanrun.TargetSkipped {
			unchanged++
		}
	}
	if unchanged != 2 {
		t.Fatalf("unchanged provenance rows = %d", unchanged)
	}
}

// Nothing new: the heavy stage settles at once with "nothing new" and no
// command reaches a sensor.
func TestDeltaGating_NothingNewFinishesFast(t *testing.T) {
	f, dh, ids := gatingDeltaFixture(t, true)
	f.hops.previous = shared.NewID()
	for _, id := range ids {
		dh.done[id] = true
	}
	f.schedule(t)
	if len(f.cmds.created) != 0 {
		t.Fatalf("commands = %v", f.cmds.created)
	}
	st := f.store.rows["templates"]
	if st.Status != scanrun.StepRunStatusCompleted || !strings.Contains(st.SkipReason, "nothing new since the last run: 3 unchanged") {
		t.Fatalf("templates = %s %q", st.Status, st.SkipReason)
	}
}

// No gating without the setting, without a previous run, or when the
// baseline cannot be read: every candidate runs (gating only saves work).
func TestDeltaGating_FailsOpenToFullScan(t *testing.T) {
	cases := map[string]func(f *chainFixture, dh *deltaHops){
		"setting off": func(f *chainFixture, dh *deltaHops) {
			f.tpl.Settings.DeltaGating = false
			f.hops.previous = shared.NewID()
		},
		"first run":       func(f *chainFixture, dh *deltaHops) {},
		"baseline errors": func(f *chainFixture, dh *deltaHops) { f.hops.previous = shared.NewID(); dh.err = errors.New("db down") },
	}
	for name, setup := range cases {
		f, dh, ids := gatingDeltaFixture(t, true)
		for _, id := range ids {
			dh.done[id] = true
		}
		setup(f, dh)
		f.schedule(t)
		if got := f.allCommandTargets(t); len(got) != 3 {
			t.Fatalf("%s: templates targets = %v, want all three", name, got)
		}
	}
}

// A light stage is never gated, whatever the setting.
func TestDeltaGating_LightStageNotGated(t *testing.T) {
	if stage.Heavy(stage.ResolveDNS) || stage.Heavy(stage.ProbeHTTP) || stage.Heavy(stage.ScanPorts) {
		t.Fatal("light stages are gated")
	}
	if !stage.Heavy(stage.VulnTemplates) || !stage.Heavy(stage.CrawlWeb) || !stage.Heavy("capture.screenshot") || !stage.Heavy("detect.services") {
		t.Fatal("heavy stages are not gated")
	}
}
