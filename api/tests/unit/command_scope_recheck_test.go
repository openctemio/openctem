package unit

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/internal/app/command"
	scanapp "github.com/openctemio/openctem/api/internal/app/scan"
	commanddom "github.com/openctemio/openctem/api/pkg/domain/command"
	"github.com/openctemio/openctem/api/pkg/domain/scanzone"
	scopedom "github.com/openctemio/openctem/api/pkg/domain/scope"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// The claim-time scope re-check (docs/architecture/active-probe-gate.md,
// "Re-check at claim"): a scan job's targets pass the dispatch gate again
// when a sensor gets it, on every hand-out path of the command service
// (Poll, claim-N, claim by id).

// recheckGate is a dispatch gate whose answer the test sets.
type recheckGate struct {
	mu       sync.Mutex
	excluded map[string]bool
	refused  map[string]string     // target -> refusal code
	zones    map[string]*shared.ID // target -> zone
	err      error
	calls    []scanapp.DispatchTargetsInput
}

func (g *recheckGate) ResolveDispatchTargets(_ context.Context, in scanapp.DispatchTargetsInput) (*scanapp.DispatchTargets, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.calls = append(g.calls, in)
	if g.err != nil {
		return nil, g.err
	}
	out := &scanapp.DispatchTargets{ZoneOf: map[string]*scanzone.Zone{}}
	for _, t := range in.Targets {
		switch {
		case g.excluded[t]:
			out.Excluded = append(out.Excluded, t)
		case g.refused[t] != "":
			out.Refused = append(out.Refused, scanapp.RefusedTarget{Target: t, Code: g.refused[t], Reason: "refused"})
		default:
			out.Allowed = append(out.Allowed, t)
			if z := g.zones[t]; z != nil && !in.SkipZoneRouting {
				out.ZoneOf[t] = &scanzone.Zone{ID: *z}
			}
		}
	}
	return out, nil
}

func (g *recheckGate) callCount() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return len(g.calls)
}

// stepFailures records the commands a re-check failed (the failure
// observer: the command handler settles the step, validation run, retest).
type stepFailures struct {
	mu    sync.Mutex
	calls []string
	done  chan struct{}
}

func newStepFailures() *stepFailures { return &stepFailures{done: make(chan struct{}, 16)} }

func (f *stepFailures) OnCommandFailed(_ context.Context, cmd *commanddom.Command, msg, code string) {
	var p struct {
		StepKey string `json:"step_key"`
	}
	_ = json.Unmarshal(cmd.Payload, &p)
	f.mu.Lock()
	f.calls = append(f.calls, string(cmd.Type)+"|"+p.StepKey+"|"+code+"|"+string(cmd.Status)+"|"+msg)
	f.mu.Unlock()
	f.done <- struct{}{}
}

func (f *stepFailures) wait(t *testing.T) {
	t.Helper()
	select {
	case <-f.done:
	case <-time.After(5 * time.Second):
		t.Fatal("the step was not failed")
	}
}

func (f *stepFailures) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.calls)
}

// recheckRepo is the mock repository with claim-N and the re-check's
// conditional writes.
type recheckRepo struct {
	*cmdMockRepo
	fails, narrows int
	loseRace       bool // the conditional writes lose to a concurrent claim
}

func newRecheckRepo() *recheckRepo { return &recheckRepo{cmdMockRepo: newCmdMockRepo()} }

func (r *recheckRepo) ClaimManyForSensor(_ context.Context, tenantID, sensorID shared.ID, _ []string, ids []shared.ID) ([]shared.ID, error) {
	var out []shared.ID
	for _, id := range ids {
		c := r.commands[id.String()]
		if c == nil || c.TenantID != tenantID || c.Status != commanddom.CommandStatusPending {
			continue
		}
		c.Acknowledge()
		sid := sensorID
		c.SensorID = &sid
		out = append(out, id)
	}
	return out, nil
}

func (r *recheckRepo) CountHeldScans(context.Context, shared.ID, shared.ID) (int, error) {
	return 0, nil
}

func (r *recheckRepo) NarrowPendingPayload(_ context.Context, cmd *commanddom.Command, payload json.RawMessage) (bool, error) {
	c := r.commands[cmd.ID.String()]
	if r.loseRace || c == nil || c.TenantID != cmd.TenantID || c.Status != commanddom.CommandStatusPending || string(c.Payload) != string(cmd.Payload) {
		return false, nil
	}
	c.Payload = payload
	r.narrows++
	return true, nil
}

func (r *recheckRepo) FailPending(_ context.Context, cmd *commanddom.Command, message string) (bool, error) {
	c := r.commands[cmd.ID.String()]
	if r.loseRace || c == nil || c.TenantID != cmd.TenantID || c.Status != commanddom.CommandStatusPending {
		return false, nil
	}
	c.Fail(message)
	r.fails++
	return true, nil
}

func (r *recheckRepo) add(tenantID shared.ID, typ commanddom.CommandType, payload string, gate *commanddom.DispatchGate) *commanddom.Command {
	c := &commanddom.Command{ID: shared.NewID(), TenantID: tenantID, Type: typ,
		Status: commanddom.CommandStatusPending, Payload: json.RawMessage(payload), DispatchGate: gate}
	r.commands[c.ID.String()] = c
	return c
}

func payloadTargetList(t *testing.T, raw json.RawMessage) ([]string, any, []any) {
	t.Helper()
	var p struct {
		Targets []string       `json:"targets"`
		Target  any            `json:"target"`
		Context map[string]any `json:"context"`
	}
	if err := json.Unmarshal(raw, &p); err != nil {
		t.Fatalf("payload %s: %v", raw, err)
	}
	ctxTargets, _ := p.Context["targets"].([]any)
	return p.Targets, p.Target, ctxTargets
}

type recheckFixture struct {
	tenant, sensor shared.ID
	repo           *recheckRepo
	gate           *recheckGate
	steps          *stepFailures
	svc            *command.Service
}

func newRecheckFixture() *recheckFixture {
	f := &recheckFixture{tenant: shared.NewID(), sensor: shared.NewID(), repo: newRecheckRepo(),
		gate:  &recheckGate{excluded: map[string]bool{}, refused: map[string]string{}, zones: map[string]*shared.ID{}},
		steps: newStepFailures()}
	f.svc = command.NewService(f.repo, newCmdTestLogger(), command.WithScopeRecheck(f.gate))
	f.svc.SetFailureObserver(f.steps)
	return f
}

// handOut is one hand-out path of the command service.
type handOut struct {
	name string
	run  func(f *recheckFixture, c *commanddom.Command) (*commanddom.Command, error)
}

var handOutPaths = []handOut{
	{"poll", func(f *recheckFixture, c *commanddom.Command) (*commanddom.Command, error) {
		cmds, err := f.svc.Poll(context.Background(), command.PollInput{TenantID: f.tenant.String(), SensorID: f.sensor.String(), Limit: 10})
		return find(cmds, c), err
	}},
	{"claim-N", func(f *recheckFixture, c *commanddom.Command) (*commanddom.Command, error) {
		cmds, err := f.svc.Claim(context.Background(), command.ClaimInput{TenantID: f.tenant.String(), SensorID: f.sensor.String(), Limit: 10, MaxJobs: 10})
		return find(cmds, c), err
	}},
	{"claim by id", func(f *recheckFixture, c *commanddom.Command) (*commanddom.Command, error) {
		return f.svc.Acknowledge(context.Background(), f.tenant.String(), f.sensor.String(), c.ID.String())
	}},
}

func find(cmds []*commanddom.Command, c *commanddom.Command) *commanddom.Command {
	for _, x := range cmds {
		if x.ID == c.ID {
			return x
		}
	}
	return nil
}

const stepPayload = `{"scanner":"nuclei","scan_run_id":"` + "11111111-1111-1111-1111-111111111111" +
	`","step_key":"probe","scan_run_step_id":"22222222-2222-2222-2222-222222222222","timeout_seconds":3600,` +
	`"targets":["a.example.com","b.example.com","c.example.com"],"context":{"targets":["a.example.com","b.example.com","c.example.com"]}}`

// A target excluded (or now out of tier, unconfirmed, out of the act
// scope) after the job was queued is taken out of the job, on every path;
// the rest of the job is handed out, and the stored payload is narrowed too.
func TestScopeRecheck_TrimsTargetsRefusedSinceDispatch(t *testing.T) {
	for _, path := range handOutPaths {
		for code, setup := range map[string]func(g *recheckGate){
			"excluded":     func(g *recheckGate) { g.excluded["b.example.com"] = true },
			"tier_exceeds": func(g *recheckGate) { g.refused["b.example.com"] = scopedom.RefusalTierExceeds },
			"needs_review": func(g *recheckGate) { g.refused["b.example.com"] = scopedom.RefusalNeedsReview },
			"out_of_scope": func(g *recheckGate) { g.refused["b.example.com"] = scopedom.RefusalOutOfDataScope },
			"zone_none":    func(g *recheckGate) { g.refused["b.example.com"] = scopedom.RefusalZoneNone },
		} {
			t.Run(path.name+"/"+code, func(t *testing.T) {
				f := newRecheckFixture()
				setup(f.gate)
				c := f.repo.add(f.tenant, commanddom.CommandTypeScan, stepPayload,
					&commanddom.DispatchGate{Tier: 1, ActScope: true, Actor: "33333333-3333-3333-3333-333333333333"})
				got, err := path.run(f, c)
				if err != nil || got == nil {
					t.Fatalf("hand-out: %v %v", got, err)
				}
				targets, _, ctxTargets := payloadTargetList(t, got.Payload)
				if strings.Join(targets, ",") != "a.example.com,c.example.com" || len(ctxTargets) != 2 {
					t.Fatalf("handed out targets %v (context %v), want a and c", targets, ctxTargets)
				}
				stored, _, _ := payloadTargetList(t, f.repo.commands[c.ID.String()].Payload)
				if strings.Join(stored, ",") != "a.example.com,c.example.com" {
					t.Fatalf("stored targets %v: the result binding would still accept the refused one", stored)
				}
				if !strings.Contains(string(got.Payload), `"timeout_seconds":3600`) {
					t.Fatalf("the rest of the payload changed: %s", got.Payload)
				}
				if f.steps.count() != 0 {
					t.Fatal("a narrowed job failed its step")
				}
			})
		}
	}
}

// The gate gets what the dispatch recorded: tier, passive, act scope and
// actor, the claiming sensor (zone membership), and the re-check flag.
func TestScopeRecheck_GatesWithTheRecordedInputs(t *testing.T) {
	f := newRecheckFixture()
	actor := shared.NewID()
	f.repo.add(f.tenant, commanddom.CommandTypeScan, `{"scanner":"subfinder","targets":["example.com"]}`,
		&commanddom.DispatchGate{Tier: 0, Passive: true, ActScope: true, Actor: actor.String()})
	if _, err := f.svc.Poll(context.Background(), command.PollInput{TenantID: f.tenant.String(), SensorID: f.sensor.String(), Limit: 10}); err != nil {
		t.Fatal(err)
	}
	if f.gate.callCount() != 1 {
		t.Fatalf("gate calls = %d", f.gate.callCount())
	}
	in := f.gate.calls[0]
	if in.TenantID != f.tenant || in.SensorID == nil || *in.SensorID != f.sensor || !in.AllowNonNetworkTargets ||
		!in.PassiveOnly || !in.ActScope || in.FallbackUser == nil || *in.FallbackUser != actor ||
		in.Tier == nil || *in.Tier != scopedom.TierPassive || in.DryRun {
		t.Fatalf("gate input %+v", in)
	}
}

// A job whose every target is refused is not handed out: it is failed with
// SCOPE_CHANGED (on the command and its step), once.
func TestScopeRecheck_FailsAJobWithNothingLeft(t *testing.T) {
	for _, path := range handOutPaths {
		t.Run(path.name, func(t *testing.T) {
			f := newRecheckFixture()
			f.gate.excluded["a.example.com"] = true
			f.gate.refused["b.example.com"] = scopedom.RefusalTierExceeds
			f.gate.refused["c.example.com"] = scopedom.RefusalRejected
			c := f.repo.add(f.tenant, commanddom.CommandTypeScan, stepPayload, &commanddom.DispatchGate{Tier: 1})
			got, err := path.run(f, c)
			if got != nil {
				t.Fatalf("a job with no target left was handed out: %s", got.Payload)
			}
			if path.name == "claim by id" {
				if !errors.Is(err, command.ErrScopeChanged) || !errors.Is(err, command.ErrCommandClaimed) || !errors.Is(err, shared.ErrConflict) {
					t.Fatalf("claim by id: %v, want ErrScopeChanged (read as claimed)", err)
				}
			} else if err != nil {
				t.Fatal(err)
			}
			stored := f.repo.commands[c.ID.String()]
			if stored.Status != commanddom.CommandStatusFailed || !strings.HasPrefix(stored.ErrorMessage, "SCOPE_CHANGED: ") ||
				!strings.Contains(stored.ErrorMessage, "a.example.com (excluded)") ||
				!strings.Contains(stored.ErrorMessage, "b.example.com (tier_exceeds)") {
				t.Fatalf("stored %s %q", stored.Status, stored.ErrorMessage)
			}
			f.steps.wait(t)
			if f.steps.count() != 1 || !strings.Contains(f.steps.calls[0], "scan|probe|SCOPE_CHANGED|failed|SCOPE_CHANGED: ") {
				t.Fatalf("step failures %v", f.steps.calls)
			}

			// A second claim attempt neither hands it out nor records again.
			if again, _ := path.run(f, c); again != nil {
				t.Fatal("the failed job was handed out on a second claim")
			}
			time.Sleep(50 * time.Millisecond)
			if f.repo.fails != 1 || f.steps.count() != 1 {
				t.Fatalf("recorded %d failures, %d step failures; want 1 and 1", f.repo.fails, f.steps.count())
			}
		})
	}
}

// Two claims racing on the same job: only the one whose conditional write
// wins records the failure and reports the step; the loser hands nothing out.
func TestScopeRecheck_ConcurrentFailIsRecordedOnce(t *testing.T) {
	f := newRecheckFixture()
	f.gate.excluded["a.example.com"] = true
	c := f.repo.add(f.tenant, commanddom.CommandTypeScan,
		`{"scanner":"nuclei","scan_run_id":"11111111-1111-1111-1111-111111111111","step_key":"probe","target":"a.example.com"}`, nil)
	f.repo.loseRace = true // another claim settled it between the read and the write
	got, err := f.svc.Acknowledge(context.Background(), f.tenant.String(), f.sensor.String(), c.ID.String())
	if got != nil || err == nil {
		t.Fatal("the job was handed out")
	}
	time.Sleep(50 * time.Millisecond)
	if f.repo.fails != 0 || f.steps.count() != 0 {
		t.Fatalf("recorded %d failures, %d step failures for a job another claim settled", f.repo.fails, f.steps.count())
	}
}

// A gate that cannot decide hands nothing out and fails nothing: the job
// stays pending for a later claim (fail closed).
func TestScopeRecheck_GateErrorWithholdsTheJob(t *testing.T) {
	for _, path := range handOutPaths {
		t.Run(path.name, func(t *testing.T) {
			f := newRecheckFixture()
			f.gate.err = errors.New("scope store down")
			c := f.repo.add(f.tenant, commanddom.CommandTypeScan, stepPayload, &commanddom.DispatchGate{Tier: 1})
			got, err := path.run(f, c)
			if got != nil {
				t.Fatal("handed out a job the gate could not check")
			}
			if path.name == "claim by id" && !errors.Is(err, command.ErrScopeRecheckUnavailable) {
				t.Fatalf("claim by id: %v", err)
			}
			if st := f.repo.commands[c.ID.String()].Status; st != commanddom.CommandStatusPending {
				t.Fatalf("status %s, want pending (claimable later)", st)
			}
			if f.repo.fails != 0 || f.steps.count() != 0 {
				t.Fatal("a gate error failed the job")
			}
			// The gate recovers: the next claim hands it out.
			f.gate.err = nil
			if got, err := path.run(f, c); err != nil || got == nil {
				t.Fatalf("after recovery: %v %v", got, err)
			}
		})
	}
}

// A job whose targets now route to another scan zone (the zone shrunk or
// was deleted) is refused: it may not leave the zone it was routed to.
func TestScopeRecheck_ZoneChangedIsRefused(t *testing.T) {
	f := newRecheckFixture()
	zoneA, zoneB := shared.NewID(), shared.NewID()
	f.gate.zones["10.0.0.5"] = &zoneB // moved to zone B
	f.gate.zones["10.0.0.6"] = &zoneA
	// 10.0.0.7 is now unzoned
	c := f.repo.add(f.tenant, commanddom.CommandTypeScan,
		`{"scanner":"nmap","targets":["10.0.0.5","10.0.0.6","10.0.0.7"]}`, &commanddom.DispatchGate{Tier: 1})
	c.ScanZoneID = &zoneA
	cmds, err := f.svc.Poll(context.Background(), command.PollInput{TenantID: f.tenant.String(), SensorID: f.sensor.String(), Limit: 10})
	if err != nil || len(cmds) != 1 {
		t.Fatalf("poll: %v %v", cmds, err)
	}
	if targets, _, _ := payloadTargetList(t, cmds[0].Payload); strings.Join(targets, ",") != "10.0.0.6" {
		t.Fatalf("targets %v, want only the one still in zone A", targets)
	}

	// An unzoned job whose target now routes into a zone is refused too.
	g := newRecheckFixture()
	g.gate.zones["198.51.100.7"] = &zoneA
	u := g.repo.add(g.tenant, commanddom.CommandTypeScan, `{"scanner":"nmap","target":"198.51.100.7"}`, &commanddom.DispatchGate{Tier: 1})
	if got, _ := g.svc.Acknowledge(context.Background(), g.tenant.String(), g.sensor.String(), u.ID.String()); got != nil {
		t.Fatal("an unzoned job was handed out after its target moved into a zone")
	}
	if !strings.Contains(g.repo.commands[u.ID.String()].ErrorMessage, "zone_changed") {
		t.Fatalf("error %q", g.repo.commands[u.ID.String()].ErrorMessage)
	}
}

// Jobs nothing changed for are handed out exactly as stored; non-scan
// commands without a record are not re-checked (no gate call); the chunks
// of one step (one record) cost one gate call.
func TestScopeRecheck_UnaffectedJobsAndCost(t *testing.T) {
	f := newRecheckFixture()
	g := &commanddom.DispatchGate{Tier: 1, ActScope: true}
	chunk1 := f.repo.add(f.tenant, commanddom.CommandTypeScan, `{"scanner":"nuclei","targets":["a.example.com"],"n":1}`, g)
	chunk2 := f.repo.add(f.tenant, commanddom.CommandTypeScan, `{"scanner":"nuclei","targets":["b.example.com"],"n":2}`, g)
	health := f.repo.add(f.tenant, commanddom.CommandTypeHealthCheck, `{}`, nil)
	content := f.repo.add(f.tenant, commanddom.CommandTypeRefreshContent, `{"targets":["x"]}`, nil)
	cmds, err := f.svc.Claim(context.Background(), command.ClaimInput{TenantID: f.tenant.String(), SensorID: f.sensor.String(), Limit: 10, MaxJobs: 10})
	if err != nil || len(cmds) != 4 {
		t.Fatalf("claim: %d %v", len(cmds), err)
	}
	for _, want := range []*commanddom.Command{chunk1, chunk2, health, content} {
		got := find(cmds, want)
		if got == nil || string(got.Payload) != string(want.Payload) {
			t.Fatalf("command %s changed or missing", want.ID)
		}
	}
	if f.gate.callCount() != 1 {
		t.Fatalf("gate calls = %d, want 1 for two chunks of one step", f.gate.callCount())
	}
	if f.repo.narrows != 0 || f.repo.fails != 0 {
		t.Fatal("an unaffected job was written")
	}

	// Only non-scan commands: no gate call at all.
	h := newRecheckFixture()
	h.repo.add(h.tenant, commanddom.CommandTypeHealthCheck, `{}`, nil)
	if _, err := h.svc.Poll(context.Background(), command.PollInput{TenantID: h.tenant.String(), SensorID: h.sensor.String(), Limit: 10}); err != nil {
		t.Fatal(err)
	}
	if h.gate.callCount() != 0 {
		t.Fatal("a non-scan command cost a gate call")
	}
}

// A scan command queued before the record existed is re-checked with the
// baseline: passive (only rejected names refused), no tier, no act scope.
func TestScopeRecheck_ScanWithoutRecordUsesTheBaseline(t *testing.T) {
	f := newRecheckFixture()
	f.repo.add(f.tenant, commanddom.CommandTypeScan, `{"scanner":"nuclei","target":"a.example.com"}`, nil)
	if _, err := f.svc.Poll(context.Background(), command.PollInput{TenantID: f.tenant.String(), SensorID: f.sensor.String(), Limit: 10}); err != nil {
		t.Fatal(err)
	}
	if f.gate.callCount() != 1 {
		t.Fatalf("gate calls %d", f.gate.callCount())
	}
	in := f.gate.calls[0]
	if !in.PassiveOnly || in.ActScope || in.Tier == nil || *in.Tier != scopedom.TierPassive || !in.AllowNonNetworkTargets {
		t.Fatalf("baseline input %+v", in)
	}
}

// The re-check never acts on, or hands out, another tenant's command, even
// if a repository bug returned one.
func TestScopeRecheck_NeverActsAcrossTenants(t *testing.T) {
	f := newRecheckFixture()
	other := shared.NewID()
	foreign := f.repo.add(other, commanddom.CommandTypeScan, `{"scanner":"nuclei","target":"a.example.com"}`, &commanddom.DispatchGate{Tier: 1})
	f.gate.excluded["a.example.com"] = true
	// The mock's pending query is not tenant-scoped: the poll sees it.
	cmds, err := f.svc.Poll(context.Background(), command.PollInput{TenantID: f.tenant.String(), SensorID: f.sensor.String(), Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if find(cmds, foreign) != nil {
		t.Fatal("another tenant's command was handed out")
	}
	if f.repo.commands[foreign.ID.String()].Status != commanddom.CommandStatusPending || f.gate.callCount() != 0 {
		t.Fatal("the re-check acted on another tenant's command")
	}
	// Claim by id of another tenant's command stays not found.
	if _, err := f.svc.Acknowledge(context.Background(), f.tenant.String(), f.sensor.String(), foreign.ID.String()); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("claim by id across tenants: %v", err)
	}
}

// "target" follows the narrowing: kept when kept, the one target left
// otherwise, dropped when several are left.
func TestScopeRecheck_SingleTargetFieldFollowsTheNarrowing(t *testing.T) {
	f := newRecheckFixture()
	f.gate.excluded["a.example.com"] = true
	c := f.repo.add(f.tenant, commanddom.CommandTypeScan,
		`{"scanner":"httpx","target":"a.example.com","targets":["a.example.com","b.example.com"]}`, &commanddom.DispatchGate{Tier: 1})
	got, err := f.svc.Acknowledge(context.Background(), f.tenant.String(), f.sensor.String(), c.ID.String())
	if err != nil {
		t.Fatal(err)
	}
	targets, target, _ := payloadTargetList(t, got.Payload)
	if strings.Join(targets, ",") != "b.example.com" || target != "b.example.com" {
		t.Fatalf("targets %v target %v", targets, target)
	}
}

// Validate, retest and connector_scan commands are re-checked with the
// record their dispatcher stored: an excluded target fails the job with
// SCOPE_CHANGED and the failure observer settles what waits on it.
func TestScopeRecheck_ProbeAndConnectorCommands(t *testing.T) {
	probe := commanddom.ProbeDispatchGate
	connector := commanddom.DispatchGate{Tier: 1, Validated: true, NoZoneRouting: true, ActScope: true,
		Actor: "33333333-3333-3333-3333-333333333333"}
	for _, tc := range []struct {
		typ     commanddom.CommandType
		payload string
		gate    *commanddom.DispatchGate
	}{
		{commanddom.CommandTypeValidate,
			`{"job_id":"j","executor_kind":"safe_check","target":{"asset_id":"a","type":"domain","address":"gone.example.com"}}`, &probe},
		{commanddom.CommandTypeRetest,
			`{"scanner":"nuclei","retest_id":"r","targets":["gone.example.com"],"items":[{"ref":"f","target":"gone.example.com"}]}`, &probe},
		{commanddom.CommandTypeConnectorScan,
			`{"scanner":"tenable_sc","targets":["gone.example.com"]}`, &connector},
	} {
		t.Run(string(tc.typ), func(t *testing.T) {
			for _, path := range handOutPaths {
				f := newRecheckFixture()
				f.gate.excluded["gone.example.com"] = true
				c := f.repo.add(f.tenant, tc.typ, tc.payload, tc.gate)
				if got, _ := path.run(f, c); got != nil {
					t.Fatalf("%s: a job with no target left was handed out", path.name)
				}
				stored := f.repo.commands[c.ID.String()]
				if stored.Status != commanddom.CommandStatusFailed || !strings.Contains(stored.ErrorMessage, "gone.example.com (excluded)") {
					t.Fatalf("%s: stored %s %q", path.name, stored.Status, stored.ErrorMessage)
				}
				f.steps.wait(t)
				if !strings.HasPrefix(f.steps.calls[0], string(tc.typ)+"||SCOPE_CHANGED|failed|") {
					t.Fatalf("%s: observer %v", path.name, f.steps.calls)
				}
				in := f.gate.calls[0]
				if in.AllowNonNetworkTargets || in.Tier == nil || *in.Tier != scopedom.TierActive || in.PassiveOnly ||
					in.SkipZoneRouting != tc.gate.NoZoneRouting || in.ActScope != tc.gate.ActScope {
					t.Fatalf("%s: gate input %+v", path.name, in)
				}
			}
		})
	}
}

// A connector scan runs outside every zone: a target that routes into a
// zone is not refused as a zone change; an unchanged probe is handed out.
func TestScopeRecheck_ConnectorIgnoresZonesAndProbeKept(t *testing.T) {
	f := newRecheckFixture()
	zone := shared.NewID()
	f.gate.zones["10.0.0.5"] = &zone
	c := f.repo.add(f.tenant, commanddom.CommandTypeConnectorScan, `{"scanner":"tenable_sc","targets":["10.0.0.5"]}`,
		&commanddom.DispatchGate{Tier: 1, Validated: true, NoZoneRouting: true})
	v := f.repo.add(f.tenant, commanddom.CommandTypeValidate,
		`{"job_id":"j","target":{"asset_id":"a","type":"domain","address":"ok.example.com"}}`, &commanddom.DispatchGate{Tier: 1, Validated: true})
	cmds, err := f.svc.Poll(context.Background(), command.PollInput{TenantID: f.tenant.String(), SensorID: f.sensor.String(), Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if find(cmds, c) == nil || find(cmds, v) == nil {
		t.Fatalf("handed out %d commands, want the connector scan and the probe", len(cmds))
	}
	if got := find(cmds, v); string(got.Payload) != string(v.Payload) {
		t.Fatal("an unchanged probe was rewritten")
	}
}
