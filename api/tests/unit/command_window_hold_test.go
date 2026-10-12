package unit

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/internal/app/command"
	swapp "github.com/openctemio/openctem/api/internal/app/scanwindow"
	commanddom "github.com/openctemio/openctem/api/pkg/domain/command"
	swdom "github.com/openctemio/openctem/api/pkg/domain/scanwindow"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Scan windows at the claim (RFC-067 §6.1) and when a window closes under
// running work (§6.4), on every hand-out path of the command service.

// windowRepo is the mock repository with the window hold's writes.
type windowRepo struct {
	*recheckRepo
	deferred map[string]commanddom.WindowDeferral
	siblings []*commanddom.Command
	recorded map[string][]string
	running  map[string]int
	closedAt map[string]time.Time
	requeued []string
	released int
}

func newWindowRepo() *windowRepo {
	return &windowRepo{recheckRepo: newRecheckRepo(), deferred: map[string]commanddom.WindowDeferral{},
		recorded: map[string][]string{}, running: map[string]int{}, closedAt: map[string]time.Time{}}
}

func (r *windowRepo) pendingAsRead(cmd *commanddom.Command) *commanddom.Command {
	c := r.commands[cmd.ID.String()]
	if c == nil || c.TenantID != cmd.TenantID || c.Status != commanddom.CommandStatusPending || string(c.Payload) != string(cmd.Payload) {
		return nil
	}
	return c
}

func (r *windowRepo) DeferPending(_ context.Context, cmd *commanddom.Command, d commanddom.WindowDeferral) (bool, error) {
	c := r.pendingAsRead(cmd)
	if c == nil {
		return false, nil
	}
	until := d.Until
	c.ScheduledAt = &until
	r.deferred[c.ID.String()] = d
	return true, nil
}

func (r *windowRepo) SplitPending(_ context.Context, cmd *commanddom.Command, keep, wait json.RawMessage, d commanddom.WindowDeferral) (shared.ID, bool, error) {
	c := r.pendingAsRead(cmd)
	if c == nil {
		return shared.ID{}, false, nil
	}
	c.Payload = keep
	sib := *c
	sib.ID = shared.NewID()
	sib.Payload = wait
	until := d.Until
	sib.ScheduledAt = &until
	r.commands[sib.ID.String()] = &sib
	r.siblings = append(r.siblings, &sib)
	r.deferred[sib.ID.String()] = d
	return sib.ID, true, nil
}

func (r *windowRepo) RecordWindowPolicies(_ context.Context, cmd *commanddom.Command, ids []string) (bool, error) {
	r.recorded[cmd.ID.String()] = ids
	return true, nil
}

func (r *windowRepo) CountRunningUnderPolicies(_ context.Context, _ shared.ID, ids []string) (map[string]int, error) {
	out := map[string]int{}
	for _, id := range ids {
		out[id] = r.running[id]
	}
	return out, nil
}

func (r *windowRepo) ReleaseWindowHolds(context.Context, shared.ID) (int64, error) {
	r.released++
	return 0, nil
}

func (r *windowRepo) RunningProbing(_ context.Context, tenantID shared.ID, _ int) ([]*commanddom.RunningCommand, error) {
	var out []*commanddom.RunningCommand
	for _, c := range r.commands {
		if c.TenantID != tenantID || (c.Status != commanddom.CommandStatusRunning && c.Status != commanddom.CommandStatusAcknowledged) {
			continue
		}
		rc := &commanddom.RunningCommand{Command: c, SensorID: c.SensorID, LeaseEpoch: c.LeaseEpoch}
		if at, ok := r.closedAt[c.ID.String()]; ok {
			rc.WindowClosedAt = &at
		}
		out = append(out, rc)
	}
	return out, nil
}

func (r *windowRepo) MarkWindowClosed(_ context.Context, _ shared.ID, ids []shared.ID, at time.Time) error {
	for _, id := range ids {
		if _, ok := r.closedAt[id.String()]; !ok {
			r.closedAt[id.String()] = at
		}
	}
	return nil
}

func (r *windowRepo) ClearWindowClosed(_ context.Context, _ shared.ID, ids []shared.ID) error {
	for _, id := range ids {
		delete(r.closedAt, id.String())
	}
	return nil
}

func (r *windowRepo) RequeueForWindow(_ context.Context, rc *commanddom.RunningCommand, d commanddom.WindowDeferral) (bool, error) {
	c := r.commands[rc.Command.ID.String()]
	if c == nil || c.LeaseEpoch != rc.LeaseEpoch {
		return false, nil
	}
	c.Status = commanddom.CommandStatusPending
	c.SensorID = nil
	until := d.Until
	c.ScheduledAt = &until
	delete(r.closedAt, c.ID.String())
	r.deferred[c.ID.String()] = d
	r.requeued = append(r.requeued, c.ID.String())
	return true, nil
}

// windowAssets names the assets behind targets.
type windowAssets map[string][]swdom.TargetAsset

func (w windowAssets) MatchTargetAssets(_ context.Context, _ shared.ID, targets []string) (map[string][]swdom.TargetAsset, error) {
	out := map[string][]swdom.TargetAsset{}
	for _, t := range targets {
		out[t] = w[t]
	}
	return out, nil
}

// askedPolicies records the tenants the policies were listed for.
type askedPolicies struct {
	*fakeWindowPolicies
	tenants []shared.ID
}

func (a *askedPolicies) List(ctx context.Context, tenantID shared.ID, f swdom.Filter) ([]*swdom.Policy, error) {
	a.tenants = append(a.tenants, tenantID)
	return a.fakeWindowPolicies.List(ctx, tenantID, f)
}

// monday10 is the fixtures' clock: Monday 2026-10-05 10:00 UTC.
var monday10 = time.Date(2026, 10, 5, 10, 0, 0, 0, time.UTC)

type windowFixture struct {
	*recheckFixture
	repo     *windowRepo
	policies *askedPolicies
}

func newWindowFixture(assets windowAssets) *windowFixture {
	rf := newRecheckFixture()
	repo := newWindowRepo()
	rf.repo = repo.recheckRepo
	policies := &askedPolicies{fakeWindowPolicies: &fakeWindowPolicies{}}
	res := swapp.NewResolver(policies, nil)
	res.SetAssets(assets)
	rf.svc = command.NewService(repo, newCmdTestLogger(), command.WithScanWindows(res),
		command.WithClock(func() time.Time { return monday10 }))
	rf.svc.SetFailureObserver(rf.steps)
	return &windowFixture{recheckFixture: rf, repo: repo, policies: policies}
}

// weeklyPolicy is an enabled policy of the fixture's tenant with one
// weekly UTC slot.
func (f *windowFixture) weeklyPolicy(t *testing.T, name string, kind swdom.Kind, sel swdom.Selector, days []int, start, end string, mut ...func(*swdom.Spec)) *swdom.Policy {
	t.Helper()
	spec := swdom.Spec{Name: name, Kind: kind, MinTier: swdom.TierActive, Timezone: "UTC", Enabled: true,
		Selector: sel, Slots: []swdom.Slot{{Days: days, Start: start, End: end}}}
	for _, m := range mut {
		m(&spec)
	}
	p, err := swdom.NewPolicy(f.tenant, spec, nil, monday10)
	if err != nil {
		t.Fatal(err)
	}
	f.policies.policies = append(f.policies.policies, p)
	return p
}

func holdOf(t *testing.T, d commanddom.WindowDeferral) swdom.Hold {
	t.Helper()
	var h swdom.Hold
	if err := json.Unmarshal(d.Hold, &h); err != nil {
		t.Fatalf("hold %s: %v", d.Hold, err)
	}
	return h
}

const windowPayload = `{"scanner":"nuclei","targets":["app.example.com"],"config":{"rate_limit":50}}`

// Outside its window the job is not handed out, on any path: it is
// deferred (at most an hour at a time) with the reason and the opening, its
// expiry and its run's deadline move with the wait, and it stays pending.
func TestWindowHold_OutsideTheWindowDefers(t *testing.T) {
	for _, path := range handOutPaths {
		t.Run(path.name, func(t *testing.T) {
			f := newWindowFixture(nil)
			f.weeklyPolicy(t, "weekends only", swdom.KindAllow, swdom.Selector{}, []int{6}, "09:00", "17:00")
			c := f.repo.add(f.tenant, commanddom.CommandTypeScan, windowPayload, nil)

			got, err := path.run(f.recheckFixture, c)
			if got != nil {
				t.Fatal("handed out outside its window")
			}
			if path.name == "claim by id" && !errors.Is(err, command.ErrOutsideWindow) {
				t.Fatalf("claim by id: %v", err)
			}
			d, ok := f.repo.deferred[c.ID.String()]
			if !ok {
				t.Fatal("not deferred")
			}
			saturday := time.Date(2026, 10, 10, 9, 0, 0, 0, time.UTC)
			if !d.Until.Equal(monday10.Add(time.Hour)) || !d.ExtendExpiry || d.RunOpensAt == nil || !d.RunOpensAt.Equal(saturday) {
				t.Fatalf("deferral = %+v, want an hour ahead, expiry extended, run deadline from Saturday 09:00", d)
			}
			h := holdOf(t, d)
			if h.Reason != swdom.HoldWindow || h.NextOpenAt == nil || !h.NextOpenAt.Equal(saturday) ||
				len(h.Blocking) != 1 || h.Blocking[0].Name != "weekends only" {
				t.Fatalf("hold = %+v", h)
			}
			if f.repo.commands[c.ID.String()].Status != commanddom.CommandStatusPending {
				t.Fatal("a deferred job must stay pending")
			}
		})
	}
}

// Inside its window the job goes, with the policy's rate cap.
func TestWindowHold_InsideTheWindowCarriesTheRateCap(t *testing.T) {
	for _, path := range handOutPaths {
		t.Run(path.name, func(t *testing.T) {
			f := newWindowFixture(nil)
			f.weeklyPolicy(t, "business hours", swdom.KindAllow, swdom.Selector{}, weekdaysISO, "09:00", "17:00",
				func(s *swdom.Spec) { s.RateLimitRPS = 7 })
			c := f.repo.add(f.tenant, commanddom.CommandTypeScan, windowPayload, nil)
			got, err := path.run(f.recheckFixture, c)
			if err != nil || got == nil {
				t.Fatalf("hand-out: %v %v", got, err)
			}
			if v := payloadMap(t, got.Payload)["config"].(map[string]any)["rate_limit"]; v != float64(7) {
				t.Fatalf("rate_limit = %v, want the window's 7", v)
			}
			if len(f.repo.deferred) != 0 {
				t.Fatal("an open job was deferred")
			}
		})
	}
}

var weekdaysISO = []int{1, 2, 3, 4, 5}

// A job of a run step with targets inside and outside their windows is
// split: the open targets go now, the others wait in a sibling job of the
// same step.
func TestWindowHold_SplitsAStepJob(t *testing.T) {
	assets := windowAssets{"b.example.com": {{ID: shared.NewID().String(), Name: "b.example.com", Tags: []string{"Business-Hours"}}}}
	for _, path := range handOutPaths {
		t.Run(path.name, func(t *testing.T) {
			f := newWindowFixture(assets)
			f.weeklyPolicy(t, "b after hours only", swdom.KindAllow, swdom.Selector{Tags: []string{"business-hours"}}, []int{6}, "00:00", "00:00")
			c := f.repo.add(f.tenant, commanddom.CommandTypeScan, stepPayload, nil)
			step := shared.NewID()
			c.StepRunID = &step

			got, err := path.run(f.recheckFixture, c)
			if err != nil || got == nil {
				t.Fatalf("hand-out: %v %v", got, err)
			}
			if targets, _, ctxTargets := payloadTargetList(t, got.Payload); !slices.Equal(targets, []string{"a.example.com", "c.example.com"}) ||
				len(ctxTargets) != 2 {
				t.Fatalf("handed out targets %v (context %v), want a and c", targets, ctxTargets)
			}
			if len(f.repo.siblings) != 1 {
				t.Fatalf("siblings = %d, want one waiting job", len(f.repo.siblings))
			}
			sib := f.repo.siblings[0]
			if targets, _, _ := payloadTargetList(t, sib.Payload); !slices.Equal(targets, []string{"b.example.com"}) ||
				sib.StepRunID == nil || *sib.StepRunID != step || sib.ScheduledAt == nil {
				t.Fatalf("sibling = %+v %s", sib, sib.Payload)
			}
		})
	}
}

// Any other job (a validation, a retest) waits whole until every target
// is open.
func TestWindowHold_OtherJobsWaitWhole(t *testing.T) {
	assets := windowAssets{"b.example.com": {{ID: shared.NewID().String(), Tags: []string{"business-hours"}}}}
	f := newWindowFixture(assets)
	f.weeklyPolicy(t, "b on Saturdays", swdom.KindAllow, swdom.Selector{Tags: []string{"business-hours"}}, []int{6}, "00:00", "00:00")
	c := f.repo.add(f.tenant, commanddom.CommandTypeValidate, `{"targets":["a.example.com","b.example.com"]}`, nil)
	cmds, err := f.svc.Poll(context.Background(), command.PollInput{TenantID: f.tenant.String(), SensorID: f.sensor.String(), Limit: 10})
	if err != nil || find(cmds, c) != nil {
		t.Fatalf("poll: %v, handed out %v", err, find(cmds, c))
	}
	if _, ok := f.repo.deferred[c.ID.String()]; !ok || len(f.repo.siblings) != 0 {
		t.Fatal("a validation must wait whole, not be split")
	}
}

// Targets that never open are re-checked hourly without extending the
// job's expiry or the run's deadline.
func TestWindowHold_NeverOpens(t *testing.T) {
	f := newWindowFixture(nil)
	p, err := swdom.NewPolicy(f.tenant, swdom.Spec{Name: "past slot", Kind: swdom.KindAllow, MinTier: 1, Timezone: "UTC",
		Enabled: true, OneOffs: []swdom.OneOff{{StartsAt: monday10.Add(-48 * time.Hour), EndsAt: monday10.Add(-47 * time.Hour)}}}, nil, monday10)
	if err != nil {
		t.Fatal(err)
	}
	f.policies.policies = []*swdom.Policy{p}
	c := f.repo.add(f.tenant, commanddom.CommandTypeScan, windowPayload, nil)
	if cmds, _ := f.svc.Poll(context.Background(), command.PollInput{TenantID: f.tenant.String(), SensorID: f.sensor.String(), Limit: 10}); find(cmds, c) != nil {
		t.Fatal("handed out a job whose window never opens")
	}
	d := f.repo.deferred[c.ID.String()]
	if !d.Until.Equal(monday10.Add(time.Hour)) || d.ExtendExpiry || d.RunOpensAt != nil || !holdOf(t, d).Never {
		t.Fatalf("deferral = %+v", d)
	}
}

// Passive (T0) work is not governed by an active-tier policy.
func TestWindowHold_PassiveToolIsNotHeld(t *testing.T) {
	f := newWindowFixture(nil)
	f.weeklyPolicy(t, "blackout", swdom.KindBlackout, swdom.Selector{}, weekdaysISO, "00:00", "00:00")
	c := f.repo.add(f.tenant, commanddom.CommandTypeScan, `{"scanner":"subfinder","targets":["example.com"]}`, nil)
	cmds, err := f.svc.Poll(context.Background(), command.PollInput{TenantID: f.tenant.String(), SensorID: f.sensor.String(), Limit: 10})
	if err != nil || find(cmds, c) == nil {
		t.Fatalf("passive job held: %v", err)
	}
}

// A reached concurrency cap defers the job a minute; the cap counts what
// this poll hands out too.
func TestWindowHold_ConcurrencyCap(t *testing.T) {
	f := newWindowFixture(nil)
	p := f.weeklyPolicy(t, "one at a time", swdom.KindAllow, swdom.Selector{}, weekdaysISO, "09:00", "17:00",
		func(s *swdom.Spec) { s.MaxConcurrent = 1 })
	a := f.repo.add(f.tenant, commanddom.CommandTypeScan, windowPayload, nil)
	b := f.repo.add(f.tenant, commanddom.CommandTypeScan, `{"scanner":"nuclei","targets":["other.example.com"]}`, nil)
	cmds, err := f.svc.Poll(context.Background(), command.PollInput{TenantID: f.tenant.String(), SensorID: f.sensor.String(), Limit: 10})
	if err != nil || len(cmds) != 1 {
		t.Fatalf("poll handed out %d jobs (%v), want one under a cap of 1", len(cmds), err)
	}
	held := a
	if find(cmds, a) != nil {
		held = b
	}
	d, ok := f.repo.deferred[held.ID.String()]
	if !ok || !d.Until.Equal(monday10.Add(time.Minute)) || holdOf(t, d).Reason != swdom.HoldConcurrency {
		t.Fatalf("capped job deferral = %+v", d)
	}
	if ids := f.repo.recorded[cmds[0].ID.String()]; len(ids) != 1 || ids[0] != p.ID.String() {
		t.Fatalf("recorded policies = %v", ids)
	}

	// Already at the cap: nothing goes.
	f2 := newWindowFixture(nil)
	p2 := f2.weeklyPolicy(t, "one at a time", swdom.KindAllow, swdom.Selector{}, weekdaysISO, "09:00", "17:00",
		func(s *swdom.Spec) { s.MaxConcurrent = 1 })
	f2.repo.running[p2.ID.String()] = 1
	c := f2.repo.add(f2.tenant, commanddom.CommandTypeScan, windowPayload, nil)
	if _, err := f2.svc.Acknowledge(context.Background(), f2.tenant.String(), f2.sensor.String(), c.ID.String()); !errors.Is(err, command.ErrOutsideWindow) {
		t.Fatalf("claim by id at the cap: %v", err)
	}
}

// A policy store that cannot be read withholds probing jobs for this poll
// (fail closed) and writes nothing.
func TestWindowHold_LookupErrorWithholds(t *testing.T) {
	f := newWindowFixture(nil)
	f.policies.err = errors.New("db down")
	c := f.repo.add(f.tenant, commanddom.CommandTypeScan, windowPayload, nil)
	other := f.repo.add(f.tenant, commanddom.CommandTypeHealthCheck, `{}`, nil)
	cmds, err := f.svc.Poll(context.Background(), command.PollInput{TenantID: f.tenant.String(), SensorID: f.sensor.String(), Limit: 10})
	if err != nil || find(cmds, c) != nil || find(cmds, other) == nil {
		t.Fatalf("poll: %v; probing job handed out = %v, health check = %v", err, find(cmds, c) != nil, find(cmds, other) != nil)
	}
	if len(f.repo.deferred) != 0 {
		t.Fatal("a failed lookup must not write a deferral")
	}
}

// The hold reads only the polling tenant's policies and never decides
// another tenant's job.
func TestWindowHold_NeverActsAcrossTenants(t *testing.T) {
	f := newWindowFixture(nil)
	f.weeklyPolicy(t, "weekends only", swdom.KindAllow, swdom.Selector{}, []int{6}, "09:00", "17:00")
	foreign := f.repo.add(shared.NewID(), commanddom.CommandTypeScan, windowPayload, nil)
	_, _ = f.svc.Poll(context.Background(), command.PollInput{TenantID: f.tenant.String(), SensorID: f.sensor.String(), Limit: 10})
	if _, ok := f.repo.deferred[foreign.ID.String()]; ok {
		t.Fatal("another tenant's job was deferred")
	}
	for _, tid := range f.policies.tenants {
		if tid != f.tenant {
			t.Fatalf("policies listed for tenant %s", tid)
		}
	}
}

// An active override suspends the organization's policies.
func TestWindowHold_OverrideLetsTheJobGo(t *testing.T) {
	f := newWindowFixture(nil)
	f.weeklyPolicy(t, "weekends only", swdom.KindAllow, swdom.Selector{}, []int{6}, "09:00", "17:00")
	o, err := swdom.NewOverride(f.tenant, nil, "incident 4711 rescan now", time.Hour, nil, monday10.Add(-time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	res := swapp.NewResolver(f.policies, fixedOverrides{o})
	f.svc = command.NewService(f.repo, newCmdTestLogger(), command.WithScanWindows(res),
		command.WithClock(func() time.Time { return monday10 }))
	c := f.repo.add(f.tenant, commanddom.CommandTypeScan, windowPayload, nil)
	cmds, err := f.svc.Poll(context.Background(), command.PollInput{TenantID: f.tenant.String(), SensorID: f.sensor.String(), Limit: 10})
	if err != nil || find(cmds, c) == nil {
		t.Fatalf("override not honored: %v", err)
	}
}

type fixedOverrides []*swdom.Override

func (o fixedOverrides) ListActive(context.Context, shared.ID, time.Time) ([]*swdom.Override, error) {
	return o, nil
}

type windowTenantList []shared.ID

func (w windowTenantList) TenantsWithWindows(context.Context) ([]shared.ID, error) { return w, nil }

// A window that closes under a running job: first it is marked, after the
// grace it goes back to the queue for the next opening (unpinned, so its
// sensor is told to stop); a job whose window is open again is unmarked.
func TestEnforceClosedWindows_GraceThenRequeue(t *testing.T) {
	f := newWindowFixture(nil)
	f.weeklyPolicy(t, "evening freeze", swdom.KindBlackout, swdom.Selector{}, []int{1}, "09:30", "12:00",
		func(s *swdom.Spec) { s.GraceMinutes = 15 })
	c := f.repo.add(f.tenant, commanddom.CommandTypeScan, windowPayload, nil)
	sensor := f.sensor
	c.Status, c.SensorID, c.LeaseEpoch = commanddom.CommandStatusRunning, &sensor, 3
	tenants := windowTenantList{f.tenant}

	if n, err := f.svc.EnforceClosedWindows(context.Background(), tenants); err != nil || n != 0 {
		t.Fatalf("first pass requeued %d (%v), want the grace first", n, err)
	}
	if _, marked := f.repo.closedAt[c.ID.String()]; !marked {
		t.Fatal("first pass did not mark the job")
	}
	f.repo.closedAt[c.ID.String()] = monday10.Add(-16 * time.Minute)
	if n, err := f.svc.EnforceClosedWindows(context.Background(), tenants); err != nil || n != 1 {
		t.Fatalf("after the grace requeued %d (%v), want 1", n, err)
	}
	if c.Status != commanddom.CommandStatusPending || c.SensorID != nil || c.ScheduledAt == nil ||
		holdOf(t, f.repo.deferred[c.ID.String()]).Reason != swdom.HoldClosed {
		t.Fatalf("requeued job = %+v", c)
	}

	// Window open again within the grace: unmarked, left running.
	g := newWindowFixture(nil)
	g.weeklyPolicy(t, "early freeze", swdom.KindBlackout, swdom.Selector{}, []int{1}, "06:00", "07:00")
	r := g.repo.add(g.tenant, commanddom.CommandTypeScan, windowPayload, nil)
	r.Status, r.SensorID = commanddom.CommandStatusRunning, &sensor
	g.repo.closedAt[r.ID.String()] = monday10.Add(-time.Minute)
	if _, err := g.svc.EnforceClosedWindows(context.Background(), windowTenantList{g.tenant}); err != nil {
		t.Fatal(err)
	}
	if _, marked := g.repo.closedAt[r.ID.String()]; marked || r.Status != commanddom.CommandStatusRunning {
		t.Fatal("a job back inside its window must be unmarked and left running")
	}
}

// Grace 0 (and program windows, which have none) stops the job at once.
func TestEnforceClosedWindows_NoGrace(t *testing.T) {
	f := newWindowFixture(nil)
	f.weeklyPolicy(t, "hard stop", swdom.KindBlackout, swdom.Selector{}, []int{1}, "09:30", "12:00",
		func(s *swdom.Spec) { s.GraceMinutes = 0 })
	c := f.repo.add(f.tenant, commanddom.CommandTypeScan, windowPayload, nil)
	sensor := f.sensor
	c.Status, c.SensorID = commanddom.CommandStatusAcknowledged, &sensor
	if n, err := f.svc.EnforceClosedWindows(context.Background(), windowTenantList{f.tenant}); err != nil || n != 1 {
		t.Fatalf("requeued %d (%v), want 1 at once", n, err)
	}
}
