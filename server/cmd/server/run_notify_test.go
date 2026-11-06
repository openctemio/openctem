package main

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	scanrundom "github.com/openctemio/openctem/api/pkg/domain/scanrun"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

type recordedEvent struct {
	channel, tenant string
	data            any
}

type recordingHub struct {
	mu     sync.Mutex
	events []recordedEvent
}

func (h *recordingHub) BroadcastEvent(channel string, data any, tenantID string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.events = append(h.events, recordedEvent{channel, tenantID, data})
}

func (h *recordingHub) snapshot() []recordedEvent {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]recordedEvent{}, h.events...)
}

// A burst of changes to one run is one event per window, on the run's
// channel and in the run's tenant; another run gets its own.
func TestRunChangeThrottle_Coalesces(t *testing.T) {
	hub := &recordingHub{}
	th := newRunChangeThrottle(hub, 20*time.Millisecond)
	tenant, run, other := shared.NewID(), shared.NewID(), shared.NewID()
	for i := 0; i < 50; i++ {
		th.RunChanged(tenant, run)
	}
	th.RunChanged(tenant, other)

	deadline := time.Now().Add(2 * time.Second)
	for len(hub.snapshot()) < 2 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	time.Sleep(40 * time.Millisecond) // nothing more may arrive
	got := hub.snapshot()
	if len(got) != 2 {
		t.Fatalf("events = %d, want 1 per run (2)", len(got))
	}
	seen := map[string]bool{}
	for _, e := range got {
		if e.tenant != tenant.String() {
			t.Errorf("event in tenant %s, want the run's tenant", e.tenant)
		}
		ev, ok := e.data.(runChangeEvent)
		if !ok || ev.Type != "run.changed" || e.channel != "run:"+ev.RunID {
			t.Errorf("event = %+v on %s", e.data, e.channel)
		}
		seen[ev.RunID] = true
	}
	if !seen[run.String()] || !seen[other.String()] {
		t.Fatalf("runs notified = %v", seen)
	}

	// After the window a new change is notified again.
	th.RunChanged(tenant, run)
	time.Sleep(60 * time.Millisecond)
	if len(hub.snapshot()) != 3 {
		t.Fatalf("a change after the window was not notified")
	}
}

type fakeRuns struct {
	runs map[string]*scanrundom.Run
}

func (f fakeRuns) GetRun(_ context.Context, tenantID, runID string) (*scanrundom.Run, error) {
	r, ok := f.runs[runID]
	if !ok || r.TenantID.String() != tenantID {
		return nil, shared.ErrNotFound
	}
	return r, nil
}

// run:{id} is open for a run of the caller's tenant; another tenant's run
// (or a missing one) is refused. Finding runs are checked further (finding
// scope) and are covered with the run handlers' access tests.
func TestWSChannelAccess_CanSeeRun(t *testing.T) {
	tenant, other := shared.NewID(), shared.NewID()
	mine := &scanrundom.Run{ID: shared.NewID(), TenantID: tenant, Kind: scanrundom.RunKindScan}
	theirs := &scanrundom.Run{ID: shared.NewID(), TenantID: other, Kind: scanrundom.RunKindScan}
	a := wsChannelAccess{runs: fakeRuns{runs: map[string]*scanrundom.Run{
		mine.ID.String(): mine, theirs.ID.String(): theirs,
	}}}
	user := shared.NewID().String()

	if ok, err := a.CanSeeRun(context.Background(), tenant.String(), user, mine.ID.String()); err != nil || !ok {
		t.Fatalf("own run: %v %v", ok, err)
	}
	if ok, err := a.CanSeeRun(context.Background(), tenant.String(), user, theirs.ID.String()); ok || !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("another tenant's run: %v %v, want refused", ok, err)
	}
	if ok, _ := a.CanSeeRun(context.Background(), tenant.String(), user, "not-a-run"); ok {
		t.Fatal("a malformed run id was accepted")
	}
	if ok, _ := (wsChannelAccess{}).CanSeeRun(context.Background(), tenant.String(), user, mine.ID.String()); ok {
		t.Fatal("no run reader: accepted")
	}
}
