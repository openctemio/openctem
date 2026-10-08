package main

import (
	"context"
	"sync"
	"time"

	"github.com/openctemio/openctem/api/internal/app/scanrun"
	"github.com/openctemio/openctem/api/internal/infra/websocket"
	"github.com/openctemio/openctem/api/pkg/domain/permission"
	scanrundom "github.com/openctemio/openctem/api/pkg/domain/scanrun"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// runChangeEvent is what a run:{id} subscriber receives: only that the run
// changed. It re-reads the run through the gated endpoints, so the event
// itself carries nothing the subscriber could not otherwise see.
type runChangeEvent struct {
	Type  string `json:"type"`
	RunID string `json:"run_id"`
}

// runChangeThrottle coalesces a run's changes: the first change of a run
// schedules one event `wait` later; changes in between ride along. A busy
// run with hundreds of chunks costs its watchers one refresh per window.
type runChangeThrottle struct {
	hub     eventBroadcaster
	wait    time.Duration
	mu      sync.Mutex
	pending map[shared.ID]bool
}

// eventBroadcaster is the broadcast of the websocket hub (*websocket.Hub).
type eventBroadcaster interface {
	BroadcastEvent(channel string, data any, tenantID string)
}

func newRunChangeThrottle(hub eventBroadcaster, wait time.Duration) *runChangeThrottle {
	return &runChangeThrottle{hub: hub, wait: wait, pending: map[shared.ID]bool{}}
}

var _ scanrun.RunNotifier = (*runChangeThrottle)(nil)

func (t *runChangeThrottle) RunChanged(tenantID, runID shared.ID) {
	t.mu.Lock()
	if t.pending[runID] {
		t.mu.Unlock()
		return
	}
	t.pending[runID] = true
	t.mu.Unlock()
	time.AfterFunc(t.wait, func() {
		t.mu.Lock()
		delete(t.pending, runID)
		t.mu.Unlock()
		t.hub.BroadcastEvent(websocket.MakeChannel(websocket.ChannelTypeRun, runID.String()),
			runChangeEvent{Type: "run.changed", RunID: runID.String()}, tenantID.String())
	})
}

// runReader reads a run of a tenant (*scanrun.Service).
type runReader interface {
	GetRun(ctx context.Context, tenantID, runID string) (*scanrundom.Run, error)
}

// CanSeeRun applies the run reads' rules to the run:{id} channel: the run
// must exist in the tenant, and a run about a finding (retest, validation)
// also needs findings:read and that finding in the user's data scope.
func (a wsChannelAccess) CanSeeRun(ctx context.Context, tenantID, userID, runID string) (bool, error) {
	if a.runs == nil {
		return false, nil
	}
	if _, err := shared.IDFromString(runID); err != nil {
		return false, err
	}
	run, err := a.runs.GetRun(ctx, tenantID, runID)
	if err != nil {
		return false, err
	}
	kind := run.KindOrDefault()
	if kind != scanrundom.RunKindRetest && kind != scanrundom.RunKindValidation {
		return true, nil
	}
	if ok, err := a.roles.HasPermission(ctx, tenantID, userID, permission.FindingsRead.String()); err != nil || !ok {
		return false, err
	}
	findingID, _ := run.Subject["finding_id"].(string)
	if findingID == "" {
		return false, nil
	}
	return a.CanSeeFinding(ctx, tenantID, userID, findingID)
}
