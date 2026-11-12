package command

// When a scan window closes under running work (RFC-067 §6.4, decision W7):
// no new chunk is handed out (the claim hold); the running chunk may go on
// for the smallest grace of the windows that now block it (program windows:
// none); then it is returned to the queue, deferred to the next opening,
// and its sensor is told to stop (the heartbeat cancel list of re-queued
// commands). Whatever the old holder reports afterwards fails the lease
// fence. A chunk whose window opens again within the grace is left alone.

import (
	"context"
	"time"

	commanddom "github.com/openctemio/openctem/api/pkg/domain/command"
	swdom "github.com/openctemio/openctem/api/pkg/domain/scanwindow"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// WindowTenants lists the tenants that have scan windows (enabled policies
// or program testing windows).
type WindowTenants interface {
	TenantsWithWindows(ctx context.Context) ([]shared.ID, error)
}

// maxClosingPerTenant bounds one pass over a tenant's running work.
const maxClosingPerTenant = 1000

// EnforceClosedWindows makes one pass: it marks running probing jobs that
// are outside their windows and returns to the queue those whose grace has
// passed. It returns how many it returned.
func (s *Service) EnforceClosedWindows(ctx context.Context, tenants WindowTenants) (int, error) {
	store, ok := s.repo.(commanddom.WindowClosingStore)
	if s.windows == nil || tenants == nil || !ok {
		return 0, nil
	}
	ids, err := tenants.TenantsWithWindows(ctx)
	if err != nil {
		return 0, err
	}
	total := 0
	for _, tenantID := range ids {
		n, err := s.enforceTenantWindows(ctx, store, tenantID)
		if err != nil {
			s.logger.Warn("scan windows: running work not checked", "tenant_id", tenantID.String(), "error", err)
			continue
		}
		total += n
	}
	return total, nil
}

func (s *Service) enforceTenantWindows(ctx context.Context, store commanddom.WindowClosingStore, tenantID shared.ID) (int, error) {
	running, err := store.RunningProbing(ctx, tenantID, maxClosingPerTenant)
	if err != nil || len(running) == 0 {
		return 0, err
	}
	var targets []string
	for _, rc := range running {
		targets = append(targets, windowTargets(rc.Command)...)
	}
	snap, err := s.windows.Load(ctx, tenantID, targets, s.clock())
	if err != nil {
		return 0, err // fail closed would stop work on a lookup error; leave it running and retry next pass
	}
	now := snap.Now()
	var mark, clear []shared.ID
	requeued := 0
	for _, rc := range running {
		c := rc.Command
		if !c.TenantID.Equals(tenantID) {
			continue
		}
		var all []swdom.Source
		for _, t := range windowTargets(c) {
			all = append(all, snap.SourcesFor(t, c.ScanZoneID)...)
		}
		d := swdom.Decide(all, commandTier(c), now)
		if d.Open {
			if rc.WindowClosedAt != nil {
				clear = append(clear, c.ID)
			}
			continue
		}
		grace := time.Duration(d.GraceMinutes) * time.Minute
		if rc.WindowClosedAt == nil && grace > 0 {
			mark = append(mark, c.ID)
			continue
		}
		if rc.WindowClosedAt != nil && now.Sub(*rc.WindowClosedAt) < grace {
			continue
		}
		def := deferralOf(d, now)
		def.Hold = holdJSON(swdom.Hold{Reason: swdom.HoldClosed, NextOpenAt: d.NextOpen, Never: d.Never,
			Blocking: d.Blocking, CheckedAt: now})
		won, err := store.RequeueForWindow(ctx, rc, def)
		if err != nil {
			s.logger.Warn("scan windows: running job not returned to the queue", "command_id", c.ID.String(), "error", err)
			continue
		}
		if won {
			requeued++
			s.logger.Info("scan window closed: running job returned to the queue for the next opening",
				"tenant_id", tenantID.String(), "command_id", c.ID.String(), "next_open", d.NextOpen)
		}
	}
	if err := store.MarkWindowClosed(ctx, tenantID, mark, now); err != nil {
		return requeued, err
	}
	if err := store.ClearWindowClosed(ctx, tenantID, clear); err != nil {
		return requeued, err
	}
	return requeued, nil
}
