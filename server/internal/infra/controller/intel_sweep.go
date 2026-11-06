package controller

import (
	"context"
	"sync"
	"time"

	"github.com/openctemio/openctem/api/internal/app/threat"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// IntelSweeper is the work after a threat intel feed (KEV or EPSS) changed:
// queue the open findings whose intel moved, refresh the stored EPSS, reconcile
// the KEV flags and report material changes to the vulnerability event log.
// The refresh controllers run it after a direct sync and the vulnerability
// bundle importer runs it after it applied the same feed from a signed
// release, so the work is the same whichever path delivered the data.
// Concurrent calls are serialized.
type IntelSweeper struct {
	escalator threat.KEVEscalator
	// intelQueue is optional: nil disables the recompute (no panic).
	intelQueue IntelChangeQueue
	events     IntelEventEmitter
	logger     *logger.Logger

	mu sync.Mutex
	// lastSweep is when the findings were last compared with the catalogs
	// (recompute queue, KEV escalation); see sweepDue.
	lastSweep time.Time
}

// NewIntelSweeper creates the sweeper of one feed. escalator (KEV only) and
// queue may be nil.
func NewIntelSweeper(escalator threat.KEVEscalator, queue IntelChangeQueue, log *logger.Logger) *IntelSweeper {
	return &IntelSweeper{escalator: escalator, intelQueue: queue, logger: log}
}

// SetEventEmitter wires the vulnerability event log (nil: no events).
func (w *IntelSweeper) SetEventEmitter(e IntelEventEmitter) {
	w.mu.Lock()
	w.events = e
	w.mu.Unlock()
}

// findingSweepEvery: the comparison of open findings with the catalogs runs
// after every changed sync and at least this often even when the source
// answered 304 or failed, so findings created since (or a sweep that failed)
// are still reconciled.
const findingSweepEvery = 24 * time.Hour

// sweepDue reports whether the open findings are compared with the catalogs
// on this run: after a sync that changed something, or when the last sweep
// is findingSweepEvery old.
func sweepDue(changed bool, lastSweep, now time.Time) bool {
	return changed || lastSweep.IsZero() || now.Sub(lastSweep) >= findingSweepEvery
}

// Run sweeps for one feed ("epss" or "kev"). changed: the feed's data moved
// on this run; synced: the source did not fail (the event log is read only
// then). It returns the number of findings it reconciled.
func (w *IntelSweeper) Run(ctx context.Context, feed string, changed, synced bool) int {
	w.mu.Lock()
	defer w.mu.Unlock()
	processed := 0
	sweep := sweepDue(changed, w.lastSweep, time.Now())
	sweepOK := true

	// Before the escalator writes is_in_kev: compare each open finding with
	// the fresh catalogs. A failed enqueue must not fail the sync.
	if sweep && w.intelQueue != nil {
		n, err := w.intelQueue.EnqueueIntelChanges(ctx)
		if err != nil {
			// The crossings are found by comparing the stored EPSS with the
			// catalog: refreshing the stored values now would lose them, so
			// the refresh waits for the next run.
			w.logger.Warn("queue findings with changed intel failed; stored EPSS not refreshed", "error", err)
			sweepOK = false
		} else {
			if n > 0 {
				w.logger.Info("findings with changed intel queued for a priority recompute", "assets", n)
			}
			// Every changed CVE, not only threshold crossings: the CI gate
			// judges the stored score against any threshold a policy sets.
			if feed == intelFeedEPSS {
				if m, rerr := w.intelQueue.RefreshFindingEPSS(ctx); rerr != nil {
					w.logger.Warn("refresh stored EPSS on open findings failed", "error", rerr)
				} else if m > 0 {
					w.logger.Info("stored EPSS refreshed on open findings", "findings", m)
				}
			}
		}
	}

	// After KEV sync, flag (and unflag) findings by KEV membership. The
	// affected assets were queued above (EnqueueIntelChanges); severity is
	// never rewritten, the exploitation floor carries KEV into priority.
	if sweep && w.escalator != nil {
		res, err := w.escalator.EscalateKEVFindings(ctx)
		if err != nil {
			w.logger.Warn("KEV auto-escalation failed", "error", err)
			sweepOK = false
		} else if res.Flagged > 0 || res.Unflagged > 0 {
			w.logger.Info("KEV reconciliation completed",
				"findings_flagged", res.Flagged,
				"findings_unflagged", res.Unflagged,
				"tenants_touched", len(res.Tenants),
			)
			processed += res.Flagged + res.Unflagged
		}
	}

	if sweep && sweepOK {
		w.lastSweep = time.Now()
	}

	// The event log compares the stored catalog with what it saw before,
	// so it also picks up a sync an operator ran by hand.
	if w.events != nil && synced {
		var err error
		if feed == intelFeedKEV {
			_, err = w.events.EmitKEV(ctx)
		} else {
			_, err = w.events.EmitEPSS(ctx)
		}
		if err != nil {
			w.logger.Warn("vulnerability events not emitted", "source", feed, "error", err)
		}
	}
	return processed
}
