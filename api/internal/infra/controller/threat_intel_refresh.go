package controller

import (
	"context"
	"time"

	"github.com/openctemio/openctem/api/internal/app/threat"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// IntelChangeQueue queues the assets of open findings whose threat intel
// moved in a way a scoring model can see (docs/architecture/scoring-versions.md,
// "Intel updates"). Implemented by postgres.ScoringRepository.
type IntelChangeQueue interface {
	EnqueueIntelChanges(ctx context.Context) (int64, error)
	// RefreshFindingEPSS writes the catalog EPSS score and percentile onto
	// every open finding whose CVE's values changed (tenant by tenant, in
	// batches), so readers of the stored value (the CI gate's
	// epss_threshold) see today's score.
	RefreshFindingEPSS(ctx context.Context) (int64, error)
}

// IntelEventEmitter reports the material KEV and EPSS changes after a sync
// (*vulnevent.Emitter, docs/rfcs/RFC-117-emerging-threat-alerts.md).
type IntelEventEmitter interface {
	EmitKEV(ctx context.Context) (int, error)
	EmitEPSS(ctx context.Context) (int, error)
}

// Which feed a refresh controller syncs.
const (
	intelFeedEPSS = "epss"
	intelFeedKEV  = "kev"
)

// ThreatIntelRefreshController periodically refreshes one threat intel feed.
// The EPSS refresh runs daily (FIRST publishes once a day); the KEV refresh
// runs hourly with a conditional request, so a CISA addition reaches
// findings and emerging-threat alerts within the hour. After a sync it
// queues a priority recompute for only the open findings whose CVE changed
// (an EPSS threshold crossed, KEV membership changed), never a whole
// tenant; the KEV refresh then auto-escalates findings whose CVEs appear in
// the catalog. Both report material changes to the vulnerability event log.
type ThreatIntelRefreshController struct {
	service   *threat.IntelService
	escalator threat.KEVEscalator
	// intelQueue is optional: nil disables the recompute (no panic).
	intelQueue IntelChangeQueue
	events     IntelEventEmitter
	feed       string
	logger     *logger.Logger
	// lastSweep is when the findings were last compared with the catalogs
	// (recompute queue, KEV escalation); see sweepDue.
	lastSweep time.Time
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

// NewThreatIntelRefreshController creates the daily EPSS refresh. queue may
// be nil.
func NewThreatIntelRefreshController(service *threat.IntelService, queue IntelChangeQueue, log *logger.Logger) *ThreatIntelRefreshController {
	return &ThreatIntelRefreshController{service: service, intelQueue: queue, feed: intelFeedEPSS, logger: log}
}

// NewKEVRefreshController creates the hourly KEV refresh. queue may be nil.
func NewKEVRefreshController(service *threat.IntelService, escalator threat.KEVEscalator, queue IntelChangeQueue, log *logger.Logger) *ThreatIntelRefreshController {
	return &ThreatIntelRefreshController{service: service, escalator: escalator, intelQueue: queue, feed: intelFeedKEV, logger: log}
}

// SetEventEmitter wires the vulnerability event log (nil: no events).
func (c *ThreatIntelRefreshController) SetEventEmitter(e IntelEventEmitter) { c.events = e }

// Name returns the controller name.
func (c *ThreatIntelRefreshController) Name() string {
	if c.feed == intelFeedKEV {
		return "kev-refresh"
	}
	return "threat-intel-refresh"
}

// Interval: hourly for KEV, daily for EPSS.
func (c *ThreatIntelRefreshController) Interval() time.Duration {
	if c.feed == intelFeedKEV {
		return time.Hour
	}
	return 24 * time.Hour
}

// Reconcile fetches and persists the feed, queues the findings whose intel
// moved, auto-escalates KEV findings and reports material changes.
func (c *ThreatIntelRefreshController) Reconcile(ctx context.Context) (int, error) {
	var r threat.IntelSyncResult
	if c.feed == intelFeedKEV {
		r = c.service.SyncKEV(ctx)
	} else {
		r = c.service.SyncEPSS(ctx)
	}
	processed := 0
	switch {
	case r.Error != nil:
		c.logger.Warn("threat intel sync failed", "source", r.Source, "error", r.Error)
	case r.NotModified:
		c.logger.Debug("threat intel unchanged", "source", r.Source)
	default:
		processed += r.RecordsSynced
		c.logger.Info("threat intel synced", "source", r.Source, "records", r.RecordsSynced, "duration_ms", r.DurationMs)
	}
	sweep := sweepDue(r.Error == nil && !r.NotModified, c.lastSweep, time.Now())
	sweepOK := true

	// Before the escalator writes is_in_kev: compare each open finding with
	// the fresh catalogs. A failed enqueue must not fail the sync.
	if sweep && c.intelQueue != nil {
		n, err := c.intelQueue.EnqueueIntelChanges(ctx)
		if err != nil {
			// The crossings are found by comparing the stored EPSS with the
			// catalog: refreshing the stored values now would lose them, so
			// the refresh waits for the next run.
			c.logger.Warn("queue findings with changed intel failed; stored EPSS not refreshed", "error", err)
			sweepOK = false
		} else {
			if n > 0 {
				c.logger.Info("findings with changed intel queued for a priority recompute", "assets", n)
			}
			// Every changed CVE, not only threshold crossings: the CI gate
			// judges the stored score against any threshold a policy sets.
			if c.feed == intelFeedEPSS {
				if m, rerr := c.intelQueue.RefreshFindingEPSS(ctx); rerr != nil {
					c.logger.Warn("refresh stored EPSS on open findings failed", "error", rerr)
				} else if m > 0 {
					c.logger.Info("stored EPSS refreshed on open findings", "findings", m)
				}
			}
		}
	}

	// After KEV sync, auto-escalate + flag findings with CVEs in the KEV
	// catalog. A severity change queues its asset by itself (trigger).
	if sweep && c.escalator != nil {
		res, err := c.escalator.EscalateKEVFindings(ctx)
		if err != nil {
			c.logger.Warn("KEV auto-escalation failed", "error", err)
			sweepOK = false
		} else if res.Escalated > 0 || res.Flagged > 0 || res.Unflagged > 0 {
			c.logger.Info("KEV reconciliation completed",
				"findings_escalated", res.Escalated,
				"findings_flagged", res.Flagged,
				"findings_unflagged", res.Unflagged,
				"tenants_touched", len(res.Tenants),
			)
			processed += res.Escalated + res.Flagged + res.Unflagged
		}
	}

	if sweep && sweepOK {
		c.lastSweep = time.Now()
	}

	// The event log compares the stored catalog with what it saw before,
	// so it also picks up a sync an operator ran by hand.
	if c.events != nil && r.Error == nil {
		var err error
		if c.feed == intelFeedKEV {
			_, err = c.events.EmitKEV(ctx)
		} else {
			_, err = c.events.EmitEPSS(ctx)
		}
		if err != nil {
			c.logger.Warn("vulnerability events not emitted", "source", r.Source, "error", err)
		}
	}

	return processed, nil
}

// Exclusive: it runs on one API replica at a time (controller lease, RFC-046
// P1.8); two replicas sweeping at once would delete or fetch twice.
func (c *ThreatIntelRefreshController) Exclusive() bool { return true }
