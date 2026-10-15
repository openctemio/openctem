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
}

// ThreatIntelRefreshController periodically refreshes EPSS scores and the KEV
// catalog. Runs every 24 hours. Fetches the latest data from FIRST.org (EPSS)
// and CISA (KEV) through ThreatIntelService.SyncAll, then queues a priority
// recompute for only the open findings whose CVE changed (an EPSS threshold
// crossed, KEV membership changed), never a whole tenant, and auto-escalates
// findings whose CVEs appear in the KEV catalog.
type ThreatIntelRefreshController struct {
	service   *threat.IntelService
	escalator threat.KEVEscalator
	// intelQueue is optional: nil disables the recompute (no panic).
	intelQueue IntelChangeQueue
	logger     *logger.Logger
}

// NewThreatIntelRefreshController creates a new controller. queue may be nil.
func NewThreatIntelRefreshController(service *threat.IntelService, escalator threat.KEVEscalator, queue IntelChangeQueue, log *logger.Logger) *ThreatIntelRefreshController {
	return &ThreatIntelRefreshController{service: service, escalator: escalator, intelQueue: queue, logger: log}
}

// Name returns the controller name.
func (c *ThreatIntelRefreshController) Name() string { return "threat-intel-refresh" }

// Interval returns 24 hours — daily refresh.
func (c *ThreatIntelRefreshController) Interval() time.Duration { return 24 * time.Hour }

// Reconcile fetches and persists the latest EPSS + KEV data, queues the
// findings whose intel moved, then auto-escalates KEV findings.
func (c *ThreatIntelRefreshController) Reconcile(ctx context.Context) (int, error) {
	results := c.service.SyncAll(ctx)

	processed := 0
	for _, r := range results {
		if r.Error != nil {
			c.logger.Warn("threat intel sync failed", "source", r.Source, "error", r.Error)
		} else {
			processed += r.RecordsSynced
			c.logger.Info("threat intel synced", "source", r.Source, "records", r.RecordsSynced, "duration_ms", r.DurationMs)
		}
	}

	// Before the escalator writes is_in_kev: compare each open finding with
	// the fresh catalogs. A failed enqueue must not fail the sync.
	if c.intelQueue != nil {
		n, err := c.intelQueue.EnqueueIntelChanges(ctx)
		if err != nil {
			c.logger.Warn("queue findings with changed intel failed", "error", err)
		} else if n > 0 {
			c.logger.Info("findings with changed intel queued for a priority recompute", "assets", n)
		}
	}

	// After KEV sync, auto-escalate + flag findings with CVEs in the KEV
	// catalog. A severity change queues its asset by itself (trigger).
	if c.escalator != nil {
		res, err := c.escalator.EscalateKEVFindings(ctx)
		if err != nil {
			c.logger.Warn("KEV auto-escalation failed", "error", err)
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

	return processed, nil
}

// Exclusive: it runs on one API replica at a time (controller lease, RFC-046
// P1.8); two replicas sweeping at once would delete or fetch twice.
func (c *ThreatIntelRefreshController) Exclusive() bool { return true }
