package controller

import (
	"context"
	"time"

	"github.com/openctemio/api/internal/app/threat"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/logger"
)

// ThreatIntelRefreshController periodically refreshes EPSS scores and KEV catalog.
// Runs every 24 hours. Fetches latest data from FIRST.org (EPSS) and CISA (KEV),
// then persists to database via ThreatIntelService.SyncAll().
// After sync, auto-escalates findings whose CVEs appear in the KEV catalog and
// enqueues a priority reclassify for every tenant whose findings changed.
type ThreatIntelRefreshController struct {
	service   *threat.IntelService
	escalator threat.KEVEscalator
	// reclassifyQueue receives one ReasonKEVRefresh request per tenant touched
	// by KEV escalation so their priority_class is recomputed. Optional — a nil
	// queue disables enqueue (no panic). Same instance services.go hands the
	// PriorityReclassifyController.
	reclassifyQueue ReclassifyQueue
	logger          *logger.Logger
}

// NewThreatIntelRefreshController creates a new controller. queue may be nil
// (enqueue becomes a no-op).
func NewThreatIntelRefreshController(service *threat.IntelService, escalator threat.KEVEscalator, queue ReclassifyQueue, log *logger.Logger) *ThreatIntelRefreshController {
	return &ThreatIntelRefreshController{service: service, escalator: escalator, reclassifyQueue: queue, logger: log}
}

// Name returns the controller name.
func (c *ThreatIntelRefreshController) Name() string { return "threat-intel-refresh" }

// Interval returns 24 hours — daily refresh.
func (c *ThreatIntelRefreshController) Interval() time.Duration { return 24 * time.Hour }

// Reconcile fetches and persists latest EPSS + KEV data, then auto-escalates findings.
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

	// After KEV sync, auto-escalate + flag findings with CVEs in the KEV catalog.
	if c.escalator != nil {
		res, err := c.escalator.EscalateKEVFindings(ctx)
		if err != nil {
			c.logger.Warn("KEV auto-escalation failed", "error", err)
		} else {
			if res.Escalated > 0 || res.Flagged > 0 {
				c.logger.Info("KEV reconciliation completed",
					"findings_escalated", res.Escalated,
					"findings_flagged", res.Flagged,
					"tenants_touched", len(res.Tenants),
				)
				processed += res.Escalated + res.Flagged
			}
			// Recompute priority for the touched findings: severity=critical +
			// is_in_kev=true should push them toward P0, but that only happens
			// if the classifier re-runs. Best-effort — a failed enqueue must
			// not fail the KEV sync.
			c.enqueueReclassify(ctx, res.Tenants)
		}
	}

	return processed, nil
}

// enqueueReclassify pushes one ReasonKEVRefresh request per affected tenant.
// Nil-safe (no queue → no-op) and best-effort (enqueue errors are logged, not
// returned).
func (c *ThreatIntelRefreshController) enqueueReclassify(ctx context.Context, tenants []shared.ID) {
	if c.reclassifyQueue == nil || len(tenants) == 0 {
		return
	}
	for _, tid := range tenants {
		req := ReclassifyRequest{
			TenantID:  tid,
			Reason:    ReasonKEVRefresh,
			EnqueueAt: time.Now().UTC(),
		}
		if err := c.reclassifyQueue.Enqueue(ctx, req); err != nil {
			c.logger.Warn("enqueue reclassify after KEV refresh failed",
				"tenant_id", tid.String(),
				"error", err,
			)
		}
	}
}
