package controller

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/logger"
)

// SLABreachEvent is emitted once per finding on the transition into
// the `breached` SLA state. Downstream consumers (notification outbox,
// Jira commenter, PagerDuty router) subscribe via the publisher.
//
// B4: closes the feedback edge where SLA status was
// previously computed but never acted on. Dedup via the SLA breach
// transition itself — a second controller run won't re-emit because
// rows already in `breached` state don't match the UPDATE WHERE clause.
type SLABreachEvent struct {
	TenantID        shared.ID
	FindingID       shared.ID
	SLADeadline     time.Time
	OverdueDuration time.Duration
	At              time.Time
}

// SLABreachPublisher delivers breach events to downstream consumers.
// Optional — nil publisher means "log only" (legacy behaviour).
type SLABreachPublisher interface {
	Publish(ctx context.Context, event SLABreachEvent) error
}

// SLABreachTxPublisher is an optional extension of SLABreachPublisher that
// enqueues a breach event inside a caller-supplied transaction. When the wired
// publisher implements it, the controller couples the `breached` state change
// and the notification enqueue in ONE transaction, so a crash/failure between
// them can't leave a finding permanently breached with its notification lost
// (the breach UPDATE's WHERE clause excludes already-breached rows, so a lost
// notification would never be retried).
type SLABreachTxPublisher interface {
	PublishTx(ctx context.Context, tx *sql.Tx, event SLABreachEvent) error
}

// breachSelectUpdateQuery transitions overdue findings to `breached` and
// RETURNs the fields the publisher needs. Shared by the tx and legacy paths.
const breachSelectUpdateQuery = `
	UPDATE findings SET
		sla_status = 'breached',
		updated_at = NOW()
	WHERE sla_deadline < NOW()
	  AND sla_deadline IS NOT NULL
	  AND (sla_status IS NULL OR sla_status NOT IN ('breached', 'not_applicable'))
	  AND status NOT IN ('closed', 'resolved', 'false_positive', 'verified')
	RETURNING tenant_id, id, sla_deadline
`

type breachRow struct {
	tenantID    string
	findingID   string
	slaDeadline time.Time
}

// SLAEscalationController periodically checks for overdue findings
// and updates their sla_status to 'breached'. Runs every 15 minutes.
//
// Note: This operates across all tenants intentionally — it's a system-level
// background job that marks overdue findings within their own rows.
// Each finding's tenant_id remains unchanged.
//
// RFC-005 Gap 7 + B4: Automated SLA Escalation with publisher.
type SLAEscalationController struct {
	db     *sql.DB
	logger *logger.Logger
	// B4: optional publisher that fires one event per newly-breached
	// finding. Nil → legacy log-only behaviour.
	publisher SLABreachPublisher
}

// NewSLAEscalationController creates a new SLA escalation controller.
func NewSLAEscalationController(db *sql.DB, log *logger.Logger) *SLAEscalationController {
	return &SLAEscalationController{
		db:     db,
		logger: log,
	}
}

// SetBreachPublisher wires the breach-event publisher. Safe after
// construction; nil disables publishing.
func (c *SLAEscalationController) SetBreachPublisher(p SLABreachPublisher) {
	c.publisher = p
}

// Name returns the controller name.
func (c *SLAEscalationController) Name() string { return "sla-escalation" }

// Interval returns 15 minutes.
func (c *SLAEscalationController) Interval() time.Duration { return 15 * time.Minute }

// Reconcile checks for overdue findings and marks them as breached.
//
// B4: For every row newly-transitioned into `breached`, a SLABreachEvent
// is emitted via the publisher. Dedup is structural — the WHERE clause
// excludes rows already in `breached`, so a second run won't re-emit.
func (c *SLAEscalationController) Reconcile(ctx context.Context) (int, error) {
	total, err := c.markBreached(ctx)
	if err != nil {
		return 0, err
	}
	c.markWarning(ctx) // advisory + idempotent; never blocks the breach pass
	return total, nil
}

// markBreached transitions overdue findings to `breached` and fans the events
// out to the publisher. When the publisher is transaction-aware the state
// change and the enqueues commit atomically; otherwise it falls back to the
// legacy autocommit-then-publish path.
func (c *SLAEscalationController) markBreached(ctx context.Context) (int, error) {
	if txPub, ok := c.publisher.(SLABreachTxPublisher); ok {
		return c.markBreachedTx(ctx, txPub)
	}
	return c.markBreachedLegacy(ctx)
}

// markBreachedTx couples the breach UPDATE and the notification enqueues in one
// transaction: if any enqueue fails (or the process dies before commit) the
// whole batch rolls back and is retried on the next tick, instead of leaving
// findings breached with their notifications silently dropped.
func (c *SLAEscalationController) markBreachedTx(ctx context.Context, txPub SLABreachTxPublisher) (int, error) {
	tx, err := c.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("sla escalation begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	rows, err := tx.QueryContext(ctx, breachSelectUpdateQuery)
	if err != nil {
		return 0, fmt.Errorf("sla escalation: %w", err)
	}
	// Collect + close BEFORE enqueuing: lib/pq forbids a second statement on
	// the same tx while these rows are still open.
	breaches, scanErr := c.scanBreaches(rows)
	_ = rows.Close()
	if scanErr != nil {
		return 0, scanErr
	}
	c.logBreachCounts(breaches)

	now := time.Now().UTC()
	for _, br := range breaches {
		ev, ok := breachEvent(br, now)
		if !ok {
			continue
		}
		if err := txPub.PublishTx(ctx, tx, ev); err != nil {
			// Roll back the whole batch — these findings stay non-breached
			// and are retried next run, keeping state ⇔ notification in sync.
			return 0, fmt.Errorf("enqueue sla breach (finding %s): %w", br.findingID, err)
		}
	}

	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("sla escalation commit: %w", err)
	}
	return len(breaches), nil
}

// markBreachedLegacy is the pre-existing behaviour for a nil / non-transactional
// publisher: autocommit the UPDATE, then best-effort publish (errors logged).
func (c *SLAEscalationController) markBreachedLegacy(ctx context.Context) (int, error) {
	rows, err := c.db.QueryContext(ctx, breachSelectUpdateQuery)
	if err != nil {
		return 0, fmt.Errorf("sla escalation: %w", err)
	}
	breaches, scanErr := c.scanBreaches(rows)
	_ = rows.Close()
	if scanErr != nil {
		return 0, scanErr
	}
	c.logBreachCounts(breaches)

	if c.publisher != nil {
		now := time.Now().UTC()
		for _, br := range breaches {
			ev, ok := breachEvent(br, now)
			if !ok {
				continue
			}
			if err := c.publisher.Publish(ctx, ev); err != nil {
				c.logger.Warn("sla breach publish failed",
					"finding_id", br.findingID, "error", err)
			}
		}
	}
	return len(breaches), nil
}

func (c *SLAEscalationController) scanBreaches(rows *sql.Rows) ([]breachRow, error) {
	var breaches []breachRow
	for rows.Next() {
		var br breachRow
		if err := rows.Scan(&br.tenantID, &br.findingID, &br.slaDeadline); err != nil {
			return nil, fmt.Errorf("scan breach row: %w", err)
		}
		breaches = append(breaches, br)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate breach rows: %w", err)
	}
	return breaches, nil
}

func (c *SLAEscalationController) logBreachCounts(breaches []breachRow) {
	byTenant := make(map[string]int)
	for _, br := range breaches {
		byTenant[br.tenantID]++
	}
	for tid, count := range byTenant {
		c.logger.Warn("SLA breached findings detected", "tenant_id", tid, "count", count)
	}
}

// breachEvent builds the event for a row; ok=false when an ID can't be parsed.
func breachEvent(br breachRow, now time.Time) (SLABreachEvent, bool) {
	tid, err := shared.IDFromString(br.tenantID)
	if err != nil {
		return SLABreachEvent{}, false
	}
	fid, err := shared.IDFromString(br.findingID)
	if err != nil {
		return SLABreachEvent{}, false
	}
	return SLABreachEvent{
		TenantID:        tid,
		FindingID:       fid,
		SLADeadline:     br.slaDeadline,
		OverdueDuration: now.Sub(br.slaDeadline),
		At:              now,
	}, true
}

// markWarning flags findings approaching their deadline (within 3 days). It is
// idempotent and advisory — errors are logged, never returned.
func (c *SLAEscalationController) markWarning(ctx context.Context) {
	// Mark findings approaching deadline (within 3 days) as warning
	warningQuery := `
		UPDATE findings SET
			sla_status = 'warning',
			updated_at = NOW()
		WHERE sla_deadline IS NOT NULL
		  AND sla_deadline > NOW()
		  AND sla_deadline < NOW() + INTERVAL '3 days'
		  AND (sla_status IS NULL OR sla_status = 'on_track')
		  AND status NOT IN ('closed', 'resolved', 'false_positive', 'verified')
	`

	warningResult, err := c.db.ExecContext(ctx, warningQuery)
	if err != nil {
		c.logger.Warn("sla warning update failed", "error", err)
	} else {
		warned, _ := warningResult.RowsAffected()
		if warned > 0 {
			c.logger.Info("SLA warning findings updated", "count", warned)
		}
	}
}
