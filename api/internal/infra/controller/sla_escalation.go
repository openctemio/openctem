package controller

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// SLABreachEvent is emitted once per finding on the transition into
// the `overdue` SLA state (a breach of its deadline). Downstream consumers
// (notification outbox, Jira commenter, PagerDuty router) subscribe via the
// publisher.
//
// B4: closes the feedback edge where SLA status was
// previously computed but never acted on. Dedup via the SLA state
// transition itself — a second controller run won't re-emit because
// rows already in `overdue` state don't match the UPDATE WHERE clause.
type SLABreachEvent struct {
	TenantID        shared.ID
	FindingID       shared.ID
	SLADeadline     time.Time
	OverdueDuration time.Duration
	At              time.Time
	// FindingSeverity is the breached finding's own severity. The
	// notification is sent at max(high, FindingSeverity).
	FindingSeverity string
}

// SLABreachPublisher delivers breach events to downstream consumers.
// Optional — nil publisher means "log only" (legacy behavior).
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

// SLAWarningPublisher delivers "approaching deadline" events. Optional — nil
// means log-only. Unlike breach, warnings are advisory (fire-and-forget); they
// don't need a transactional publisher because a lost warning is re-derivable
// (the finding is still in `warning` until it breaches, and re-notifying on the
// next tick would only duplicate — which the transition guard already prevents,
// since a row leaves `on_track` exactly once).
type SLAWarningPublisher interface {
	PublishWarning(ctx context.Context, event SLAWarningEvent) error
}

// SLAWarningEvent describes a finding that just entered the warning window.
type SLAWarningEvent struct {
	TenantID      shared.ID
	FindingID     shared.ID
	SLADeadline   time.Time
	TimeRemaining time.Duration
	At            time.Time
}

// SetWarningPublisher wires the warning-event publisher. Safe after construction
// and before the controller starts; nil-safe.
func (c *SLAEscalationController) SetWarningPublisher(p SLAWarningPublisher) {
	c.warningPublisher = p
}

// breachSelectUpdateQuery transitions open, past-deadline findings to the
// `overdue` SLA status and RETURNs the fields the publisher needs. Shared by
// the tx and legacy paths.
//
// Vocabulary: this writes 'overdue', NOT 'breached'. 'breached' is not a member
// of the SLAStatus enum (pkg/domain/vulnerability: on_track/warning/overdue/
// exceeded/not_applicable), is rejected by the findings.sla_status CHECK
// constraint (migration 000012), and is NOT counted by the dashboard breach
// query (sla_status IN ('exceeded','overdue')). 'overdue' is the enum value for
// an OPEN finding past its deadline (the domain reserves 'exceeded' for a finding
// that was closed after its deadline), it satisfies the CHECK constraint, and it
// is what both the dashboard counter and the worst_sla_status rank agree on.
//
// Status exclusion mirrors the dashboard's closed-category set so an
// accepted-risk / accepted / duplicate finding is never marked overdue.
//
// The status always changes; whether anyone is told is the governing policy's
// escalation_enabled (column `notify`). The UPDATE repeats the status guard so
// a row another replica already moved is not returned twice.
const breachSelectUpdateQuery = `
	WITH due AS (
		SELECT f.id, COALESCE(pol.escalation_enabled, TRUE) AS notify
		FROM findings f` + effectivePolicyJoin + `
		WHERE f.sla_deadline < NOW()
		  AND f.sla_deadline IS NOT NULL
		  AND (f.sla_status IS NULL OR f.sla_status NOT IN ('overdue', 'exceeded', 'not_applicable'))
		  AND f.status NOT IN ('resolved', 'false_positive', 'accepted', 'duplicate', 'verified', 'accepted_risk')
		  AND NOT f.branch_only
	)
	UPDATE findings SET
		sla_status = 'overdue',
		updated_at = NOW()
	FROM due
	WHERE findings.id = due.id
	  AND (findings.sla_status IS NULL OR findings.sla_status NOT IN ('overdue', 'exceeded', 'not_applicable'))
	RETURNING findings.tenant_id, findings.id, findings.sla_deadline, findings.severity, due.notify
`

// effectivePolicyJoin resolves, per finding, the SLA policy that governs it:
// the asset's own active policy, else the tenant's active default — the same
// choice SLA deadline calculation makes (sla_repository.GetByAsset). A finding
// with no policy keeps the platform defaults (80 % warning, the domain default
// for a new policy; escalation on).
const effectivePolicyJoin = `
		LEFT JOIN LATERAL (
			SELECT p.warning_threshold_percent, p.escalation_enabled
			FROM sla_policies p
			WHERE p.tenant_id = f.tenant_id
			  AND p.is_active
			  AND (p.asset_id = f.asset_id OR (p.asset_id IS NULL AND p.is_default))
			ORDER BY p.asset_id NULLS LAST, p.created_at ASC
			LIMIT 1
		) pol ON TRUE`

type breachRow struct {
	tenantID    string
	findingID   string
	slaDeadline time.Time
	severity    string
	// notify is the governing policy's escalation_enabled (true without one).
	notify bool
}

// SLAEscalationController periodically checks for overdue findings
// and updates their sla_status to 'overdue'. Runs every 15 minutes.
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
	// finding. Nil → legacy log-only behavior.
	publisher SLABreachPublisher
	// Optional publisher that fires one event per finding newly transitioned
	// into the `warning` (approaching-deadline) state. Nil → log-only, which was
	// the only behavior before: warnings updated the row but told no one.
	warningPublisher SLAWarningPublisher
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
		if !br.notify {
			continue // escalation is off for this finding's policy
		}
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

// markBreachedLegacy is the pre-existing behavior for a nil / non-transactional
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
			if !br.notify {
				continue // escalation is off for this finding's policy
			}
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
		var sev sql.NullString
		if err := rows.Scan(&br.tenantID, &br.findingID, &br.slaDeadline, &sev, &br.notify); err != nil {
			return nil, fmt.Errorf("scan breach row: %w", err)
		}
		br.severity = sev.String
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
		FindingSeverity: br.severity,
	}, true
}

// warningSelectUpdateQuery flags open findings once the governing policy's
// warning_threshold_percent of their remediation window has elapsed, RETURNING
// the rows that actually transitioned so each is notified once. The window
// starts at first_detected_at (created_at when unset); for a regression whose
// deadline was restarted at reopen this makes the window look longer, so the
// warning comes earlier, never later. The `sla_status IS NULL OR = 'on_track'`
// guard makes the transition happen exactly once.
const warningSelectUpdateQuery = `
	WITH due AS (
		SELECT f.id, COALESCE(pol.escalation_enabled, TRUE) AS notify
		FROM findings f` + effectivePolicyJoin + `
		WHERE f.sla_deadline IS NOT NULL
		  AND f.sla_deadline > NOW()
		  AND (f.sla_status IS NULL OR f.sla_status = 'on_track')
		  AND f.status NOT IN ('resolved', 'false_positive', 'accepted', 'duplicate', 'verified', 'accepted_risk')
		  AND NOT f.branch_only
		  AND NOW() >= COALESCE(f.first_detected_at, f.created_at)
		      + (f.sla_deadline - COALESCE(f.first_detected_at, f.created_at))
		        * (COALESCE(pol.warning_threshold_percent, 80)::float8 / 100.0)
	)
	UPDATE findings SET
		sla_status = 'warning',
		updated_at = NOW()
	FROM due
	WHERE findings.id = due.id
	  AND (findings.sla_status IS NULL OR findings.sla_status = 'on_track')
	RETURNING findings.tenant_id, findings.id, findings.sla_deadline, findings.severity, due.notify
`

// markWarning flags findings that crossed their policy's warning threshold. It
// is idempotent and advisory — errors are logged, never returned.
func (c *SLAEscalationController) markWarning(ctx context.Context) {
	rows, err := c.db.QueryContext(ctx, warningSelectUpdateQuery)
	if err != nil {
		c.logger.Warn("sla warning update failed", "error", err)
		return
	}
	warned, err := c.scanBreaches(rows) // same (tenant_id, id, sla_deadline) shape
	if err != nil {
		c.logger.Warn("sla warning scan failed", "error", err)
		return
	}
	if len(warned) == 0 {
		return
	}
	c.logger.Info("SLA warning findings updated", "count", len(warned))

	// Notify once per newly-warned finding (advisory — errors never block).
	if c.warningPublisher == nil {
		return
	}
	now := time.Now()
	for _, w := range warned {
		if !w.notify {
			continue // escalation is off for this finding's policy
		}
		ev, ok := warningEvent(w, now)
		if !ok {
			continue
		}
		if err := c.warningPublisher.PublishWarning(ctx, ev); err != nil {
			c.logger.Warn("sla warning publish failed", "finding_id", w.findingID, "error", err)
		}
	}
}

// warningEvent builds the event for a row; ok=false when an ID can't be parsed.
func warningEvent(w breachRow, now time.Time) (SLAWarningEvent, bool) {
	tid, err := shared.IDFromString(w.tenantID)
	if err != nil {
		return SLAWarningEvent{}, false
	}
	fid, err := shared.IDFromString(w.findingID)
	if err != nil {
		return SLAWarningEvent{}, false
	}
	return SLAWarningEvent{
		TenantID:      tid,
		FindingID:     fid,
		SLADeadline:   w.slaDeadline,
		TimeRemaining: w.slaDeadline.Sub(now),
		At:            now,
	}, true
}
