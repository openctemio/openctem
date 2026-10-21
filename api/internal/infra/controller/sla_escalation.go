package controller

// SLA escalation: announces SLA breaches and at-risk deadlines once per SLA
// episode (api/docs/architecture/sla-escalation.md).

import (
	"context"
	"database/sql"
	"fmt"
	"time"
	"unicode/utf8"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// SLABreachEvent is emitted once per SLA episode of a finding whose deadline
// passed while it was open. Downstream consumers (notification outbox, ticket
// commenter, paging router) subscribe via the publisher.
//
// Dedup is by findings.sla_breach_notified_at: the job selects only rows
// where it is NULL and sets it in the same statement, whoever set sla_status
// to overdue. A new SLA clock or a reopen clears it (trg_findings_sla_episode),
// which starts a new episode.
type SLABreachEvent struct {
	TenantID        shared.ID
	FindingID       shared.ID
	FindingTitle    string
	SLADeadline     time.Time
	OverdueDuration time.Duration
	At              time.Time
	// FindingSeverity is the breached finding's own severity. The
	// notification is sent at max(high, FindingSeverity).
	FindingSeverity string
}

// SLABreachPublisher delivers breach events to downstream consumers.
// Optional — nil publisher means "log only".
type SLABreachPublisher interface {
	Publish(ctx context.Context, event SLABreachEvent) error
}

// SLABreachTxPublisher is an optional extension of SLABreachPublisher that
// enqueues a breach event inside a caller-supplied transaction. When the wired
// publisher implements it, the notified-at write, the timeline row and the
// notification enqueue commit together, so a crash between them cannot mark a
// breach announced while its notification is lost.
type SLABreachTxPublisher interface {
	PublishTx(ctx context.Context, tx *sql.Tx, event SLABreachEvent) error
}

// SLAWarningPublisher delivers "approaching deadline" events. Optional — nil
// means log-only.
type SLAWarningPublisher interface {
	PublishWarning(ctx context.Context, event SLAWarningEvent) error
}

// SLAWarningTxPublisher is the transactional form of SLAWarningPublisher, used
// the same way as SLABreachTxPublisher.
type SLAWarningTxPublisher interface {
	PublishWarningTx(ctx context.Context, tx *sql.Tx, event SLAWarningEvent) error
}

// SLAWarningEvent describes a finding that just entered the at-risk window.
type SLAWarningEvent struct {
	TenantID      shared.ID
	FindingID     shared.ID
	FindingTitle  string
	SLADeadline   time.Time
	TimeRemaining time.Duration
	At            time.Time
}

// SetWarningPublisher wires the warning-event publisher. Safe after construction
// and before the controller starts; nil-safe.
func (c *SLAEscalationController) SetWarningPublisher(p SLAWarningPublisher) {
	c.warningPublisher = p
}

const (
	// slaEscalationBatch is how many findings one transaction announces.
	slaEscalationBatch = 1000
	// slaEscalationMaxBatches bounds one tick; the rest waits for the next.
	slaEscalationMaxBatches = 20
	// maxNotificationTitle bounds the finding title copied into a notice.
	maxNotificationTitle = 200
)

// slaClockStartSQL is when the current SLA clock started. sla_started_at is
// written with every deadline (trg_findings_sla_episode); the fallback covers
// a row written before the column existed.
const slaClockStartSQL = `COALESCE(f.sla_started_at, GREATEST(f.first_detected_at, f.last_reopened_at), f.created_at)`

// breachSelectUpdateQuery announces open, past-deadline findings whose breach
// was not announced in this SLA episode: it sets sla_status to overdue (the
// enum value for an open finding past its deadline, counted by the dashboard)
// and sla_breach_notified_at, writes one sla_breach timeline row per finding,
// and RETURNs what the publisher needs. Selecting on the notified-at column
// instead of on sla_status means a breach is announced whoever moved the
// status (a reopen, an un-suppression, a status change after the deadline).
//
// FOR UPDATE SKIP LOCKED plus the repeated guard in the UPDATE keep two
// replicas from announcing the same row; LIMIT bounds the transaction.
//
// The status always changes; whether anyone is told is the governing policy's
// escalation_enabled (column `notify`). The timeline row is written either way.
var breachSelectUpdateQuery = `
	WITH due AS (
		SELECT f.id, COALESCE(pol.escalation_enabled, TRUE) AS notify
		FROM findings f` + effectivePolicyJoin + `
		WHERE f.sla_breach_notified_at IS NULL
		  AND f.sla_deadline IS NOT NULL
		  AND f.sla_deadline < NOW()
		  AND NOT f.branch_only
		  AND ` + vulnerability.OpenStatusSQL("f.status") + `
		ORDER BY f.sla_deadline
		LIMIT $1
		FOR UPDATE OF f SKIP LOCKED
	), upd AS (
		UPDATE findings SET
			sla_status = 'overdue',
			sla_breach_notified_at = NOW(),
			sla_at_risk_notified_at = COALESCE(findings.sla_at_risk_notified_at, NOW()),
			updated_at = NOW()
		FROM due
		WHERE findings.id = due.id
		  AND findings.sla_breach_notified_at IS NULL
		RETURNING findings.tenant_id, findings.id, findings.sla_deadline, findings.severity, findings.title, due.notify
	), act AS (
		INSERT INTO finding_activities (tenant_id, finding_id, activity_type, actor_type, actor_name, changes, source)
		SELECT upd.tenant_id, upd.id, 'sla_breach', 'system', 'system: SLA',
			jsonb_build_object('sla_deadline', to_char(upd.sla_deadline AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'),
				'notified', upd.notify),
			'auto'
		FROM upd
	)
	SELECT tenant_id, id, sla_deadline, severity, title, notify FROM upd
`

// warningSelectUpdateQuery announces open findings once the governing
// policy's warning_threshold_percent of their remediation window has passed,
// measured from the start of the current clock (sla_started_at), so a clock
// that starts again does not warn at once. Same once-per-episode rule as the
// breach (sla_at_risk_notified_at); a finding already overdue is left to the
// breach pass.
var warningSelectUpdateQuery = `
	WITH due AS (
		SELECT f.id, COALESCE(pol.escalation_enabled, TRUE) AS notify
		FROM findings f` + effectivePolicyJoin + `
		WHERE f.sla_at_risk_notified_at IS NULL
		  AND f.sla_breach_notified_at IS NULL
		  AND f.sla_deadline IS NOT NULL
		  AND f.sla_deadline > NOW()
		  AND NOT f.branch_only
		  AND ` + vulnerability.OpenStatusSQL("f.status") + `
		  AND NOW() >= ` + slaClockStartSQL + `
		      + (f.sla_deadline - ` + slaClockStartSQL + `)
		        * (COALESCE(pol.warning_threshold_percent, 80)::float8 / 100.0)
		ORDER BY f.sla_deadline
		LIMIT $1
		FOR UPDATE OF f SKIP LOCKED
	), upd AS (
		UPDATE findings SET
			sla_status = CASE WHEN findings.sla_status IS NULL OR findings.sla_status = 'on_track' THEN 'warning' ELSE findings.sla_status END,
			sla_at_risk_notified_at = NOW(),
			updated_at = NOW()
		FROM due
		WHERE findings.id = due.id
		  AND findings.sla_at_risk_notified_at IS NULL
		RETURNING findings.tenant_id, findings.id, findings.sla_deadline, findings.severity, findings.title, due.notify
	), act AS (
		INSERT INTO finding_activities (tenant_id, finding_id, activity_type, actor_type, actor_name, changes, source)
		SELECT upd.tenant_id, upd.id, 'sla_warning', 'system', 'system: SLA',
			jsonb_build_object('sla_deadline', to_char(upd.sla_deadline AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'),
				'notified', upd.notify),
			'auto'
		FROM upd
	)
	SELECT tenant_id, id, sla_deadline, severity, title, notify FROM upd
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

// escalationRow is one finding a pass announced.
type escalationRow struct {
	tenantID    string
	findingID   string
	slaDeadline time.Time
	severity    string
	title       string
	// notify is the governing policy's escalation_enabled (true without one).
	notify bool
}

// SLAEscalationController periodically announces SLA breaches and at-risk
// deadlines. Runs every 15 minutes on every replica; the row locks and the
// notified-at guard make each announcement happen once.
//
// It operates across all tenants on purpose (a system job): every row it
// writes, every timeline row and every notification carries the finding's own
// tenant_id.
type SLAEscalationController struct {
	db     *sql.DB
	logger *logger.Logger
	// publisher fires one event per announced breach. Nil → log only.
	publisher SLABreachPublisher
	// warningPublisher fires one event per announced at-risk finding. Nil →
	// log only.
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

// Reconcile announces breaches, then at-risk findings. A failed warning pass
// is logged and never blocks the breach pass.
func (c *SLAEscalationController) Reconcile(ctx context.Context) (int, error) {
	total, err := c.runPasses(ctx, breachSelectUpdateQuery, c.publishBreaches)
	if err != nil {
		return total, err
	}
	if _, err := c.runPasses(ctx, warningSelectUpdateQuery, c.publishWarnings); err != nil {
		c.logger.Warn("sla warning pass failed", "error", err)
	}
	return total, nil
}

// publishFunc enqueues the notifications of one batch. inTx reports whether
// they were enqueued in tx (committed with the state change); otherwise the
// caller publishes them after the commit through publishAfter.
type publishFunc func(ctx context.Context, tx *sql.Tx, rows []escalationRow, now time.Time) (inTx bool, err error)

// runPasses runs query in batches of slaEscalationBatch, each in its own
// transaction, until a batch comes back short or the tick's bound is reached.
func (c *SLAEscalationController) runPasses(ctx context.Context, query string, publish publishFunc) (int, error) {
	total := 0
	for i := 0; i < slaEscalationMaxBatches; i++ {
		n, err := c.runBatch(ctx, query, publish)
		total += n
		if err != nil {
			return total, err
		}
		if n < slaEscalationBatch {
			break
		}
	}
	return total, nil
}

func (c *SLAEscalationController) runBatch(ctx context.Context, query string, publish publishFunc) (int, error) {
	tx, err := c.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("sla escalation begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	rows, err := tx.QueryContext(ctx, query, slaEscalationBatch)
	if err != nil {
		return 0, fmt.Errorf("sla escalation: %w", err)
	}
	// Collect + close BEFORE enqueuing: lib/pq forbids a second statement on
	// the same tx while these rows are still open.
	batch, scanErr := scanEscalationRows(rows)
	_ = rows.Close()
	if scanErr != nil {
		return 0, scanErr
	}
	if len(batch) == 0 {
		return 0, nil
	}
	c.logCounts(batch)

	now := time.Now().UTC()
	inTx, err := publish(ctx, tx, batch, now)
	if err != nil {
		// Roll back the whole batch: these findings stay unannounced and are
		// retried next tick, keeping state and notification in sync.
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("sla escalation commit: %w", err)
	}
	if !inTx {
		c.publishAfter(ctx, query, batch, now)
	}
	return len(batch), nil
}

func (c *SLAEscalationController) publishBreaches(ctx context.Context, tx *sql.Tx, batch []escalationRow, now time.Time) (bool, error) {
	txPub, ok := c.publisher.(SLABreachTxPublisher)
	if !ok {
		return false, nil
	}
	for _, r := range batch {
		ev, ok := breachEvent(r, now)
		if !ok || !r.notify {
			continue
		}
		if err := txPub.PublishTx(ctx, tx, ev); err != nil {
			return true, fmt.Errorf("enqueue sla breach (finding %s): %w", r.findingID, err)
		}
	}
	return true, nil
}

func (c *SLAEscalationController) publishWarnings(ctx context.Context, tx *sql.Tx, batch []escalationRow, now time.Time) (bool, error) {
	txPub, ok := c.warningPublisher.(SLAWarningTxPublisher)
	if !ok {
		return false, nil
	}
	for _, r := range batch {
		ev, ok := warningEvent(r, now)
		if !ok || !r.notify {
			continue
		}
		if err := txPub.PublishWarningTx(ctx, tx, ev); err != nil {
			return true, fmt.Errorf("enqueue sla warning (finding %s): %w", r.findingID, err)
		}
	}
	return true, nil
}

// publishAfter is the best-effort path for a publisher that cannot enqueue in
// the transaction: errors are logged.
func (c *SLAEscalationController) publishAfter(ctx context.Context, query string, batch []escalationRow, now time.Time) {
	for _, r := range batch {
		if !r.notify {
			continue
		}
		if query == breachSelectUpdateQuery {
			if c.publisher == nil {
				return
			}
			if ev, ok := breachEvent(r, now); ok {
				if err := c.publisher.Publish(ctx, ev); err != nil {
					c.logger.Warn("sla breach publish failed", "finding_id", r.findingID, "error", err)
				}
			}
			continue
		}
		if c.warningPublisher == nil {
			return
		}
		if ev, ok := warningEvent(r, now); ok {
			if err := c.warningPublisher.PublishWarning(ctx, ev); err != nil {
				c.logger.Warn("sla warning publish failed", "finding_id", r.findingID, "error", err)
			}
		}
	}
}

func scanEscalationRows(rows *sql.Rows) ([]escalationRow, error) {
	var out []escalationRow
	for rows.Next() {
		var r escalationRow
		var sev, title sql.NullString
		if err := rows.Scan(&r.tenantID, &r.findingID, &r.slaDeadline, &sev, &title, &r.notify); err != nil {
			return nil, fmt.Errorf("scan sla escalation row: %w", err)
		}
		r.severity = sev.String
		r.title = truncateTitle(title.String)
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate sla escalation rows: %w", err)
	}
	return out, nil
}

// truncateTitle bounds a finding title (scanner-supplied text) copied into a
// notification.
func truncateTitle(s string) string {
	if utf8.RuneCountInString(s) <= maxNotificationTitle {
		return s
	}
	r := []rune(s)
	return string(r[:maxNotificationTitle]) + "…"
}

func (c *SLAEscalationController) logCounts(batch []escalationRow) {
	byTenant := make(map[string]int)
	for _, r := range batch {
		byTenant[r.tenantID]++
	}
	for tid, count := range byTenant {
		c.logger.Info("SLA escalation announced findings", "tenant_id", tid, "count", count)
	}
}

// breachEvent builds the event for a row; ok=false when an ID can't be parsed.
func breachEvent(r escalationRow, now time.Time) (SLABreachEvent, bool) {
	tid, err := shared.IDFromString(r.tenantID)
	if err != nil {
		return SLABreachEvent{}, false
	}
	fid, err := shared.IDFromString(r.findingID)
	if err != nil {
		return SLABreachEvent{}, false
	}
	return SLABreachEvent{
		TenantID:        tid,
		FindingID:       fid,
		FindingTitle:    r.title,
		SLADeadline:     r.slaDeadline,
		OverdueDuration: now.Sub(r.slaDeadline),
		At:              now,
		FindingSeverity: r.severity,
	}, true
}

// warningEvent builds the event for a row; ok=false when an ID can't be parsed.
func warningEvent(r escalationRow, now time.Time) (SLAWarningEvent, bool) {
	tid, err := shared.IDFromString(r.tenantID)
	if err != nil {
		return SLAWarningEvent{}, false
	}
	fid, err := shared.IDFromString(r.findingID)
	if err != nil {
		return SLAWarningEvent{}, false
	}
	return SLAWarningEvent{
		TenantID:      tid,
		FindingID:     fid,
		FindingTitle:  r.title,
		SLADeadline:   r.slaDeadline,
		TimeRemaining: r.slaDeadline.Sub(now),
		At:            now,
	}, true
}
