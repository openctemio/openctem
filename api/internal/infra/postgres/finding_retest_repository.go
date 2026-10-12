package postgres

// Continuous retest persistence (RFC-039, docs/rfcs/RFC-039-continuous-retest.md):
// finding_retests (one row per attempt), finding_retest_cursors (the
// auto-retest scheduler's per-tenant tick) and the settle transaction that
// completes a retest, moves its finding and writes the activity entry at once.

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/pkg/domain/retest"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

// A finding's retest history is listed 20 at a time by default, 100 at most.
const (
	listFindingRetestsDefault = 20
	listFindingRetestsMax     = 100
)

// FindingRetestRepository stores retests.
type FindingRetestRepository struct {
	db *DB
}

// NewFindingRetestRepository creates the repository.
func NewFindingRetestRepository(db *DB) *FindingRetestRepository {
	return &FindingRetestRepository{db: db}
}

const findingRetestColumns = `id, tenant_id, finding_id, asset_id, trigger, requested_by, status, outcome, reason,
	reason_code, sensor_id, prior_status, result_status, template_id, target, check_command_id, reach_command_id,
	deadline_at, created_at, completed_at, run_id`

// Create inserts a pending retest. A second pending retest of the same finding
// violates ux_finding_retests_one_pending and returns retest.ErrInFlight.
func (r *FindingRetestRepository) Create(ctx context.Context, rt *retest.Retest) error {
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO finding_retests (id, tenant_id, finding_id, asset_id, trigger, requested_by, status,
			prior_status, template_id, target, deadline_at, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, 'pending', $7, $8, $9, $10, $11)`,
		rt.ID.String(), rt.TenantID.String(), rt.FindingID.String(), nullIDValue(rt.AssetID),
		string(rt.Trigger), nullIDPtr(rt.RequestedBy), string(rt.PriorStatus),
		rt.TemplateID, rt.Target, rt.DeadlineAt, rt.CreatedAt)
	if err != nil {
		if isUniqueViolation(err) {
			return retest.ErrInFlight
		}
		return fmt.Errorf("create finding retest: %w", err)
	}
	return nil
}

// SetCommands records the two commands a pending retest dispatched.
func (r *FindingRetestRepository) SetCommands(ctx context.Context, tenantID, id shared.ID, check, reach *shared.ID) error {
	_, err := r.db.ExecContext(ctx, `
		UPDATE finding_retests SET check_command_id = $3, reach_command_id = $4
		WHERE tenant_id = $1 AND id = $2 AND status = 'pending'`,
		tenantID.String(), id.String(), nullIDPtr(check), nullIDPtr(reach))
	if err != nil {
		return fmt.Errorf("set retest commands: %w", err)
	}
	return nil
}

// SetRun records the scan run that holds a pending retest's commands. The
// run must belong to the same tenant (composite foreign key).
func (r *FindingRetestRepository) SetRun(ctx context.Context, tenantID, id, runID shared.ID) error {
	_, err := r.db.ExecContext(ctx, `
		UPDATE finding_retests SET run_id = $3
		WHERE tenant_id = $1 AND id = $2 AND status = 'pending'`,
		tenantID.String(), id.String(), runID.String())
	if err != nil {
		return fmt.Errorf("set retest run: %w", err)
	}
	return nil
}

// GetByID returns one retest of the tenant.
func (r *FindingRetestRepository) GetByID(ctx context.Context, tenantID, id shared.ID) (*retest.Retest, error) {
	row := r.db.QueryRowContext(ctx, `SELECT `+findingRetestColumns+` FROM finding_retests WHERE tenant_id = $1 AND id = $2`,
		tenantID.String(), id.String())
	rt, err := scanRetest(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("%w: retest not found", shared.ErrNotFound)
	}
	return rt, err
}

// FindPendingByCommand returns the pending retest one of whose commands is
// commandID, or nil when there is none (already settled, or not a retest).
func (r *FindingRetestRepository) FindPendingByCommand(ctx context.Context, tenantID, commandID shared.ID) (*retest.Retest, error) {
	row := r.db.QueryRowContext(ctx, `SELECT `+findingRetestColumns+` FROM finding_retests
		WHERE tenant_id = $1 AND status = 'pending' AND (check_command_id = $2 OR reach_command_id = $2)
		LIMIT 1`, tenantID.String(), commandID.String())
	rt, err := scanRetest(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return rt, err
}

// ListByFinding returns a finding's retests, newest first.
func (r *FindingRetestRepository) ListByFinding(ctx context.Context, tenantID, findingID shared.ID, limit int) ([]*retest.Retest, error) {
	if limit <= 0 || limit > listFindingRetestsMax {
		limit = listFindingRetestsDefault
	}
	rows, err := r.db.QueryContext(ctx, `SELECT `+findingRetestColumns+` FROM finding_retests
		WHERE tenant_id = $1 AND finding_id = $2 ORDER BY created_at DESC LIMIT $3`,
		tenantID.String(), findingID.String(), limit)
	if err != nil {
		return nil, fmt.Errorf("list finding retests: %w", err)
	}
	defer rows.Close()
	// Not pre-sized from limit: the caller's value comes from a query
	// parameter (clamped above, but the allocation must not depend on it).
	out := make([]*retest.Retest, 0, listFindingRetestsDefault)
	for rows.Next() {
		rt, err := scanRetest(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, rt)
	}
	return out, rows.Err()
}

// LastRequestedAt is when the finding's most recent retest was requested, or nil.
func (r *FindingRetestRepository) LastRequestedAt(ctx context.Context, tenantID, findingID shared.ID) (*time.Time, error) {
	var at sql.NullTime
	err := r.db.QueryRowContext(ctx, `SELECT MAX(created_at) FROM finding_retests WHERE tenant_id = $1 AND finding_id = $2`,
		tenantID.String(), findingID.String()).Scan(&at)
	if err != nil {
		return nil, fmt.Errorf("last retest: %w", err)
	}
	if !at.Valid {
		return nil, nil
	}
	return &at.Time, nil
}

// CountPending counts the tenant's pending retests of one trigger.
func (r *FindingRetestRepository) CountPending(ctx context.Context, tenantID shared.ID, trigger retest.Trigger) (int, error) {
	var n int
	err := r.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM finding_retests WHERE tenant_id = $1 AND trigger = $2 AND status = 'pending'`,
		tenantID.String(), string(trigger)).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("count pending retests: %w", err)
	}
	return n, nil
}

// CountPendingForAsset counts pending retests against one asset (all triggers).
func (r *FindingRetestRepository) CountPendingForAsset(ctx context.Context, tenantID, assetID shared.ID) (int, error) {
	var n int
	err := r.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM finding_retests WHERE tenant_id = $1 AND asset_id = $2 AND status = 'pending'`,
		tenantID.String(), assetID.String()).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("count pending asset retests: %w", err)
	}
	return n, nil
}

// CountCreatedSince counts the tenant's retests of one trigger requested since t.
func (r *FindingRetestRepository) CountCreatedSince(ctx context.Context, tenantID shared.ID, trigger retest.Trigger, since time.Time) (int, error) {
	var n int
	err := r.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM finding_retests WHERE tenant_id = $1 AND trigger = $2 AND created_at >= $3`,
		tenantID.String(), string(trigger), since).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("count retests: %w", err)
	}
	return n, nil
}

// ListSettleCandidates returns pending retests, across tenants, that the sweep
// should settle now: their deadline passed, or every command they dispatched
// reached a terminal state (or none was recorded — the dispatch failed).
func (r *FindingRetestRepository) ListSettleCandidates(ctx context.Context, now time.Time, limit int) ([]*retest.Retest, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := r.db.QueryContext(ctx, `
		SELECT `+prefixColumns("fr", findingRetestColumns)+`
		FROM finding_retests fr
		LEFT JOIN commands cc ON cc.id = fr.check_command_id
		LEFT JOIN commands rc ON rc.id = fr.reach_command_id
		WHERE fr.status = 'pending'
			AND (
				fr.deadline_at <= $1
				OR (
					(fr.check_command_id IS NULL OR cc.status IS NULL OR cc.status IN ('completed', 'failed', 'canceled', 'expired'))
					AND (fr.reach_command_id IS NULL OR rc.status IS NULL OR rc.status IN ('completed', 'failed', 'canceled', 'expired'))
					AND fr.created_at <= $1 - INTERVAL '1 minute'
				)
			)
		ORDER BY fr.deadline_at
		LIMIT $2`, now, limit)
	if err != nil {
		return nil, fmt.Errorf("list retests to settle: %w", err)
	}
	defer rows.Close()
	out := make([]*retest.Retest, 0)
	for rows.Next() {
		rt, err := scanRetest(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, rt)
	}
	return out, rows.Err()
}

// Settle completes a pending retest in one transaction: it locks the retest row
// (a concurrent settle waits, then sees it completed and does nothing), locks
// the finding row and reads its current status, moves the finding when the
// decision says so, completes the retest and writes the retest_completed
// activity with actor "system: retest". Nothing is half-applied.
func (r *FindingRetestRepository) Settle(ctx context.Context, in retest.SettleInput) (retest.SettleResult, error) {
	var res retest.SettleResult
	err := r.db.Transaction(ctx, func(tx *sql.Tx) error {
		var status string
		err := tx.QueryRowContext(ctx, `SELECT status FROM finding_retests WHERE tenant_id = $1 AND id = $2 FOR UPDATE`,
			in.TenantID.String(), in.RetestID.String()).Scan(&status)
		if errors.Is(err, sql.ErrNoRows) || (err == nil && status != string(retest.StatusPending)) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("lock retest: %w", err)
		}

		var current string
		err = tx.QueryRowContext(ctx, `SELECT status FROM findings WHERE tenant_id = $1 AND id = $2 FOR UPDATE`,
			in.TenantID.String(), in.FindingID.String()).Scan(&current)
		findingGone := errors.Is(err, sql.ErrNoRows)
		if err != nil && !findingGone {
			return fmt.Errorf("lock finding: %w", err)
		}
		res.PriorStatus = vulnerability.FindingStatus(current)
		res.ResultStatus = res.PriorStatus

		if !findingGone && in.Decide != nil {
			d := in.Decide(res.PriorStatus)
			if d.Change && d.Next != res.PriorStatus {
				if err := moveFindingInTx(ctx, tx, in, res.PriorStatus, d.Next); err != nil {
					return err
				}
				res.Moved = true
				res.ResultStatus = d.Next
			}
		}

		if _, err := tx.ExecContext(ctx, `
			UPDATE finding_retests
			SET status = 'completed', outcome = $3, reason = $4, result_status = $5, reason_code = $6, sensor_id = $7,
				completed_at = NOW()
			WHERE tenant_id = $1 AND id = $2`,
			in.TenantID.String(), in.RetestID.String(), string(in.Outcome), truncateReason(in.Reason),
			nullString(string(res.ResultStatus)), nullString(string(in.ReasonCode)), nullIDPtr(in.SensorID)); err != nil {
			return fmt.Errorf("complete retest: %w", err)
		}

		if !findingGone {
			changes := make(map[string]any, len(in.Activity)+3)
			for k, v := range in.Activity {
				changes[k] = v
			}
			changes["old_status"] = string(res.PriorStatus)
			changes["new_status"] = string(res.ResultStatus)
			changes["moved"] = res.Moved
			if err := insertRetestActivity(ctx, tx, in.TenantID, in.FindingID, vulnerability.ActivityRetestCompleted, nil, changes, in.Source); err != nil {
				return err
			}
		}
		res.Applied = true
		return nil
	})
	return res, err
}

// moveFindingInTx writes the retest's status change on a locked finding row.
// A move the finding lifecycle does not allow is refused, and the whole
// settle rolls back.
func moveFindingInTx(ctx context.Context, tx *sql.Tx, in retest.SettleInput, prior, next vulnerability.FindingStatus) error {
	if err := vulnerability.CheckPlatformTransitions(next, prior); err != nil {
		return fmt.Errorf("move finding: %w", err)
	}
	var err error
	if next == vulnerability.FindingStatusResolved {
		_, err = tx.ExecContext(ctx, `
			UPDATE findings
			SET status = 'resolved', resolution = $3, resolution_method = $4,
				resolved_at = NOW(), resolved_by = $5, updated_at = NOW()
			WHERE tenant_id = $1 AND id = $2`,
			in.TenantID.String(), in.FindingID.String(), retest.ResolutionNote(in.TemplateID),
			string(retest.ResolutionMethodRetestVerified), nullIDPtr(in.ResolvedBy))
	} else {
		_, err = tx.ExecContext(ctx, `
			UPDATE findings
			SET status = $3, resolution = NULL, resolution_method = NULL,
				resolved_at = NULL, resolved_by = NULL, updated_at = NOW()
			WHERE tenant_id = $1 AND id = $2`,
			in.TenantID.String(), in.FindingID.String(), string(next))
	}
	if err != nil {
		return fmt.Errorf("move finding: %w", err)
	}
	return nil
}

// RecordRequested writes the retest_requested activity entry.
func (r *FindingRetestRepository) RecordRequested(ctx context.Context, rt *retest.Retest, source vulnerability.ActivitySource) error {
	changes := map[string]any{
		"retest_id":   rt.ID.String(),
		"trigger":     string(rt.Trigger),
		"template_id": rt.TemplateID,
		"target":      rt.Target,
		"status":      string(rt.PriorStatus),
	}
	return r.db.Transaction(ctx, func(tx *sql.Tx) error {
		return insertRetestActivity(ctx, tx, rt.TenantID, rt.FindingID, vulnerability.ActivityRetestRequested, rt.RequestedBy, changes, source)
	})
}

// insertRetestActivity appends a finding activity. A user-requested entry has
// that user as actor; otherwise the actor is the system, named "system: retest".
func insertRetestActivity(ctx context.Context, tx *sql.Tx, tenantID, findingID shared.ID, typ vulnerability.ActivityType,
	actor *shared.ID, changes map[string]any, source vulnerability.ActivitySource,
) error {
	raw, err := json.Marshal(changes)
	if err != nil {
		return fmt.Errorf("marshal retest activity: %w", err)
	}
	actorType, actorName := vulnerability.ActorTypeSystem, sql.NullString{String: retest.ActorName, Valid: true}
	if actor != nil {
		actorType, actorName = vulnerability.ActorTypeUser, sql.NullString{}
	}
	_, err = tx.ExecContext(ctx, `
		INSERT INTO finding_activities (id, tenant_id, finding_id, activity_type, actor_id, actor_type, actor_name,
			changes, source, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, NOW())`,
		shared.NewID().String(), tenantID.String(), findingID.String(), string(typ), nullIDPtr(actor),
		string(actorType), actorName, raw, nullString(string(source)))
	if err != nil {
		return fmt.Errorf("insert retest activity: %w", err)
	}
	return nil
}

// --- auto-retest scheduler ---

// ListDueAutoTenants lists tenants with settings.retest.auto_enabled whose tick
// is due (no cursor yet, or next_run_at <= now), least recently served first.
func (r *FindingRetestRepository) ListDueAutoTenants(ctx context.Context, now time.Time, limit int) ([]retest.AutoTenant, error) {
	if limit <= 0 {
		limit = 50
	}
	rows, err := r.db.QueryContext(ctx, `
		SELECT t.id, c.next_run_at,
			COALESCE(NULLIF(t.settings->'retest'->>'interval_hours', '')::int, 0),
			COALESCE(NULLIF(t.settings->'retest'->>'daily_cap', '')::int, 0)
		FROM tenants t
		LEFT JOIN finding_retest_cursors c ON c.tenant_id = t.id
		WHERE (t.settings->'retest'->>'auto_enabled') = 'true'
			AND (c.next_run_at IS NULL OR c.next_run_at <= $1)
		ORDER BY c.next_run_at NULLS FIRST
		LIMIT $2`, now, limit)
	if err != nil {
		return nil, fmt.Errorf("list auto-retest tenants: %w", err)
	}
	defer rows.Close()
	out := make([]retest.AutoTenant, 0)
	for rows.Next() {
		var (
			idStr string
			next  sql.NullTime
			t     retest.AutoTenant
		)
		if err := rows.Scan(&idStr, &next, &t.IntervalHours, &t.DailyCap); err != nil {
			return nil, fmt.Errorf("scan auto-retest tenant: %w", err)
		}
		id, err := shared.IDFromString(idStr)
		if err != nil {
			continue
		}
		t.TenantID = id
		if next.Valid {
			at := next.Time
			t.NextRunAt = &at
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// ClaimTenantTick claims one tick of a tenant for this caller by moving
// next_run_at from the value it listed (seen; nil = no cursor yet) to next.
// Every API replica runs the scheduler and lists the same due tenants; a
// concurrent claim waits on the row lock, re-reads next_run_at, finds it moved
// and matches no row (or loses the INSERT race). Exactly one replica queues the
// tick's retests, and nothing is locked while it does.
func (r *FindingRetestRepository) ClaimTenantTick(ctx context.Context, tenantID shared.ID, seen *time.Time, next time.Time) (bool, error) {
	var (
		res sql.Result
		err error
	)
	if seen == nil {
		res, err = r.db.ExecContext(ctx, `
			INSERT INTO finding_retest_cursors (tenant_id, next_run_at, updated_at) VALUES ($1, $2, NOW())
			ON CONFLICT (tenant_id) DO NOTHING`, tenantID.String(), next)
	} else {
		res, err = r.db.ExecContext(ctx, `
			UPDATE finding_retest_cursors SET next_run_at = $3, updated_at = NOW()
			WHERE tenant_id = $1 AND next_run_at = $2`, tenantID.String(), *seen, next)
	}
	if err != nil {
		return false, fmt.Errorf("claim retest tick: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("claim retest tick: %w", err)
	}
	return n == 1, nil
}

// ListAutoCandidates returns up to limit findings of the tenant due for an auto
// retest: nuclei findings with a template id, in an eligible status (resolved
// only when resolved after resolvedSince), on an active asset, with no pending
// retest and no retest requested after retestedBefore. Never-retested and
// least recently retested first.
func (r *FindingRetestRepository) ListAutoCandidates(ctx context.Context, tenantID shared.ID, retestedBefore, resolvedSince time.Time, limit int) ([]shared.ID, error) {
	if limit <= 0 {
		limit = 50
	}
	rows, err := r.db.QueryContext(ctx, `
		SELECT f.id
		FROM findings f
		JOIN assets a ON a.id = f.asset_id AND a.tenant_id = f.tenant_id AND a.status = 'active'
		LEFT JOIN LATERAL (
			SELECT MAX(fr.created_at) AS last_at,
				BOOL_OR(fr.status = 'pending') AS pending
			FROM finding_retests fr
			WHERE fr.tenant_id = f.tenant_id AND fr.finding_id = f.id
		) lr ON TRUE
		WHERE f.tenant_id = $1
			AND f.tool_name = 'nuclei'
			AND COALESCE(f.rule_id, '') <> ''
			AND f.status = ANY($2)
			AND (f.status <> 'resolved' OR f.resolved_at >= $3)
			AND (f.status <> 'resolved' OR f.resolution IS NULL OR f.resolution <> 'suppressed')
			AND COALESCE(lr.pending, FALSE) = FALSE
			AND (lr.last_at IS NULL OR lr.last_at < $4)
		ORDER BY lr.last_at NULLS FIRST, f.created_at
		LIMIT $5`,
		tenantID.String(), pq.Array(retest.EligibleStatuses()), resolvedSince, retestedBefore, limit)
	if err != nil {
		return nil, fmt.Errorf("list auto-retest candidates: %w", err)
	}
	defer rows.Close()
	out := make([]shared.ID, 0, limit)
	for rows.Next() {
		var idStr string
		if err := rows.Scan(&idStr); err != nil {
			return nil, fmt.Errorf("scan auto-retest candidate: %w", err)
		}
		if id, err := shared.IDFromString(idStr); err == nil {
			out = append(out, id)
		}
	}
	return out, rows.Err()
}

// --- scanning ---

type retestScanner interface {
	Scan(dest ...any) error
}

func scanRetest(s retestScanner) (*retest.Retest, error) {
	var (
		id, tenantID, findingID                string
		assetID, requestedBy, outcome, reason  sql.NullString
		reasonCode, sensorID                   sql.NullString
		resultStatus, checkCmd, reachCmd       sql.NullString
		trigger, status, priorStatus, template string
		target                                 string
		deadline, created                      time.Time
		completed                              sql.NullTime
		runID                                  sql.NullString
	)
	if err := s.Scan(&id, &tenantID, &findingID, &assetID, &trigger, &requestedBy, &status, &outcome, &reason,
		&reasonCode, &sensorID, &priorStatus, &resultStatus, &template, &target, &checkCmd, &reachCmd, &deadline, &created, &completed, &runID); err != nil {
		return nil, err
	}
	rt := &retest.Retest{
		Trigger:      retest.Trigger(trigger),
		Status:       retest.Status(status),
		Outcome:      retest.Outcome(outcome.String),
		Reason:       reason.String,
		ReasonCode:   retest.ReasonCode(reasonCode.String),
		SensorID:     optionalID(sensorID),
		PriorStatus:  vulnerability.FindingStatus(priorStatus),
		ResultStatus: vulnerability.FindingStatus(resultStatus.String),
		TemplateID:   template,
		Target:       target,
		DeadlineAt:   deadline,
		CreatedAt:    created,
		RunID:        optionalID(runID),
	}
	var err error
	if rt.ID, err = shared.IDFromString(id); err != nil {
		return nil, fmt.Errorf("retest id: %w", err)
	}
	if rt.TenantID, err = shared.IDFromString(tenantID); err != nil {
		return nil, fmt.Errorf("retest tenant: %w", err)
	}
	if rt.FindingID, err = shared.IDFromString(findingID); err != nil {
		return nil, fmt.Errorf("retest finding: %w", err)
	}
	if assetID.Valid {
		rt.AssetID, _ = shared.IDFromString(assetID.String)
	}
	rt.RequestedBy = optionalID(requestedBy)
	rt.CheckCommandID = optionalID(checkCmd)
	rt.ReachCommandID = optionalID(reachCmd)
	if completed.Valid {
		at := completed.Time
		rt.CompletedAt = &at
	}
	return rt, nil
}

func optionalID(s sql.NullString) *shared.ID {
	if !s.Valid {
		return nil
	}
	id, err := shared.IDFromString(s.String)
	if err != nil {
		return nil
	}
	return &id
}

// truncateReason bounds the free-text reason (it can carry a sensor summary).
func truncateReason(s string) string {
	const maxReason = 1000
	if len(s) > maxReason {
		return s[:maxReason]
	}
	return s
}

// prefixColumns qualifies a comma-separated column list with a table alias.
func prefixColumns(alias, cols string) string {
	parts := strings.Split(cols, ",")
	for i, p := range parts {
		parts[i] = alias + "." + strings.TrimSpace(p)
	}
	return strings.Join(parts, ", ")
}
