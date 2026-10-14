package postgres

// The coverage planner's side of the ledger (RFC-093): due batches, queued
// and blocked pairs, and settlement from the runs that took them.

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/coverage"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func coverageIDStrings(ids []shared.ID) []string {
	out := make([]string, len(ids))
	for i, id := range ids {
		out[i] = id.String()
	}
	return out
}

// DueBatch returns due or failed pairs of a capability whose time has come.
func (r *AssetCoverageRepository) DueBatch(ctx context.Context, tenantID shared.ID, capability string, limit int) ([]coverage.DueTarget, error) {
	if limit <= 0 {
		return nil, nil
	}
	rows, err := r.db.QueryContext(ctx, `
		SELECT a.id, a.name, a.asset_type, COALESCE(a.sub_type, ''), c.fail_streak
		FROM asset_coverage c
		JOIN assets a ON a.tenant_id = c.tenant_id AND a.id = c.asset_id
		WHERE c.tenant_id = $1 AND c.capability = $2 AND c.vantage = ''
		  AND c.state IN ('due', 'failed') AND (c.next_due_at IS NULL OR c.next_due_at <= now())
		  AND a.deleted_at IS NULL AND a.status = 'active'
		ORDER BY c.priority DESC, c.next_due_at ASC NULLS FIRST, a.id
		LIMIT $3`, tenantID.String(), capability, limit)
	if err != nil {
		return nil, fmt.Errorf("list due coverage: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []coverage.DueTarget
	for rows.Next() {
		var (
			d       coverage.DueTarget
			id, typ string
		)
		if err := rows.Scan(&id, &d.Name, &typ, &d.SubType, &d.FailStreak); err != nil {
			return nil, err
		}
		if d.AssetID, err = shared.IDFromString(id); err != nil {
			continue
		}
		d.Type = asset.AssetType(typ)
		out = append(out, d)
	}
	return out, rows.Err()
}

// MarkQueued records that the pairs were handed to a run.
func (r *AssetCoverageRepository) MarkQueued(ctx context.Context, tenantID shared.ID, capability string, assetIDs []shared.ID, runID shared.ID, tool string) error {
	if len(assetIDs) == 0 {
		return nil
	}
	_, err := r.db.ExecContext(ctx, `
		UPDATE asset_coverage SET state = 'queued', reason = '', queued_at = now(), last_attempt_at = now(),
		       last_run_id = $4, last_tool = $5, updated_at = now()
		WHERE tenant_id = $1 AND capability = $2 AND vantage = '' AND asset_id = ANY($3::uuid[])`,
		tenantID.String(), capability, pq.Array(coverageIDStrings(assetIDs)), runID.String(), coverage.Clip(tool, coverage.MaxCodeLen))
	if err != nil {
		return fmt.Errorf("mark coverage queued: %w", err)
	}
	return nil
}

// MarkBlocked records the gate's refusal of each pair.
func (r *AssetCoverageRepository) MarkBlocked(ctx context.Context, tenantID shared.ID, capability string, reasons map[shared.ID]string, recheck time.Duration) error {
	if len(reasons) == 0 {
		return nil
	}
	ids := make([]string, 0, len(reasons))
	codes := make([]string, 0, len(reasons))
	for id, code := range reasons {
		ids = append(ids, id.String())
		codes = append(codes, coverage.Clip(code, coverage.MaxCodeLen))
	}
	_, err := r.db.ExecContext(ctx, `
		UPDATE asset_coverage c SET state = 'blocked', reason = w.code,
		       next_due_at = now() + make_interval(secs => $5), updated_at = now()
		FROM unnest($3::uuid[], $4::text[]) AS w(asset_id, code)
		WHERE c.tenant_id = $1 AND c.capability = $2 AND c.vantage = '' AND c.asset_id = w.asset_id`,
		tenantID.String(), capability, pq.Array(ids), pq.Array(codes), recheck.Seconds())
	if err != nil {
		return fmt.Errorf("mark coverage blocked: %w", err)
	}
	return nil
}

// QueuedRuns returns the runs that hold queued pairs of the tenant.
func (r *AssetCoverageRepository) QueuedRuns(ctx context.Context, tenantID shared.ID) ([]coverage.RunState, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT r.id, c.capability, r.status, COALESCE(r.error_message, ''), max(c.last_tool),
		       COALESCE(r.unfinished_targets, '[]'::jsonb), min(c.queued_at)
		FROM asset_coverage c
		JOIN scan_runs r ON r.tenant_id = c.tenant_id AND r.id = c.last_run_id
		WHERE c.tenant_id = $1 AND c.state = 'queued'
		GROUP BY r.id, c.capability, r.status, r.error_message, r.unfinished_targets`, tenantID.String())
	if err != nil {
		return nil, fmt.Errorf("list coverage runs: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []coverage.RunState
	for rows.Next() {
		var (
			rs         coverage.RunState
			id         string
			unfinished []byte
		)
		if err := rows.Scan(&id, &rs.Capability, &rs.Status, &rs.Error, &rs.Tool, &unfinished, &rs.QueuedAt); err != nil {
			return nil, err
		}
		if rs.RunID, err = shared.IDFromString(id); err != nil {
			continue
		}
		rs.Unfinished = unfinishedTargets(unfinished)
		out = append(out, rs)
	}
	return out, rows.Err()
}

// unfinishedTargets reads scan_runs.unfinished_targets: a list of target
// strings, or of objects with a "target" member.
func unfinishedTargets(raw []byte) []string {
	var plain []string
	if json.Unmarshal(raw, &plain) == nil {
		return plain
	}
	var objs []struct {
		Target string `json:"target"`
	}
	if json.Unmarshal(raw, &objs) != nil {
		return nil
	}
	out := make([]string, 0, len(objs))
	for _, o := range objs {
		if o.Target != "" {
			out = append(out, o.Target)
		}
	}
	return out
}

// expectsHTTPServiceSQL is true when a web origin of the pair's asset was
// observed since the pair was queued: an origin on the name (any port), on
// the open port's host:port, or on its host when the port is the scheme's
// default.
const expectsHTTPServiceSQL = `EXISTS (
	SELECT 1 FROM assets o
	WHERE o.tenant_id = c.tenant_id AND o.asset_type = 'service' AND o.sub_type = 'http'
	  AND o.deleted_at IS NULL AND o.last_seen >= c.queued_at - interval '1 minute'
	  AND (
	    (a.asset_type <> 'service' AND (split_part(split_part(o.name, '://', 2), '/', 1) = a.name
	        OR split_part(split_part(o.name, '://', 2), '/', 1) LIKE a.name || ':%'))
	    OR (a.asset_type = 'service' AND (
	        split_part(split_part(o.name, '://', 2), '/', 1) = regexp_replace(a.name, ':[a-z]+$', '')
	        OR (split_part(split_part(o.name, '://', 2), '/', 1) = split_part(a.name, ':', 1)
	            AND ((split_part(a.name, ':', 2) = '443' AND o.name LIKE 'https://%')
	              OR (split_part(a.name, ':', 2) = '80' AND o.name LIKE 'http://%')))))
	  ))`

const settleCoveredSQL = `
	UPDATE asset_coverage c SET state = 'covered', reason = '',
	       last_outcome = CASE WHEN $5 AND NOT ` + expectsHTTPServiceSQL + ` THEN '` + coverage.OutcomeNoOutput + `' ELSE '` + coverage.OutcomeOK + `' END,
	       last_error = '', last_success_at = now(), fail_streak = 0,
	       next_due_at = now() + make_interval(secs => $4), updated_at = now()
	FROM assets a
	WHERE c.tenant_id = $1 AND c.last_run_id = $2 AND c.capability = $3 AND c.vantage = '' AND c.state = 'queued'
	  AND a.tenant_id = c.tenant_id AND a.id = c.asset_id`

// SettleRun settles the queued pairs of a finished run.
func (r *AssetCoverageRepository) SettleRun(ctx context.Context, tenantID shared.ID, run coverage.RunState, rule coverage.Rule, success bool, unfinished []shared.ID) (int, error) {
	every := rule.Every
	if every <= 0 {
		every = 24 * time.Hour
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }()

	n := 0
	if len(unfinished) > 0 || !success {
		// Failed pairs: the whole run, or the targets it did not finish.
		q := `
			UPDATE asset_coverage c SET state = 'failed', reason = '',
			       last_outcome = $4, last_error = $5, fail_streak = c.fail_streak + 1,
			       next_due_at = now() + least(make_interval(secs => $6), make_interval(secs => 3600 * power(2, least(c.fail_streak, 5)))),
			       updated_at = now()
			WHERE c.tenant_id = $1 AND c.last_run_id = $2 AND c.capability = $3 AND c.vantage = '' AND c.state = 'queued'`
		args := []any{tenantID.String(), run.RunID.String(), run.Capability, coverage.OutcomeFailed,
			coverage.Clip(run.Error, coverage.MaxErrorLen), min(every, 24*time.Hour).Seconds()}
		if success {
			q += ` AND c.asset_id = ANY($7::uuid[])`
			args = append(args, pq.Array(coverageIDStrings(unfinished)))
			args[4] = "the run did not finish this target"
		}
		res, err := tx.ExecContext(ctx, q, args...)
		if err != nil {
			return 0, fmt.Errorf("settle failed coverage: %w", err)
		}
		k, _ := res.RowsAffected()
		n += int(k)
	}
	if success {
		// $5: the rule expects a web origin of the asset; without one the
		// pair is covered with no output (the yield check counts them).
		res, err := tx.ExecContext(ctx, settleCoveredSQL,
			tenantID.String(), run.RunID.String(), run.Capability, every.Seconds(), rule.Expects == "http_service")
		if err != nil {
			return 0, fmt.Errorf("settle covered coverage: %w", err)
		}
		k, _ := res.RowsAffected()
		n += int(k)
	}
	return n, tx.Commit()
}

// QueuedTargets returns the queued pairs a run holds.
func (r *AssetCoverageRepository) QueuedTargets(ctx context.Context, tenantID, runID shared.ID, capability string) ([]coverage.DueTarget, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT a.id, a.name, a.asset_type, COALESCE(a.sub_type, ''), c.fail_streak
		FROM asset_coverage c
		JOIN assets a ON a.tenant_id = c.tenant_id AND a.id = c.asset_id
		WHERE c.tenant_id = $1 AND c.last_run_id = $2 AND c.capability = $3 AND c.vantage = '' AND c.state = 'queued'`,
		tenantID.String(), runID.String(), capability)
	if err != nil {
		return nil, fmt.Errorf("list queued coverage: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []coverage.DueTarget
	for rows.Next() {
		var (
			d       coverage.DueTarget
			id, typ string
		)
		if err := rows.Scan(&id, &d.Name, &typ, &d.SubType, &d.FailStreak); err != nil {
			return nil, err
		}
		if d.AssetID, err = shared.IDFromString(id); err != nil {
			continue
		}
		d.Type = asset.AssetType(typ)
		out = append(out, d)
	}
	return out, rows.Err()
}

// AttemptsSince counts the tenant's pairs attempted since t.
func (r *AssetCoverageRepository) AttemptsSince(ctx context.Context, tenantID shared.ID, t time.Time) (int, error) {
	var n int
	err := r.db.QueryRowContext(ctx, `SELECT count(*) FROM asset_coverage
		WHERE tenant_id = $1 AND last_attempt_at >= $2 AND capability NOT LIKE 'dns.%'`, tenantID.String(), t).Scan(&n)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return 0, fmt.Errorf("count coverage attempts: %w", err)
	}
	return n, nil
}

var _ coverage.Planner = (*AssetCoverageRepository)(nil)

// Health returns one entry per capability of the tenant's ledger.
func (r *AssetCoverageRepository) Health(ctx context.Context, tenantID shared.ID, cadence map[string]time.Duration) ([]coverage.CapabilityHealth, error) {
	caps := make([]string, 0, len(cadence))
	secs := make([]float64, 0, len(cadence))
	for c, d := range cadence {
		caps = append(caps, c)
		secs = append(secs, d.Seconds())
	}
	rows, err := r.db.QueryContext(ctx, `
		SELECT c.capability,
		       count(*) FILTER (WHERE c.state NOT IN ('blocked', 'paused', 'not_applicable')),
		       count(*) FILTER (WHERE c.state NOT IN ('blocked', 'paused', 'not_applicable')
		                          AND COALESCE(c.last_success_at, c.created_at) < now() - make_interval(secs => 2 * COALESCE(p.every, 86400))),
		       count(*) FILTER (WHERE c.fail_streak >= $4),
		       count(*) FILTER (WHERE c.last_outcome = 'ok' AND c.last_success_at > now() - interval '24 hours'),
		       count(*) FILTER (WHERE c.last_outcome = 'no_output' AND c.last_success_at > now() - interval '24 hours')
		FROM asset_coverage c
		LEFT JOIN unnest($2::text[], $3::float8[]) AS p(cap, every) ON p.cap = c.capability
		WHERE c.tenant_id = $1 AND c.vantage = ''
		GROUP BY c.capability
		ORDER BY c.capability`,
		tenantID.String(), pq.Array(caps), pq.Array(secs), coverage.FailingStreak)
	if err != nil {
		return nil, fmt.Errorf("coverage health: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []coverage.CapabilityHealth
	for rows.Next() {
		var h coverage.CapabilityHealth
		if err := rows.Scan(&h.Capability, &h.Applicable, &h.Gaps, &h.Failing, &h.OK, &h.NoOutput); err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

// ClaimAlert claims an alert key for ttl through the controller lease
// table: a second claim before it expires fails, on any replica.
func (r *AssetCoverageRepository) ClaimAlert(ctx context.Context, key string, ttl time.Duration) (bool, error) {
	_, ok, err := NewControllerLeaseRepository(r.db).TryAcquire(ctx, "coverage-alert:"+key, LeaseHolderID(), ttl)
	return ok, err
}

var _ coverage.HealthReader = (*AssetCoverageRepository)(nil)
