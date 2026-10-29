package postgres

// The coverage planner's side of the ledger (RFC-093): due batches, queued
// and blocked pairs, and settlement from the runs that took them.

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/command"
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

// JitterSQL is coverage.JitterFraction of the row "c" in SQL: the first 32
// bits of md5("<asset id>|<capability>") as a fraction of 2^32, in [0, 1).
const JitterSQL = `(('x' || substr(md5(c.asset_id::text || '|' || c.capability), 1, 8))::bit(32)::bigint / 4294967296.0)`

// jitteredIntervalSQL is now() + secs × (1 + spread × jitter), secs being a
// parameter placeholder.
func jitteredIntervalSQL(secs string) string {
	return `now() + make_interval(secs => (` + secs + `::float8 * (1 + ` + strconv.FormatFloat(coverage.JitterSpread, 'f', -1, 64) +
		` * ` + JitterSQL + `))::float8)`
}

// plannableSQL is the condition on the row "c" of a pair the planner may
// pick once next_due_at has passed: a plannable state, or paused for a
// target-side outcome (its recheck).
var plannableSQL = `(c.state IN ` + plannableStatesSQL + ` OR (c.state = 'paused' AND c.reason IN (` + quotedList(coverage.TargetSideOutcomes()) + `)))`

func quotedList(vals []string) string {
	q := make([]string, len(vals))
	for i, v := range vals {
		q[i] = pq.QuoteLiteral(v)
	}
	return strings.Join(q, ", ")
}

// plannableStatesSQL are the states the planner picks once next_due_at has
// passed: due and failed (after the back-off), covered (the cadence has
// elapsed) and blocked (the gate's refusal is rechecked; scope may have
// changed). The partial index idx_asset_coverage_plannable covers them.
const plannableStatesSQL = `('due', 'failed', 'covered', 'blocked')`

// maxWaitedSecs bounds DueTarget.Waited (a pair never scheduled reads as
// waiting this long).
const maxWaitedSecs = 1e9

// DueBatch returns the pairs of a capability whose time has come: due,
// failed, covered past its cadence, blocked past its recheck and paused for
// a target-side outcome past its recheck. When at
// least one is due now, pairs due within lookahead are taken as well (one
// run instead of several one-target runs); when none is due now, nothing.
// Each pair says how long it has been due (the planner's batch rule).
func (r *AssetCoverageRepository) DueBatch(ctx context.Context, tenantID shared.ID, capability string, limit int, lookahead time.Duration) ([]coverage.DueTarget, error) {
	if limit <= 0 {
		return nil, nil
	}
	if lookahead < 0 {
		lookahead = 0
	}
	rows, err := r.db.QueryContext(ctx, `
		SELECT a.id, a.name, a.asset_type, COALESCE(a.sub_type, ''), c.fail_streak,
		       (c.next_due_at IS NULL OR c.next_due_at <= now()),
		       COALESCE(greatest(extract(epoch FROM now() - c.next_due_at), 0), 1e9)::float8
		FROM asset_coverage c
		JOIN assets a ON a.tenant_id = c.tenant_id AND a.id = c.asset_id
		WHERE c.tenant_id = $1 AND c.capability = $2 AND c.vantage = ''
		  AND `+plannableSQL+`
		  AND (c.next_due_at IS NULL OR c.next_due_at <= now() + make_interval(secs => $4))
		  AND a.deleted_at IS NULL AND a.status = 'active'
		ORDER BY c.priority DESC, c.next_due_at ASC NULLS FIRST, a.id
		LIMIT $3`, tenantID.String(), capability, limit, lookahead.Seconds())
	if err != nil {
		return nil, fmt.Errorf("list due coverage: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var (
		out    []coverage.DueTarget
		anyDue bool
	)
	for rows.Next() {
		var (
			d       coverage.DueTarget
			id, typ string
			dueNow  bool
			waited  float64
		)
		if err := rows.Scan(&id, &d.Name, &typ, &d.SubType, &d.FailStreak, &dueNow, &waited); err != nil {
			return nil, err
		}
		if d.AssetID, err = shared.IDFromString(id); err != nil {
			continue
		}
		anyDue = anyDue || dueNow
		d.Waited = time.Duration(min(waited, maxWaitedSecs) * float64(time.Second))
		d.Type = asset.AssetType(typ)
		out = append(out, d)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if !anyDue {
		return nil, nil
	}
	return out, nil
}

// HasScopeEntries reports whether the tenant has an active, unexpired
// scope entry of any type (without one the gate refuses every target of a
// coverage run).
func (r *AssetCoverageRepository) HasScopeEntries(ctx context.Context, tenantID shared.ID) (bool, error) {
	var ok bool
	err := r.db.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM scope_targets
		WHERE tenant_id = $1 AND status = 'active' AND (expires_at IS NULL OR expires_at > now()))`, tenantID.String()).Scan(&ok)
	if err != nil {
		return false, fmt.Errorf("read scope entries: %w", err)
	}
	return ok, nil
}

// PausedForReadiness returns, per capability, the readiness reason of its
// paused pairs (one reason per capability; the planner keeps them equal).
func (r *AssetCoverageRepository) PausedForReadiness(ctx context.Context, tenantID shared.ID) (map[string]string, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT capability, min(reason) FROM asset_coverage
		WHERE tenant_id = $1 AND vantage = '' AND state = 'paused' AND reason = ANY($2::text[])
		GROUP BY capability`, tenantID.String(), pq.Array(coverage.ReadinessReasons()))
	if err != nil {
		return nil, fmt.Errorf("list paused coverage: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := map[string]string{}
	for rows.Next() {
		var c, reason string
		if err := rows.Scan(&c, &reason); err != nil {
			return nil, err
		}
		out[c] = reason
	}
	return out, rows.Err()
}

// PauseForReadiness pauses the capability's pairs whose time has come with
// the readiness reason, and moves pairs paused for another readiness
// reason to this one; they may resume after retryAfter. Pairs already
// paused for this reason are not written again (no churn every pass).
func (r *AssetCoverageRepository) PauseForReadiness(ctx context.Context, tenantID shared.ID, capability, reason string, retryAfter time.Duration) (int, error) {
	if !coverage.IsReadinessReason(reason) {
		return 0, fmt.Errorf("%w: %q is not a readiness reason", shared.ErrValidation, reason)
	}
	if retryAfter < 0 {
		retryAfter = 0
	}
	res, err := r.db.ExecContext(ctx, `
		UPDATE asset_coverage c SET state = 'paused', reason = $3,
		       next_due_at = now() + make_interval(secs => $5), updated_at = now()
		WHERE c.tenant_id = $1 AND c.capability = $2 AND c.vantage = ''
		  AND ((c.state IN `+plannableStatesSQL+` AND (c.next_due_at IS NULL OR c.next_due_at <= now()))
		       OR (c.state = 'paused' AND c.reason = ANY($4::text[]) AND c.reason <> $3))`,
		tenantID.String(), capability, reason, pq.Array(coverage.ReadinessReasons()), retryAfter.Seconds())
	if err != nil {
		return 0, fmt.Errorf("pause coverage: %w", err)
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}

// ResumeFromReadiness makes the capability's pairs paused for a readiness
// reason due now, once their retry time has passed (the batch size and the
// one active run per capability bound the burst).
func (r *AssetCoverageRepository) ResumeFromReadiness(ctx context.Context, tenantID shared.ID, capability string) (int, error) {
	res, err := r.db.ExecContext(ctx, `
		UPDATE asset_coverage c SET state = 'due', reason = '', next_due_at = now(), updated_at = now()
		WHERE c.tenant_id = $1 AND c.capability = $2 AND c.vantage = ''
		  AND c.state = 'paused' AND c.reason = ANY($3::text[])
		  AND (c.next_due_at IS NULL OR c.next_due_at <= now())`,
		tenantID.String(), capability, pq.Array(coverage.ReadinessReasons()))
	if err != nil {
		return 0, fmt.Errorf("resume coverage: %w", err)
	}
	n, _ := res.RowsAffected()
	return int(n), nil
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

// MarkBlocked records the gate's refusal of each pair; the planner offers
// it again after recheck (stretched by the pair's jitter).
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
		       next_due_at = `+jitteredIntervalSQL("$5")+`, updated_at = now()
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

var settleCoveredSQL = `
	UPDATE asset_coverage c SET state = 'covered', reason = '',
	       last_outcome = CASE WHEN $5 AND NOT ` + expectsHTTPServiceSQL + ` THEN '` + coverage.OutcomeNoOutput + `' ELSE '` + coverage.OutcomeOK + `' END,
	       last_error = '', last_success_at = now(), fail_streak = 0,
	       next_due_at = ` + jitteredIntervalSQL("$4") + `, updated_at = now()
	FROM assets a
	WHERE c.tenant_id = $1 AND c.last_run_id = $2 AND c.capability = $3 AND c.vantage = '' AND c.state = 'queued'
	  AND c.asset_id = ANY($6::uuid[])
	  AND a.tenant_id = c.tenant_id AND a.id = c.asset_id`

// SettleCovered settles queued pairs of a run as covered; each is due again
// after the cadence stretched by its jitter.
func (r *AssetCoverageRepository) SettleCovered(ctx context.Context, tenantID, runID shared.ID, capability string, assetIDs []shared.ID, every time.Duration, expectsOrigin bool) (int, error) {
	if len(assetIDs) == 0 {
		return 0, nil
	}
	if every <= 0 {
		every = 24 * time.Hour
	}
	// $5: the rule expects a web origin of the asset; without one the pair
	// is covered with no output (the yield check counts them).
	res, err := r.db.ExecContext(ctx, settleCoveredSQL, tenantID.String(), runID.String(), capability,
		every.Seconds(), expectsOrigin, pq.Array(coverageIDStrings(assetIDs)))
	if err != nil {
		return 0, fmt.Errorf("settle covered coverage: %w", err)
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}

// SettleFailed settles queued pairs of a run as failed, each with its own
// outcome and error.
func (r *AssetCoverageRepository) SettleFailed(ctx context.Context, tenantID, runID shared.ID, capability string, failed []coverage.FailedPair, every time.Duration) (int, error) {
	if len(failed) == 0 {
		return 0, nil
	}
	if every <= 0 || every > 24*time.Hour {
		every = 24 * time.Hour
	}
	ids := make([]string, len(failed))
	outcomes := make([]string, len(failed))
	errs := make([]string, len(failed))
	for i, f := range failed {
		ids[i] = f.AssetID.String()
		outcomes[i] = coverage.Clip(f.Outcome, coverage.MaxCodeLen)
		errs[i] = coverage.Clip(f.Error, coverage.MaxErrorLen)
	}
	res, err := r.db.ExecContext(ctx, `
		UPDATE asset_coverage c SET state = 'failed', reason = '',
		       last_outcome = w.outcome, last_error = w.err, fail_streak = c.fail_streak + 1,
		       next_due_at = now() + least(make_interval(secs => $7), make_interval(secs => 3600 * power(2, least(c.fail_streak, 5)))),
		       updated_at = now()
		FROM unnest($4::uuid[], $5::text[], $6::text[]) AS w(asset_id, outcome, err)
		WHERE c.tenant_id = $1 AND c.last_run_id = $2 AND c.capability = $3 AND c.vantage = '' AND c.state = 'queued'
		  AND c.asset_id = w.asset_id`,
		tenantID.String(), runID.String(), capability, pq.Array(ids), pq.Array(outcomes), pq.Array(errs), every.Seconds())
	if err != nil {
		return 0, fmt.Errorf("settle failed coverage: %w", err)
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}

// targetSideStreakSQL is the pair's consecutive target-side observations
// including this one: the streak goes on when the previous outcome was
// target-side too, else it starts at 1.
var targetSideStreakSQL = `(CASE WHEN c.last_outcome IN (` + quotedList(coverage.TargetSideOutcomes()) + `)
	THEN least(c.fail_streak + 1, 32767) ELSE 1 END)`

// SettleTargetSide settles queued pairs of a run whose target did not
// answer: paused with the outcome as the reason, the streak counted, and
// rechecked on coverage.TargetSideRecheck's schedule (1 day, 3 days, then
// weekly), stretched by the pair's jitter.
func (r *AssetCoverageRepository) SettleTargetSide(ctx context.Context, tenantID, runID shared.ID, capability string, pairs []coverage.FailedPair) (int, error) {
	if len(pairs) == 0 {
		return 0, nil
	}
	ids := make([]string, len(pairs))
	outcomes := make([]string, len(pairs))
	errs := make([]string, len(pairs))
	for i, f := range pairs {
		ids[i] = f.AssetID.String()
		outcomes[i] = coverage.Clip(f.Outcome, coverage.MaxCodeLen)
		errs[i] = coverage.Clip(f.Error, coverage.MaxErrorLen)
	}
	sched := make([]float64, len(coverage.TargetSideRechecks))
	for i, d := range coverage.TargetSideRechecks {
		sched[i] = d.Seconds()
	}
	// $7: the schedule in seconds; the n-th consecutive observation takes
	// entry min(n, len) (1-based).
	res, err := r.db.ExecContext(ctx, `
		UPDATE asset_coverage c SET state = 'paused', reason = w.outcome,
		       last_outcome = w.outcome, last_error = w.err, fail_streak = `+targetSideStreakSQL+`,
		       next_due_at = `+jitteredIntervalSQL(`($7::float8[])[least(`+targetSideStreakSQL+`, cardinality($7::float8[]))]`)+`,
		       updated_at = now()
		FROM unnest($4::uuid[], $5::text[], $6::text[]) AS w(asset_id, outcome, err)
		WHERE c.tenant_id = $1 AND c.last_run_id = $2 AND c.capability = $3 AND c.vantage = '' AND c.state = 'queued'
		  AND c.asset_id = w.asset_id`,
		tenantID.String(), runID.String(), capability, pq.Array(ids), pq.Array(outcomes), pq.Array(errs), pq.Array(sched))
	if err != nil {
		return 0, fmt.Errorf("settle target-side coverage: %w", err)
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}

// RunTasks returns every task of a run: the commands of its steps (splits
// and follow-ups carry the same step) and the commands that name the run.
func (r *AssetCoverageRepository) RunTasks(ctx context.Context, tenantID, runID shared.ID) ([]coverage.TaskResult, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT c.status, COALESCE(c.error_message, ''), c.payload, COALESCE(c.result, 'null'::jsonb)
		FROM commands c
		WHERE c.tenant_id = $1
		  AND (c.scan_run_step_id IN (SELECT s.id FROM scan_run_steps s
		                              JOIN scan_runs r ON r.id = s.scan_run_id AND r.tenant_id = $1
		                              WHERE s.scan_run_id = $2)
		       OR c.payload->>'scan_run_id' = $2::text)
		ORDER BY c.created_at, c.id`, tenantID.String(), runID.String())
	if err != nil {
		return nil, fmt.Errorf("list run tasks: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []coverage.TaskResult
	for rows.Next() {
		var (
			t               coverage.TaskResult
			payload, result []byte
		)
		if err := rows.Scan(&t.Status, &t.Error, &payload, &result); err != nil {
			return nil, err
		}
		t.Targets = command.PayloadTargets(payload)
		if string(result) != "null" {
			t.Result = result
		}
		out = append(out, t)
	}
	return out, rows.Err()
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
//
// A pair paused because the target stopped answering (unreachable, timeout)
// still applies: once its last success is older than twice the cadence it
// is a gap, so a host that went dark shows up in the gaps and their alert.
// Pairs paused for readiness (no capable sensor) are counted as Paused.
func (r *AssetCoverageRepository) Health(ctx context.Context, tenantID shared.ID, cadence map[string]time.Duration) ([]coverage.CapabilityHealth, error) {
	caps := make([]string, 0, len(cadence))
	secs := make([]float64, 0, len(cadence))
	for c, d := range cadence {
		caps = append(caps, c)
		secs = append(secs, d.Seconds())
	}
	rows, err := r.db.QueryContext(ctx, `
		SELECT c.capability,
		       count(*) FILTER (WHERE c.state NOT IN ('blocked', 'not_applicable')
		                          AND NOT (c.state = 'paused' AND c.reason = ANY($5::text[]))),
		       count(*) FILTER (WHERE c.state NOT IN ('blocked', 'not_applicable')
		                          AND NOT (c.state = 'paused' AND c.reason = ANY($5::text[]))
		                          AND COALESCE(c.last_success_at, c.created_at) < now() - make_interval(secs => 2 * COALESCE(p.every, 86400))),
		       count(*) FILTER (WHERE c.state = 'failed' AND c.fail_streak >= $4),
		       count(*) FILTER (WHERE c.last_outcome = 'ok' AND c.last_success_at > now() - interval '24 hours'),
		       count(*) FILTER (WHERE c.last_outcome = 'no_output' AND c.last_success_at > now() - interval '24 hours'),
		       count(*) FILTER (WHERE c.state = 'paused' AND c.reason = ANY($5::text[])),
		       COALESCE(min(c.reason) FILTER (WHERE c.state = 'paused' AND c.reason = ANY($5::text[])), '')
		FROM asset_coverage c
		LEFT JOIN unnest($2::text[], $3::float8[]) AS p(cap, every) ON p.cap = c.capability
		WHERE c.tenant_id = $1 AND c.vantage = ''
		GROUP BY c.capability
		ORDER BY c.capability`,
		tenantID.String(), pq.Array(caps), pq.Array(secs), coverage.FailingStreak, pq.Array(coverage.ReadinessReasons()))
	if err != nil {
		return nil, fmt.Errorf("coverage health: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []coverage.CapabilityHealth
	for rows.Next() {
		var h coverage.CapabilityHealth
		if err := rows.Scan(&h.Capability, &h.Applicable, &h.Gaps, &h.Failing, &h.OK, &h.NoOutput, &h.Paused, &h.PausedReason); err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

// AlertStates returns the tenant's stored coverage alert states.
func (r *AssetCoverageRepository) AlertStates(ctx context.Context, tenantID shared.ID) ([]coverage.AlertState, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT capability, kind, reason, active, sent_count, last_count, sent_at, cleared_at
		FROM asset_coverage_alerts WHERE tenant_id = $1`, tenantID.String())
	if err != nil {
		return nil, fmt.Errorf("list coverage alert states: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []coverage.AlertState
	for rows.Next() {
		var (
			st            coverage.AlertState
			sent, cleared sql.NullTime
		)
		if err := rows.Scan(&st.Capability, &st.Kind, &st.Reason, &st.Active, &st.SentCount, &st.LastCount, &sent, &cleared); err != nil {
			return nil, err
		}
		st.SentAt, st.ClearedAt = coverageTime(sent), coverageTime(cleared)
		out = append(out, st)
	}
	return out, rows.Err()
}

// SaveAlertStates upserts coverage alert states of the tenant.
func (r *AssetCoverageRepository) SaveAlertStates(ctx context.Context, tenantID shared.ID, states []coverage.AlertState) error {
	if len(states) == 0 {
		return nil
	}
	n := len(states)
	caps, kinds, reasons := make([]string, n), make([]string, n), make([]string, n)
	active := make([]bool, n)
	sent, last := make([]int64, n), make([]int64, n)
	sentAt, clearedAt := make([]*time.Time, n), make([]*time.Time, n)
	for i, st := range states {
		caps[i] = coverage.Clip(st.Capability, coverage.MaxCodeLen)
		kinds[i] = coverage.Clip(st.Kind, 32)
		reasons[i] = coverage.Clip(st.Reason, coverage.MaxCodeLen)
		active[i], sent[i], last[i] = st.Active, int64(st.SentCount), int64(st.LastCount)
		sentAt[i], clearedAt[i] = st.SentAt, st.ClearedAt
	}
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO asset_coverage_alerts (tenant_id, capability, kind, reason, active, sent_count, last_count, sent_at, cleared_at, updated_at)
		SELECT $1, w.capability, w.kind, w.reason, w.active, w.sent, w.last,
		       NULLIF(w.sent_at, '')::timestamptz, NULLIF(w.cleared_at, '')::timestamptz, now()
		FROM unnest($2::text[], $3::text[], $4::text[], $5::bool[], $6::bigint[], $7::bigint[], $8::text[], $9::text[])
		     AS w(capability, kind, reason, active, sent, last, sent_at, cleared_at)
		ON CONFLICT (tenant_id, capability, kind, reason) DO UPDATE SET
		    active = EXCLUDED.active, sent_count = EXCLUDED.sent_count, last_count = EXCLUDED.last_count,
		    sent_at = EXCLUDED.sent_at, cleared_at = EXCLUDED.cleared_at, updated_at = now()`,
		tenantID.String(), pq.Array(caps), pq.Array(kinds), pq.Array(reasons), pq.Array(active),
		pq.Array(sent), pq.Array(last), pq.Array(timeArray(sentAt)), pq.Array(timeArray(clearedAt)))
	if err != nil {
		return fmt.Errorf("save coverage alert states: %w", err)
	}
	return nil
}

// timeArray turns optional times into RFC 3339 text ("" for a missing
// time, read back as NULL).
func timeArray(ts []*time.Time) []string {
	out := make([]string, len(ts))
	for i, t := range ts {
		if t != nil {
			out[i] = t.UTC().Format(time.RFC3339Nano)
		}
	}
	return out
}

var _ coverage.HealthReader = (*AssetCoverageRepository)(nil)
