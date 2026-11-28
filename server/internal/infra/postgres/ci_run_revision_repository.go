package postgres

// Verdict revisions of CI runs and re-judging after a decision
// (docs/rfcs/RFC-077-ci-enforced-gate-and-pr-feedback.md, "Verdict
// revisions"). Every statement is tenant-scoped.

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/server/pkg/domain/cirun"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
)

func truncateJobID(s string) string {
	if len(s) > 64 {
		return s[:64]
	}
	return s
}

func revisionIDStrings(ids []shared.ID) []string {
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		if !id.IsZero() {
			out = append(out, id.String())
		}
	}
	return out
}

// insertRevisionTx appends one verdict revision.
func insertRevisionTx(ctx context.Context, tx *sql.Tx, v cirun.VerdictRevision) error {
	at := v.CreatedAt
	if at.IsZero() {
		at = time.Now().UTC()
	}
	detail := []byte(v.Detail)
	if len(detail) == 0 {
		detail = []byte("{}")
	}
	_, err := tx.ExecContext(ctx, `INSERT INTO ci_run_verdicts (tenant_id, run_id, revision, verdict, detail, cause,
			decision_ids, actor_ids, reopened, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7::uuid[], $8::uuid[], $9, $10)`,
		v.TenantID.String(), v.RunID.String(), v.Revision, v.Verdict, detail, v.Cause,
		pq.Array(revisionIDStrings(v.DecisionIDs)), pq.Array(revisionIDStrings(v.ActorIDs)), v.Reopened, at)
	return err
}

// RunSnapshot returns the run's judge snapshot (nil: none).
func (r *CIRunRepository) RunSnapshot(ctx context.Context, tenantID, runID shared.ID) ([]byte, error) {
	var raw []byte
	err := r.db.QueryRowContext(ctx, `SELECT policy_snapshot FROM ci_runs WHERE tenant_id = $1 AND id = $2`,
		tenantID.String(), runID.String()).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, cirun.ErrRunNotFound
	}
	return raw, err
}

// RejudgeCandidates (see cirun.RevisionRepository). The latest run is picked
// among every run of the pull request and pipeline created in the window,
// running ones included: when a newer run exists (a new push, a re-run) the
// older failing one is not a candidate, so a new push never inherits a pass.
func (r *CIRunRepository) RejudgeCandidates(ctx context.Context, tenantID shared.ID, f cirun.RejudgeFilter) ([]cirun.Run, error) {
	limit := f.Limit
	if limit <= 0 || limit > cirun.MaxRejudgeRuns {
		limit = cirun.MaxRejudgeRuns
	}
	if f.FindingID == nil && f.AssetID == nil && !f.AnyRepository {
		return nil, nil
	}
	rows, err := r.db.QueryContext(ctx, `SELECT `+ciRunColumns+` FROM (
			SELECT DISTINCT ON (c.repository_asset_id, c.pull_request, COALESCE(c.pipeline_id::text, c.id::text)) c.*
			FROM ci_runs c
			WHERE c.tenant_id = $1 AND c.pull_request <> '' AND c.created_at > $2
			  AND ($3::uuid IS NULL OR c.repository_asset_id = $3)
			  AND ($4::uuid IS NULL OR c.repository_asset_id =
			       (SELECT fa.asset_id FROM findings fa WHERE fa.tenant_id = $1 AND fa.id = $4))
			ORDER BY c.repository_asset_id, c.pull_request, COALESCE(c.pipeline_id::text, c.id::text), c.created_at DESC
		) latest
		WHERE latest.status = 'evaluated' AND latest.verdict = 'fail' AND NOT latest.fork AND latest.commit_verified
		  AND latest.provider IN ('github', 'gitlab') AND latest.policy_snapshot IS NOT NULL
		  AND COALESCE(latest.verdict_revised_at, latest.evaluated_at) > $2
		  AND ($4::uuid IS NULL OR EXISTS (SELECT 1 FROM ci_run_findings rf
		      JOIN findings f ON f.tenant_id = rf.tenant_id AND f.fingerprint = rf.fingerprint
		      WHERE rf.tenant_id = latest.tenant_id AND rf.run_id = latest.id AND f.id = $4
		        AND f.asset_id = latest.repository_asset_id))
		ORDER BY latest.created_at
		LIMIT $5`,
		tenantID.String(), f.Since, nullID(f.AssetID), nullID(f.FindingID), limit)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	out := []cirun.Run{}
	for rows.Next() {
		run, err := scanCIRun(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, run)
	}
	return out, rows.Err()
}

// appendRevisionSQL makes a re-judged revision the run's current verdict and
// queues its decoration.
const appendRevisionSQL = `UPDATE ci_runs SET verdict = $3, verdict_detail = $4, verdict_revision = $5,
		verdict_revised_at = $6, updated_at = NOW(),` + decorationQueued + `
	WHERE tenant_id = $1 AND id = $2 AND status = 'evaluated'`

// AppendVerdictRevision (see cirun.RevisionRepository). The run row is
// locked for the whole re-judge, so two decisions racing on one run are
// judged one after the other and the second sees both; revision numbers
// follow the order of the commits.
func (r *CIRunRepository) AppendVerdictRevision(ctx context.Context, tenantID, runID shared.ID, a cirun.RevisionAppend) (*cirun.VerdictRevision, error) {
	var (
		out       *cirun.VerdictRevision
		pausedNow bool
		paused    bool
	)
	err := r.db.Transaction(ctx, func(tx *sql.Tx) error {
		locked, err := scanCIRun(tx.QueryRowContext(ctx, `SELECT `+ciRunColumns+` FROM ci_runs
			WHERE tenant_id = $1 AND id = $2 FOR UPDATE`, tenantID.String(), runID.String()))
		if errors.Is(err, sql.ErrNoRows) {
			return cirun.ErrRunNotFound
		}
		if err != nil {
			return err
		}
		rev, err := a.Build(&locked)
		if err != nil || rev == nil {
			return err
		}
		rev.TenantID, rev.RunID = tenantID, runID
		rev.Revision = locked.CurrentRevision() + 1
		if rev.Reopened && a.ActorID != nil && a.ReopenLimit > 0 {
			stop, now, err := reopenBreakerTx(ctx, tx, tenantID, *a.ActorID, a.ReopenLimit)
			if err != nil {
				return err
			}
			if stop {
				paused, pausedNow = true, now
				return nil
			}
		}
		if locked.VerdictRevision == 0 && locked.Verdict != "" && len(locked.VerdictDetail) > 0 {
			at := time.Time{}
			if locked.EvaluatedAt != nil {
				at = *locked.EvaluatedAt
			}
			if err := insertRevisionTx(ctx, tx, cirun.VerdictRevision{TenantID: tenantID, RunID: runID, Revision: 1,
				Verdict: locked.Verdict, Detail: locked.VerdictDetail, Cause: cirun.RevisionCauseEvaluate, CreatedAt: at}); err != nil {
				return err
			}
		}
		if err := insertRevisionTx(ctx, tx, *rev); err != nil {
			return err
		}
		res, err := tx.ExecContext(ctx, appendRevisionSQL,
			tenantID.String(), runID.String(), rev.Verdict, []byte(rev.Detail), rev.Revision, rev.CreatedAt)
		if err != nil {
			return err
		}
		if err := requireOneRow(res, cirun.ErrRunNotFound); err != nil {
			return err
		}
		out = rev
		return nil
	})
	if err != nil {
		return nil, err
	}
	if paused {
		return nil, &cirun.ErrReopenPaused{PausedNow: pausedNow}
	}
	return out, nil
}

// reopenBreakerTx serializes one person's reopens (advisory lock on tenant
// and person) and says whether this one must stop: the person is paused, or
// reached limit reopens in the last hour (then paused now, pausedNow true).
func reopenBreakerTx(ctx context.Context, tx *sql.Tx, tenantID, actorID shared.ID, limit int) (stop, pausedNow bool, err error) {
	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('ci_reopen:' || $1 || ':' || $2, 0))`,
		tenantID.String(), actorID.String()); err != nil {
		return false, false, err
	}
	var exists bool
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM ci_reopen_pauses WHERE tenant_id = $1 AND user_id = $2)`,
		tenantID.String(), actorID.String()).Scan(&exists); err != nil {
		return false, false, err
	}
	if exists {
		return true, false, nil
	}
	var n int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM ci_run_verdicts
		WHERE tenant_id = $1 AND reopened AND created_at > NOW() - INTERVAL '1 hour' AND actor_ids @> ARRAY[$2::uuid]`,
		tenantID.String(), actorID.String()).Scan(&n); err != nil {
		return false, false, err
	}
	if n < limit {
		return false, false, nil
	}
	res, err := tx.ExecContext(ctx, `INSERT INTO ci_reopen_pauses (tenant_id, user_id, reopens) VALUES ($1, $2, $3)
		ON CONFLICT (tenant_id, user_id) DO NOTHING`, tenantID.String(), actorID.String(), n)
	if err != nil {
		return false, false, err
	}
	created, _ := res.RowsAffected()
	return true, created == 1, nil
}

// ListVerdictRevisions (see cirun.RevisionRepository).
func (r *CIRunRepository) ListVerdictRevisions(ctx context.Context, tenantID, runID shared.ID) ([]cirun.VerdictRevision, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT revision, verdict, detail, cause, decision_ids::text[], actor_ids::text[],
			reopened, created_at
		FROM ci_run_verdicts WHERE tenant_id = $1 AND run_id = $2 ORDER BY revision`, tenantID.String(), runID.String())
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	out := []cirun.VerdictRevision{}
	for rows.Next() {
		v := cirun.VerdictRevision{TenantID: tenantID, RunID: runID}
		var decisions, actors []string
		var detail []byte
		if err := rows.Scan(&v.Revision, &v.Verdict, &detail, &v.Cause, pq.Array(&decisions), pq.Array(&actors),
			&v.Reopened, &v.CreatedAt); err != nil {
			return nil, err
		}
		v.Detail = detail
		v.DecisionIDs = parseIDs(decisions)
		v.ActorIDs = parseIDs(actors)
		out = append(out, v)
	}
	return out, rows.Err()
}

func parseIDs(ss []string) []shared.ID {
	out := make([]shared.ID, 0, len(ss))
	for _, s := range ss {
		if id, err := shared.IDFromString(s); err == nil {
			out = append(out, id)
		}
	}
	return out
}

// MarkGateJobRetried (see cirun.RevisionRepository).
func (r *CIRunRepository) MarkGateJobRetried(ctx context.Context, tenantID, runID shared.ID, revision int) (bool, error) {
	res, err := r.db.ExecContext(ctx, `UPDATE ci_runs SET gate_job_retried_revision = $3
		WHERE tenant_id = $1 AND id = $2 AND gate_job_retried_revision < $3`, tenantID.String(), runID.String(), revision)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n == 1, err
}

// ReopenOnDecision reads the tenant's switch.
func (r *CIRunRepository) ReopenOnDecision(ctx context.Context, tenantID shared.ID) (bool, error) {
	var on bool
	err := r.db.QueryRowContext(ctx, `SELECT ci_reopen_on_decision FROM tenants WHERE id = $1`, tenantID.String()).Scan(&on)
	if errors.Is(err, sql.ErrNoRows) {
		return false, shared.ErrNotFound
	}
	return on, err
}

// SetReopenOnDecision writes the tenant's switch.
func (r *CIRunRepository) SetReopenOnDecision(ctx context.Context, tenantID shared.ID, on bool) error {
	res, err := r.db.ExecContext(ctx, `UPDATE tenants SET ci_reopen_on_decision = $2 WHERE id = $1`, tenantID.String(), on)
	if err != nil {
		return err
	}
	return requireOneRow(res, shared.ErrNotFound)
}

// ReopenPauses lists the tenant's paused people, oldest pause first.
func (r *CIRunRepository) ReopenPauses(ctx context.Context, tenantID shared.ID) ([]cirun.ReopenPause, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT user_id, paused_at, reopens FROM ci_reopen_pauses
		WHERE tenant_id = $1 ORDER BY paused_at LIMIT 200`, tenantID.String())
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	out := []cirun.ReopenPause{}
	for rows.Next() {
		var p cirun.ReopenPause
		var uid string
		if err := rows.Scan(&uid, &p.PausedAt, &p.Reopens); err != nil {
			return nil, err
		}
		p.UserID, _ = shared.IDFromString(uid)
		out = append(out, p)
	}
	return out, rows.Err()
}

// ResumeReopen removes a person's pause (false when there was none).
func (r *CIRunRepository) ResumeReopen(ctx context.Context, tenantID, userID shared.ID) (bool, error) {
	res, err := r.db.ExecContext(ctx, `DELETE FROM ci_reopen_pauses WHERE tenant_id = $1 AND user_id = $2`,
		tenantID.String(), userID.String())
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n == 1, err
}
