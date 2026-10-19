package postgres

// Remediation suggestions (docs/rfcs/RFC-098-remediation-tasks.md §5): the
// generator's candidate reads and its run, and the reads and decisions of
// the suggestions inbox. Every statement carries the tenant.

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/pkg/domain/remediation"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/pagination"
)

// RemediationSuggestionRepository stores remediation suggestions.
type RemediationSuggestionRepository struct {
	db *DB
}

// NewRemediationSuggestionRepository creates the repository.
func NewRemediationSuggestionRepository(db *DB) *RemediationSuggestionRepository {
	return &RemediationSuggestionRepository{db: db}
}

// maxCandidates bounds one tenant's generator input.
const maxCandidates = 50000

// TenantsWithKeysForPlatform lists the tenants that have keyed findings or
// open suggestions (the generator's work list). Only the background job
// calls it.
func (r *RemediationSuggestionRepository) TenantsWithKeysForPlatform(ctx context.Context) ([]shared.ID, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT tenant_id FROM finding_remediation_keys
		UNION
		SELECT tenant_id FROM remediation_suggestions WHERE state IN ('proposed', 'snoozed')`)
	if err != nil {
		return nil, fmt.Errorf("list suggestion tenants: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []shared.ID
	for rows.Next() {
		var id shared.ID
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("list suggestion tenants: %w", err)
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// Candidates reads the tenant's open, keyed, non-pentest findings that are
// not the primary member of an active task, with the asset's primary owner
// (the first primary user and the first primary group).
func (r *RemediationSuggestionRepository) Candidates(ctx context.Context, tenantID shared.ID) ([]remediation.Candidate, error) {
	q := `
		SELECT f.id, frk.remediation_key, frk.title, f.asset_id, COALESCE(f.priority_class, ''), f.severity,
		       COALESCE(f.is_in_kev, false), f.sla_deadline, ` + FindingRiskPointsSQL + `,
		       ou.user_id, og.group_id, COALESCE(f.rule_id, ''), COALESCE(f.title, f.message, '')
		FROM finding_remediation_keys frk
		JOIN findings f ON f.id = frk.finding_id AND f.tenant_id = frk.tenant_id
		LEFT JOIN assets a ON a.id = f.asset_id AND a.tenant_id = f.tenant_id
		LEFT JOIN LATERAL (
			SELECT ao.user_id FROM asset_owners ao
			JOIN users u ON u.id = ao.user_id
			JOIN tenant_members tm ON tm.user_id = ao.user_id AND tm.tenant_id = f.tenant_id
			WHERE ao.asset_id = a.id AND ao.ownership_type = 'primary' AND ao.user_id IS NOT NULL
			ORDER BY ao.assigned_at, ao.id LIMIT 1) ou ON true
		LEFT JOIN LATERAL (
			SELECT ao.group_id FROM asset_owners ao
			JOIN groups g ON g.id = ao.group_id AND g.tenant_id = f.tenant_id
			WHERE ao.asset_id = a.id AND ao.ownership_type = 'primary' AND ao.group_id IS NOT NULL
			ORDER BY ao.assigned_at, ao.id LIMIT 1) og ON true
		WHERE frk.tenant_id = $1
		  AND frk.algorithm_version >= $4
		  AND f.source <> 'pentest'
		  AND f.status <> ALL($2::text[])
		  AND NOT EXISTS (SELECT 1 FROM remediation_task_members m
		                  WHERE m.tenant_id = f.tenant_id AND m.finding_id = f.id AND m.left_at IS NULL AND m.role = 'primary')
		ORDER BY f.id
		LIMIT $3`
	// A key derived by older key rules is never trusted: the generator
	// re-derives the tenant's keys first (SuggestionService.RunTenant).
	rows, err := r.db.QueryContext(ctx, q, tenantID.String(), closedStatusArray(), maxCandidates, remediation.KeyAlgorithmVersion)
	if err != nil {
		return nil, fmt.Errorf("read suggestion candidates: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []remediation.Candidate
	for rows.Next() {
		var (
			c                    remediation.Candidate
			assetID, user, group sql.NullString
			sla                  sql.NullTime
		)
		if err := rows.Scan(&c.FindingID, &c.Key, &c.Title, &assetID, &c.PriorityClass, &c.Severity, &c.InKEV, &sla,
			&c.RiskPoints, &user, &group, &c.RuleID, &c.FindingTitle); err != nil {
			return nil, fmt.Errorf("read suggestion candidates: %w", err)
		}
		c.AssetID, c.SLADeadline = rtNullID(assetID), rtTimePtr(sla)
		c.Owner = remediation.Owner{UserID: rtNullID(user), GroupID: rtNullID(group)}
		out = append(out, c)
	}
	return out, rows.Err()
}

// AcceptedActions returns the tenant's actions for these keys, each with its
// live tasks.
func (r *RemediationSuggestionRepository) AcceptedActions(ctx context.Context, tenantID shared.ID, keys []string) (map[string]remediation.AcceptedAction, error) {
	out := map[string]remediation.AcceptedAction{}
	if len(keys) == 0 {
		return out, nil
	}
	rows, err := r.db.QueryContext(ctx, `
		SELECT a.id, a.action_key, a.title, a.auto_join, t.id, t.assignee_user_id, t.assignee_group_id, t.state
		FROM remediation_actions a
		LEFT JOIN remediation_tasks t ON t.action_id = a.id AND t.tenant_id = a.tenant_id
		     AND t.state NOT IN ('done', 'closed_unverified', 'canceled', 'archived')
		WHERE a.tenant_id = $1 AND a.action_key = ANY($2::text[])
		ORDER BY a.action_key, t.created_at`, tenantID.String(), pq.Array(keys))
	if err != nil {
		return nil, fmt.Errorf("read accepted actions: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var (
			a                   remediation.AcceptedAction
			taskID, user, group sql.NullString
			state               sql.NullString
		)
		if err := rows.Scan(&a.ID, &a.Key, &a.Title, &a.AutoJoin, &taskID, &user, &group, &state); err != nil {
			return nil, fmt.Errorf("read accepted actions: %w", err)
		}
		cur, ok := out[a.Key]
		if !ok {
			cur = a
		}
		if tid := rtNullID(taskID); tid != nil {
			cur.Tasks = append(cur.Tasks, remediation.ActionTask{ID: *tid,
				Owner: remediation.Owner{UserID: rtNullID(user), GroupID: rtNullID(group)},
				State: remediation.TaskState(state.String)})
		}
		out[a.Key] = cur
	}
	return out, rows.Err()
}

// Exclusions returns, per key, the findings a person took out of that fix.
func (r *RemediationSuggestionRepository) Exclusions(ctx context.Context, tenantID shared.ID) (map[string]map[shared.ID]bool, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT action_key, finding_id FROM remediation_key_exclusions WHERE tenant_id = $1`, tenantID.String())
	if err != nil {
		return nil, fmt.Errorf("read key exclusions: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := map[string]map[shared.ID]bool{}
	for rows.Next() {
		var (
			key string
			id  shared.ID
		)
		if err := rows.Scan(&key, &id); err != nil {
			return nil, fmt.Errorf("read key exclusions: %w", err)
		}
		if out[key] == nil {
			out[key] = map[shared.ID]bool{}
		}
		out[key][id] = true
	}
	return out, rows.Err()
}

type openSuggestion struct {
	id           shared.ID
	state        remediation.SuggestionState
	snoozedUntil *time.Time
}

// ApplyRun stores one generator run for a tenant in one transaction, under a
// per-tenant lock so two runs never interleave: an open suggestion with the
// same identity is updated in place (a snoozed one past its date is proposed
// again); a new identity is inserted unless a person dismissed it and it has
// not changed materially; an open suggestion the run no longer produces is
// expired; then up to the daily cap of held-back proposals are surfaced, by
// rank.
func (r *RemediationSuggestionRepository) ApplyRun(ctx context.Context, tenantID shared.ID, ss []remediation.Suggestion, now time.Time) (remediation.RunStats, error) {
	var st remediation.RunStats
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return st, fmt.Errorf("begin suggestion run: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('remediation_suggestions:' || $1, 0))`, tenantID.String()); err != nil {
		return st, fmt.Errorf("lock suggestion run: %w", err)
	}
	open, err := r.openSuggestionsInTx(ctx, tx, tenantID)
	if err != nil {
		return st, err
	}
	seen := map[string]bool{}
	for i := range ss {
		s := &ss[i]
		seen[s.Identity] = true
		if cur, ok := open[s.Identity]; ok {
			wake := cur.state == remediation.SuggestionSnoozed && cur.snoozedUntil != nil && !cur.snoozedUntil.After(now)
			if err := updateSuggestionInTx(ctx, tx, tenantID, cur.id, s, wake); err != nil {
				return st, err
			}
			st.Updated++
			if wake {
				st.Woken++
			}
			continue
		}
		prev, err := lastDismissedInTx(ctx, tx, tenantID, s.Identity)
		if err != nil {
			return st, err
		}
		if prev != nil && !remediation.MateriallyChanged(*prev, *s) {
			st.Held++
			continue
		}
		if err := insertSuggestionInTx(ctx, tx, tenantID, s); err != nil {
			return st, err
		}
		st.Created++
	}
	for identity, cur := range open {
		if seen[identity] {
			continue
		}
		if _, err := tx.ExecContext(ctx, `UPDATE remediation_suggestions SET state = 'expired', version = version + 1, updated_at = now()
			WHERE tenant_id = $1 AND id = $2`, tenantID.String(), cur.id.String()); err != nil {
			return st, fmt.Errorf("expire suggestion: %w", err)
		}
		st.Expired++
	}
	surfaced, err := surfaceInTx(ctx, tx, tenantID, now)
	if err != nil {
		return st, err
	}
	st.Surfaced = surfaced
	statsJSON, _ := json.Marshal(st)
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO remediation_suggestion_runs (tenant_id, last_run_at, last_stats) VALUES ($1, $2, $3)
		ON CONFLICT (tenant_id) DO UPDATE SET last_run_at = EXCLUDED.last_run_at, last_stats = EXCLUDED.last_stats`,
		tenantID.String(), now, statsJSON); err != nil {
		return st, fmt.Errorf("record suggestion run: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return st, fmt.Errorf("commit suggestion run: %w", err)
	}
	return st, nil
}

func (r *RemediationSuggestionRepository) openSuggestionsInTx(ctx context.Context, tx *sql.Tx, tenantID shared.ID) (map[string]openSuggestion, error) {
	rows, err := tx.QueryContext(ctx, `SELECT id, identity, state, snoozed_until FROM remediation_suggestions
		WHERE tenant_id = $1 AND state IN ('proposed', 'snoozed') FOR UPDATE`, tenantID.String())
	if err != nil {
		return nil, fmt.Errorf("read open suggestions: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := map[string]openSuggestion{}
	for rows.Next() {
		var (
			o        openSuggestion
			identity string
			state    string
			snoozed  sql.NullTime
		)
		if err := rows.Scan(&o.id, &identity, &state, &snoozed); err != nil {
			return nil, fmt.Errorf("read open suggestions: %w", err)
		}
		o.state, o.snoozedUntil = remediation.SuggestionState(state), rtTimePtr(snoozed)
		out[identity] = o
	}
	return out, rows.Err()
}

func lastDismissedInTx(ctx context.Context, tx *sql.Tx, tenantID shared.ID, identity string) (*remediation.DismissedSnapshot, error) {
	var snap remediation.DismissedSnapshot
	err := tx.QueryRowContext(ctx, `SELECT member_count, risk_points, has_urgent FROM remediation_suggestions
		WHERE tenant_id = $1 AND identity = $2 AND state = 'dismissed'
		ORDER BY decided_at DESC NULLS LAST LIMIT 1`, tenantID.String(), identity).Scan(&snap.MemberCount, &snap.RiskPoints, &snap.HasUrgent)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read dismissed suggestion: %w", err)
	}
	return &snap, nil
}

func suggestionJSON(s *remediation.Suggestion) (parts, risk, spec []byte, err error) {
	if parts, err = json.Marshal(s.Partitions); err != nil {
		return nil, nil, nil, err
	}
	if risk, err = json.Marshal(s.RiskParts); err != nil {
		return nil, nil, nil, err
	}
	if spec, err = json.Marshal(s.FixSpec); err != nil {
		return nil, nil, nil, err
	}
	return parts, risk, spec, nil
}

func insertSuggestionInTx(ctx context.Context, tx *sql.Tx, tenantID shared.ID, s *remediation.Suggestion) error {
	parts, risk, spec, err := suggestionJSON(s)
	if err != nil {
		return fmt.Errorf("encode suggestion: %w", err)
	}
	_, err = tx.ExecContext(ctx, `
		INSERT INTO remediation_suggestions (tenant_id, kind, algorithm, algorithm_version, action_key, key_kind, title, identity,
			target_action_id, target_task_id, partitions, finding_ids, member_count, omitted_count, risk_points, risk_parts,
			has_urgent, earliest_deadline, confidence, fix_spec)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12::uuid[], $13, $14, $15, $16, $17, $18, $19, $20)`,
		tenantID.String(), string(s.Kind), s.Algorithm, s.AlgorithmVersion, s.Key, s.KeyKind, clipTitle(s.Title), s.Identity,
		idArg(s.TargetActionID), idArg(s.TargetTaskID), parts, pq.Array(rtIDStrings(s.FindingIDs)), s.MemberCount, s.Truncated,
		s.RiskPoints, risk, s.HasUrgent, timeArg(s.EarliestDeadline), s.Confidence, spec)
	if err != nil {
		return fmt.Errorf("insert suggestion: %w", err)
	}
	return nil
}

func updateSuggestionInTx(ctx context.Context, tx *sql.Tx, tenantID, id shared.ID, s *remediation.Suggestion, wake bool) error {
	parts, risk, spec, err := suggestionJSON(s)
	if err != nil {
		return fmt.Errorf("encode suggestion: %w", err)
	}
	_, err = tx.ExecContext(ctx, `
		UPDATE remediation_suggestions SET title = $3, partitions = $4, finding_ids = $5::uuid[], member_count = $6,
			omitted_count = $7, risk_points = $8, risk_parts = $9, has_urgent = $10, earliest_deadline = $11,
			confidence = $12, fix_spec = $13, algorithm_version = $14,
			state = CASE WHEN $15 THEN 'proposed' ELSE state END,
			snoozed_until = CASE WHEN $15 THEN NULL ELSE snoozed_until END,
			version = CASE WHEN finding_ids IS DISTINCT FROM $5::uuid[] OR $15 THEN version + 1 ELSE version END,
			updated_at = CASE WHEN finding_ids IS DISTINCT FROM $5::uuid[] OR $15 THEN now() ELSE updated_at END
		WHERE tenant_id = $1 AND id = $2`,
		tenantID.String(), id.String(), clipTitle(s.Title), parts, pq.Array(rtIDStrings(s.FindingIDs)), s.MemberCount,
		s.Truncated, s.RiskPoints, risk, s.HasUrgent, timeArg(s.EarliestDeadline), s.Confidence, spec, s.AlgorithmVersion, wake)
	if err != nil {
		return fmt.Errorf("update suggestion: %w", err)
	}
	return nil
}

func clipTitle(s string) string {
	if len(s) <= remediation.MaxTaskTitle {
		return s
	}
	n := remediation.MaxTaskTitle
	for n > 0 && s[n]&0xC0 == 0x80 {
		n--
	}
	return s[:n]
}

// surfaceInTx shows held-back proposals, best first, up to the daily cap.
func surfaceInTx(ctx context.Context, tx *sql.Tx, tenantID shared.ID, now time.Time) (int, error) {
	var shown int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM remediation_suggestions
		WHERE tenant_id = $1 AND surfaced_at >= $2`, tenantID.String(), now.Add(-24*time.Hour)).Scan(&shown); err != nil {
		return 0, fmt.Errorf("count surfaced suggestions: %w", err)
	}
	room := remediation.DailySurfaceCap - shown
	if room <= 0 {
		return 0, nil
	}
	res, err := tx.ExecContext(ctx, `
		UPDATE remediation_suggestions SET surfaced_at = $2
		WHERE tenant_id = $1 AND id IN (
			SELECT id FROM remediation_suggestions
			WHERE tenant_id = $1 AND state = 'proposed' AND surfaced_at IS NULL
			ORDER BY risk_points DESC, member_count DESC, earliest_deadline ASC NULLS LAST, id
			LIMIT $3)`, tenantID.String(), now, room)
	if err != nil {
		return 0, fmt.Errorf("surface suggestions: %w", err)
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}

// RunInfo returns the tenant's last run and last digest.
func (r *RemediationSuggestionRepository) RunInfo(ctx context.Context, tenantID shared.ID) (lastRun, lastDigest *time.Time, err error) {
	var run, digest sql.NullTime
	err = r.db.QueryRowContext(ctx, `SELECT last_run_at, last_digest_at FROM remediation_suggestion_runs WHERE tenant_id = $1`,
		tenantID.String()).Scan(&run, &digest)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil, nil
	}
	if err != nil {
		return nil, nil, fmt.Errorf("read suggestion run: %w", err)
	}
	return rtTimePtr(run), rtTimePtr(digest), nil
}

// SurfacedSince counts the proposals surfaced since a time (still open).
func (r *RemediationSuggestionRepository) SurfacedSince(ctx context.Context, tenantID shared.ID, since time.Time) (int, error) {
	var n int
	err := r.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM remediation_suggestions
		WHERE tenant_id = $1 AND state = 'proposed' AND surfaced_at > $2`, tenantID.String(), since).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("count new suggestions: %w", err)
	}
	return n, nil
}

// MarkDigest records that the tenant's digest went out.
func (r *RemediationSuggestionRepository) MarkDigest(ctx context.Context, tenantID shared.ID, at time.Time) error {
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO remediation_suggestion_runs (tenant_id, last_digest_at) VALUES ($1, $2)
		ON CONFLICT (tenant_id) DO UPDATE SET last_digest_at = EXCLUDED.last_digest_at`, tenantID.String(), at)
	if err != nil {
		return fmt.Errorf("record suggestion digest: %w", err)
	}
	return nil
}

const suggestionCols = `s.id, s.tenant_id, s.kind, s.algorithm, s.algorithm_version, s.action_key, s.key_kind, s.title,
	s.identity, s.target_action_id, s.target_task_id, s.partitions, s.finding_ids, s.member_count, s.omitted_count,
	s.risk_points, s.risk_parts, s.has_urgent, s.earliest_deadline, s.confidence, s.fix_spec, s.state,
	COALESCE(s.dismiss_reason, ''), s.state_note, s.decided_by, s.decided_at, s.snoozed_until, s.surfaced_at,
	s.version, s.created_at, s.updated_at`

// visibleLateral counts, per suggestion, its findings in the scope and their
// risk; scopeCond is over "f".
func visibleLateral(scopeCond string) string {
	return ` CROSS JOIN LATERAL (
		SELECT COUNT(*)::int AS vis, COALESCE(SUM(` + FindingRiskPointsSQL + `), 0)::int AS vrisk,
		       MIN(f.sla_deadline) AS vdl
		FROM findings f WHERE f.tenant_id = s.tenant_id AND f.id = ANY(s.finding_ids) AND ` + scopeCond + `) v`
}

func scanSuggestion(scan func(dest ...any) error, extra ...any) (*remediation.Suggestion, error) {
	var (
		s                                  remediation.Suggestion
		kind, state                        string
		action, task, decidedBy            sql.NullString
		parts, risk, spec                  []byte
		ids                                pq.StringArray
		deadline, decidedAt, snoozed, surf sql.NullTime
	)
	dest := []any{&s.ID, &s.TenantID, &kind, &s.Algorithm, &s.AlgorithmVersion, &s.Key, &s.KeyKind, &s.Title,
		&s.Identity, &action, &task, &parts, &ids, &s.MemberCount, &s.Truncated,
		&s.RiskPoints, &risk, &s.HasUrgent, &deadline, &s.Confidence, &spec, &state,
		&s.DismissReason, &s.StateNote, &decidedBy, &decidedAt, &snoozed, &surf,
		&s.Version, &s.CreatedAt, &s.UpdatedAt}
	if err := scan(append(dest, extra...)...); err != nil {
		return nil, err
	}
	s.Kind, s.State = remediation.SuggestionKind(kind), remediation.SuggestionState(state)
	s.TargetActionID, s.TargetTaskID, s.DecidedBy = rtNullID(action), rtNullID(task), rtNullID(decidedBy)
	s.EarliestDeadline, s.DecidedAt, s.SnoozedUntil, s.SurfacedAt = rtTimePtr(deadline), rtTimePtr(decidedAt), rtTimePtr(snoozed), rtTimePtr(surf)
	_ = json.Unmarshal(parts, &s.Partitions)
	_ = json.Unmarshal(risk, &s.RiskParts)
	_ = json.Unmarshal(spec, &s.FixSpec)
	for _, raw := range ids {
		if id, err := shared.IDFromString(raw); err == nil {
			s.FindingIDs = append(s.FindingIDs, id)
		}
	}
	for i := range s.Partitions {
		p := &s.Partitions[i]
		if p.OwnerUser != "" {
			if id, err := shared.IDFromString(p.OwnerUser); err == nil {
				p.Owner.UserID = &id
			}
		}
		if p.OwnerGroup != "" {
			if id, err := shared.IDFromString(p.OwnerGroup); err == nil {
				p.Owner.GroupID = &id
			}
		}
	}
	return &s, nil
}

func suggestionWhere(tenantID shared.ID, f remediation.SuggestionFilter) (string, []any) {
	args := []any{tenantID.String()}
	conds := []string{"s.tenant_id = $1"}
	next := func(v any) string {
		args = append(args, v)
		return fmt.Sprintf("$%d", len(args))
	}
	states := f.States
	if len(states) == 0 {
		states = []remediation.SuggestionState{remediation.SuggestionProposed}
	}
	ss := make([]string, len(states))
	for i, s := range states {
		ss[i] = string(s)
	}
	conds = append(conds, "s.state = ANY("+next(pq.StringArray(ss))+"::text[])")
	if !f.IncludeQueued {
		conds = append(conds, "(s.state <> 'proposed' OR s.surfaced_at IS NOT NULL)")
	}
	if len(f.Kinds) > 0 {
		ks := make([]string, len(f.Kinds))
		for i, k := range f.Kinds {
			ks[i] = string(k)
		}
		conds = append(conds, "s.kind = ANY("+next(pq.StringArray(ks))+"::text[])")
	}
	if f.KeyKind != "" {
		conds = append(conds, "s.key_kind = "+next(f.KeyKind))
	}
	if f.MinRisk > 0 {
		conds = append(conds, "s.risk_points >= "+next(f.MinRisk))
	}
	if q := strings.TrimSpace(f.Search); q != "" {
		conds = append(conds, "s.title ILIKE "+next("%"+escapeLikePattern(q)+"%"))
	}
	return strings.Join(conds, " AND "), args
}

// ListSuggestions lists suggestions, best first. With a scope, only the
// suggestions with at least one finding in it, with the counts, risk and
// deadline over those findings.
func (r *RemediationSuggestionRepository) ListSuggestions(ctx context.Context, tenantID shared.ID, f remediation.SuggestionFilter, page pagination.Pagination) (pagination.Result[*remediation.Suggestion], error) {
	where, args := suggestionWhere(tenantID, f)
	scopeCond, args := dataScopeCond("f.asset_id", f.Scope, args)
	from := ` FROM remediation_suggestions s` + visibleLateral(scopeCond) + ` WHERE ` + where + ` AND v.vis > 0`
	var total int64
	if err := r.db.QueryRowContext(ctx, `SELECT COUNT(*)`+from, args...).Scan(&total); err != nil {
		return pagination.Result[*remediation.Suggestion]{}, fmt.Errorf("count suggestions: %w", err)
	}
	q := `SELECT ` + suggestionCols + `, v.vis, v.vrisk, v.vdl` + from +
		` ORDER BY v.vrisk DESC, v.vis DESC, v.vdl ASC NULLS LAST, s.id` +
		fmt.Sprintf(` LIMIT %d OFFSET %d`, page.Limit(), page.Offset())
	rows, err := r.db.QueryContext(ctx, q, args...)
	if err != nil {
		return pagination.Result[*remediation.Suggestion]{}, fmt.Errorf("list suggestions: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := make([]*remediation.Suggestion, 0)
	for rows.Next() {
		s, err := scanScopedSuggestion(rows.Scan, f.Scope)
		if err != nil {
			return pagination.Result[*remediation.Suggestion]{}, fmt.Errorf("scan suggestion: %w", err)
		}
		out = append(out, s)
	}
	if err := rows.Err(); err != nil {
		return pagination.Result[*remediation.Suggestion]{}, fmt.Errorf("list suggestions: %w", err)
	}
	return pagination.NewResult(out, total, page), nil
}

// scanScopedSuggestion reads a suggestion with its visible counts; for a
// restricted reader the counts, risk and deadline become those over the
// visible findings and the hidden findings are left out of the lists.
func scanScopedSuggestion(scan func(dest ...any) error, scope *shared.DataScope) (*remediation.Suggestion, error) {
	var (
		vis, vrisk int
		vdl        sql.NullTime
	)
	s, err := scanSuggestion(scan, &vis, &vrisk, &vdl)
	if err != nil {
		return nil, err
	}
	if scope != nil && vis < s.MemberCount {
		s.HiddenMembers = s.MemberCount - vis
		s.MemberCount, s.RiskPoints, s.EarliestDeadline = vis, vrisk, rtTimePtr(vdl)
		// Hidden finding ids never leave the server.
		s.FindingIDs = nil
		s.Partitions = nil
		s.RiskParts = remediation.RiskParts{}
	}
	return s, nil
}

// GetSuggestion returns a suggestion the scope can see (at least one
// finding in it).
func (r *RemediationSuggestionRepository) GetSuggestion(ctx context.Context, tenantID, id shared.ID, scope *shared.DataScope) (*remediation.Suggestion, error) {
	args := []any{tenantID.String(), id.String()}
	scopeCond, args := dataScopeCond("f.asset_id", scope, args)
	q := `SELECT ` + suggestionCols + `, v.vis, v.vrisk, v.vdl FROM remediation_suggestions s` + visibleLateral(scopeCond) +
		` WHERE s.tenant_id = $1 AND s.id = $2 AND v.vis > 0`
	s, err := scanScopedSuggestion(r.db.QueryRowContext(ctx, q, args...).Scan, scope)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, remediation.ErrSuggestionNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get suggestion: %w", err)
	}
	return s, nil
}

// SuggestionMembers lists a suggestion's findings in the scope, with their
// location, rule, installed version, scanner advice and the active task that
// holds them now. The fix code of a secret finding is never returned (it
// may carry the secret).
func (r *RemediationSuggestionRepository) SuggestionMembers(ctx context.Context, tenantID, id shared.ID, scope *shared.DataScope, page pagination.Pagination) (pagination.Result[remediation.SuggestionMember], error) {
	args := []any{tenantID.String(), id.String()}
	scopeCond, args := dataScopeCond("f.asset_id", scope, args)
	joins := ` FROM remediation_suggestions s
		JOIN findings f ON f.tenant_id = s.tenant_id AND f.id = ANY(s.finding_ids)
		LEFT JOIN assets a ON a.id = f.asset_id AND a.tenant_id = f.tenant_id`
	where := ` WHERE s.tenant_id = $1 AND s.id = $2 AND ` + scopeCond
	var total int64
	if err := r.db.QueryRowContext(ctx, `SELECT COUNT(*)`+joins+where, args...).Scan(&total); err != nil {
		return pagination.Result[remediation.SuggestionMember]{}, fmt.Errorf("count suggestion members: %w", err)
	}
	rows, err := r.db.QueryContext(ctx, `SELECT f.id, COALESCE(f.title, f.message, ''), f.severity, f.status,
		COALESCE(f.priority_class, ''), f.asset_id, COALESCE(a.name, ''), f.sla_deadline,
		COALESCE(f.rule_id, ''), COALESCE(f.cwe_ids, '{}'::text[]), COALESCE(f.file_path, ''), COALESCE(f.start_line, 0),
		COALESCE(f.first_detected_branch, ''), COALESCE(f.network_port, 0), COALESCE(f.network_transport, ''),
		COALESCE((SELECT array_agg(x.v) FROM (SELECT jsonb_array_elements_text(f.metadata->'affected_assets') AS v
			WHERE jsonb_typeof(f.metadata->'affected_assets') = 'array' LIMIT 6) x), '{}'::text[]),
		COALESCE(a.criticality, ''),
		COALESCE((SELECT p.name FROM software_versions sv
			JOIN software_products p ON p.id = sv.product_id AND (p.tenant_id IS NULL OR p.tenant_id = f.tenant_id)
			WHERE sv.id = f.component_id AND (sv.tenant_id IS NULL OR sv.tenant_id = f.tenant_id)),
			f.metadata->'version_match'->>'product', ''),
		COALESCE((SELECT sv.raw FROM software_versions sv
			WHERE sv.id = f.component_id AND (sv.tenant_id IS NULL OR sv.tenant_id = f.tenant_id)),
			f.metadata->'version_match'->>'version', ''),
		COALESCE(f.remediation->>'recommendation', ''),
		CASE WHEN f.finding_type = 'secret' OR f.secret_type IS NOT NULL OR f.source = 'secret' THEN ''
		     ELSE COALESCE(f.remediation->>'fix_code', '') END,
		at.id, COALESCE(at.title, '')`+joins+`
		LEFT JOIN LATERAL (SELECT t.id, t.title FROM remediation_task_members m
			JOIN remediation_tasks t ON t.tenant_id = m.tenant_id AND t.id = m.task_id
			WHERE m.tenant_id = f.tenant_id AND m.finding_id = f.id AND m.left_at IS NULL AND m.role = 'primary'
			LIMIT 1) at ON true`+where+
		` ORDER BY `+FindingRiskPointsSQL+` DESC, f.sla_deadline ASC NULLS LAST, f.id`+
		fmt.Sprintf(` LIMIT %d OFFSET %d`, page.Limit(), page.Offset()), args...)
	if err != nil {
		return pagination.Result[remediation.SuggestionMember]{}, fmt.Errorf("list suggestion members: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := make([]remediation.SuggestionMember, 0)
	for rows.Next() {
		var (
			m         remediation.SuggestionMember
			assetID   sql.NullString
			sla       sql.NullTime
			cwes      pq.StringArray
			targets   pq.StringArray
			taskID    sql.NullString
			taskTitle string
		)
		if err := rows.Scan(&m.FindingID, &m.Title, &m.Severity, &m.Status, &m.PriorityClass, &assetID, &m.AssetName, &sla,
			&m.RuleID, &cwes, &m.FilePath, &m.StartLine, &m.Branch, &m.NetworkPort, &m.NetworkTransport, &targets,
			&m.AssetCriticality, &m.PackageName, &m.InstalledVersion, &m.Recommendation, &m.FixCode, &taskID, &taskTitle); err != nil {
			return pagination.Result[remediation.SuggestionMember]{}, fmt.Errorf("scan suggestion member: %w", err)
		}
		m.AssetID, m.SLADeadline = rtNullID(assetID), rtTimePtr(sla)
		m.CWEIDs, m.LocationTargets = []string(cwes), []string(targets)
		if id := rtNullID(taskID); id != nil {
			m.ActiveTask = &remediation.TaskRef{ID: *id, Title: taskTitle}
		}
		out = append(out, m)
	}
	if err := rows.Err(); err != nil {
		return pagination.Result[remediation.SuggestionMember]{}, fmt.Errorf("list suggestion members: %w", err)
	}
	return pagination.NewResult(out, total, page), nil
}

// DecideSuggestion moves an open suggestion (proposed or snoozed) at the
// caller's version to dismissed, snoozed or proposed (reopen of a dismissed
// or snoozed one). Anything else answers ErrSuggestionDecided.
func (r *RemediationSuggestionRepository) DecideSuggestion(ctx context.Context, tenantID, id shared.ID, version int, d remediation.SuggestionDecision) (*remediation.Suggestion, error) {
	from := `('proposed', 'snoozed')`
	if d.State == remediation.SuggestionProposed {
		from = `('dismissed', 'snoozed')`
	}
	var reason any
	if d.Reason != "" {
		reason = string(d.Reason)
	}
	res, err := r.db.ExecContext(ctx, `
		UPDATE remediation_suggestions SET state = $4, dismiss_reason = $5, state_note = $6, snoozed_until = $7,
			decided_by = $8, decided_at = now(), version = version + 1, updated_at = now(),
			surfaced_at = COALESCE(surfaced_at, now())
		WHERE tenant_id = $1 AND id = $2 AND version = $3 AND state IN `+from,
		tenantID.String(), id.String(), version, string(d.State), reason, d.Note, timeArg(d.SnoozedUntil), idArg(d.ActorID))
	if err != nil {
		if isUniqueViolation(err) {
			// Reopening while the generator already proposed the same fix again.
			return nil, remediation.ErrSuggestionDecided
		}
		return nil, fmt.Errorf("decide suggestion: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return nil, remediation.ErrSuggestionDecided
	}
	return r.GetSuggestion(ctx, tenantID, id, nil)
}

// CountSuggestions summarizes the open suggestions the scope can see.
func (r *RemediationSuggestionRepository) CountSuggestions(ctx context.Context, tenantID shared.ID, scope *shared.DataScope) (remediation.SuggestionCounts, error) {
	args := []any{tenantID.String()}
	scopeCond, args := dataScopeCond("f.asset_id", scope, args)
	rows, err := r.db.QueryContext(ctx, `SELECT s.state, s.kind, s.surfaced_at IS NOT NULL, COUNT(*)
		FROM remediation_suggestions s`+visibleLateral(scopeCond)+`
		WHERE s.tenant_id = $1 AND s.state IN ('proposed', 'snoozed') AND v.vis > 0
		GROUP BY 1, 2, 3`, args...)
	if err != nil {
		return remediation.SuggestionCounts{}, fmt.Errorf("count suggestions: %w", err)
	}
	defer func() { _ = rows.Close() }()
	c := remediation.SuggestionCounts{ByKind: map[string]int{}}
	for rows.Next() {
		var (
			state, kind string
			surfaced    bool
			n           int
		)
		if err := rows.Scan(&state, &kind, &surfaced, &n); err != nil {
			return c, fmt.Errorf("count suggestions: %w", err)
		}
		switch {
		case state == string(remediation.SuggestionSnoozed):
			c.Snoozed += n
		case surfaced:
			c.Proposed += n
			c.ByKind[kind] += n
		default:
			c.Queued += n
		}
	}
	return c, rows.Err()
}

var _ remediation.SuggestionRepository = (*RemediationSuggestionRepository)(nil)
