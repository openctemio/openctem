package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/pkg/domain/assetgroup"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/pagination"
)

// The rule store of asset groups: rules, member sources, exclusions and the
// join/leave history. Every statement names the tenant, so a group or asset
// of another tenant is never read or written.

var _ assetgroup.RuleStore = (*AssetGroupRepository)(nil)

func idPtrString(id *shared.ID) any {
	if id == nil || id.IsZero() {
		return nil
	}
	return id.String()
}

func scanRuleState(groupID shared.ID, raw []byte, editor sql.NullString, status string, evaluated sql.NullTime, excluded int) (*assetgroup.RuleState, error) {
	st := &assetgroup.RuleState{GroupID: groupID, Status: status, Excluded: excluded}
	if len(raw) > 0 {
		rule, err := assetgroup.ParseRule(raw)
		if err != nil {
			return nil, fmt.Errorf("stored rule of group %s: %w", groupID, err)
		}
		st.Rule = rule
	}
	if editor.Valid {
		if id, err := shared.IDFromString(editor.String); err == nil {
			st.EditorID = &id
		}
	}
	if evaluated.Valid {
		t := evaluated.Time
		st.EvaluatedAt = &t
	}
	return st, nil
}

// GetRuleState implements assetgroup.RuleStore.
func (r *AssetGroupRepository) GetRuleState(ctx context.Context, tenantID, groupID shared.ID) (*assetgroup.RuleState, error) {
	var (
		raw       []byte
		editor    sql.NullString
		status    string
		evaluated sql.NullTime
		excluded  int
	)
	err := r.db.QueryRowContext(ctx, `
		SELECT ag.rule, ag.rule_editor_id::text, ag.rule_status, ag.rule_evaluated_at,
			(SELECT COUNT(*) FROM asset_group_exclusions e WHERE e.asset_group_id = ag.id)
		FROM asset_groups ag WHERE ag.tenant_id = $1 AND ag.id = $2`,
		tenantID.String(), groupID.String()).Scan(&raw, &editor, &status, &evaluated, &excluded)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, shared.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get group rule: %w", err)
	}
	return scanRuleState(groupID, raw, editor, status, evaluated, excluded)
}

// GetRuleSummaries implements assetgroup.RuleStore.
func (r *AssetGroupRepository) GetRuleSummaries(ctx context.Context, tenantID shared.ID, groupIDs []shared.ID) (map[shared.ID]*assetgroup.RuleState, error) {
	out := map[shared.ID]*assetgroup.RuleState{}
	if len(groupIDs) == 0 {
		return out, nil
	}
	rows, err := r.db.QueryContext(ctx, `
		SELECT ag.id::text, ag.rule, ag.rule_editor_id::text, ag.rule_status, ag.rule_evaluated_at
		FROM asset_groups ag
		WHERE ag.tenant_id = $1 AND ag.id = ANY($2::uuid[]) AND ag.rule IS NOT NULL`,
		tenantID.String(), pq.Array(memberIDStrings(groupIDs)))
	if err != nil {
		return nil, fmt.Errorf("list group rules: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var (
			idStr     string
			raw       []byte
			editor    sql.NullString
			status    string
			evaluated sql.NullTime
		)
		if err := rows.Scan(&idStr, &raw, &editor, &status, &evaluated); err != nil {
			return nil, fmt.Errorf("scan group rule: %w", err)
		}
		id, err := shared.IDFromString(idStr)
		if err != nil {
			continue
		}
		st, err := scanRuleState(id, raw, editor, status, evaluated, 0)
		if err != nil {
			continue
		}
		out[id] = st
	}
	return out, rows.Err()
}

// SetRule implements assetgroup.RuleStore.
func (r *AssetGroupRepository) SetRule(ctx context.Context, tenantID, groupID shared.ID, rule *assetgroup.Rule, editorID, _ *shared.ID) error {
	var doc any
	if rule != nil {
		b, err := rule.JSON()
		if err != nil {
			return fmt.Errorf("encode group rule: %w", err)
		}
		doc = string(b)
	} else {
		editorID = nil
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("set group rule: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	res, err := tx.ExecContext(ctx, `
		UPDATE asset_groups SET rule = $3::jsonb, rule_editor_id = $4, rule_status = 'idle',
			rule_evaluated_at = NULL, updated_at = NOW()
		WHERE tenant_id = $1 AND id = $2`,
		tenantID.String(), groupID.String(), doc, idPtrString(editorID))
	if err != nil {
		return fmt.Errorf("set group rule: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return shared.ErrNotFound
	}
	if rule == nil {
		// Without a rule the members it brought in are plain members, and
		// the exclusions have nothing to exclude from.
		if _, err := tx.ExecContext(ctx, `UPDATE asset_group_members SET source = 'manual'
			WHERE asset_group_id = $1 AND source = 'rule'`, groupID.String()); err != nil {
			return fmt.Errorf("release rule members: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM asset_group_exclusions WHERE asset_group_id = $1`, groupID.String()); err != nil {
			return fmt.Errorf("clear exclusions: %w", err)
		}
	}
	return tx.Commit()
}

// SetRuleStatus implements assetgroup.RuleStore.
func (r *AssetGroupRepository) SetRuleStatus(ctx context.Context, tenantID, groupID shared.ID, status string) error {
	_, err := r.db.ExecContext(ctx, `
		UPDATE asset_groups SET rule_status = $3, rule_evaluated_at = NOW()
		WHERE tenant_id = $1 AND id = $2 AND rule IS NOT NULL`,
		tenantID.String(), groupID.String(), status)
	if err != nil {
		return fmt.Errorf("set group rule status: %w", err)
	}
	return nil
}

// ListRuleGroups implements assetgroup.RuleStore.
func (r *AssetGroupRepository) ListRuleGroups(ctx context.Context, tenantID shared.ID) ([]assetgroup.RuleGroupRef, error) {
	q := `SELECT id::text, tenant_id::text, rule_editor_id::text FROM asset_groups WHERE rule IS NOT NULL`
	var args []any
	if !tenantID.IsZero() {
		q += ` AND tenant_id = $1`
		args = append(args, tenantID.String())
	}
	q += ` ORDER BY tenant_id, id`
	rows, err := r.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("list rule groups: %w", err)
	}
	defer rows.Close()
	var out []assetgroup.RuleGroupRef
	for rows.Next() {
		var gid, tid string
		var editor sql.NullString
		if err := rows.Scan(&gid, &tid, &editor); err != nil {
			return nil, fmt.Errorf("scan rule group: %w", err)
		}
		g, err1 := shared.IDFromString(gid)
		t, err2 := shared.IDFromString(tid)
		if err1 != nil || err2 != nil {
			continue
		}
		ref := assetgroup.RuleGroupRef{GroupID: g, TenantID: t}
		if editor.Valid {
			if e, err := shared.IDFromString(editor.String); err == nil {
				ref.EditorID = &e
			}
		}
		out = append(out, ref)
	}
	return out, rows.Err()
}

// ruleTargetCTE is the evaluation result as rows: the tenant's live assets
// among the given ids that the group does not exclude. $1 group, $2 tenant,
// $3 asset ids.
const ruleTargetCTE = `target AS (
	SELECT a.id, a.name FROM assets a
	WHERE a.tenant_id = $2 AND a.deleted_at IS NULL AND a.id = ANY($3::uuid[])
	  AND NOT EXISTS (SELECT 1 FROM asset_group_exclusions e WHERE e.asset_group_id = $1 AND e.asset_id = a.id)
)`

// ApplyRule implements assetgroup.RuleStore.
func (r *AssetGroupRepository) ApplyRule(ctx context.Context, in assetgroup.ApplyInput) (assetgroup.ApplyResult, error) {
	var res assetgroup.ApplyResult
	gid, tid := in.GroupID.String(), in.TenantID.String()
	ids := pq.Array(memberIDStrings(in.AssetIDs))

	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return res, fmt.Errorf("apply group rule: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	// One evaluation of a group at a time.
	var locked int
	if err := tx.QueryRowContext(ctx, `SELECT 1 FROM asset_groups WHERE id = $1 AND tenant_id = $2 FOR UPDATE`, gid, tid).Scan(&locked); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return res, shared.ErrNotFound
		}
		return res, fmt.Errorf("lock group: %w", err)
	}

	if in.Cap > 0 {
		var total int
		//nolint:gosec // G202: ruleTargetCTE is a fixed SQL fragment
		if err := tx.QueryRowContext(ctx, `WITH `+ruleTargetCTE+`
			SELECT COUNT(*) FROM (
				SELECT id FROM target
				UNION
				SELECT asset_id FROM asset_group_members WHERE asset_group_id = $1 AND source <> 'rule'
			) u`, gid, tid, ids).Scan(&total); err != nil {
			return res, fmt.Errorf("count group result: %w", err)
		}
		if total > in.Cap {
			res.OverCap = true
			return res, nil
		}
	}

	//nolint:gosec // G202: ruleTargetCTE is a fixed SQL fragment
	left, err := tx.ExecContext(ctx, `WITH `+ruleTargetCTE+`,
		gone AS (
			DELETE FROM asset_group_members m
			WHERE m.asset_group_id = $1 AND m.source = 'rule'
			  AND NOT EXISTS (SELECT 1 FROM target t WHERE t.id = m.asset_id)
			RETURNING m.asset_id
		)
		INSERT INTO asset_group_member_history (tenant_id, asset_group_id, asset_id, asset_name, action, source, reason)
		SELECT $2, $1, g.asset_id, COALESCE(a.name, ''), 'left', 'rule', 'no_longer_matches'
		FROM gone g LEFT JOIN assets a ON a.id = g.asset_id`, gid, tid, ids)
	if err != nil {
		return res, fmt.Errorf("remove rule members: %w", err)
	}
	n, _ := left.RowsAffected()
	res.Left = int(n)

	//nolint:gosec // G202: ruleTargetCTE is a fixed SQL fragment
	joined, err := tx.ExecContext(ctx, `WITH `+ruleTargetCTE+`,
		ins AS (
			INSERT INTO asset_group_members (asset_group_id, asset_id, source)
			SELECT $1, t.id, 'rule' FROM target t
			ON CONFLICT DO NOTHING
			RETURNING asset_id
		)
		INSERT INTO asset_group_member_history (tenant_id, asset_group_id, asset_id, asset_name, action, source, reason)
		SELECT $2, $1, t.id, t.name, 'joined', 'rule', 'matches_rule'
		FROM ins JOIN target t ON t.id = ins.asset_id`, gid, tid, ids)
	if err != nil {
		return res, fmt.Errorf("add rule members: %w", err)
	}
	n, _ = joined.RowsAffected()
	res.Joined = int(n)

	if _, err := tx.ExecContext(ctx, `UPDATE asset_groups SET rule_status = 'ok', rule_evaluated_at = NOW()
		WHERE id = $1 AND tenant_id = $2`, gid, tid); err != nil {
		return res, fmt.Errorf("record evaluation: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return res, fmt.Errorf("commit group rule: %w", err)
	}
	return res, nil
}

// RuleMemberIDs implements assetgroup.RuleStore.
func (r *AssetGroupRepository) RuleMemberIDs(ctx context.Context, tenantID, groupID shared.ID, source string) ([]shared.ID, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT m.asset_id::text FROM asset_group_members m
		JOIN asset_groups g ON g.id = m.asset_group_id AND g.tenant_id = $1
		WHERE m.asset_group_id = $2 AND m.source = $3`,
		tenantID.String(), groupID.String(), source)
	if err != nil {
		return nil, fmt.Errorf("list members by source: %w", err)
	}
	defer rows.Close()
	var out []shared.ID
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			return nil, err
		}
		if id, err := shared.IDFromString(s); err == nil {
			out = append(out, id)
		}
	}
	return out, rows.Err()
}

// AddMembers implements assetgroup.RuleStore.
func (r *AssetGroupRepository) AddMembers(ctx context.Context, tenantID, groupID shared.ID, assetIDs []shared.ID, source string, actorID *shared.ID) (int, error) {
	if len(assetIDs) == 0 {
		return 0, nil
	}
	if !assetgroup.ValidSource(source) || source == assetgroup.SourceRule {
		return 0, fmt.Errorf("%w: invalid member source", shared.ErrValidation)
	}
	reason := assetgroup.ReasonAddedByHand
	if source == assetgroup.SourcePaste {
		reason = assetgroup.ReasonAddedByPaste
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("add members: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	ids := pq.Array(memberIDStrings(assetIDs))
	var added int
	err = tx.QueryRowContext(ctx, `
		WITH own AS (
			SELECT a.id, a.name FROM assets a
			WHERE a.tenant_id = $1 AND a.deleted_at IS NULL AND a.id = ANY($3::uuid[])
			  AND EXISTS (SELECT 1 FROM asset_groups g WHERE g.id = $2 AND g.tenant_id = $1)
		), ins AS (
			INSERT INTO asset_group_members (asset_group_id, asset_id, source)
			SELECT $2, id, $4 FROM own
			ON CONFLICT (asset_group_id, asset_id) DO UPDATE SET source = EXCLUDED.source
				WHERE asset_group_members.source = 'rule'
			RETURNING asset_id, (xmax = 0) AS inserted
		), hist AS (
			INSERT INTO asset_group_member_history (tenant_id, asset_group_id, asset_id, asset_name, action, source, reason, actor_id)
			SELECT $1, $2, o.id, o.name, 'joined', $4, $5, $6
			FROM ins JOIN own o ON o.id = ins.asset_id WHERE ins.inserted
			RETURNING 1
		), unex AS (
			DELETE FROM asset_group_exclusions e WHERE e.asset_group_id = $2 AND e.asset_id IN (SELECT id FROM own)
			RETURNING 1
		)
		SELECT (SELECT COUNT(*) FROM hist)`,
		tenantID.String(), groupID.String(), ids, source, reason, idPtrString(actorID)).Scan(&added)
	if err != nil {
		return 0, fmt.Errorf("add members: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("add members: %w", err)
	}
	return added, nil
}

// RemoveMembers implements assetgroup.RuleStore.
func (r *AssetGroupRepository) RemoveMembers(ctx context.Context, tenantID, groupID shared.ID, assetIDs []shared.ID, exclude bool, actorID *shared.ID) (int, error) {
	if len(assetIDs) == 0 {
		return 0, nil
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("remove members: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	ids := pq.Array(memberIDStrings(assetIDs))
	var removed int
	err = tx.QueryRowContext(ctx, `
		WITH gone AS (
			DELETE FROM asset_group_members m USING asset_groups g
			WHERE m.asset_group_id = $2 AND g.id = m.asset_group_id AND g.tenant_id = $1
			  AND m.asset_id = ANY($3::uuid[])
			RETURNING m.asset_id, m.source
		), hist AS (
			INSERT INTO asset_group_member_history (tenant_id, asset_group_id, asset_id, asset_name, action, source, reason, actor_id)
			SELECT $1, $2, x.asset_id, COALESCE(a.name, ''), 'left', x.source, 'removed_by_hand', $4
			FROM gone x LEFT JOIN assets a ON a.id = x.asset_id
			RETURNING 1
		)
		SELECT (SELECT COUNT(*) FROM hist)`,
		tenantID.String(), groupID.String(), ids, idPtrString(actorID)).Scan(&removed)
	if err != nil {
		return 0, fmt.Errorf("remove members: %w", err)
	}
	if exclude {
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO asset_group_exclusions (asset_group_id, asset_id, excluded_by)
			SELECT $2, a.id, $4 FROM assets a
			WHERE a.tenant_id = $1 AND a.id = ANY($3::uuid[])
			  AND EXISTS (SELECT 1 FROM asset_groups g WHERE g.id = $2 AND g.tenant_id = $1)
			ON CONFLICT DO NOTHING`,
			tenantID.String(), groupID.String(), ids, idPtrString(actorID)); err != nil {
			return 0, fmt.Errorf("exclude members: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("remove members: %w", err)
	}
	return removed, nil
}

func scanHistory(rows *sql.Rows) ([]*assetgroup.HistoryEntry, error) {
	var out []*assetgroup.HistoryEntry
	for rows.Next() {
		var (
			id, gid, aid, name, gname, action, source, reason string
			actor                                             sql.NullString
			at                                                time.Time
		)
		if err := rows.Scan(&id, &gid, &gname, &aid, &name, &action, &source, &reason, &actor, &at); err != nil {
			return nil, fmt.Errorf("scan history: %w", err)
		}
		e := &assetgroup.HistoryEntry{AssetName: name, GroupName: gname, Action: action, Source: source, Reason: reason, CreatedAt: at}
		e.ID, _ = shared.IDFromString(id)
		e.GroupID, _ = shared.IDFromString(gid)
		e.AssetID, _ = shared.IDFromString(aid)
		if actor.Valid {
			if a, err := shared.IDFromString(actor.String); err == nil {
				e.ActorID = &a
			}
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

const historyColumns = `h.id::text, h.asset_group_id::text, COALESCE(g.name, ''), h.asset_id::text, h.asset_name,
	h.action, h.source, h.reason, h.actor_id::text, h.created_at`

// ListHistory implements assetgroup.RuleStore.
func (r *AssetGroupRepository) ListHistory(ctx context.Context, tenantID, groupID shared.ID, page pagination.Pagination) (pagination.Result[*assetgroup.HistoryEntry], error) {
	return r.listHistory(ctx, `h.tenant_id = $1 AND h.asset_group_id = $2`, tenantID, groupID, page)
}

// ListAssetHistory implements assetgroup.RuleStore.
func (r *AssetGroupRepository) ListAssetHistory(ctx context.Context, tenantID, assetID shared.ID, page pagination.Pagination) (pagination.Result[*assetgroup.HistoryEntry], error) {
	return r.listHistory(ctx, `h.tenant_id = $1 AND h.asset_id = $2`, tenantID, assetID, page)
}

func (r *AssetGroupRepository) listHistory(ctx context.Context, where string, tenantID, keyID shared.ID, page pagination.Pagination) (pagination.Result[*assetgroup.HistoryEntry], error) {
	var total int64
	//nolint:gosec // G202: where is a fixed SQL fragment
	if err := r.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM asset_group_member_history h WHERE `+where,
		tenantID.String(), keyID.String()).Scan(&total); err != nil {
		return pagination.Result[*assetgroup.HistoryEntry]{}, fmt.Errorf("count history: %w", err)
	}
	//nolint:gosec // G202: where and historyColumns are fixed SQL fragments
	rows, err := r.db.QueryContext(ctx, `SELECT `+historyColumns+`
		FROM asset_group_member_history h LEFT JOIN asset_groups g ON g.id = h.asset_group_id
		WHERE `+where+` ORDER BY h.created_at DESC, h.id DESC LIMIT $3 OFFSET $4`,
		tenantID.String(), keyID.String(), page.Limit(), page.Offset())
	if err != nil {
		return pagination.Result[*assetgroup.HistoryEntry]{}, fmt.Errorf("list history: %w", err)
	}
	defer rows.Close()
	entries, err := scanHistory(rows)
	if err != nil {
		return pagination.Result[*assetgroup.HistoryEntry]{}, err
	}
	return pagination.NewResult(entries, total, page), nil
}

// RelatedAssetIDs implements assetgroup.RuleStore.
func (r *AssetGroupRepository) RelatedAssetIDs(ctx context.Context, tenantID shared.ID, hostIDs []shared.ID) ([]shared.ID, error) {
	if len(hostIDs) == 0 {
		return nil, nil
	}
	rows, err := r.db.QueryContext(ctx, `
		SELECT x.id::text FROM assets x
		WHERE x.tenant_id = $1 AND x.deleted_at IS NULL
		  AND x.asset_class IN ('service', 'web_endpoint', 'certificate', 'application')
		  AND NOT (x.id = ANY($2::uuid[]))
		  AND (x.parent_id = ANY($2::uuid[])
		    OR EXISTS (SELECT 1 FROM asset_relationships ar
		        WHERE ar.tenant_id = $1
		          AND ar.relationship_type IN ('runs_on', 'exposes', 'serves_certificate', 'contains')
		          AND ((ar.source_asset_id = x.id AND ar.target_asset_id = ANY($2::uuid[]))
		            OR (ar.target_asset_id = x.id AND ar.source_asset_id = ANY($2::uuid[])))))`,
		tenantID.String(), pq.Array(memberIDStrings(hostIDs)))
	if err != nil {
		return nil, fmt.Errorf("related assets: %w", err)
	}
	defer rows.Close()
	var out []shared.ID
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			return nil, err
		}
		if id, err := shared.IDFromString(s); err == nil {
			out = append(out, id)
		}
	}
	return out, rows.Err()
}

func (r *AssetGroupRepository) uses(ctx context.Context, q string, tenantID, groupID shared.ID) ([]assetgroup.Use, error) {
	rows, err := r.db.QueryContext(ctx, q, tenantID.String(), groupID.String())
	if err != nil {
		return nil, fmt.Errorf("group uses: %w", err)
	}
	defer rows.Close()
	var out []assetgroup.Use
	for rows.Next() {
		var id, name string
		if err := rows.Scan(&id, &name); err != nil {
			return nil, err
		}
		if uid, err := shared.IDFromString(id); err == nil {
			out = append(out, assetgroup.Use{ID: uid, Name: name})
		}
	}
	return out, rows.Err()
}

// ScanUses implements assetgroup.RuleStore.
func (r *AssetGroupRepository) ScanUses(ctx context.Context, tenantID, groupID shared.ID) ([]assetgroup.Use, error) {
	return r.uses(ctx, `
		SELECT s.id::text, s.name FROM scans s
		WHERE s.tenant_id = $1 AND s.archived_at IS NULL
		  AND (s.asset_group_id = $2 OR $2::uuid = ANY(s.asset_group_ids))
		ORDER BY s.name LIMIT 50`, tenantID, groupID)
}

// TeamUses implements assetgroup.RuleStore.
func (r *AssetGroupRepository) TeamUses(ctx context.Context, tenantID, groupID shared.ID) ([]assetgroup.Use, error) {
	return r.uses(ctx, `
		SELECT DISTINCT t.id::text, t.name FROM group_asset_scope_rules sr
		JOIN groups t ON t.id = sr.group_id AND t.tenant_id = sr.tenant_id
		WHERE sr.tenant_id = $1 AND sr.is_active AND $2::uuid = ANY(sr.match_asset_group_ids)
		ORDER BY t.name LIMIT 50`, tenantID, groupID)
}

// EditorActive implements assetgroup.RuleStore.
func (r *AssetGroupRepository) EditorActive(ctx context.Context, tenantID, userID shared.ID) (bool, error) {
	var ok bool
	err := r.db.QueryRowContext(ctx, `
		SELECT EXISTS (SELECT 1 FROM tenant_members
			WHERE tenant_id = $1 AND user_id = $2 AND status = 'active'
			  AND (expires_at IS NULL OR expires_at > NOW()))`,
		tenantID.String(), userID.String()).Scan(&ok)
	if err != nil {
		return false, fmt.Errorf("check rule editor: %w", err)
	}
	return ok, nil
}

// ExcludedIDs implements assetgroup.RuleStore.
func (r *AssetGroupRepository) ExcludedIDs(ctx context.Context, tenantID, groupID shared.ID) ([]shared.ID, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT e.asset_id::text FROM asset_group_exclusions e
		JOIN asset_groups g ON g.id = e.asset_group_id AND g.tenant_id = $1
		WHERE e.asset_group_id = $2`, tenantID.String(), groupID.String())
	if err != nil {
		return nil, fmt.Errorf("list exclusions: %w", err)
	}
	defer rows.Close()
	var out []shared.ID
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			return nil, err
		}
		if id, err := shared.IDFromString(s); err == nil {
			out = append(out, id)
		}
	}
	return out, rows.Err()
}
