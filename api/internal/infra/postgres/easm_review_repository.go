package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/internal/app/easm"
	"github.com/openctemio/openctem/api/pkg/domain/attribution"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// The attribution review queue (RFC-036 §6.4) on asset_attributions and
// easm_evidence. Every query is tenant-scoped; a non-nil data scope narrows
// rows to the caller's assets exactly as the asset list does.

var _ easm.ReviewStore = (*AttributionRepository)(nil)

// ListForReview returns one page of assets whose attribution is in q.States,
// most confident first, with their evidence.
func (r *AttributionRepository) ListForReview(ctx context.Context, tenantID shared.ID, scopeUserID *shared.ID, q easm.ReviewQuery) (*easm.ReviewPage, error) {
	states := make([]string, len(q.States))
	for i, s := range q.States {
		states[i] = string(s)
	}
	args := []any{tenantID.String(), pq.Array(states), q.MinConfidence}
	where := []string{
		"aa.tenant_id = $1", "aa.state = ANY($2)", "aa.confidence >= $3",
		"a.tenant_id = aa.tenant_id", "a.deleted_at IS NULL",
	}
	if len(q.Types) > 0 {
		args = append(args, pq.Array(q.Types))
		where = append(where, fmt.Sprintf("a.asset_type = ANY($%d)", len(args)))
	}
	if q.Search != "" {
		args = append(args, wrapLikePattern(q.Search))
		where = append(where, fmt.Sprintf("a.name ILIKE $%d", len(args)))
	}
	if q.Reason != "" {
		args = append(args, q.Reason)
		where = append(where, fmt.Sprintf("aa.reason = $%d", len(args)))
	}
	sc, args := scopeClause("a.id", scopeUserID, tenantID, args)
	from := " FROM asset_attributions aa JOIN assets a ON a.id = aa.asset_id WHERE " + strings.Join(where, " AND ") + sc

	page := &easm.ReviewPage{Items: []easm.ReviewItem{}}
	if err := r.db.QueryRowContext(ctx, "SELECT count(*)"+from, args...).Scan(&page.Total); err != nil {
		return nil, fmt.Errorf("count review queue: %w", err)
	}
	args = append(args, q.Limit, q.Offset)
	rows, err := r.db.QueryContext(ctx, `
		SELECT a.id, a.name, a.asset_type, aa.state, aa.confidence, aa.reason, aa.created_at, a.last_seen`+from+
		fmt.Sprintf(" ORDER BY aa.confidence DESC, aa.created_at, a.id LIMIT $%d OFFSET $%d", len(args)-1, len(args)),
		args...)
	if err != nil {
		return nil, fmt.Errorf("list review queue: %w", err)
	}
	defer rows.Close()
	index := map[string]int{}
	ids := []string{}
	for rows.Next() {
		var (
			it       easm.ReviewItem
			lastSeen sql.NullTime
		)
		if err := rows.Scan(&it.AssetID, &it.Name, &it.Type, &it.State, &it.Confidence, &it.Reason, &it.InQueueAt, &lastSeen); err != nil {
			return nil, err
		}
		it.LastSeen = nullTimeValue(lastSeen)
		it.Evidence = []easm.ReviewEvidence{}
		index[it.AssetID] = len(page.Items)
		ids = append(ids, it.AssetID)
		page.Items = append(page.Items, it)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(ids) == 0 {
		return page, nil
	}

	ev, err := r.db.QueryContext(ctx, `
		SELECT asset_id, rule, technique, source, weight, observed, first_observed_at, last_observed_at
		FROM easm_evidence WHERE tenant_id = $1 AND asset_id = ANY($2::uuid[])
		ORDER BY asset_id, weight DESC, first_observed_at`, tenantID.String(), pq.Array(ids))
	if err != nil {
		return nil, fmt.Errorf("list review evidence: %w", err)
	}
	defer ev.Close()
	for ev.Next() {
		var (
			assetID  string
			e        easm.ReviewEvidence
			observed []byte
		)
		if err := ev.Scan(&assetID, &e.Rule, &e.Technique, &e.Source, &e.Weight, &observed, &e.FirstObservedAt, &e.LastObservedAt); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(observed, &e.Observed)
		if i, ok := index[assetID]; ok {
			page.Items[i].Evidence = append(page.Items[i].Evidence, e)
		}
	}
	return page, ev.Err()
}

// SaveDecisions records one person's decision on many assets in a single
// statement. Only assets of the tenant that are not deleted are written; the
// result maps each written asset to its previous state ("" = no record).
func (r *AttributionRepository) SaveDecisions(ctx context.Context, tenantID shared.ID, assetIDs []string, state attribution.State, decidedBy string) (map[string]attribution.State, error) {
	if !state.Valid() {
		return nil, fmt.Errorf("%w: invalid attribution state %q", shared.ErrValidation, state)
	}
	out := map[string]attribution.State{}
	if len(assetIDs) == 0 {
		return out, nil
	}
	var by any
	if id, err := shared.IDFromString(decidedBy); err == nil {
		by = id.String()
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("save attribution decisions: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	// prev reads the statement's snapshot, so it holds the state before the
	// upsert.
	rows, err := tx.QueryContext(ctx, `
		WITH prev AS (
			SELECT asset_id, state FROM asset_attributions
			WHERE tenant_id = $2 AND asset_id = ANY($1::uuid[])
		), up AS (
			INSERT INTO asset_attributions (asset_id, tenant_id, state, confidence, reason, decided_by, decided_at)
			SELECT a.id, a.tenant_id, $3, 0, '', (SELECT u.id FROM users u WHERE u.id = $4::uuid), now()
			FROM assets a WHERE a.id = ANY($1::uuid[]) AND a.tenant_id = $2 AND a.deleted_at IS NULL
			ON CONFLICT (asset_id) DO UPDATE SET
				state      = EXCLUDED.state,
				decided_by = EXCLUDED.decided_by,
				decided_at = now(),
				updated_at = now()
			WHERE asset_attributions.tenant_id = $2
			RETURNING asset_id
		)
		SELECT up.asset_id, COALESCE(prev.state, '') FROM up LEFT JOIN prev ON prev.asset_id = up.asset_id`,
		pq.Array(assetIDs), tenantID.String(), string(state), by)
	if err != nil {
		return nil, fmt.Errorf("save attribution decisions: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var id, prev string
		if err := rows.Scan(&id, &prev); err != nil {
			_ = rows.Close()
			return nil, err
		}
		out[id] = attribution.State(prev)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	_ = rows.Close()
	written := make([]string, 0, len(out))
	for id := range out {
		written = append(written, id)
	}
	if err := syncTombstones(ctx, tx, tenantID, written, state, by); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("save attribution decisions: %w", err)
	}
	return out, nil
}
