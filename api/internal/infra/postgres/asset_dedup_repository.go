package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// AssetDedupReview represents a pending dedup review entry. The json names
// are the API contract the duplicate-review page reads; without them the
// list was encoded with Go field names and the page showed empty rows.
type AssetDedupReview struct {
	ID                string     `json:"id"`
	TenantID          string     `json:"tenant_id"`
	NormalizedName    string     `json:"normalized_name"`
	AssetType         string     `json:"asset_type"`
	KeepAssetID       string     `json:"keep_asset_id"`
	KeepAssetName     string     `json:"keep_asset_name"`
	KeepFindingCount  int        `json:"keep_finding_count"`
	MergeAssetIDs     []string   `json:"merge_asset_ids"`
	MergeAssetNames   []string   `json:"merge_asset_names"`
	MergeFindingCount int        `json:"merge_finding_count"`
	Status            string     `json:"status"`
	ReviewedBy        *string    `json:"reviewed_by,omitempty"`
	ReviewedAt        *time.Time `json:"reviewed_at,omitempty"`
	MergedAt          *time.Time `json:"merged_at,omitempty"`
	CreatedAt         time.Time  `json:"created_at"`
	// Reason says why the review was raised (one of the asset.DuplicateReason*
	// values; nil for reviews raised before reasons were recorded).
	Reason *string `json:"reason"`
	// Evidence is what the assets share, e.g. {"kind":"mac","value":"..."}.
	Evidence map[string]any `json:"evidence"`
}

// AssetDedupRepository handles dedup review and merge operations.
type AssetDedupRepository struct {
	db *DB
}

// NewAssetDedupRepository creates a new dedup repository.
func NewAssetDedupRepository(db *DB) *AssetDedupRepository {
	return &AssetDedupRepository{db: db}
}

// dedupReviewInScope is the predicate "every asset of the review (the kept
// one and each one to merge) is in the data scope" for the review aliased
// as the table itself. A review that would merge an asset the caller cannot
// see is out of scope as a whole: listing it would reveal that asset and
// approving it would delete it. A nil scope returns "TRUE".
func dedupReviewInScope(scope *shared.DataScope, args []any) (string, []any) {
	if scope == nil {
		return sqlTrue, args
	}
	keep, scopeArgs := dataScopeCondAt("keep_asset_id", scope, len(args)+1)
	merge, _ := dataScopeCondAt("m.id", scope, len(args)+1)
	return "(" + keep + " AND NOT EXISTS (SELECT 1 FROM unnest(merge_asset_ids) AS m(id) WHERE NOT " + merge + "))",
		append(args, scopeArgs...)
}

// ListPendingReviews returns the pending dedup reviews of a tenant whose
// assets are all in scope (nil = every review).
func (r *AssetDedupRepository) ListPendingReviews(ctx context.Context, tenantID string, scope *shared.DataScope) ([]AssetDedupReview, error) {
	scopeCond, args := dedupReviewInScope(scope, []any{tenantID})
	//nolint:gosec // G202: scopeCond is built from fixed SQL and numbered placeholders
	query := `
		SELECT id, tenant_id, normalized_name, asset_type,
			keep_asset_id, keep_asset_name, keep_finding_count,
			merge_asset_ids, merge_asset_names, merge_finding_count,
			status, reviewed_by, reviewed_at, merged_at, created_at,
			reason, COALESCE(evidence, '{}'::jsonb)
		FROM asset_dedup_review
		WHERE tenant_id = $1 AND status = 'pending' AND ` + scopeCond + `
		ORDER BY merge_finding_count DESC, created_at ASC
		LIMIT 100
	`
	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list pending reviews: %w", err)
	}
	defer func() { _ = rows.Close() }()

	reviews := []AssetDedupReview{}
	for rows.Next() {
		var rev AssetDedupReview
		var evidence []byte
		err := rows.Scan(
			&rev.ID, &rev.TenantID, &rev.NormalizedName, &rev.AssetType,
			&rev.KeepAssetID, &rev.KeepAssetName, &rev.KeepFindingCount,
			pq.Array(&rev.MergeAssetIDs), pq.Array(&rev.MergeAssetNames), &rev.MergeFindingCount,
			&rev.Status, &rev.ReviewedBy, &rev.ReviewedAt, &rev.MergedAt, &rev.CreatedAt,
			&rev.Reason, &evidence,
		)
		if err != nil {
			return nil, fmt.Errorf("scan review: %w", err)
		}
		rev.Evidence = map[string]any{}
		if err := json.Unmarshal(evidence, &rev.Evidence); err != nil {
			return nil, fmt.Errorf("decode review evidence: %w", err)
		}
		reviews = append(reviews, rev)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return reviews, nil
}

// UpsertReview enqueues (or refreshes) a pending duplicate-asset review. It is
// idempotent: the partial unique index uq_asset_dedup_review_pending ensures at
// most one pending review per (tenant, keep asset), so repeated scans update the
// existing pending row instead of creating duplicates.
func (r *AssetDedupRepository) UpsertReview(
	ctx context.Context,
	tenantID, normalizedName, assetType, keepID, keepName string, keepFindingCount int,
	mergeIDs, mergeNames []string, mergeFindingCount int,
) error {
	if len(mergeIDs) == 0 {
		return nil
	}
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO asset_dedup_review (
			tenant_id, normalized_name, asset_type,
			keep_asset_id, keep_asset_name, keep_finding_count,
			merge_asset_ids, merge_asset_names, merge_finding_count, status, reason
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,'pending','`+asset.DuplicateReasonSharedIP+`')
		ON CONFLICT (tenant_id, keep_asset_id) WHERE status = 'pending'
		DO UPDATE SET
			reason = EXCLUDED.reason,
			normalized_name = EXCLUDED.normalized_name,
			asset_type = EXCLUDED.asset_type,
			keep_asset_name = EXCLUDED.keep_asset_name,
			keep_finding_count = EXCLUDED.keep_finding_count,
			merge_asset_ids = EXCLUDED.merge_asset_ids,
			merge_asset_names = EXCLUDED.merge_asset_names,
			merge_finding_count = EXCLUDED.merge_finding_count,
			created_at = NOW()
	`, tenantID, normalizedName, assetType, keepID, keepName, keepFindingCount,
		pq.Array(mergeIDs), pq.Array(mergeNames), mergeFindingCount)
	if err != nil {
		return fmt.Errorf("upsert dedup review: %w", err)
	}
	return nil
}

// EnqueueIdentityReview raises (or extends) a pending duplicate review for
// rev.KeepID. Unlike UpsertReview, merge candidates already on the pending
// review are kept: identity conflicts arrive one pair at a time. A pair an
// operator already rejected (either direction) is not raised again. Never
// merges anything.
func (r *AssetDedupRepository) EnqueueIdentityReview(ctx context.Context, tenantID string, rev asset.DuplicateReview) (bool, error) {
	if rev.KeepID == "" || len(rev.MergeIDs) == 0 {
		return false, nil
	}
	evidence, err := json.Marshal(rev.Evidence)
	if err != nil {
		return false, fmt.Errorf("encode review evidence: %w", err)
	}

	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return false, fmt.Errorf("begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	// Drop candidates an operator already decided to keep separate.
	open, err := openDuplicateCandidates(ctx, tx, tenantID, rev.KeepID, rev.MergeIDs)
	if err != nil {
		return false, err
	}

	ids := make([]string, 0, len(rev.MergeIDs))
	names := make([]string, 0, len(rev.MergeIDs))
	for i, id := range rev.MergeIDs {
		if !open[id] || id == rev.KeepID {
			continue
		}
		open[id] = false // once
		ids = append(ids, id)
		name := ""
		if i < len(rev.MergeNames) {
			name = rev.MergeNames[i]
		}
		names = append(names, name)
	}
	if len(ids) == 0 {
		return false, nil
	}

	// One pending review per kept asset (uq_asset_dedup_review_pending):
	// extend it with the new candidates.
	var existingID string
	var existingIDs, existingNames []string
	err = tx.QueryRowContext(ctx, `
		SELECT id, merge_asset_ids, merge_asset_names FROM asset_dedup_review
		WHERE tenant_id = $1 AND keep_asset_id = $2 AND status = 'pending'
		FOR UPDATE`, tenantID, rev.KeepID).Scan(&existingID, pq.Array(&existingIDs), pq.Array(&existingNames))
	switch {
	case errors.Is(err, sql.ErrNoRows):
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO asset_dedup_review (
				tenant_id, normalized_name, asset_type,
				keep_asset_id, keep_asset_name, keep_finding_count,
				merge_asset_ids, merge_asset_names, merge_finding_count, status, reason, evidence
			) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,'pending',$10,$11)`,
			tenantID, rev.NormalizedName, rev.AssetType, rev.KeepID, rev.KeepName, rev.KeepFindingCount,
			pq.Array(ids), pq.Array(names), rev.MergeFindingCount, rev.Reason, evidence); err != nil {
			return false, fmt.Errorf("insert identity review: %w", err)
		}
	case err != nil:
		return false, fmt.Errorf("lock pending review: %w", err)
	default:
		have := make(map[string]bool, len(existingIDs))
		for _, id := range existingIDs {
			have[id] = true
		}
		added := false
		for i, id := range ids {
			if !have[id] {
				existingIDs = append(existingIDs, id)
				existingNames = append(existingNames, names[i])
				added = true
			}
		}
		if !added {
			return false, tx.Commit()
		}
		if _, err := tx.ExecContext(ctx, `
			UPDATE asset_dedup_review SET
				merge_asset_ids = $2, merge_asset_names = $3,
				merge_finding_count = merge_finding_count + $4,
				reason = $5, evidence = $6
			WHERE id = $1`,
			existingID, pq.Array(existingIDs), pq.Array(existingNames), rev.MergeFindingCount,
			rev.Reason, evidence); err != nil {
			return false, fmt.Errorf("extend identity review: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return false, fmt.Errorf("commit identity review: %w", err)
	}
	return true, nil
}

// openDuplicateCandidates returns the merge candidates that no rejected
// review already pairs with keepID, in either direction.
func openDuplicateCandidates(ctx context.Context, tx *sql.Tx, tenantID, keepID string, mergeIDs []string) (map[string]bool, error) {
	rows, err := tx.QueryContext(ctx, `
		SELECT m FROM unnest($3::uuid[]) AS m
		WHERE NOT EXISTS (
			SELECT 1 FROM asset_dedup_review d
			WHERE d.tenant_id = $1 AND d.status = 'rejected'
			  AND ((d.keep_asset_id = $2 AND m = ANY(d.merge_asset_ids))
			    OR (d.keep_asset_id = m AND $2 = ANY(d.merge_asset_ids))))`,
		tenantID, keepID, pq.Array(mergeIDs))
	if err != nil {
		return nil, fmt.Errorf("filter rejected pairs: %w", err)
	}
	defer func() { _ = rows.Close() }()
	open := map[string]bool{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("scan candidate: %w", err)
		}
		open[id] = true
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate candidates: %w", err)
	}
	return open, nil
}

// ApproveAndMerge executes a merge: moves every row that references the merge
// assets onto the keep asset, then deletes the merge assets.
// tenantID is verified against the review to prevent cross-tenant access,
// and a non-nil scope must cover every asset of the review (checked on the
// locked row, so a concurrent refresh of the review cannot slip past it).
func (r *AssetDedupRepository) ApproveAndMerge(ctx context.Context, tenantID string, reviewID string, reviewedBy string, scope *shared.DataScope) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	// Lock and get the review — tenant_id and data scope enforced
	var rev AssetDedupReview
	scopeCond, args := dedupReviewInScope(scope, []any{reviewID, tenantID})
	//nolint:gosec // G202: scopeCond is built from fixed SQL and numbered placeholders
	err = tx.QueryRowContext(ctx, `
		SELECT id, tenant_id, keep_asset_id, merge_asset_ids, status
		FROM asset_dedup_review
		WHERE id = $1 AND tenant_id = $2 AND `+scopeCond+`
		FOR UPDATE
	`, args...).Scan(&rev.ID, &rev.TenantID, &rev.KeepAssetID, pq.Array(&rev.MergeAssetIDs), &rev.Status)
	if errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("%w: dedup review not found", shared.ErrNotFound)
	}
	if err != nil {
		return fmt.Errorf("get review: %w", err)
	}
	if rev.Status != "pending" {
		return fmt.Errorf("%w: review already %s", shared.ErrConflict, rev.Status)
	}

	keepID := rev.KeepAssetID
	mergeIDs := rev.MergeAssetIDs

	// Move everything that references the merged assets onto the kept one
	// (see asset_merge_plan.go for the full list and how each table is
	// handled). Every statement runs in this transaction: a failure aborts the
	// merge instead of deleting the assets with part of their data.
	if err := mergeAssetReferences(ctx, tx, rev.TenantID, rev.ID, keepID, mergeIDs); err != nil {
		return err
	}

	// Touch the keep asset. Finding counts are computed on read (JOIN), not
	// stored on the assets row — there is no assets.finding_count column.
	// A crown-jewel designation on a merged asset carries over to the kept
	// one, so a merge never silently demotes a crown jewel.
	_, err = tx.ExecContext(ctx, `
		UPDATE assets SET updated_at = NOW(),
		       is_crown_jewel = is_crown_jewel OR EXISTS (
		           SELECT 1 FROM assets m
		            WHERE m.tenant_id = $2 AND m.id = ANY($3::uuid[]) AND m.is_crown_jewel)
		 WHERE id = $1 AND tenant_id = $2`, keepID, tenantID, pq.Array(mergeIDs))
	if err != nil {
		return fmt.Errorf("touch keep asset: %w", err)
	}

	// Log merges. Name subqueries are tenant-scoped as defense-in-depth:
	// keepID/mergeID already come from a tenant-scoped review row, but
	// filtering here prevents any future code path that forgets the join
	// from leaking an asset name across tenants.
	for _, mergeID := range mergeIDs {
		_, err = tx.ExecContext(ctx, `
			INSERT INTO asset_merge_log (
				tenant_id, kept_asset_id, kept_asset_name,
				merged_asset_id, merged_asset_name,
				correlation_type, action, source, created_at
			)
			SELECT
				$1, $2, (SELECT name FROM assets WHERE id = $2 AND tenant_id = $1),
				$3, (SELECT name FROM assets WHERE id = $3 AND tenant_id = $1),
				'admin_review', 'merge', 'admin', NOW()
		`, rev.TenantID, keepID, mergeID)
		if err != nil {
			return fmt.Errorf("log merge: %w", err)
		}
	}

	// Delete merged assets
	_, err = tx.ExecContext(ctx,
		"DELETE FROM assets WHERE id = ANY($1) AND tenant_id = $2",
		pq.Array(mergeIDs), rev.TenantID,
	)
	if err != nil {
		return fmt.Errorf("delete merged assets: %w", err)
	}

	// Mark review as merged
	now := time.Now()
	_, err = tx.ExecContext(ctx, `
		UPDATE asset_dedup_review SET
			status = 'merged',
			reviewed_by = $2,
			reviewed_at = $3,
			merged_at = $3
		WHERE id = $1
	`, reviewID, reviewedBy, now)
	if err != nil {
		return fmt.Errorf("update review status: %w", err)
	}

	return tx.Commit()
}

// RejectReview marks a review as rejected (keep assets separate).
// tenantID is verified to prevent cross-tenant access; a non-nil scope must
// cover every asset of the review.
func (r *AssetDedupRepository) RejectReview(ctx context.Context, tenantID string, reviewID string, reviewedBy string, scope *shared.DataScope) error {
	now := time.Now()
	scopeCond, args := dedupReviewInScope(scope, []any{reviewID, tenantID, reviewedBy, now})
	//nolint:gosec // G202: scopeCond is built from fixed SQL and numbered placeholders
	res, err := r.db.ExecContext(ctx, `
		UPDATE asset_dedup_review SET
			status = 'rejected',
			reviewed_by = $3,
			reviewed_at = $4
		WHERE id = $1 AND tenant_id = $2 AND status = 'pending' AND `+scopeCond, args...)
	if err != nil {
		return err
	}
	// Zero rows means no pending review with this id in this tenant. Reporting
	// success there told the caller a rejection happened when nothing changed.
	if n, err := res.RowsAffected(); err == nil && n == 0 {
		return fmt.Errorf("%w: no pending dedup review with this id", shared.ErrNotFound)
	}
	return nil
}

// GetMergeLog returns recent merge events. A non-nil scope keeps the events
// whose kept asset is in it (the merged asset no longer exists).
func (r *AssetDedupRepository) GetMergeLog(ctx context.Context, tenantID string, limit int, scope *shared.DataScope) ([]map[string]any, error) {
	if limit <= 0 || limit > 100 {
		limit = 50
	}
	scopeCond, args := dataScopeCond("kept_asset_id", scope, []any{tenantID, limit})
	//nolint:gosec // G202: scopeCond is built from fixed SQL and numbered placeholders
	query := `
		SELECT id, kept_asset_id, kept_asset_name, merged_asset_id, merged_asset_name,
			correlation_type, correlation_value, action, old_name, new_name, source, created_at
		FROM asset_merge_log
		WHERE tenant_id = $1 AND ` + scopeCond + `
		ORDER BY created_at DESC
		LIMIT $2
	`
	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var results []map[string]any
	cols, _ := rows.Columns()
	for rows.Next() {
		values := make([]any, len(cols))
		ptrs := make([]any, len(cols))
		for i := range values {
			ptrs[i] = &values[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			return nil, err
		}
		row := make(map[string]any)
		for i, col := range cols {
			// lib/pq scans TEXT/VARCHAR columns into an interface{} as []byte.
			// Left as-is, JSON-encoding turns every text field (asset names,
			// reason, ...) into a base64 blob in the admin merge-log response.
			// Convert to string so they serialize as readable text.
			if b, ok := values[i].([]byte); ok {
				row[col] = string(b)
			} else {
				row[col] = values[i]
			}
		}
		results = append(results, row)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return results, nil
}
