package postgres

import (
	"context"
	"fmt"
	"time"

	"github.com/lib/pq"
)

// AssetDedupReview represents a pending dedup review entry.
type AssetDedupReview struct {
	ID                string
	TenantID          string
	NormalizedName    string
	AssetType         string
	KeepAssetID       string
	KeepAssetName     string
	KeepFindingCount  int
	MergeAssetIDs     []string
	MergeAssetNames   []string
	MergeFindingCount int
	Status            string
	ReviewedBy        *string
	ReviewedAt        *time.Time
	MergedAt          *time.Time
	CreatedAt         time.Time
}

// AssetDedupRepository handles dedup review and merge operations.
type AssetDedupRepository struct {
	db *DB
}

// NewAssetDedupRepository creates a new dedup repository.
func NewAssetDedupRepository(db *DB) *AssetDedupRepository {
	return &AssetDedupRepository{db: db}
}

// ListPendingReviews returns pending dedup reviews for a tenant.
func (r *AssetDedupRepository) ListPendingReviews(ctx context.Context, tenantID string) ([]AssetDedupReview, error) {
	query := `
		SELECT id, tenant_id, normalized_name, asset_type,
			keep_asset_id, keep_asset_name, keep_finding_count,
			merge_asset_ids, merge_asset_names, merge_finding_count,
			status, reviewed_by, reviewed_at, merged_at, created_at
		FROM asset_dedup_review
		WHERE tenant_id = $1 AND status = 'pending'
		ORDER BY merge_finding_count DESC, created_at ASC
		LIMIT 100
	`
	rows, err := r.db.QueryContext(ctx, query, tenantID)
	if err != nil {
		return nil, fmt.Errorf("list pending reviews: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var reviews []AssetDedupReview
	for rows.Next() {
		var rev AssetDedupReview
		err := rows.Scan(
			&rev.ID, &rev.TenantID, &rev.NormalizedName, &rev.AssetType,
			&rev.KeepAssetID, &rev.KeepAssetName, &rev.KeepFindingCount,
			pq.Array(&rev.MergeAssetIDs), pq.Array(&rev.MergeAssetNames), &rev.MergeFindingCount,
			&rev.Status, &rev.ReviewedBy, &rev.ReviewedAt, &rev.MergedAt, &rev.CreatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("scan review: %w", err)
		}
		reviews = append(reviews, rev)
	}
	return reviews, nil
}

// ApproveAndMerge executes a merge: moves findings/services/relationships from
// merge assets into the keep asset, then deletes merge assets.
// tenantID is verified against the review to prevent cross-tenant access.
func (r *AssetDedupRepository) ApproveAndMerge(ctx context.Context, tenantID string, reviewID string, reviewedBy string) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	// Lock and get the review — tenant_id enforced
	var rev AssetDedupReview
	err = tx.QueryRowContext(ctx, `
		SELECT id, tenant_id, keep_asset_id, merge_asset_ids, status
		FROM asset_dedup_review
		WHERE id = $1 AND tenant_id = $2
		FOR UPDATE
	`, reviewID, tenantID).Scan(&rev.ID, &rev.TenantID, &rev.KeepAssetID, pq.Array(&rev.MergeAssetIDs), &rev.Status)
	if err != nil {
		return fmt.Errorf("get review: %w", err)
	}
	if rev.Status != "pending" {
		return fmt.Errorf("review already %s", rev.Status)
	}

	keepID := rev.KeepAssetID
	mergeIDs := rev.MergeAssetIDs

	// Move references from merge assets to keep asset
	// All UPDATEs include tenant_id to prevent cross-tenant data corruption
	tables := []struct {
		table  string
		column string
	}{
		{"findings", "asset_id"},
		{"asset_services", "asset_id"},
		{"asset_relationships", "source_asset_id"},
		{"asset_relationships", "target_asset_id"},
		{"compliance_mappings", "asset_id"},
		{"suppressions", "asset_id"},
		{"asset_state_history", "asset_id"},
	}

	for _, t := range tables {
		query := fmt.Sprintf(
			"UPDATE %s SET %s = $1 WHERE %s = ANY($2) AND tenant_id = $3",
			t.table, t.column, t.column,
		)
		_, err = tx.ExecContext(ctx, query, keepID, pq.Array(mergeIDs), tenantID)
		if err != nil {
			// Table might not exist (optional features) — log but don't fail
			if isUndefinedTableError(err) {
				continue
			}
			return fmt.Errorf("move %s.%s: %w", t.table, t.column, err)
		}
	}

	// Update finding_count on keep asset — tenant_id enforced
	_, err = tx.ExecContext(ctx, `
		UPDATE assets SET
			finding_count = (SELECT COUNT(*) FROM findings WHERE asset_id = $1 AND tenant_id = $2),
			updated_at = NOW()
		WHERE id = $1 AND tenant_id = $2
	`, keepID, tenantID)
	if err != nil {
		return fmt.Errorf("update finding count: %w", err)
	}

	// Log merges
	for _, mergeID := range mergeIDs {
		_, err = tx.ExecContext(ctx, `
			INSERT INTO asset_merge_log (
				tenant_id, kept_asset_id, kept_asset_name,
				merged_asset_id, merged_asset_name,
				correlation_type, action, source, created_at
			)
			SELECT
				$1, $2, (SELECT name FROM assets WHERE id = $2),
				$3, (SELECT name FROM assets WHERE id = $3),
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
// tenantID is verified to prevent cross-tenant access.
func (r *AssetDedupRepository) RejectReview(ctx context.Context, tenantID string, reviewID string, reviewedBy string) error {
	now := time.Now()
	_, err := r.db.ExecContext(ctx, `
		UPDATE asset_dedup_review SET
			status = 'rejected',
			reviewed_by = $3,
			reviewed_at = $4
		WHERE id = $1 AND tenant_id = $2 AND status = 'pending'
	`, reviewID, tenantID, reviewedBy, now)
	return err
}

func isUndefinedTableError(err error) bool {
	if pqErr, ok := err.(*pq.Error); ok { //nolint:errorlint
		return pqErr.Code == "42P01" // undefined_table
	}
	return false
}

// GetMergeLog returns recent merge events.
func (r *AssetDedupRepository) GetMergeLog(ctx context.Context, tenantID string, limit int) ([]map[string]any, error) {
	if limit <= 0 || limit > 100 {
		limit = 50
	}
	query := `
		SELECT id, kept_asset_id, kept_asset_name, merged_asset_id, merged_asset_name,
			correlation_type, correlation_value, action, old_name, new_name, source, created_at
		FROM asset_merge_log
		WHERE tenant_id = $1
		ORDER BY created_at DESC
		LIMIT $2
	`
	rows, err := r.db.QueryContext(ctx, query, tenantID, limit)
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
			row[col] = values[i]
		}
		results = append(results, row)
	}
	return results, nil
}

