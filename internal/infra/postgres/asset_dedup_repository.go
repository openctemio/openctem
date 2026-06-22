package postgres

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
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
			merge_asset_ids, merge_asset_names, merge_finding_count, status
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,'pending')
		ON CONFLICT (tenant_id, keep_asset_id) WHERE status = 'pending'
		DO UPDATE SET
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

	// (1) Tables with no UNIQUE constraint on asset_id: plain re-point (move).
	// NOTE: asset_state_history is deliberately NOT moved — it is an immutable
	// audit log (UPDATE is blocked by a trigger), and the merged asset's history
	// is cleaned up by FK cascade when the asset is deleted below.
	plainTables := []string{"findings", "compliance_mappings", "suppressions"}
	for _, table := range plainTables {
		// SAVEPOINT so an "undefined table" error (optional features that
		// aren't installed) can be rolled back without aborting the whole
		// transaction — in Postgres any statement error poisons the tx.
		if _, err = tx.ExecContext(ctx, "SAVEPOINT sp_move"); err != nil {
			return fmt.Errorf("savepoint: %w", err)
		}
		//nolint:gosec // G201: `table` is an internal constant from plainTables, never user input.
		q := fmt.Sprintf("UPDATE %s SET asset_id = $1 WHERE asset_id = ANY($2) AND tenant_id = $3", table)
		if _, e := tx.ExecContext(ctx, q, keepID, pq.Array(mergeIDs), tenantID); e != nil {
			if isUndefinedTableError(e) {
				if _, rbErr := tx.ExecContext(ctx, "ROLLBACK TO SAVEPOINT sp_move"); rbErr != nil {
					return fmt.Errorf("rollback savepoint: %w", rbErr)
				}
				continue
			}
			return fmt.Errorf("move %s: %w", table, e)
		}
		if _, err = tx.ExecContext(ctx, "RELEASE SAVEPOINT sp_move"); err != nil {
			return fmt.Errorf("release savepoint: %w", err)
		}
	}

	// (2) Tables with a UNIQUE constraint involving asset_id: conflict-safe
	// re-point. A blind UPDATE here violated the UNIQUE constraint and aborted
	// the whole merge for the common case (e.g. two hosts both exposing tcp/443,
	// or sharing a component). asset_components was previously omitted entirely,
	// so its rows were lost to FK cascade — fixed here.
	uniqueTables := []struct {
		table     string
		tenantCol string
		idCol     string
		keyCols   []string
	}{
		{"asset_services", "tenant_id", "id", []string{"port", "protocol"}},
		{"asset_components", "tenant_id", "id", []string{"component_id", "path"}},
		{"business_unit_assets", "tenant_id", "id", []string{"business_unit_id"}},
		{"asset_group_members", "", "ctid", []string{"asset_group_id"}}, // no tenant_id / id col
	}
	for _, t := range uniqueTables {
		if err := r.repointUnique(ctx, tx, t.table, "asset_id", t.tenantCol, t.idCol, t.keyCols, keepID, mergeIDs, tenantID); err != nil {
			return err
		}
	}

	// (3) Relationships: directed edges with UNIQUE(tenant, source, target, type)
	// and a no-self-ref CHECK. Drop edges that would become self-loops after the
	// merge, then conflict-safe re-point source and target endpoints.
	selfLoop := `DELETE FROM asset_relationships WHERE tenant_id = $3 AND (
		(source_asset_id = ANY($2) AND target_asset_id = $1) OR
		(source_asset_id = $1 AND target_asset_id = ANY($2)) OR
		(source_asset_id = ANY($2) AND target_asset_id = ANY($2)))`
	if _, err = tx.ExecContext(ctx, selfLoop, keepID, pq.Array(mergeIDs), tenantID); err != nil {
		return fmt.Errorf("drop self-loop relationships: %w", err)
	}
	if err := r.repointUnique(ctx, tx, "asset_relationships", "source_asset_id", "tenant_id", "id",
		[]string{"target_asset_id", "relationship_type"}, keepID, mergeIDs, tenantID); err != nil {
		return err
	}
	if err := r.repointUnique(ctx, tx, "asset_relationships", "target_asset_id", "tenant_id", "id",
		[]string{"source_asset_id", "relationship_type"}, keepID, mergeIDs, tenantID); err != nil {
		return err
	}

	// Touch the keep asset. Finding counts are computed on read (JOIN), not
	// stored on the assets row — there is no assets.finding_count column.
	_, err = tx.ExecContext(ctx, `UPDATE assets SET updated_at = NOW() WHERE id = $1 AND tenant_id = $2`, keepID, tenantID)
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

// repointUnique moves rows referencing the merge assets onto the keep asset for
// a table that has a UNIQUE constraint over (fk, keyCols...). It (1) drops merge
// rows whose key already exists on the keep asset, (2) drops merge-vs-merge
// duplicates keeping the lowest idCol per key, then (3) re-points the survivors.
// Rows dropped in (1)/(2) are cleaned up by FK cascade when the merge assets are
// deleted. Key comparisons use `=` so NULLs are treated as distinct, matching
// PostgreSQL UNIQUE-index semantics. tenantCol="" for tables without a tenant_id
// column; idCol may be a real column ("id") or the system column "ctid".
func (r *AssetDedupRepository) repointUnique(
	ctx context.Context, tx *sql.Tx,
	table, fk, tenantCol, idCol string, keyCols []string,
	keepID string, mergeIDs []string, tenantID string,
) error {
	keyMatch := func(a, b string) string {
		parts := make([]string, 0, len(keyCols))
		for _, c := range keyCols {
			parts = append(parts, fmt.Sprintf("%s.%s = %s.%s", a, c, b, c))
		}
		return strings.Join(parts, " AND ")
	}
	merge := pq.Array(mergeIDs)
	hasTenant := tenantCol != ""

	// 1. drop merge rows whose key already exists on the keep asset.
	//    params: $1=keep, $2=merge, [$3=tenant]
	var mT, kT string
	args1 := []any{keepID, merge}
	if hasTenant {
		mT = fmt.Sprintf(" AND m.%s = $3", tenantCol)
		kT = fmt.Sprintf(" AND k.%s = $3", tenantCol)
		args1 = append(args1, tenantID)
	}
	//nolint:gosec // G201: table/fk/key identifiers come from the fixed uniqueTables/relationship lists, never user input.
	q1 := fmt.Sprintf(`DELETE FROM %[1]s m WHERE m.%[2]s = ANY($2)%[3]s
		AND EXISTS (SELECT 1 FROM %[1]s k WHERE k.%[2]s = $1%[4]s AND %[5]s)`,
		table, fk, mT, kT, keyMatch("k", "m"))
	if _, err := tx.ExecContext(ctx, q1, args1...); err != nil {
		if isUndefinedTableError(err) {
			return nil
		}
		return fmt.Errorf("dedup %s vs keep: %w", table, err)
	}
	// 2. drop merge-vs-merge duplicates, keeping the lowest idCol per key.
	//    params: $1=merge, [$2=tenant] (keep is not referenced here)
	var mT2, bT string
	args2 := []any{merge}
	if hasTenant {
		mT2 = fmt.Sprintf(" AND m.%s = $2", tenantCol)
		bT = fmt.Sprintf(" AND b.%s = $2", tenantCol)
		args2 = append(args2, tenantID)
	}
	//nolint:gosec // G201: table/fk/key identifiers come from the fixed uniqueTables/relationship lists, never user input.
	q2 := fmt.Sprintf(`DELETE FROM %[1]s m WHERE m.%[2]s = ANY($1)%[3]s
		AND EXISTS (SELECT 1 FROM %[1]s b WHERE b.%[2]s = ANY($1)%[5]s AND %[4]s AND b.%[6]s < m.%[6]s)`,
		table, fk, mT2, keyMatch("b", "m"), bT, idCol)
	if _, err := tx.ExecContext(ctx, q2, args2...); err != nil {
		return fmt.Errorf("dedup %s internal: %w", table, err)
	}
	// 3. re-point survivors. params: $1=keep, $2=merge, [$3=tenant]
	var upT string
	args3 := []any{keepID, merge}
	if hasTenant {
		upT = fmt.Sprintf(" AND %s = $3", tenantCol)
		args3 = append(args3, tenantID)
	}
	//nolint:gosec // G201: table/fk identifiers come from the fixed uniqueTables/relationship lists, never user input.
	q3 := fmt.Sprintf(`UPDATE %[1]s SET %[2]s = $1 WHERE %[2]s = ANY($2)%[3]s`, table, fk, upT)
	if _, err := tx.ExecContext(ctx, q3, args3...); err != nil {
		return fmt.Errorf("move %s: %w", table, err)
	}
	return nil
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
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return results, nil
}
