package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/openctemio/api/pkg/domain/datasource"
	"github.com/openctemio/api/pkg/domain/shared"
)

// AssetSourceRepository implements datasource.AssetSourceRepository using PostgreSQL.
type AssetSourceRepository struct {
	db *DB
}

// NewAssetSourceRepository creates a new AssetSourceRepository.
func NewAssetSourceRepository(db *DB) *AssetSourceRepository {
	return &AssetSourceRepository{db: db}
}

// Ensure AssetSourceRepository implements datasource.AssetSourceRepository
var _ datasource.AssetSourceRepository = (*AssetSourceRepository)(nil)

// Create creates a new asset source record.
func (r *AssetSourceRepository) Create(ctx context.Context, as *datasource.AssetSource) error {
	contributedData, err := json.Marshal(as.ContributedData())
	if err != nil {
		return fmt.Errorf("marshal contributed_data: %w", err)
	}

	query := `
		INSERT INTO asset_sources (
			id, asset_id, source_type, source_id,
			first_seen_at, last_seen_at, source_ref,
			contributed_data, confidence, is_primary, seen_count,
			created_at, updated_at
		) VALUES (
			$1, $2, $3, $4,
			$5, $6, $7,
			$8, $9, $10, $11,
			$12, $13
		)
	`

	_, err = r.db.ExecContext(ctx, query,
		as.ID().String(),
		as.AssetID().String(),
		as.SourceType().String(),
		nullIDPtr(as.SourceID()),
		as.FirstSeenAt(),
		as.LastSeenAt(),
		nullString(as.SourceRef()),
		contributedData,
		as.Confidence(),
		as.IsPrimary(),
		as.SeenCount(),
		as.CreatedAt(),
		as.UpdatedAt(),
	)
	if err != nil {
		if isUniqueViolation(err) {
			return fmt.Errorf("asset source already exists for this asset and source")
		}
		return fmt.Errorf("create asset source: %w", err)
	}

	return nil
}

// GetByID retrieves an asset source by ID.
func (r *AssetSourceRepository) GetByID(ctx context.Context, id shared.ID) (*datasource.AssetSource, error) {
	query := `
		SELECT id, asset_id, source_type, source_id,
			   first_seen_at, last_seen_at, source_ref,
			   contributed_data, confidence, is_primary, seen_count,
			   created_at, updated_at
		FROM asset_sources
		WHERE id = $1
	`

	row := r.db.QueryRowContext(ctx, query, id.String())
	return r.scanAssetSource(row)
}

// GetByAssetAndSource retrieves an asset source by asset ID, source type, and source ID.
func (r *AssetSourceRepository) GetByAssetAndSource(ctx context.Context, assetID shared.ID, sourceType datasource.SourceType, sourceID *shared.ID) (*datasource.AssetSource, error) {
	var query string
	var args []any

	if sourceID != nil {
		query = `
			SELECT id, asset_id, source_type, source_id,
				   first_seen_at, last_seen_at, source_ref,
				   contributed_data, confidence, is_primary, seen_count,
				   created_at, updated_at
			FROM asset_sources
			WHERE asset_id = $1 AND source_type = $2 AND source_id = $3
		`
		args = []any{assetID.String(), sourceType.String(), sourceID.String()}
	} else {
		query = `
			SELECT id, asset_id, source_type, source_id,
				   first_seen_at, last_seen_at, source_ref,
				   contributed_data, confidence, is_primary, seen_count,
				   created_at, updated_at
			FROM asset_sources
			WHERE asset_id = $1 AND source_type = $2 AND source_id IS NULL
		`
		args = []any{assetID.String(), sourceType.String()}
	}

	row := r.db.QueryRowContext(ctx, query, args...)
	return r.scanAssetSource(row)
}

// Update updates an existing asset source.
func (r *AssetSourceRepository) Update(ctx context.Context, as *datasource.AssetSource) error {
	contributedData, err := json.Marshal(as.ContributedData())
	if err != nil {
		return fmt.Errorf("marshal contributed_data: %w", err)
	}

	query := `
		UPDATE asset_sources SET
			last_seen_at = $2,
			source_ref = $3,
			contributed_data = $4,
			confidence = $5,
			is_primary = $6,
			seen_count = $7,
			updated_at = $8
		WHERE id = $1
	`

	result, err := r.db.ExecContext(ctx, query,
		as.ID().String(),
		as.LastSeenAt(),
		nullString(as.SourceRef()),
		contributedData,
		as.Confidence(),
		as.IsPrimary(),
		as.SeenCount(),
		as.UpdatedAt(),
	)
	if err != nil {
		return fmt.Errorf("update asset source: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("rows affected: %w", err)
	}
	if rowsAffected == 0 {
		return datasource.ErrAssetSourceNotFound
	}

	return nil
}

// Upsert creates or updates an asset source.
func (r *AssetSourceRepository) Upsert(ctx context.Context, as *datasource.AssetSource) error {
	contributedData, err := json.Marshal(as.ContributedData())
	if err != nil {
		return fmt.Errorf("marshal contributed_data: %w", err)
	}

	query := `
		INSERT INTO asset_sources (
			id, asset_id, source_type, source_id,
			first_seen_at, last_seen_at, source_ref,
			contributed_data, confidence, is_primary, seen_count,
			created_at, updated_at
		) VALUES (
			$1, $2, $3, $4,
			$5, $6, $7,
			$8, $9, $10, $11,
			$12, $13
		)
		ON CONFLICT (asset_id, source_type, source_id)
		DO UPDATE SET
			last_seen_at = EXCLUDED.last_seen_at,
			source_ref = COALESCE(EXCLUDED.source_ref, asset_sources.source_ref),
			contributed_data = asset_sources.contributed_data || EXCLUDED.contributed_data,
			confidence = GREATEST(asset_sources.confidence, EXCLUDED.confidence),
			seen_count = asset_sources.seen_count + 1,
			updated_at = EXCLUDED.updated_at
	`

	_, err = r.db.ExecContext(ctx, query,
		as.ID().String(),
		as.AssetID().String(),
		as.SourceType().String(),
		nullIDPtr(as.SourceID()),
		as.FirstSeenAt(),
		as.LastSeenAt(),
		nullString(as.SourceRef()),
		contributedData,
		as.Confidence(),
		as.IsPrimary(),
		as.SeenCount(),
		as.CreatedAt(),
		as.UpdatedAt(),
	)
	if err != nil {
		return fmt.Errorf("upsert asset source: %w", err)
	}

	return nil
}

// Delete deletes an asset source by ID.
func (r *AssetSourceRepository) Delete(ctx context.Context, id shared.ID) error {
	query := `DELETE FROM asset_sources WHERE id = $1`

	result, err := r.db.ExecContext(ctx, query, id.String())
	if err != nil {
		return fmt.Errorf("delete asset source: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("rows affected: %w", err)
	}
	if rowsAffected == 0 {
		return datasource.ErrAssetSourceNotFound
	}

	return nil
}

// DeleteByAsset deletes all asset sources for an asset.
func (r *AssetSourceRepository) DeleteByAsset(ctx context.Context, assetID shared.ID) error {
	query := `DELETE FROM asset_sources WHERE asset_id = $1`

	_, err := r.db.ExecContext(ctx, query, assetID.String())
	if err != nil {
		return fmt.Errorf("delete asset sources by asset: %w", err)
	}

	return nil
}

// DeleteBySource deletes all asset sources for a data source.
func (r *AssetSourceRepository) DeleteBySource(ctx context.Context, sourceID shared.ID) error {
	query := `DELETE FROM asset_sources WHERE source_id = $1`

	_, err := r.db.ExecContext(ctx, query, sourceID.String())
	if err != nil {
		return fmt.Errorf("delete asset sources by source: %w", err)
	}

	return nil
}

// List lists asset sources with filtering and pagination.
// nolint:dupl // Similar pattern to FindingDataSourceRepository.List - intentional for type safety
func (r *AssetSourceRepository) List(ctx context.Context, filter datasource.AssetSourceFilter, opts datasource.AssetSourceListOptions) (datasource.AssetSourceListResult, error) {
	result := datasource.AssetSourceListResult{
		Data:    make([]*datasource.AssetSource, 0),
		Page:    opts.Page,
		PerPage: opts.PerPage,
	}

	if opts.Page < 1 {
		opts.Page = 1
	}
	if opts.PerPage < 1 {
		opts.PerPage = 20
	}

	// Build query
	var conditions []string
	var args []any
	argIdx := 1

	if !filter.AssetID.IsZero() {
		conditions = append(conditions, fmt.Sprintf("asset_id = $%d", argIdx))
		args = append(args, filter.AssetID.String())
		argIdx++
	}

	if !filter.SourceID.IsZero() {
		conditions = append(conditions, fmt.Sprintf("source_id = $%d", argIdx))
		args = append(args, filter.SourceID.String())
		argIdx++
	}

	if filter.SourceType != "" {
		conditions = append(conditions, fmt.Sprintf("source_type = $%d", argIdx))
		args = append(args, filter.SourceType.String())
		argIdx++
	}

	if filter.IsPrimary != nil {
		conditions = append(conditions, fmt.Sprintf("is_primary = $%d", argIdx))
		args = append(args, *filter.IsPrimary)
		argIdx++
	}

	whereClause := ""
	if len(conditions) > 0 {
		whereClause = "WHERE " + strings.Join(conditions, " AND ")
	}

	// Get total count
	countQuery := "SELECT COUNT(*) FROM asset_sources " + whereClause
	err := r.db.QueryRowContext(ctx, countQuery, args...).Scan(&result.Total)
	if err != nil {
		return result, fmt.Errorf("count asset sources: %w", err)
	}

	// Calculate pagination
	result.TotalPages = int((result.Total + int64(opts.PerPage) - 1) / int64(opts.PerPage))

	// Build order clause
	orderBy := "last_seen_at DESC"
	if opts.SortBy != "" {
		validSortFields := map[string]bool{
			"first_seen_at": true,
			"last_seen_at":  true,
			"confidence":    true,
		}
		if validSortFields[opts.SortBy] {
			order := sortOrderASC
			if opts.SortOrder == sortOrderDescLower {
				order = sortOrderDESC
			}
			orderBy = opts.SortBy + " " + order
		}
	}

	// Get data with pagination
	offset := (opts.Page - 1) * opts.PerPage
	args = append(args, opts.PerPage, offset)

	query := fmt.Sprintf(`
		SELECT id, asset_id, source_type, source_id,
			   first_seen_at, last_seen_at, source_ref,
			   contributed_data, confidence, is_primary, seen_count,
			   created_at, updated_at
		FROM asset_sources
		%s
		ORDER BY %s
		LIMIT $%d OFFSET $%d
	`, whereClause, orderBy, argIdx, argIdx+1)

	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return result, fmt.Errorf("list asset sources: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		as, err := r.scanAssetSourceRow(rows)
		if err != nil {
			return result, err
		}
		result.Data = append(result.Data, as)
	}

	if err := rows.Err(); err != nil {
		return result, fmt.Errorf("iterate rows: %w", err)
	}

	return result, nil
}

// GetByAsset retrieves all sources for an asset.
func (r *AssetSourceRepository) GetByAsset(ctx context.Context, assetID shared.ID) ([]*datasource.AssetSource, error) {
	query := `
		SELECT id, asset_id, source_type, source_id,
			   first_seen_at, last_seen_at, source_ref,
			   contributed_data, confidence, is_primary, seen_count,
			   created_at, updated_at
		FROM asset_sources
		WHERE asset_id = $1
		ORDER BY is_primary DESC, last_seen_at DESC
	`

	rows, err := r.db.QueryContext(ctx, query, assetID.String())
	if err != nil {
		return nil, fmt.Errorf("get asset sources: %w", err)
	}
	defer rows.Close()

	var sources []*datasource.AssetSource
	for rows.Next() {
		as, err := r.scanAssetSourceRow(rows)
		if err != nil {
			return nil, err
		}
		sources = append(sources, as)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate rows: %w", err)
	}

	return sources, nil
}

// GetPrimaryByAsset retrieves the primary source for an asset.
func (r *AssetSourceRepository) GetPrimaryByAsset(ctx context.Context, assetID shared.ID) (*datasource.AssetSource, error) {
	query := `
		SELECT id, asset_id, source_type, source_id,
			   first_seen_at, last_seen_at, source_ref,
			   contributed_data, confidence, is_primary, seen_count,
			   created_at, updated_at
		FROM asset_sources
		WHERE asset_id = $1 AND is_primary = true
	`

	row := r.db.QueryRowContext(ctx, query, assetID.String())
	return r.scanAssetSource(row)
}

// SetPrimary sets a source as the primary source for an asset.
func (r *AssetSourceRepository) SetPrimary(ctx context.Context, assetSourceID shared.ID) error {
	// Get the asset ID first
	var assetID string
	err := r.db.QueryRowContext(ctx, "SELECT asset_id FROM asset_sources WHERE id = $1", assetSourceID.String()).Scan(&assetID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return datasource.ErrAssetSourceNotFound
		}
		return fmt.Errorf("get asset source: %w", err)
	}

	// Update: the trigger will handle unsetting other primaries
	query := `UPDATE asset_sources SET is_primary = true, updated_at = NOW() WHERE id = $1`
	_, err = r.db.ExecContext(ctx, query, assetSourceID.String())
	if err != nil {
		return fmt.Errorf("set primary: %w", err)
	}

	return nil
}

// CountBySource returns the number of assets for a data source.
func (r *AssetSourceRepository) CountBySource(ctx context.Context, sourceID shared.ID) (int64, error) {
	query := `SELECT COUNT(DISTINCT asset_id) FROM asset_sources WHERE source_id = $1`

	var count int64
	err := r.db.QueryRowContext(ctx, query, sourceID.String()).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("count assets by source: %w", err)
	}

	return count, nil
}

// scanAssetSource scans a single row into an AssetSource.
func (r *AssetSourceRepository) scanAssetSource(row *sql.Row) (*datasource.AssetSource, error) {
	var (
		id              string
		assetID         string
		sourceType      string
		sourceID        sql.NullString
		firstSeenAt     time.Time
		lastSeenAt      time.Time
		sourceRef       sql.NullString
		contributedData []byte
		confidence      int
		isPrimary       bool
		seenCount       int
		createdAt       time.Time
		updatedAt       time.Time
	)

	err := row.Scan(
		&id, &assetID, &sourceType, &sourceID,
		&firstSeenAt, &lastSeenAt, &sourceRef,
		&contributedData, &confidence, &isPrimary, &seenCount,
		&createdAt, &updatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, datasource.ErrAssetSourceNotFound
		}
		return nil, fmt.Errorf("scan asset source: %w", err)
	}

	return r.reconstructAssetSource(
		id, assetID, sourceType, sourceID,
		firstSeenAt, lastSeenAt, sourceRef,
		contributedData, confidence, isPrimary, seenCount,
		createdAt, updatedAt,
	)
}

// scanAssetSourceRow scans a row from sql.Rows into an AssetSource.
func (r *AssetSourceRepository) scanAssetSourceRow(rows *sql.Rows) (*datasource.AssetSource, error) {
	var (
		id              string
		assetID         string
		sourceType      string
		sourceID        sql.NullString
		firstSeenAt     time.Time
		lastSeenAt      time.Time
		sourceRef       sql.NullString
		contributedData []byte
		confidence      int
		isPrimary       bool
		seenCount       int
		createdAt       time.Time
		updatedAt       time.Time
	)

	err := rows.Scan(
		&id, &assetID, &sourceType, &sourceID,
		&firstSeenAt, &lastSeenAt, &sourceRef,
		&contributedData, &confidence, &isPrimary, &seenCount,
		&createdAt, &updatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("scan asset source row: %w", err)
	}

	return r.reconstructAssetSource(
		id, assetID, sourceType, sourceID,
		firstSeenAt, lastSeenAt, sourceRef,
		contributedData, confidence, isPrimary, seenCount,
		createdAt, updatedAt,
	)
}

// reconstructAssetSource reconstructs an AssetSource from scanned values.
func (r *AssetSourceRepository) reconstructAssetSource(
	id, assetID, sourceType string,
	sourceID sql.NullString,
	firstSeenAt, lastSeenAt time.Time,
	sourceRef sql.NullString,
	contributedDataJSON []byte,
	confidence int,
	isPrimary bool,
	seenCount int,
	createdAt, updatedAt time.Time,
) (*datasource.AssetSource, error) {
	var contributedData map[string]any
	if len(contributedDataJSON) > 0 {
		if err := json.Unmarshal(contributedDataJSON, &contributedData); err != nil {
			return nil, fmt.Errorf("unmarshal contributed_data: %w", err)
		}
	}

	asID, _ := shared.IDFromString(id)
	assID, _ := shared.IDFromString(assetID)

	var srcID *shared.ID
	if sourceID.Valid {
		sid, _ := shared.IDFromString(sourceID.String)
		srcID = &sid
	}

	return datasource.ReconstructAssetSource(
		asID,
		assID,
		datasource.SourceType(sourceType),
		srcID,
		firstSeenAt,
		lastSeenAt,
		sourceRef.String,
		contributedData,
		confidence,
		isPrimary,
		seenCount,
		createdAt,
		updatedAt,
	), nil
}
