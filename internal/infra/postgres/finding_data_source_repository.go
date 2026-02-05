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

// FindingDataSourceRepository implements datasource.FindingDataSourceRepository using PostgreSQL.
type FindingDataSourceRepository struct {
	db *DB
}

// NewFindingDataSourceRepository creates a new FindingDataSourceRepository.
func NewFindingDataSourceRepository(db *DB) *FindingDataSourceRepository {
	return &FindingDataSourceRepository{db: db}
}

// Ensure FindingDataSourceRepository implements datasource.FindingDataSourceRepository
var _ datasource.FindingDataSourceRepository = (*FindingDataSourceRepository)(nil)

// Create creates a new finding data source record.
func (r *FindingDataSourceRepository) Create(ctx context.Context, fs *datasource.FindingDataSource) error {
	contributedData, err := json.Marshal(fs.ContributedData())
	if err != nil {
		return fmt.Errorf("marshal contributed_data: %w", err)
	}

	query := `
		INSERT INTO finding_data_sources (
			id, finding_id, source_type, source_id,
			first_seen_at, last_seen_at, source_ref, scan_id,
			contributed_data, confidence, is_primary, seen_count,
			created_at, updated_at
		) VALUES (
			$1, $2, $3, $4,
			$5, $6, $7, $8,
			$9, $10, $11, $12,
			$13, $14
		)
	`

	_, err = r.db.ExecContext(ctx, query,
		fs.ID().String(),
		fs.FindingID().String(),
		fs.SourceType().String(),
		nullIDPtr(fs.SourceID()),
		fs.FirstSeenAt(),
		fs.LastSeenAt(),
		nullString(fs.SourceRef()),
		nullString(fs.ScanID()),
		contributedData,
		fs.Confidence(),
		fs.IsPrimary(),
		fs.SeenCount(),
		fs.CreatedAt(),
		fs.UpdatedAt(),
	)
	if err != nil {
		if isUniqueViolation(err) {
			return fmt.Errorf("finding data source already exists for this finding and source")
		}
		return fmt.Errorf("create finding data source: %w", err)
	}

	return nil
}

// GetByID retrieves a finding data source by ID.
func (r *FindingDataSourceRepository) GetByID(ctx context.Context, id shared.ID) (*datasource.FindingDataSource, error) {
	query := `
		SELECT id, finding_id, source_type, source_id,
			   first_seen_at, last_seen_at, source_ref, scan_id,
			   contributed_data, confidence, is_primary, seen_count,
			   created_at, updated_at
		FROM finding_data_sources
		WHERE id = $1
	`

	row := r.db.QueryRowContext(ctx, query, id.String())
	return r.scanFindingDataSource(row)
}

// GetByFindingAndSource retrieves a finding data source by finding ID, source type, and source ID.
func (r *FindingDataSourceRepository) GetByFindingAndSource(ctx context.Context, findingID shared.ID, sourceType datasource.SourceType, sourceID *shared.ID) (*datasource.FindingDataSource, error) {
	var query string
	var args []any

	if sourceID != nil {
		query = `
			SELECT id, finding_id, source_type, source_id,
				   first_seen_at, last_seen_at, source_ref, scan_id,
				   contributed_data, confidence, is_primary, seen_count,
				   created_at, updated_at
			FROM finding_data_sources
			WHERE finding_id = $1 AND source_type = $2 AND source_id = $3
		`
		args = []any{findingID.String(), sourceType.String(), sourceID.String()}
	} else {
		query = `
			SELECT id, finding_id, source_type, source_id,
				   first_seen_at, last_seen_at, source_ref, scan_id,
				   contributed_data, confidence, is_primary, seen_count,
				   created_at, updated_at
			FROM finding_data_sources
			WHERE finding_id = $1 AND source_type = $2 AND source_id IS NULL
		`
		args = []any{findingID.String(), sourceType.String()}
	}

	row := r.db.QueryRowContext(ctx, query, args...)
	return r.scanFindingDataSource(row)
}

// Update updates an existing finding data source.
func (r *FindingDataSourceRepository) Update(ctx context.Context, fs *datasource.FindingDataSource) error {
	contributedData, err := json.Marshal(fs.ContributedData())
	if err != nil {
		return fmt.Errorf("marshal contributed_data: %w", err)
	}

	query := `
		UPDATE finding_data_sources SET
			last_seen_at = $2,
			source_ref = $3,
			scan_id = $4,
			contributed_data = $5,
			confidence = $6,
			is_primary = $7,
			seen_count = $8,
			updated_at = $9
		WHERE id = $1
	`

	result, err := r.db.ExecContext(ctx, query,
		fs.ID().String(),
		fs.LastSeenAt(),
		nullString(fs.SourceRef()),
		nullString(fs.ScanID()),
		contributedData,
		fs.Confidence(),
		fs.IsPrimary(),
		fs.SeenCount(),
		fs.UpdatedAt(),
	)
	if err != nil {
		return fmt.Errorf("update finding data source: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("rows affected: %w", err)
	}
	if rowsAffected == 0 {
		return fmt.Errorf("finding data source not found")
	}

	return nil
}

// Upsert creates or updates a finding data source.
func (r *FindingDataSourceRepository) Upsert(ctx context.Context, fs *datasource.FindingDataSource) error {
	contributedData, err := json.Marshal(fs.ContributedData())
	if err != nil {
		return fmt.Errorf("marshal contributed_data: %w", err)
	}

	query := `
		INSERT INTO finding_data_sources (
			id, finding_id, source_type, source_id,
			first_seen_at, last_seen_at, source_ref, scan_id,
			contributed_data, confidence, is_primary, seen_count,
			created_at, updated_at
		) VALUES (
			$1, $2, $3, $4,
			$5, $6, $7, $8,
			$9, $10, $11, $12,
			$13, $14
		)
		ON CONFLICT (finding_id, source_type, source_id)
		DO UPDATE SET
			last_seen_at = EXCLUDED.last_seen_at,
			source_ref = COALESCE(EXCLUDED.source_ref, finding_data_sources.source_ref),
			scan_id = COALESCE(EXCLUDED.scan_id, finding_data_sources.scan_id),
			contributed_data = finding_data_sources.contributed_data || EXCLUDED.contributed_data,
			confidence = GREATEST(finding_data_sources.confidence, EXCLUDED.confidence),
			seen_count = finding_data_sources.seen_count + 1,
			updated_at = EXCLUDED.updated_at
	`

	_, err = r.db.ExecContext(ctx, query,
		fs.ID().String(),
		fs.FindingID().String(),
		fs.SourceType().String(),
		nullIDPtr(fs.SourceID()),
		fs.FirstSeenAt(),
		fs.LastSeenAt(),
		nullString(fs.SourceRef()),
		nullString(fs.ScanID()),
		contributedData,
		fs.Confidence(),
		fs.IsPrimary(),
		fs.SeenCount(),
		fs.CreatedAt(),
		fs.UpdatedAt(),
	)
	if err != nil {
		return fmt.Errorf("upsert finding data source: %w", err)
	}

	return nil
}

// Delete deletes a finding data source by ID.
func (r *FindingDataSourceRepository) Delete(ctx context.Context, id shared.ID) error {
	query := `DELETE FROM finding_data_sources WHERE id = $1`

	result, err := r.db.ExecContext(ctx, query, id.String())
	if err != nil {
		return fmt.Errorf("delete finding data source: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("rows affected: %w", err)
	}
	if rowsAffected == 0 {
		return fmt.Errorf("finding data source not found")
	}

	return nil
}

// DeleteByFinding deletes all data sources for a finding.
func (r *FindingDataSourceRepository) DeleteByFinding(ctx context.Context, findingID shared.ID) error {
	query := `DELETE FROM finding_data_sources WHERE finding_id = $1`

	_, err := r.db.ExecContext(ctx, query, findingID.String())
	if err != nil {
		return fmt.Errorf("delete finding data sources by finding: %w", err)
	}

	return nil
}

// DeleteBySource deletes all finding data sources for a data source.
func (r *FindingDataSourceRepository) DeleteBySource(ctx context.Context, sourceID shared.ID) error {
	query := `DELETE FROM finding_data_sources WHERE source_id = $1`

	_, err := r.db.ExecContext(ctx, query, sourceID.String())
	if err != nil {
		return fmt.Errorf("delete finding data sources by source: %w", err)
	}

	return nil
}

// List lists finding data sources with filtering and pagination.
// nolint:dupl // Similar pattern to AssetSourceRepository.List - intentional for type safety
func (r *FindingDataSourceRepository) List(
	ctx context.Context,
	filter datasource.FindingDataSourceFilter,
	opts datasource.FindingDataSourceListOptions,
) (datasource.FindingDataSourceListResult, error) {
	result := datasource.FindingDataSourceListResult{
		Data:    make([]*datasource.FindingDataSource, 0),
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

	if !filter.FindingID.IsZero() {
		conditions = append(conditions, fmt.Sprintf("finding_id = $%d", argIdx))
		args = append(args, filter.FindingID.String())
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
	countQuery := "SELECT COUNT(*) FROM finding_data_sources " + whereClause
	err := r.db.QueryRowContext(ctx, countQuery, args...).Scan(&result.Total)
	if err != nil {
		return result, fmt.Errorf("count finding data sources: %w", err)
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
		SELECT id, finding_id, source_type, source_id,
			   first_seen_at, last_seen_at, source_ref, scan_id,
			   contributed_data, confidence, is_primary, seen_count,
			   created_at, updated_at
		FROM finding_data_sources
		%s
		ORDER BY %s
		LIMIT $%d OFFSET $%d
	`, whereClause, orderBy, argIdx, argIdx+1)

	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return result, fmt.Errorf("list finding data sources: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		fs, err := r.scanFindingDataSourceRow(rows)
		if err != nil {
			return result, err
		}
		result.Data = append(result.Data, fs)
	}

	if err := rows.Err(); err != nil {
		return result, fmt.Errorf("iterate rows: %w", err)
	}

	return result, nil
}

// GetByFinding retrieves all data sources for a finding.
func (r *FindingDataSourceRepository) GetByFinding(ctx context.Context, findingID shared.ID) ([]*datasource.FindingDataSource, error) {
	query := `
		SELECT id, finding_id, source_type, source_id,
			   first_seen_at, last_seen_at, source_ref, scan_id,
			   contributed_data, confidence, is_primary, seen_count,
			   created_at, updated_at
		FROM finding_data_sources
		WHERE finding_id = $1
		ORDER BY is_primary DESC, last_seen_at DESC
	`

	rows, err := r.db.QueryContext(ctx, query, findingID.String())
	if err != nil {
		return nil, fmt.Errorf("get finding data sources: %w", err)
	}
	defer rows.Close()

	var sources []*datasource.FindingDataSource
	for rows.Next() {
		fs, err := r.scanFindingDataSourceRow(rows)
		if err != nil {
			return nil, err
		}
		sources = append(sources, fs)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate rows: %w", err)
	}

	return sources, nil
}

// GetPrimaryByFinding retrieves the primary data source for a finding.
func (r *FindingDataSourceRepository) GetPrimaryByFinding(ctx context.Context, findingID shared.ID) (*datasource.FindingDataSource, error) {
	query := `
		SELECT id, finding_id, source_type, source_id,
			   first_seen_at, last_seen_at, source_ref, scan_id,
			   contributed_data, confidence, is_primary, seen_count,
			   created_at, updated_at
		FROM finding_data_sources
		WHERE finding_id = $1 AND is_primary = true
	`

	row := r.db.QueryRowContext(ctx, query, findingID.String())
	return r.scanFindingDataSource(row)
}

// SetPrimary sets a data source as the primary source for a finding.
func (r *FindingDataSourceRepository) SetPrimary(ctx context.Context, findingDataSourceID shared.ID) error {
	// Get the finding ID first
	var findingID string
	err := r.db.QueryRowContext(ctx, "SELECT finding_id FROM finding_data_sources WHERE id = $1", findingDataSourceID.String()).Scan(&findingID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("finding data source not found")
		}
		return fmt.Errorf("get finding data source: %w", err)
	}

	// Update: the trigger will handle unsetting other primaries
	query := `UPDATE finding_data_sources SET is_primary = true, updated_at = NOW() WHERE id = $1`
	_, err = r.db.ExecContext(ctx, query, findingDataSourceID.String())
	if err != nil {
		return fmt.Errorf("set primary: %w", err)
	}

	return nil
}

// CountBySource returns the number of findings for a data source.
func (r *FindingDataSourceRepository) CountBySource(ctx context.Context, sourceID shared.ID) (int64, error) {
	query := `SELECT COUNT(DISTINCT finding_id) FROM finding_data_sources WHERE source_id = $1`

	var count int64
	err := r.db.QueryRowContext(ctx, query, sourceID.String()).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("count findings by source: %w", err)
	}

	return count, nil
}

// scanFindingDataSource scans a single row into a FindingDataSource.
func (r *FindingDataSourceRepository) scanFindingDataSource(row *sql.Row) (*datasource.FindingDataSource, error) {
	var (
		id              string
		findingID       string
		sourceType      string
		sourceID        sql.NullString
		firstSeenAt     time.Time
		lastSeenAt      time.Time
		sourceRef       sql.NullString
		scanID          sql.NullString
		contributedData []byte
		confidence      int
		isPrimary       bool
		seenCount       int
		createdAt       time.Time
		updatedAt       time.Time
	)

	err := row.Scan(
		&id, &findingID, &sourceType, &sourceID,
		&firstSeenAt, &lastSeenAt, &sourceRef, &scanID,
		&contributedData, &confidence, &isPrimary, &seenCount,
		&createdAt, &updatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("finding data source not found")
		}
		return nil, fmt.Errorf("scan finding data source: %w", err)
	}

	return r.reconstructFindingDataSource(
		id, findingID, sourceType, sourceID,
		firstSeenAt, lastSeenAt, sourceRef, scanID,
		contributedData, confidence, isPrimary, seenCount,
		createdAt, updatedAt,
	)
}

// scanFindingDataSourceRow scans a row from sql.Rows into a FindingDataSource.
func (r *FindingDataSourceRepository) scanFindingDataSourceRow(rows *sql.Rows) (*datasource.FindingDataSource, error) {
	var (
		id              string
		findingID       string
		sourceType      string
		sourceID        sql.NullString
		firstSeenAt     time.Time
		lastSeenAt      time.Time
		sourceRef       sql.NullString
		scanID          sql.NullString
		contributedData []byte
		confidence      int
		isPrimary       bool
		seenCount       int
		createdAt       time.Time
		updatedAt       time.Time
	)

	err := rows.Scan(
		&id, &findingID, &sourceType, &sourceID,
		&firstSeenAt, &lastSeenAt, &sourceRef, &scanID,
		&contributedData, &confidence, &isPrimary, &seenCount,
		&createdAt, &updatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("scan finding data source row: %w", err)
	}

	return r.reconstructFindingDataSource(
		id, findingID, sourceType, sourceID,
		firstSeenAt, lastSeenAt, sourceRef, scanID,
		contributedData, confidence, isPrimary, seenCount,
		createdAt, updatedAt,
	)
}

// reconstructFindingDataSource reconstructs a FindingDataSource from scanned values.
func (r *FindingDataSourceRepository) reconstructFindingDataSource(
	id, findingID, sourceType string,
	sourceID sql.NullString,
	firstSeenAt, lastSeenAt time.Time,
	sourceRef, scanID sql.NullString,
	contributedDataJSON []byte,
	confidence int,
	isPrimary bool,
	seenCount int,
	createdAt, updatedAt time.Time,
) (*datasource.FindingDataSource, error) {
	var contributedData map[string]any
	if len(contributedDataJSON) > 0 {
		if err := json.Unmarshal(contributedDataJSON, &contributedData); err != nil {
			return nil, fmt.Errorf("unmarshal contributed_data: %w", err)
		}
	}

	fsID, _ := shared.IDFromString(id)
	fndID, _ := shared.IDFromString(findingID)

	var srcID *shared.ID
	if sourceID.Valid {
		sid, _ := shared.IDFromString(sourceID.String)
		srcID = &sid
	}

	return datasource.ReconstructFindingDataSource(
		fsID,
		fndID,
		datasource.SourceType(sourceType),
		srcID,
		firstSeenAt,
		lastSeenAt,
		sourceRef.String,
		scanID.String,
		contributedData,
		confidence,
		isPrimary,
		seenCount,
		createdAt,
		updatedAt,
	), nil
}
