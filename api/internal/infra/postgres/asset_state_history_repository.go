package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// AssetStateHistoryRepository implements asset.StateHistoryRepository using PostgreSQL.
type AssetStateHistoryRepository struct {
	db *DB
}

// NewAssetStateHistoryRepository creates a new AssetStateHistoryRepository.
func NewAssetStateHistoryRepository(db *DB) *AssetStateHistoryRepository {
	return &AssetStateHistoryRepository{db: db}
}

// =============================================================================
// Write Operations (Append-only)
// =============================================================================

// Create appends a new state change record.
func (r *AssetStateHistoryRepository) Create(ctx context.Context, change *asset.AssetStateChange) error {
	query := `
		INSERT INTO asset_state_history (
			id, tenant_id, asset_id,
			change_type, field, old_value, new_value,
			reason, metadata, source, changed_by, changed_at, created_at
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
	`

	var changedBy *string
	if change.ChangedBy() != nil {
		s := change.ChangedBy().String()
		changedBy = &s
	}

	_, err := r.db.ExecContext(ctx, query,
		change.ID().String(),
		change.TenantID().String(),
		change.AssetID().String(),
		change.ChangeType().String(),
		nullString(change.Field()),
		nullString(change.OldValue()),
		nullString(change.NewValue()),
		nullString(change.Reason()),
		nullString(change.Metadata()),
		nullString(change.Source().String()),
		changedBy,
		change.ChangedAt(),
		change.CreatedAt(),
	)

	if err != nil {
		return fmt.Errorf("failed to create state change: %w", err)
	}

	return nil
}

// CreateBatch appends multiple state change records in a single operation.
func (r *AssetStateHistoryRepository) CreateBatch(ctx context.Context, changes []*asset.AssetStateChange) error {
	if len(changes) == 0 {
		return nil
	}

	query := `
		INSERT INTO asset_state_history (
			id, tenant_id, asset_id,
			change_type, field, old_value, new_value,
			reason, metadata, source, changed_by, changed_at, created_at
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
	`

	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	stmt, err := tx.PrepareContext(ctx, query)
	if err != nil {
		return fmt.Errorf("failed to prepare statement: %w", err)
	}
	defer stmt.Close()

	for _, change := range changes {
		var changedBy *string
		if change.ChangedBy() != nil {
			s := change.ChangedBy().String()
			changedBy = &s
		}

		_, err := stmt.ExecContext(ctx,
			change.ID().String(),
			change.TenantID().String(),
			change.AssetID().String(),
			change.ChangeType().String(),
			nullString(change.Field()),
			nullString(change.OldValue()),
			nullString(change.NewValue()),
			nullString(change.Reason()),
			nullString(change.Metadata()),
			nullString(change.Source().String()),
			changedBy,
			change.ChangedAt(),
			change.CreatedAt(),
		)

		if err != nil {
			return fmt.Errorf("failed to insert state change: %w", err)
		}
	}

	return tx.Commit()
}

// =============================================================================
// Query Operations
// =============================================================================

// GetByID retrieves a state change by its ID.
func (r *AssetStateHistoryRepository) GetByID(ctx context.Context, tenantID, id shared.ID) (*asset.AssetStateChange, error) {
	query := r.selectQuery() + " WHERE h.tenant_id = $1 AND h.id = $2"

	row := r.db.QueryRowContext(ctx, query, tenantID.String(), id.String())
	return r.scanStateChange(row)
}

// GetByAssetID retrieves all state changes for an asset.
func (r *AssetStateHistoryRepository) GetByAssetID(ctx context.Context, tenantID, assetID shared.ID, opts asset.ListStateHistoryOptions) ([]*asset.AssetStateChange, int, error) {
	opts.AssetID = &assetID
	return r.List(ctx, tenantID, opts)
}

// List retrieves state changes with filtering and pagination.
func (r *AssetStateHistoryRepository) List(ctx context.Context, tenantID shared.ID, opts asset.ListStateHistoryOptions) ([]*asset.AssetStateChange, int, error) {
	baseQuery := r.selectQuery()
	countQuery := "SELECT COUNT(*) FROM asset_state_history h"

	var conditions []string
	var args []interface{}
	argIdx := 1

	// Always filter by tenant
	conditions = append(conditions, fmt.Sprintf("h.tenant_id = $%d", argIdx))
	args = append(args, tenantID.String())
	argIdx++

	// Optional filters
	if opts.AssetID != nil {
		conditions = append(conditions, fmt.Sprintf("h.asset_id = $%d", argIdx))
		args = append(args, opts.AssetID.String())
		argIdx++
	}

	// The single ChangeType / Source filters used to be ignored here, so e.g.
	// /state-history/appearances returned every change type. Merge them.
	changeTypes := opts.EffectiveChangeTypes()
	if len(changeTypes) > 0 {
		placeholders := make([]string, len(changeTypes))
		for i, ct := range changeTypes {
			placeholders[i] = fmt.Sprintf("$%d", argIdx)
			args = append(args, ct.String())
			argIdx++
		}
		conditions = append(conditions, fmt.Sprintf("h.change_type IN (%s)", strings.Join(placeholders, ", ")))
	}

	// A sensor filter also matches rows written before the rename.
	sources := asset.WithHistoricalSources(opts.EffectiveSources())
	if len(sources) > 0 {
		placeholders := make([]string, len(sources))
		for i, s := range sources {
			placeholders[i] = fmt.Sprintf("$%d", argIdx)
			args = append(args, s.String())
			argIdx++
		}
		conditions = append(conditions, fmt.Sprintf("h.source IN (%s)", strings.Join(placeholders, ", ")))
	}

	if opts.ChangedBy != nil {
		conditions = append(conditions, fmt.Sprintf("h.changed_by = $%d", argIdx))
		args = append(args, opts.ChangedBy.String())
		argIdx++
	}

	if len(opts.NewValues) > 0 {
		placeholders := make([]string, len(opts.NewValues))
		for i, v := range opts.NewValues {
			placeholders[i] = fmt.Sprintf("$%d", argIdx)
			args = append(args, v)
			argIdx++
		}
		conditions = append(conditions, fmt.Sprintf("h.new_value IN (%s)", strings.Join(placeholders, ", ")))
	}

	// Asset-state filters join the asset through a tenant-scoped EXISTS so the
	// count query and the page query share one WHERE clause.
	if opts.AssetScope != nil {
		conditions = append(conditions, fmt.Sprintf(
			"EXISTS (SELECT 1 FROM assets a WHERE a.id = h.asset_id AND a.tenant_id = h.tenant_id AND a.scope = $%d)", argIdx))
		args = append(args, opts.AssetScope.String())
		argIdx++
	}
	if opts.AssetInternetFacing != nil {
		facing := "EXISTS (SELECT 1 FROM assets a WHERE a.id = h.asset_id AND a.tenant_id = h.tenant_id AND (a.is_internet_accessible OR a.exposure = 'public'))"
		if !*opts.AssetInternetFacing {
			facing = "NOT " + facing
		}
		conditions = append(conditions, facing)
	}

	if opts.From != nil {
		conditions = append(conditions, fmt.Sprintf("h.changed_at >= $%d", argIdx))
		args = append(args, *opts.From)
		argIdx++
	}

	if opts.To != nil {
		conditions = append(conditions, fmt.Sprintf("h.changed_at <= $%d", argIdx))
		args = append(args, *opts.To)
		argIdx++
	}

	if opts.Scope != nil {
		cond, scopeArgs := dataScopeCondAt("h.asset_id", opts.Scope, argIdx)
		conditions = append(conditions, cond)
		args = append(args, scopeArgs...)
		argIdx += len(scopeArgs)
	}

	whereClause := ""
	if len(conditions) > 0 {
		whereClause = " WHERE " + strings.Join(conditions, " AND ")
	}

	// Count total
	var total int
	err := r.db.QueryRowContext(ctx, countQuery+whereClause, args...).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to count state changes: %w", err)
	}

	// F-D1 hardening: sortOrder is a binary literal ("ASC" | "DESC"); sort
	// column is fixed (h.changed_at). No attacker input reaches the format.
	sortOrder := sortOrderDESC
	if opts.SortOrder == sortOrderAscLower {
		sortOrder = sortOrderASC
	}

	query := baseQuery + whereClause + fmt.Sprintf(" ORDER BY h.changed_at %s", sortOrder)

	// Pagination
	if opts.Limit > 0 {
		query += fmt.Sprintf(" LIMIT $%d", argIdx)
		args = append(args, opts.Limit)
		argIdx++
	}
	if opts.Offset > 0 {
		query += fmt.Sprintf(" OFFSET $%d", argIdx)
		args = append(args, opts.Offset)
	}

	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to query state changes: %w", err)
	}
	defer rows.Close()

	changes, err := r.scanStateChanges(rows)
	if err != nil {
		return nil, 0, err
	}

	return changes, total, nil
}

// GetLatestByAsset retrieves the most recent state change for each asset.
func (r *AssetStateHistoryRepository) GetLatestByAsset(ctx context.Context, tenantID shared.ID, changeTypes []asset.StateChangeType) (map[shared.ID]*asset.AssetStateChange, error) {
	var typeFilter string
	var args []interface{}
	args = append(args, tenantID.String())

	if len(changeTypes) > 0 {
		placeholders := make([]string, len(changeTypes))
		for i, ct := range changeTypes {
			placeholders[i] = fmt.Sprintf("$%d", i+2)
			args = append(args, ct.String())
		}
		typeFilter = fmt.Sprintf("AND h.change_type IN (%s)", strings.Join(placeholders, ", "))
	}

	query := fmt.Sprintf(`
		SELECT DISTINCT ON (h.asset_id)
			h.id, h.tenant_id, h.asset_id,
			h.change_type, h.field, h.old_value, h.new_value,
			h.reason, h.metadata, h.source, h.changed_by, h.changed_at, h.created_at
		FROM asset_state_history h
		WHERE h.tenant_id = $1 %s
		ORDER BY h.asset_id, h.changed_at DESC
	`, typeFilter)

	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to query latest changes: %w", err)
	}
	defer rows.Close()

	result := make(map[shared.ID]*asset.AssetStateChange)
	for rows.Next() {
		change, err := r.scanStateChangeRow(rows)
		if err != nil {
			return nil, err
		}
		result[change.AssetID()] = change
	}

	return result, rows.Err()
}

// =============================================================================
// Shadow IT Detection Queries
// =============================================================================

// GetRecentAppearances retrieves assets that appeared within the time window.
func (r *AssetStateHistoryRepository) GetRecentAppearances(ctx context.Context, tenantID shared.ID, since time.Time, limit int) ([]*asset.AssetStateChange, error) {
	query := r.selectQuery() + `
		WHERE h.tenant_id = $1
		AND h.change_type = 'appeared'
		AND h.changed_at >= $2
		ORDER BY h.changed_at DESC
		LIMIT $3
	`

	rows, err := r.db.QueryContext(ctx, query, tenantID.String(), since, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to query recent appearances: %w", err)
	}
	defer rows.Close()

	return r.scanStateChanges(rows)
}

// GetRecentDisappearances retrieves assets that disappeared within the time window.
func (r *AssetStateHistoryRepository) GetRecentDisappearances(ctx context.Context, tenantID shared.ID, since time.Time, limit int) ([]*asset.AssetStateChange, error) {
	query := r.selectQuery() + `
		WHERE h.tenant_id = $1
		AND h.change_type = 'disappeared'
		AND h.changed_at >= $2
		ORDER BY h.changed_at DESC
		LIMIT $3
	`

	rows, err := r.db.QueryContext(ctx, query, tenantID.String(), since, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to query recent disappearances: %w", err)
	}
	defer rows.Close()

	return r.scanStateChanges(rows)
}

// GetShadowITCandidates retrieves assets that appeared but have unknown/shadow scope.
func (r *AssetStateHistoryRepository) GetShadowITCandidates(ctx context.Context, tenantID shared.ID, since time.Time, limit int) ([]*asset.AssetStateChange, error) {
	query := `
		SELECT
			h.id, h.tenant_id, h.asset_id,
			h.change_type, h.field, h.old_value, h.new_value,
			h.reason, h.metadata, h.source, h.changed_by, h.changed_at, h.created_at
		FROM asset_state_history h
		JOIN assets a ON h.asset_id = a.id
		WHERE h.tenant_id = $1
		AND h.change_type = 'appeared'
		AND h.changed_at >= $2
		AND a.scope = 'shadow'
		ORDER BY h.changed_at DESC
		LIMIT $3
	`

	rows, err := r.db.QueryContext(ctx, query, tenantID.String(), since, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to query shadow IT candidates: %w", err)
	}
	defer rows.Close()

	return r.scanStateChanges(rows)
}

// =============================================================================
// Exposure Change Queries
// =============================================================================

// GetExposureChanges retrieves all exposure-related changes within a time window.
func (r *AssetStateHistoryRepository) GetExposureChanges(ctx context.Context, tenantID shared.ID, since time.Time, limit int) ([]*asset.AssetStateChange, error) {
	query := r.selectQuery() + `
		WHERE h.tenant_id = $1
		AND h.change_type IN ('exposure_changed', 'internet_exposure_changed')
		AND h.changed_at >= $2
		ORDER BY h.changed_at DESC
		LIMIT $3
	`

	rows, err := r.db.QueryContext(ctx, query, tenantID.String(), since, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to query exposure changes: %w", err)
	}
	defer rows.Close()

	return r.scanStateChanges(rows)
}

// GetNewlyExposedAssets retrieves assets that became internet-accessible.
func (r *AssetStateHistoryRepository) GetNewlyExposedAssets(ctx context.Context, tenantID shared.ID, since time.Time, limit int) ([]*asset.AssetStateChange, error) {
	query := r.selectQuery() + `
		WHERE h.tenant_id = $1
		AND h.change_type = 'internet_exposure_changed'
		AND h.new_value = 'true'
		AND h.changed_at >= $2
		ORDER BY h.changed_at DESC
		LIMIT $3
	`

	rows, err := r.db.QueryContext(ctx, query, tenantID.String(), since, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to query newly exposed assets: %w", err)
	}
	defer rows.Close()

	return r.scanStateChanges(rows)
}

// =============================================================================
// Compliance Audit Queries
// =============================================================================

// GetComplianceChanges retrieves compliance-related changes within a time window.
func (r *AssetStateHistoryRepository) GetComplianceChanges(ctx context.Context, tenantID shared.ID, since time.Time, limit int) ([]*asset.AssetStateChange, error) {
	query := r.selectQuery() + `
		WHERE h.tenant_id = $1
		AND h.change_type IN ('compliance_changed', 'classification_changed', 'owner_changed')
		AND h.changed_at >= $2
		ORDER BY h.changed_at DESC
		LIMIT $3
	`

	rows, err := r.db.QueryContext(ctx, query, tenantID.String(), since, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to query compliance changes: %w", err)
	}
	defer rows.Close()

	return r.scanStateChanges(rows)
}

// GetChangesByUser retrieves all changes made by a specific user.
func (r *AssetStateHistoryRepository) GetChangesByUser(ctx context.Context, tenantID, userID shared.ID, opts asset.ListStateHistoryOptions) ([]*asset.AssetStateChange, int, error) {
	opts.ChangedBy = &userID
	return r.List(ctx, tenantID, opts)
}

// =============================================================================
// Statistics
// =============================================================================

// CountByType returns count of changes grouped by change type.
func (r *AssetStateHistoryRepository) CountByType(ctx context.Context, tenantID shared.ID, since time.Time, scope *shared.DataScope) (map[asset.StateChangeType]int, error) {
	scopeCond, args := dataScopeCond("asset_id", scope, []any{tenantID.String(), since})
	//nolint:gosec // G202: scopeCond is built from fixed SQL and numbered placeholders
	query := `
		SELECT change_type, COUNT(*) as count
		FROM asset_state_history
		WHERE tenant_id = $1 AND changed_at >= $2 AND ` + scopeCond + `
		GROUP BY change_type
		ORDER BY count DESC
	`

	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to get change type counts: %w", err)
	}
	defer rows.Close()

	result := make(map[asset.StateChangeType]int)
	for rows.Next() {
		var changeType string
		var count int
		if err := rows.Scan(&changeType, &count); err != nil {
			return nil, fmt.Errorf("failed to scan change type count: %w", err)
		}
		result[asset.StateChangeType(changeType)] = count
	}

	return result, rows.Err()
}

// CountBySource returns count of changes grouped by source.
func (r *AssetStateHistoryRepository) CountBySource(ctx context.Context, tenantID shared.ID, since time.Time, scope *shared.DataScope) (map[asset.ChangeSource]int, error) {
	scopeCond, args := dataScopeCond("asset_id", scope, []any{tenantID.String(), since})
	//nolint:gosec // G202: scopeCond is built from fixed SQL and numbered placeholders
	query := `
		SELECT COALESCE(source, 'unknown') as source, COUNT(*) as count
		FROM asset_state_history
		WHERE tenant_id = $1 AND changed_at >= $2 AND ` + scopeCond + `
		GROUP BY source
		ORDER BY count DESC
	`

	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to get source counts: %w", err)
	}
	defer rows.Close()

	result := make(map[asset.ChangeSource]int)
	for rows.Next() {
		var source string
		var count int
		if err := rows.Scan(&source, &count); err != nil {
			return nil, fmt.Errorf("failed to scan source count: %w", err)
		}
		result[asset.ChangeSource(source).Canonical()] += count
	}

	return result, rows.Err()
}

// GetActivityTimeline returns daily counts of changes over a time period.
func (r *AssetStateHistoryRepository) GetActivityTimeline(ctx context.Context, tenantID shared.ID, from, to time.Time, scope *shared.DataScope) ([]asset.DailyActivityCount, error) {
	scopeCond, args := dataScopeCond("asset_id", scope, []any{tenantID.String(), from, to})
	//nolint:gosec // G202: scopeCond is built from fixed SQL and numbered placeholders
	query := `
		SELECT
			DATE(changed_at) as date,
			COUNT(*) FILTER (WHERE change_type = 'appeared') as appeared,
			COUNT(*) FILTER (WHERE change_type = 'disappeared') as disappeared,
			COUNT(*) FILTER (WHERE change_type = 'recovered') as recovered,
			COUNT(*) FILTER (WHERE change_type IN ('exposure_changed', 'internet_exposure_changed')) as exposure_change,
			COUNT(*) FILTER (WHERE change_type NOT IN ('appeared', 'disappeared', 'recovered', 'exposure_changed', 'internet_exposure_changed')) as other_changes,
			COUNT(*) as total
		FROM asset_state_history
		WHERE tenant_id = $1 AND changed_at >= $2 AND changed_at <= $3 AND ` + scopeCond + `
		GROUP BY DATE(changed_at)
		ORDER BY date ASC
	`

	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to get activity timeline: %w", err)
	}
	defer rows.Close()

	var result []asset.DailyActivityCount
	for rows.Next() {
		var dac asset.DailyActivityCount
		if err := rows.Scan(
			&dac.Date,
			&dac.Appeared,
			&dac.Disappeared,
			&dac.Recovered,
			&dac.ExposureChange,
			&dac.OtherChanges,
			&dac.Total,
		); err != nil {
			return nil, fmt.Errorf("failed to scan activity count: %w", err)
		}
		result = append(result, dac)
	}

	return result, rows.Err()
}

// =============================================================================
// Helper Methods
// =============================================================================

// GetAssetRefs returns the current name/type/exposure/scope of the given
// assets, restricted to the tenant.
func (r *AssetStateHistoryRepository) GetAssetRefs(ctx context.Context, tenantID shared.ID, assetIDs []shared.ID) (map[shared.ID]asset.StateChangeAssetRef, error) {
	result := make(map[shared.ID]asset.StateChangeAssetRef, len(assetIDs))
	if len(assetIDs) == 0 {
		return result, nil
	}
	ids := make([]string, 0, len(assetIDs))
	for _, id := range assetIDs {
		ids = append(ids, id.String())
	}
	rows, err := r.db.QueryContext(ctx, `
		SELECT id, name, asset_type, exposure, scope, COALESCE(is_internet_accessible, false)
		FROM assets
		WHERE tenant_id = $1 AND id = ANY($2::uuid[])
	`, tenantID.String(), pq.Array(ids))
	if err != nil {
		return nil, fmt.Errorf("failed to query asset refs: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var idStr string
		var ref asset.StateChangeAssetRef
		if err := rows.Scan(&idStr, &ref.Name, &ref.Type, &ref.Exposure, &ref.Scope, &ref.InternetAccessible); err != nil {
			return nil, fmt.Errorf("failed to scan asset ref: %w", err)
		}
		id, err := shared.IDFromString(idStr)
		if err != nil {
			continue
		}
		result[id] = ref
	}
	return result, rows.Err()
}

func (r *AssetStateHistoryRepository) selectQuery() string {
	return `
		SELECT
			h.id, h.tenant_id, h.asset_id,
			h.change_type, h.field, h.old_value, h.new_value,
			h.reason, h.metadata, h.source, h.changed_by, h.changed_at, h.created_at
		FROM asset_state_history h
	`
}

func (r *AssetStateHistoryRepository) scanStateChange(row *sql.Row) (*asset.AssetStateChange, error) {
	var (
		id, tenantID, assetID string
		changeType            string
		field, oldValue       sql.NullString
		newValue, reason      sql.NullString
		metadata, source      sql.NullString
		changedBy             sql.NullString
		changedAt, createdAt  time.Time
	)

	err := row.Scan(
		&id, &tenantID, &assetID,
		&changeType, &field, &oldValue, &newValue,
		&reason, &metadata, &source, &changedBy, &changedAt, &createdAt,
	)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, shared.ErrNotFound
		}
		return nil, fmt.Errorf("failed to scan state change: %w", err)
	}

	return r.reconstituteStateChange(
		id, tenantID, assetID,
		changeType, field, oldValue, newValue,
		reason, metadata, source, changedBy, changedAt, createdAt,
	), nil
}

func (r *AssetStateHistoryRepository) scanStateChangeRow(rows *sql.Rows) (*asset.AssetStateChange, error) {
	var (
		id, tenantID, assetID string
		changeType            string
		field, oldValue       sql.NullString
		newValue, reason      sql.NullString
		metadata, source      sql.NullString
		changedBy             sql.NullString
		changedAt, createdAt  time.Time
	)

	err := rows.Scan(
		&id, &tenantID, &assetID,
		&changeType, &field, &oldValue, &newValue,
		&reason, &metadata, &source, &changedBy, &changedAt, &createdAt,
	)

	if err != nil {
		return nil, fmt.Errorf("failed to scan state change row: %w", err)
	}

	return r.reconstituteStateChange(
		id, tenantID, assetID,
		changeType, field, oldValue, newValue,
		reason, metadata, source, changedBy, changedAt, createdAt,
	), nil
}

func (r *AssetStateHistoryRepository) scanStateChanges(rows *sql.Rows) ([]*asset.AssetStateChange, error) {
	var changes []*asset.AssetStateChange

	for rows.Next() {
		change, err := r.scanStateChangeRow(rows)
		if err != nil {
			return nil, err
		}
		changes = append(changes, change)
	}

	return changes, rows.Err()
}

func (r *AssetStateHistoryRepository) reconstituteStateChange(
	id, tenantID, assetID string,
	changeType string,
	field, oldValue, newValue, reason, metadata, source, changedBy sql.NullString,
	changedAt, createdAt time.Time,
) *asset.AssetStateChange {
	var changedByPtr *shared.ID
	if changedBy.Valid {
		parsedChangedBy, _ := shared.IDFromString(changedBy.String)
		changedByPtr = &parsedChangedBy
	}

	parsedID, _ := shared.IDFromString(id)
	parsedTenantID, _ := shared.IDFromString(tenantID)
	parsedAssetID, _ := shared.IDFromString(assetID)

	return asset.ReconstituteStateChange(
		parsedID,
		parsedTenantID,
		parsedAssetID,
		asset.StateChangeType(changeType),
		nullStringValue(field),
		nullStringValue(oldValue),
		nullStringValue(newValue),
		nullStringValue(reason),
		nullStringValue(metadata),
		asset.ChangeSource(nullStringValue(source)).Canonical(),
		changedByPtr,
		changedAt,
		createdAt,
	)
}
