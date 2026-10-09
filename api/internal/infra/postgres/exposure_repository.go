package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/exposure"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/pagination"
)

// ExposureRepository implements exposure.Repository using PostgreSQL.
type ExposureRepository struct {
	db *DB
}

// NewExposureRepository creates a new ExposureRepository.
func NewExposureRepository(db *DB) *ExposureRepository {
	return &ExposureRepository{db: db}
}

// Create persists a new exposure event.
func (r *ExposureRepository) Create(ctx context.Context, event *exposure.ExposureEvent) error {
	details, err := json.Marshal(event.Details())
	if err != nil {
		return fmt.Errorf("failed to marshal details: %w", err)
	}

	query := `
		INSERT INTO exposure_events (
			id, tenant_id, asset_id, event_type, severity,
			state, title, description, details, fingerprint, source,
			first_seen_at, last_seen_at, resolved_at, resolved_by, resolution_notes,
			created_at, updated_at
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18)
	`

	_, err = r.db.ExecContext(ctx, query,
		event.ID().String(),
		event.TenantID().String(),

		nullIDPtr(event.AssetID()),
		event.EventType().String(),
		event.Severity().String(),
		event.State().String(),
		event.Title(),
		nullString(event.Description()),
		details,
		event.Fingerprint(),
		event.Source(),
		event.FirstSeenAt(),
		event.LastSeenAt(),
		nullTime(event.ResolvedAt()),
		nullIDPtr(event.ResolvedBy()),
		nullString(event.ResolutionNotes()),
		event.CreatedAt(),
		event.UpdatedAt(),
	)

	if err != nil {
		if isUniqueViolation(err) {
			return exposure.NewExposureEventExistsError(event.Fingerprint())
		}
		return fmt.Errorf("failed to create exposure event: %w", err)
	}

	return nil
}

// CreateInTx persists a new exposure event within an existing transaction.
func (r *ExposureRepository) CreateInTx(ctx context.Context, tx *sql.Tx, event *exposure.ExposureEvent) error {
	details, err := json.Marshal(event.Details())
	if err != nil {
		return fmt.Errorf("failed to marshal details: %w", err)
	}

	query := `
		INSERT INTO exposure_events (
			id, tenant_id, asset_id, event_type, severity,
			state, title, description, details, fingerprint, source,
			first_seen_at, last_seen_at, resolved_at, resolved_by, resolution_notes,
			created_at, updated_at
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18)
	`

	_, err = tx.ExecContext(ctx, query,
		event.ID().String(),
		event.TenantID().String(),
		nullIDPtr(event.AssetID()),
		event.EventType().String(),
		event.Severity().String(),
		event.State().String(),
		event.Title(),
		nullString(event.Description()),
		details,
		event.Fingerprint(),
		event.Source(),
		event.FirstSeenAt(),
		event.LastSeenAt(),
		nullTime(event.ResolvedAt()),
		nullIDPtr(event.ResolvedBy()),
		nullString(event.ResolutionNotes()),
		event.CreatedAt(),
		event.UpdatedAt(),
	)

	if err != nil {
		if isUniqueViolation(err) {
			return exposure.NewExposureEventExistsError(event.Fingerprint())
		}
		return fmt.Errorf("failed to create exposure event in tx: %w", err)
	}

	return nil
}

// GetByTenantAndID retrieves an exposure event by tenant and ID.
func (r *ExposureRepository) GetByTenantAndID(ctx context.Context, tenantID, id shared.ID) (*exposure.ExposureEvent, error) {
	query := r.selectQuery() + " WHERE tenant_id = $1 AND id = $2"

	row := r.db.QueryRowContext(ctx, query, tenantID.String(), id.String())
	return r.scanExposureEvent(row, id)
}

// GetByFingerprint retrieves an exposure event by fingerprint within a tenant.
func (r *ExposureRepository) GetByFingerprint(ctx context.Context, tenantID shared.ID, fingerprint string) (*exposure.ExposureEvent, error) {
	query := r.selectQuery() + " WHERE tenant_id = $1 AND fingerprint = $2"

	row := r.db.QueryRowContext(ctx, query, tenantID.String(), fingerprint)
	return r.scanExposureEvent(row, shared.ID{})
}

// Update updates an existing exposure event.
func (r *ExposureRepository) Update(ctx context.Context, event *exposure.ExposureEvent) error {
	details, err := json.Marshal(event.Details())
	if err != nil {
		return fmt.Errorf("failed to marshal details: %w", err)
	}

	query := `
		UPDATE exposure_events
		SET asset_id = $2, severity = $3, state = $4,
		    description = $5, details = $6, fingerprint = $7, last_seen_at = $8,
		    resolved_at = $9, resolved_by = $10, resolution_notes = $11, updated_at = $12
		WHERE id = $1 AND tenant_id = $13
	`

	result, err := r.db.ExecContext(ctx, query,
		event.ID().String(),

		nullIDPtr(event.AssetID()),
		event.Severity().String(),
		event.State().String(),
		nullString(event.Description()),
		details,
		event.Fingerprint(),
		event.LastSeenAt(),
		nullTime(event.ResolvedAt()),
		nullIDPtr(event.ResolvedBy()),
		nullString(event.ResolutionNotes()),
		event.UpdatedAt(),
		event.TenantID().String(),
	)

	if err != nil {
		return fmt.Errorf("failed to update exposure event: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return exposure.NewExposureEventNotFoundError(event.ID().String())
	}

	return nil
}

// Delete removes an exposure event of the tenant.
func (r *ExposureRepository) Delete(ctx context.Context, tenantID, id shared.ID) error {
	query := `DELETE FROM exposure_events WHERE tenant_id = $1 AND id = $2`

	result, err := r.db.ExecContext(ctx, query, tenantID.String(), id.String())
	if err != nil {
		return fmt.Errorf("failed to delete exposure event: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return exposure.NewExposureEventNotFoundError(id.String())
	}

	return nil
}

// List retrieves exposure events with filtering, sorting, and pagination.
func (r *ExposureRepository) List(
	ctx context.Context,
	filter exposure.Filter,
	opts exposure.ListOptions,
	page pagination.Pagination,
) (pagination.Result[*exposure.ExposureEvent], error) {
	baseQuery := r.selectQuery()
	countQuery := `SELECT COUNT(*) FROM exposure_events`

	whereClause, args := r.buildWhereClause(filter)

	if whereClause != "" {
		baseQuery += " WHERE " + whereClause
		countQuery += " WHERE " + whereClause
	}

	// Apply sorting
	orderBy := "first_seen_at DESC"
	if opts.Sort != nil && !opts.Sort.IsEmpty() {
		orderBy = opts.Sort.SQLWithDefault("first_seen_at DESC")
	}
	baseQuery += " ORDER BY " + orderBy
	baseQuery += fmt.Sprintf(" LIMIT %d OFFSET %d", page.Limit(), page.Offset())

	var total int64
	err := r.db.QueryRowContext(ctx, countQuery, args...).Scan(&total)
	if err != nil {
		return pagination.Result[*exposure.ExposureEvent]{}, fmt.Errorf("failed to count exposure events: %w", err)
	}

	rows, err := r.db.QueryContext(ctx, baseQuery, args...)
	if err != nil {
		return pagination.Result[*exposure.ExposureEvent]{}, fmt.Errorf("failed to query exposure events: %w", err)
	}
	defer rows.Close()

	var events []*exposure.ExposureEvent
	for rows.Next() {
		event, err := r.scanExposureEventFromRows(rows)
		if err != nil {
			return pagination.Result[*exposure.ExposureEvent]{}, err
		}
		events = append(events, event)
	}

	if err := rows.Err(); err != nil {
		return pagination.Result[*exposure.ExposureEvent]{}, fmt.Errorf("failed to iterate exposure events: %w", err)
	}

	return pagination.NewResult(events, total, page), nil
}

// Count returns the total number of exposure events matching the filter.
func (r *ExposureRepository) Count(ctx context.Context, filter exposure.Filter) (int64, error) {
	query := `SELECT COUNT(*) FROM exposure_events`

	whereClause, args := r.buildWhereClause(filter)
	if whereClause != "" {
		query += " WHERE " + whereClause
	}

	var count int64
	err := r.db.QueryRowContext(ctx, query, args...).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("failed to count exposure events: %w", err)
	}

	return count, nil
}

// ListByAsset retrieves all exposure events for an asset.
func (r *ExposureRepository) ListByAsset(ctx context.Context, assetID shared.ID, page pagination.Pagination) (pagination.Result[*exposure.ExposureEvent], error) {
	filter := exposure.NewFilter().WithAssetID(assetID.String())
	return r.List(ctx, filter, exposure.NewListOptions(), page)
}

// ExistsByFingerprint checks if an exposure event with the given fingerprint exists.
func (r *ExposureRepository) ExistsByFingerprint(ctx context.Context, tenantID shared.ID, fingerprint string) (bool, error) {
	query := `SELECT EXISTS(SELECT 1 FROM exposure_events WHERE tenant_id = $1 AND fingerprint = $2)`

	var exists bool
	err := r.db.QueryRowContext(ctx, query, tenantID.String(), fingerprint).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("failed to check exposure event existence: %w", err)
	}

	return exists, nil
}

// Upsert creates or updates an exposure event based on fingerprint.
func (r *ExposureRepository) Upsert(ctx context.Context, event *exposure.ExposureEvent) error {
	details, err := json.Marshal(event.Details())
	if err != nil {
		return fmt.Errorf("failed to marshal details: %w", err)
	}

	query := `
		INSERT INTO exposure_events (
			id, tenant_id, asset_id, event_type, severity,
			state, title, description, details, fingerprint, source,
			first_seen_at, last_seen_at, resolved_at, resolved_by, resolution_notes,
			created_at, updated_at
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18)
		ON CONFLICT (tenant_id, fingerprint) DO UPDATE SET
			last_seen_at = EXCLUDED.last_seen_at,
			updated_at = EXCLUDED.updated_at,
			-- Refresh the descriptive/severity fields on re-sighting: a re-scan
			-- can re-escalate an exposure (info -> critical) or reword it, and
			-- previously only the timestamps moved so the stored severity froze
			-- at its first-seen value.
			severity = EXCLUDED.severity,
			title = EXCLUDED.title,
			description = EXCLUDED.description,
			details = EXCLUDED.details
			-- state is deliberately NOT refreshed: preserve the existing
			-- (possibly user-resolved) state so a re-scan can't silently reopen
			-- a resolved exposure. Mirrors the findings upsert, which refreshes
			-- severity/scores but keeps the user-set status.
	`

	_, err = r.db.ExecContext(ctx, query,
		event.ID().String(),
		event.TenantID().String(),

		nullIDPtr(event.AssetID()),
		event.EventType().String(),
		event.Severity().String(),
		event.State().String(),
		event.Title(),
		nullString(event.Description()),
		details,
		event.Fingerprint(),
		event.Source(),
		event.FirstSeenAt(),
		event.LastSeenAt(),
		nullTime(event.ResolvedAt()),
		nullIDPtr(event.ResolvedBy()),
		nullString(event.ResolutionNotes()),
		event.CreatedAt(),
		event.UpdatedAt(),
	)

	if err != nil {
		return fmt.Errorf("failed to upsert exposure event: %w", err)
	}

	return nil
}

// BulkUpsert creates or updates multiple exposure events based on fingerprint.
// OPTIMIZED: Uses batch INSERT with ON CONFLICT for better performance than individual upserts.
func (r *ExposureRepository) BulkUpsert(ctx context.Context, events []*exposure.ExposureEvent) error {
	if len(events) == 0 {
		return nil
	}

	// For small batches, just use regular upsert (overhead of building batch query not worth it)
	if len(events) <= 3 {
		for _, event := range events {
			if err := r.Upsert(ctx, event); err != nil {
				return err
			}
		}
		return nil
	}

	query, args, err := buildExposureBulkUpsert(events)
	if err != nil {
		return err
	}
	if _, err := r.db.ExecContext(ctx, query, args...); err != nil {
		return fmt.Errorf("failed to bulk upsert exposure events: %w", err)
	}
	return nil
}

// UpsertedExposure is one row a transactional bulk upsert wrote.
type UpsertedExposure struct {
	ID          string
	TenantID    string
	Fingerprint string
	// Inserted is true for a new row, false for a re-sighting.
	Inserted bool
}

// BulkUpsertInTx is BulkUpsert inside the caller's transaction, and says
// which rows were inserted and which were re-sightings, so the caller can
// act on new rows only in the same transaction (EASM alerts).
func (r *ExposureRepository) BulkUpsertInTx(ctx context.Context, tx *sql.Tx, events []*exposure.ExposureEvent) ([]UpsertedExposure, error) {
	if len(events) == 0 {
		return nil, nil
	}
	query, args, err := buildExposureBulkUpsert(events)
	if err != nil {
		return nil, err
	}
	// xmax = 0 only on a freshly inserted tuple; an ON CONFLICT update locks
	// the existing row and sets it.
	rows, err := tx.QueryContext(ctx, query+` RETURNING id, tenant_id, fingerprint, (xmax = 0)`, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to bulk upsert exposure events: %w", err)
	}
	defer rows.Close()
	out := make([]UpsertedExposure, 0, len(events))
	for rows.Next() {
		var u UpsertedExposure
		if err := rows.Scan(&u.ID, &u.TenantID, &u.Fingerprint, &u.Inserted); err != nil {
			return nil, fmt.Errorf("scan upserted exposure: %w", err)
		}
		out = append(out, u)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("upserted exposures: %w", err)
	}
	return out, nil
}

// buildExposureBulkUpsert builds the batch INSERT ... ON CONFLICT statement.
func buildExposureBulkUpsert(events []*exposure.ExposureEvent) (string, []any, error) {
	// Fold events that share a fingerprint: the statement below cannot update
	// one row twice, and a single duplicate used to fail the whole batch.
	rows := foldExposureBatch(events)

	// Build batch INSERT query
	const numCols = 18 // number of columns in the insert
	valueStrings := make([]string, 0, len(rows))
	valueArgs := make([]any, 0, len(rows)*numCols)

	for i, row := range rows {
		event, last := row.first, row.last
		details, err := json.Marshal(last.Details())
		if err != nil {
			return "", nil, fmt.Errorf("failed to marshal details for event %d: %w", i, err)
		}

		baseIdx := i * numCols
		placeholders := make([]string, numCols)
		for j := 0; j < numCols; j++ {
			placeholders[j] = fmt.Sprintf("$%d", baseIdx+j+1)
		}
		valueStrings = append(valueStrings, "("+strings.Join(placeholders, ", ")+")")

		// Identity and state come from the first occurrence, the refreshed
		// fields from the last one: the same row one-by-one upserts leave.
		valueArgs = append(valueArgs,
			event.ID().String(),
			event.TenantID().String(),
			nullIDPtr(event.AssetID()),
			event.EventType().String(),
			last.Severity().String(),
			event.State().String(),
			last.Title(),
			nullString(last.Description()),
			details,
			event.Fingerprint(),
			event.Source(),
			row.firstSeen,
			row.lastSeen,
			nullTime(event.ResolvedAt()),
			nullIDPtr(event.ResolvedBy()),
			nullString(event.ResolutionNotes()),
			event.CreatedAt(),
			last.UpdatedAt(),
		)
	}

	query := fmt.Sprintf(`
		INSERT INTO exposure_events (
			id, tenant_id, asset_id, event_type, severity,
			state, title, description, details, fingerprint, source,
			first_seen_at, last_seen_at, resolved_at, resolved_by, resolution_notes,
			created_at, updated_at
		)
		VALUES %s
		ON CONFLICT (tenant_id, fingerprint) DO UPDATE SET
			last_seen_at = EXCLUDED.last_seen_at,
			updated_at = EXCLUDED.updated_at,
			-- Refresh the descriptive/severity fields on re-sighting: a re-scan
			-- can re-escalate an exposure (info -> critical) or reword it, and
			-- previously only the timestamps moved so the stored severity froze
			-- at its first-seen value.
			severity = EXCLUDED.severity,
			title = EXCLUDED.title,
			description = EXCLUDED.description,
			details = EXCLUDED.details
			-- state is deliberately NOT refreshed: preserve the existing
			-- (possibly user-resolved) state so a re-scan can't silently reopen
			-- a resolved exposure. Mirrors the findings upsert, which refreshes
			-- severity/scores but keeps the user-set status.
	`, strings.Join(valueStrings, ", "))

	return query, valueArgs, nil
}

// CountByState returns counts grouped by state for a tenant.
func (r *ExposureRepository) CountByState(ctx context.Context, tenantID shared.ID) (map[exposure.State]int64, error) {
	query := `
		SELECT state, COUNT(*) as count
		FROM exposure_events
		WHERE tenant_id = $1 AND ` + notOfDeletedAssetSQL("exposure_events.asset_id") + `
		GROUP BY state
	`

	rows, err := r.db.QueryContext(ctx, query, tenantID.String())
	if err != nil {
		return nil, fmt.Errorf("failed to count by state: %w", err)
	}
	defer rows.Close()

	result := make(map[exposure.State]int64)
	for rows.Next() {
		var stateStr string
		var count int64
		if err := rows.Scan(&stateStr, &count); err != nil {
			return nil, fmt.Errorf("failed to scan state count: %w", err)
		}
		state, _ := exposure.ParseState(stateStr)
		result[state] = count
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration error: %w", err)
	}

	return result, nil
}

// CountBySeverity returns counts grouped by severity for a tenant.
func (r *ExposureRepository) CountBySeverity(ctx context.Context, tenantID shared.ID) (map[exposure.Severity]int64, error) {
	query := `
		SELECT severity, COUNT(*) as count
		FROM exposure_events
		WHERE tenant_id = $1 AND ` + notOfDeletedAssetSQL("exposure_events.asset_id") + `
		GROUP BY severity
	`

	rows, err := r.db.QueryContext(ctx, query, tenantID.String())
	if err != nil {
		return nil, fmt.Errorf("failed to count by severity: %w", err)
	}
	defer rows.Close()

	result := make(map[exposure.Severity]int64)
	for rows.Next() {
		var severityStr string
		var count int64
		if err := rows.Scan(&severityStr, &count); err != nil {
			return nil, fmt.Errorf("failed to scan severity count: %w", err)
		}
		severity, _ := exposure.ParseSeverity(severityStr)
		result[severity] = count
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration error: %w", err)
	}

	return result, nil
}

// MeanTimeToResolveHours returns the average (resolved_at - first_seen_at) in
// hours across resolved events for a tenant. Returns ok=false when no resolved
// event has a resolved_at timestamp, so the caller can omit the metric.
func (r *ExposureRepository) MeanTimeToResolveHours(ctx context.Context, tenantID shared.ID) (float64, bool, error) {
	query := `
		SELECT AVG(EXTRACT(EPOCH FROM (resolved_at - first_seen_at)) / 3600.0)
		FROM exposure_events
		WHERE tenant_id = $1
		  AND state = $2
		  AND resolved_at IS NOT NULL
	`

	var avgHours sql.NullFloat64
	if err := r.db.QueryRowContext(ctx, query, tenantID.String(), exposure.StateResolved.String()).Scan(&avgHours); err != nil {
		return 0, false, fmt.Errorf("failed to compute mean time to resolve: %w", err)
	}

	if !avgHours.Valid {
		return 0, false, nil
	}

	return avgHours.Float64, true, nil
}

// Helper methods

func (r *ExposureRepository) selectQuery() string {
	return `
		SELECT id, tenant_id, asset_id, event_type, severity,
		       state, title, description, details, fingerprint, source,
		       first_seen_at, last_seen_at, resolved_at, resolved_by, resolution_notes,
		       created_at, updated_at
		FROM exposure_events
	`
}

func (r *ExposureRepository) scanExposureEvent(row *sql.Row, eventID shared.ID) (*exposure.ExposureEvent, error) {
	event, err := r.doScan(row.Scan)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, exposure.NewExposureEventNotFoundError(eventID.String())
		}
		return nil, fmt.Errorf("failed to scan exposure event: %w", err)
	}
	return event, nil
}

func (r *ExposureRepository) scanExposureEventFromRows(rows *sql.Rows) (*exposure.ExposureEvent, error) {
	return r.doScan(rows.Scan)
}

func (r *ExposureRepository) doScan(scan func(dest ...any) error) (*exposure.ExposureEvent, error) {
	var (
		idStr           string
		tenantIDStr     string
		assetIDStr      sql.NullString
		eventType       string
		severity        string
		state           string
		title           string
		description     sql.NullString
		details         []byte
		fingerprint     string
		source          string
		firstSeenAt     time.Time
		lastSeenAt      time.Time
		resolvedAt      sql.NullTime
		resolvedByStr   sql.NullString
		resolutionNotes sql.NullString
		createdAt       time.Time
		updatedAt       time.Time
	)

	err := scan(
		&idStr, &tenantIDStr, &assetIDStr, &eventType, &severity,
		&state, &title, &description, &details, &fingerprint, &source,
		&firstSeenAt, &lastSeenAt, &resolvedAt, &resolvedByStr, &resolutionNotes,
		&createdAt, &updatedAt,
	)
	if err != nil {
		return nil, err
	}

	parsedID, err := shared.IDFromString(idStr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse id: %w", err)
	}

	tenantID, err := shared.IDFromString(tenantIDStr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse tenant id: %w", err)
	}

	// canonicalAssetID := parseNullID(canonicalAssetIDStr) -> REMOVE LINE
	assetID := parseNullID(assetIDStr)
	parsedEventType, _ := exposure.ParseEventType(eventType)
	parsedSeverity, _ := exposure.ParseSeverity(severity)
	parsedState, _ := exposure.ParseState(state)
	resolvedBy := parseNullID(resolvedByStr)
	resolvedAtPtr := nullTimeValue(resolvedAt)

	var detailsMap map[string]any
	if len(details) > 0 {
		if err := json.Unmarshal(details, &detailsMap); err != nil {
			detailsMap = make(map[string]any)
		}
	}

	return exposure.Reconstitute(
		parsedID,
		tenantID,

		assetID,
		parsedEventType,
		parsedSeverity,
		parsedState,
		title,
		nullStringValue(description),
		detailsMap,
		fingerprint,
		source,
		firstSeenAt,
		lastSeenAt,
		resolvedAtPtr,
		resolvedBy,
		nullStringValue(resolutionNotes),
		createdAt,
		updatedAt,
	), nil
}

func (r *ExposureRepository) buildWhereClause(filter exposure.Filter) (string, []any) {
	// Exposures of a soft-deleted asset are history, not work: not listed.
	conditions := []string{notOfDeletedAssetSQL("exposure_events.asset_id")}
	var args []any
	argIndex := 1

	if filter.TenantID != nil && *filter.TenantID != "" {
		conditions = append(conditions, fmt.Sprintf("tenant_id = $%d", argIndex))
		args = append(args, *filter.TenantID)
		argIndex++
	}

	if filter.AssetID != nil && *filter.AssetID != "" {
		conditions = append(conditions, fmt.Sprintf("asset_id = $%d", argIndex))
		args = append(args, *filter.AssetID)
		argIndex++
	}

	if len(filter.EventTypes) > 0 {
		placeholders := make([]string, len(filter.EventTypes))
		for i, t := range filter.EventTypes {
			placeholders[i] = fmt.Sprintf("$%d", argIndex)
			args = append(args, t.String())
			argIndex++
		}
		conditions = append(conditions, fmt.Sprintf("event_type IN (%s)", strings.Join(placeholders, ", ")))
	}

	if len(filter.Severities) > 0 {
		placeholders := make([]string, len(filter.Severities))
		for i, s := range filter.Severities {
			placeholders[i] = fmt.Sprintf("$%d", argIndex)
			args = append(args, s.String())
			argIndex++
		}
		conditions = append(conditions, fmt.Sprintf("severity IN (%s)", strings.Join(placeholders, ", ")))
	}

	if len(filter.States) > 0 {
		placeholders := make([]string, len(filter.States))
		for i, s := range filter.States {
			placeholders[i] = fmt.Sprintf("$%d", argIndex)
			args = append(args, s.String())
			argIndex++
		}
		conditions = append(conditions, fmt.Sprintf("state IN (%s)", strings.Join(placeholders, ", ")))
	}

	if len(filter.Sources) > 0 {
		placeholders := make([]string, len(filter.Sources))
		for i, s := range filter.Sources {
			placeholders[i] = fmt.Sprintf("$%d", argIndex)
			args = append(args, s)
			argIndex++
		}
		conditions = append(conditions, fmt.Sprintf("source IN (%s)", strings.Join(placeholders, ", ")))
	}

	if filter.Search != nil && *filter.Search != "" {
		searchPattern := wrapLikePattern(*filter.Search)
		conditions = append(conditions, fmt.Sprintf("(title ILIKE $%d OR description ILIKE $%d)", argIndex, argIndex+1))
		args = append(args, searchPattern, searchPattern)
		argIndex += 2
	}

	if filter.FirstSeenAfter != nil {
		conditions = append(conditions, fmt.Sprintf("first_seen_at >= to_timestamp($%d)", argIndex))
		args = append(args, *filter.FirstSeenAfter)
		argIndex++
	}

	if filter.FirstSeenBefore != nil {
		conditions = append(conditions, fmt.Sprintf("first_seen_at <= to_timestamp($%d)", argIndex))
		args = append(args, *filter.FirstSeenBefore)
		argIndex++
	}

	if filter.LastSeenAfter != nil {
		conditions = append(conditions, fmt.Sprintf("last_seen_at >= to_timestamp($%d)", argIndex))
		args = append(args, *filter.LastSeenAfter)
		argIndex++
	}

	if filter.LastSeenBefore != nil {
		conditions = append(conditions, fmt.Sprintf("last_seen_at <= to_timestamp($%d)", argIndex))
		args = append(args, *filter.LastSeenBefore)
	}

	// Layer 2: a restricted member sees only exposures on in-scope assets
	// (an exposure with no asset is in nobody's asset scope).
	if filter.DataScope != nil {
		var cond string
		cond, args = dataScopeCond("asset_id", filter.DataScope, args)
		conditions = append(conditions, cond)
	}

	return strings.Join(conditions, " AND "), args
}

// exposureBatchRow is one fingerprint of a bulk upsert after folding.
type exposureBatchRow struct {
	first, last         *exposure.ExposureEvent
	firstSeen, lastSeen time.Time
}

// foldExposureBatch returns one row per (tenant, fingerprint), in order of
// first occurrence, keeping the earliest first-seen and the latest last-seen.
func foldExposureBatch(events []*exposure.ExposureEvent) []exposureBatchRow {
	index := make(map[string]int, len(events))
	rows := make([]exposureBatchRow, 0, len(events))
	for _, e := range events {
		k := e.TenantID().String() + "\x1f" + e.Fingerprint()
		i, ok := index[k]
		if !ok {
			index[k] = len(rows)
			rows = append(rows, exposureBatchRow{first: e, last: e, firstSeen: e.FirstSeenAt(), lastSeen: e.LastSeenAt()})
			continue
		}
		r := &rows[i]
		r.last = e
		if e.FirstSeenAt().Before(r.firstSeen) {
			r.firstSeen = e.FirstSeenAt()
		}
		if e.LastSeenAt().After(r.lastSeen) {
			r.lastSeen = e.LastSeenAt()
		}
	}
	return rows
}

// CountByStateAndSeverity counts the events a filter selects by state and by
// severity in one query (GROUPING SETS), for a stats card that used to send
// one COUNT per state and per severity.
func (r *ExposureRepository) CountByStateAndSeverity(ctx context.Context, filter exposure.Filter) (map[string]int64, map[string]int64, error) {
	// GROUPING(state) is 1 on the severity rows, so a NULL value can never be
	// taken for the other dimension.
	query := `SELECT GROUPING(state), COALESCE(state, ''), COALESCE(severity, ''), COUNT(*) FROM exposure_events`
	whereClause, args := r.buildWhereClause(filter)
	if whereClause != "" {
		query += " WHERE " + whereClause
	}
	query += ` GROUP BY GROUPING SETS ((state), (severity))`

	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to count exposure events by state and severity: %w", err)
	}
	defer rows.Close()

	byState := make(map[string]int64)
	bySeverity := make(map[string]int64)
	for rows.Next() {
		var severityRow int
		var state, severity string
		var n int64
		if err := rows.Scan(&severityRow, &state, &severity, &n); err != nil {
			return nil, nil, fmt.Errorf("failed to scan exposure counts: %w", err)
		}
		if severityRow == 1 {
			bySeverity[severity] = n
		} else {
			byState[state] = n
		}
	}
	if err := rows.Err(); err != nil {
		return nil, nil, fmt.Errorf("failed to read exposure counts: %w", err)
	}
	return byState, bySeverity, nil
}
