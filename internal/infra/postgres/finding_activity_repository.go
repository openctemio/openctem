package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/domain/vulnerability"
	"github.com/openctemio/api/pkg/pagination"
)

// maxPageLimit is the maximum allowed page size for activity queries.
// Security: Prevents DoS attacks via large page sizes.
const maxPageLimit = 100

// countActivitiesQuery is the base count query for finding activities.
const countActivitiesQuery = `SELECT COUNT(*) FROM finding_activities fa`

// FindingActivityRepository handles finding activity persistence.
// This repository is APPEND-ONLY - it does not support Update or Delete operations.
type FindingActivityRepository struct {
	db *DB
}

// NewFindingActivityRepository creates a new FindingActivityRepository.
func NewFindingActivityRepository(db *DB) *FindingActivityRepository {
	return &FindingActivityRepository{db: db}
}

// Create persists a new finding activity.
func (r *FindingActivityRepository) Create(ctx context.Context, activity *vulnerability.FindingActivity) error {
	changesJSON, err := json.Marshal(activity.Changes())
	if err != nil {
		return fmt.Errorf("failed to marshal changes: %w", err)
	}

	var sourceMetadataJSON []byte
	if activity.SourceMetadata() != nil && len(activity.SourceMetadata()) > 0 {
		sourceMetadataJSON, err = json.Marshal(activity.SourceMetadata())
		if err != nil {
			return fmt.Errorf("failed to marshal source metadata: %w", err)
		}
	}

	query := `
		INSERT INTO finding_activities (
			id, tenant_id, finding_id,
			activity_type, actor_id, actor_type,
			changes, source, source_metadata,
			created_at
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
	`

	var actorIDStr sql.NullString
	if activity.ActorID() != nil {
		actorIDStr = sql.NullString{String: activity.ActorID().String(), Valid: true}
	}

	_, err = r.db.ExecContext(ctx, query,
		activity.ID().String(),
		activity.TenantID().String(),
		activity.FindingID().String(),
		string(activity.ActivityType()),
		actorIDStr,
		string(activity.ActorType()),
		changesJSON,
		nullString(string(activity.Source())),
		nullBytes(sourceMetadataJSON),
		activity.CreatedAt(),
	)

	if err != nil {
		return fmt.Errorf("failed to create finding activity: %w", err)
	}

	return nil
}

// GetByID retrieves an activity by ID.
func (r *FindingActivityRepository) GetByID(ctx context.Context, id shared.ID) (*vulnerability.FindingActivity, error) {
	query := r.selectQuery() + " WHERE fa.id = $1"
	row := r.db.QueryRowContext(ctx, query, id.String())
	return r.scanActivity(row)
}

// ListByFinding retrieves activities for a finding with pagination.
// Security: tenantID is required to prevent cross-tenant data access.
func (r *FindingActivityRepository) ListByFinding(
	ctx context.Context,
	findingID shared.ID,
	tenantID shared.ID, // Security: Required for tenant isolation
	filter vulnerability.FindingActivityFilter,
	page pagination.Pagination,
) (pagination.Result[*vulnerability.FindingActivity], error) {
	baseQuery := r.selectQuery()
	countQuery := countActivitiesQuery

	whereClause, args := r.buildWhereClause(filter, findingID, tenantID)

	if whereClause != "" {
		baseQuery += " WHERE " + whereClause
		countQuery += " WHERE " + whereClause
	}

	// Always order by created_at DESC (newest first)
	baseQuery += " ORDER BY fa.created_at DESC"

	// Security: Enforce maximum limit to prevent DoS
	limit := page.Limit()
	if limit > maxPageLimit {
		limit = maxPageLimit
	}
	baseQuery += fmt.Sprintf(" LIMIT %d OFFSET %d", limit, page.Offset())

	// Get total count
	var total int64
	err := r.db.QueryRowContext(ctx, countQuery, args...).Scan(&total)
	if err != nil {
		return pagination.Result[*vulnerability.FindingActivity]{}, fmt.Errorf("failed to count activities: %w", err)
	}

	// Get activities
	rows, err := r.db.QueryContext(ctx, baseQuery, args...)
	if err != nil {
		return pagination.Result[*vulnerability.FindingActivity]{}, fmt.Errorf("failed to query activities: %w", err)
	}
	defer rows.Close()

	var activities []*vulnerability.FindingActivity
	for rows.Next() {
		activity, err := r.scanActivityFromRows(rows)
		if err != nil {
			return pagination.Result[*vulnerability.FindingActivity]{}, err
		}
		activities = append(activities, activity)
	}

	if err := rows.Err(); err != nil {
		return pagination.Result[*vulnerability.FindingActivity]{}, fmt.Errorf("failed to iterate activities: %w", err)
	}

	return pagination.NewResult(activities, total, page), nil
}

// CountByFinding counts activities for a finding.
// Security: tenantID is required to ensure tenant isolation.
func (r *FindingActivityRepository) CountByFinding(
	ctx context.Context,
	findingID shared.ID,
	tenantID shared.ID,
	filter vulnerability.FindingActivityFilter,
) (int64, error) {
	query := countActivitiesQuery

	whereClause, args := r.buildWhereClause(filter, findingID, tenantID)
	if whereClause != "" {
		query += " WHERE " + whereClause
	}

	var count int64
	err := r.db.QueryRowContext(ctx, query, args...).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("failed to count activities: %w", err)
	}

	return count, nil
}

// ListByTenant retrieves activities for a tenant with pagination.
func (r *FindingActivityRepository) ListByTenant(
	ctx context.Context,
	tenantID shared.ID,
	filter vulnerability.FindingActivityFilter,
	page pagination.Pagination,
) (pagination.Result[*vulnerability.FindingActivity], error) {
	baseQuery := r.selectQuery()
	countQuery := countActivitiesQuery

	whereClause, args := r.buildTenantWhereClause(filter, tenantID)

	if whereClause != "" {
		baseQuery += " WHERE " + whereClause
		countQuery += " WHERE " + whereClause
	}

	// Always order by created_at DESC (newest first)
	baseQuery += " ORDER BY fa.created_at DESC"

	// Security: Enforce maximum limit to prevent DoS
	limit := page.Limit()
	if limit > maxPageLimit {
		limit = maxPageLimit
	}
	baseQuery += fmt.Sprintf(" LIMIT %d OFFSET %d", limit, page.Offset())

	// Get total count
	var total int64
	err := r.db.QueryRowContext(ctx, countQuery, args...).Scan(&total)
	if err != nil {
		return pagination.Result[*vulnerability.FindingActivity]{}, fmt.Errorf("failed to count activities: %w", err)
	}

	// Get activities
	rows, err := r.db.QueryContext(ctx, baseQuery, args...)
	if err != nil {
		return pagination.Result[*vulnerability.FindingActivity]{}, fmt.Errorf("failed to query activities: %w", err)
	}
	defer rows.Close()

	var activities []*vulnerability.FindingActivity
	for rows.Next() {
		activity, err := r.scanActivityFromRows(rows)
		if err != nil {
			return pagination.Result[*vulnerability.FindingActivity]{}, err
		}
		activities = append(activities, activity)
	}

	if err := rows.Err(); err != nil {
		return pagination.Result[*vulnerability.FindingActivity]{}, fmt.Errorf("failed to iterate activities: %w", err)
	}

	return pagination.NewResult(activities, total, page), nil
}

// Helper methods

func (r *FindingActivityRepository) selectQuery() string {
	return `
		SELECT fa.id, fa.tenant_id, fa.finding_id,
			fa.activity_type, fa.actor_id, fa.actor_type,
			COALESCE(u.name, '') as actor_name,
			COALESCE(u.email, '') as actor_email,
			fa.changes, fa.source, fa.source_metadata,
			fa.created_at
		FROM finding_activities fa
		LEFT JOIN users u ON fa.actor_id = u.id
	`
}

func (r *FindingActivityRepository) scanActivity(row *sql.Row) (*vulnerability.FindingActivity, error) {
	activity, err := r.doScan(row.Scan)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("activity not found")
		}
		return nil, fmt.Errorf("failed to scan finding activity: %w", err)
	}
	return activity, nil
}

func (r *FindingActivityRepository) scanActivityFromRows(rows *sql.Rows) (*vulnerability.FindingActivity, error) {
	return r.doScan(rows.Scan)
}

func (r *FindingActivityRepository) doScan(scan func(dest ...any) error) (*vulnerability.FindingActivity, error) {
	var (
		idStr              string
		tenantIDStr        string
		findingIDStr       string
		activityType       string
		actorIDStr         sql.NullString
		actorType          string
		actorName          string
		actorEmail         string
		changesJSON        []byte
		source             sql.NullString
		sourceMetadataJSON []byte
		createdAt          time.Time
	)

	err := scan(
		&idStr, &tenantIDStr, &findingIDStr,
		&activityType, &actorIDStr, &actorType,
		&actorName, &actorEmail,
		&changesJSON, &source, &sourceMetadataJSON,
		&createdAt,
	)
	if err != nil {
		return nil, err
	}

	id, err := shared.IDFromString(idStr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse id: %w", err)
	}

	tenantID, err := shared.IDFromString(tenantIDStr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse tenant id: %w", err)
	}

	findingID, err := shared.IDFromString(findingIDStr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse finding id: %w", err)
	}

	var actorID *shared.ID
	if actorIDStr.Valid {
		aid, err := shared.IDFromString(actorIDStr.String)
		if err != nil {
			return nil, fmt.Errorf("failed to parse actor id: %w", err)
		}
		actorID = &aid
	}

	var changes map[string]interface{}
	if len(changesJSON) > 0 {
		if err := json.Unmarshal(changesJSON, &changes); err != nil {
			return nil, fmt.Errorf("failed to unmarshal changes: %w", err)
		}
	}

	var sourceMetadata map[string]interface{}
	if len(sourceMetadataJSON) > 0 {
		if err := json.Unmarshal(sourceMetadataJSON, &sourceMetadata); err != nil {
			return nil, fmt.Errorf("failed to unmarshal source metadata: %w", err)
		}
	}

	return vulnerability.ReconstituteFindingActivity(
		id,
		tenantID,
		findingID,
		vulnerability.ActivityType(activityType),
		actorID,
		vulnerability.ActorType(actorType),
		actorName,
		actorEmail,
		changes,
		vulnerability.ActivitySource(source.String),
		sourceMetadata,
		createdAt,
	), nil
}

func (r *FindingActivityRepository) buildWhereClause(filter vulnerability.FindingActivityFilter, findingID shared.ID, tenantID shared.ID) (string, []any) {
	var conditions []string
	var args []any
	argIndex := 1

	// Security: Always filter by tenant_id first to ensure tenant isolation
	conditions = append(conditions, fmt.Sprintf("fa.tenant_id = $%d", argIndex))
	args = append(args, tenantID.String())
	argIndex++

	// Always filter by finding_id
	conditions = append(conditions, fmt.Sprintf("fa.finding_id = $%d", argIndex))
	args = append(args, findingID.String())
	argIndex++

	// Filter by activity types
	if len(filter.ActivityTypes) > 0 {
		placeholders := make([]string, len(filter.ActivityTypes))
		for i, t := range filter.ActivityTypes {
			placeholders[i] = fmt.Sprintf("$%d", argIndex)
			args = append(args, string(t))
			argIndex++
		}
		conditions = append(conditions, fmt.Sprintf("fa.activity_type IN (%s)", strings.Join(placeholders, ", ")))
	}

	// Filter by actor types
	if len(filter.ActorTypes) > 0 {
		placeholders := make([]string, len(filter.ActorTypes))
		for i, at := range filter.ActorTypes {
			placeholders[i] = fmt.Sprintf("$%d", argIndex)
			args = append(args, string(at))
			argIndex++
		}
		conditions = append(conditions, fmt.Sprintf("fa.actor_type IN (%s)", strings.Join(placeholders, ", ")))
	}

	// Filter by actor IDs
	if len(filter.ActorIDs) > 0 {
		placeholders := make([]string, len(filter.ActorIDs))
		for i, aid := range filter.ActorIDs {
			placeholders[i] = fmt.Sprintf("$%d", argIndex)
			args = append(args, aid.String())
			argIndex++
		}
		conditions = append(conditions, fmt.Sprintf("fa.actor_id IN (%s)", strings.Join(placeholders, ", ")))
	}

	// Filter by sources
	if len(filter.Sources) > 0 {
		placeholders := make([]string, len(filter.Sources))
		for i, s := range filter.Sources {
			placeholders[i] = fmt.Sprintf("$%d", argIndex)
			args = append(args, string(s))
			argIndex++
		}
		conditions = append(conditions, fmt.Sprintf("fa.source IN (%s)", strings.Join(placeholders, ", ")))
	}

	// Filter by time range
	if filter.Since != nil {
		conditions = append(conditions, fmt.Sprintf("fa.created_at >= $%d", argIndex))
		args = append(args, *filter.Since)
		argIndex++
	}

	if filter.Until != nil {
		conditions = append(conditions, fmt.Sprintf("fa.created_at <= $%d", argIndex))
		args = append(args, *filter.Until)
		argIndex++
	}

	return strings.Join(conditions, " AND "), args
}

func (r *FindingActivityRepository) buildTenantWhereClause(filter vulnerability.FindingActivityFilter, tenantID shared.ID) (string, []any) {
	var conditions []string
	var args []any
	argIndex := 1

	// Always filter by tenant_id
	conditions = append(conditions, fmt.Sprintf("fa.tenant_id = $%d", argIndex))
	args = append(args, tenantID.String())
	argIndex++

	// Filter by activity types
	if len(filter.ActivityTypes) > 0 {
		placeholders := make([]string, len(filter.ActivityTypes))
		for i, t := range filter.ActivityTypes {
			placeholders[i] = fmt.Sprintf("$%d", argIndex)
			args = append(args, string(t))
			argIndex++
		}
		conditions = append(conditions, fmt.Sprintf("fa.activity_type IN (%s)", strings.Join(placeholders, ", ")))
	}

	// Filter by actor types
	if len(filter.ActorTypes) > 0 {
		placeholders := make([]string, len(filter.ActorTypes))
		for i, at := range filter.ActorTypes {
			placeholders[i] = fmt.Sprintf("$%d", argIndex)
			args = append(args, string(at))
			argIndex++
		}
		conditions = append(conditions, fmt.Sprintf("fa.actor_type IN (%s)", strings.Join(placeholders, ", ")))
	}

	// Filter by actor IDs
	if len(filter.ActorIDs) > 0 {
		placeholders := make([]string, len(filter.ActorIDs))
		for i, aid := range filter.ActorIDs {
			placeholders[i] = fmt.Sprintf("$%d", argIndex)
			args = append(args, aid.String())
			argIndex++
		}
		conditions = append(conditions, fmt.Sprintf("fa.actor_id IN (%s)", strings.Join(placeholders, ", ")))
	}

	// Filter by sources
	if len(filter.Sources) > 0 {
		placeholders := make([]string, len(filter.Sources))
		for i, s := range filter.Sources {
			placeholders[i] = fmt.Sprintf("$%d", argIndex)
			args = append(args, string(s))
			argIndex++
		}
		conditions = append(conditions, fmt.Sprintf("fa.source IN (%s)", strings.Join(placeholders, ", ")))
	}

	// Filter by time range
	if filter.Since != nil {
		conditions = append(conditions, fmt.Sprintf("fa.created_at >= $%d", argIndex))
		args = append(args, *filter.Since)
		argIndex++
	}

	if filter.Until != nil {
		conditions = append(conditions, fmt.Sprintf("fa.created_at <= $%d", argIndex))
		args = append(args, *filter.Until)
		argIndex++
	}

	return strings.Join(conditions, " AND "), args
}
