package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/domain/notification"
	"github.com/openctemio/api/pkg/pagination"
)

// NotificationRepository implements notification.Repository.
type NotificationRepository struct {
	db *DB
}

// NewNotificationRepository creates a new notification repository.
func NewNotificationRepository(db *DB) *NotificationRepository {
	return &NotificationRepository{db: db}
}

// Create inserts a new notification.
func (r *NotificationRepository) Create(ctx context.Context, n *notification.Notification) error {
	query := `
		INSERT INTO notifications (id, tenant_id, audience, audience_id, notification_type, title, body, severity, resource_type, resource_id, url, actor_id, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)`

	var audienceID, resourceID, actorID *string
	if n.AudienceID() != nil {
		s := n.AudienceID().String()
		audienceID = &s
	}
	if n.ResourceID() != nil {
		s := n.ResourceID().String()
		resourceID = &s
	}
	if n.ActorID() != nil {
		s := n.ActorID().String()
		actorID = &s
	}

	_, err := r.db.ExecContext(ctx, query,
		n.ID(),
		n.TenantID(),
		n.Audience(),
		audienceID,
		n.NotificationType(),
		n.Title(),
		n.Body(),
		n.Severity(),
		n.ResourceType(),
		resourceID,
		n.URL(),
		actorID,
		n.CreatedAt(),
	)
	if err != nil {
		return fmt.Errorf("failed to create notification: %w", err)
	}
	return nil
}

// List returns notifications visible to a user with audience filtering and read status.
// Uses COUNT(*) OVER() window function to get total count in a single query.
// Group membership is resolved via subquery to avoid an extra DB roundtrip.
func (r *NotificationRepository) List(
	ctx context.Context,
	tenantID, userID shared.ID,
	filter notification.ListFilter,
	page pagination.Pagination,
) (pagination.Result[*notification.Notification], error) {
	var result pagination.Result[*notification.Notification]

	// Build WHERE clause
	where, args := r.buildWhereClause(tenantID, userID, filter)

	// Single query with COUNT(*) OVER() to avoid a separate count query.
	query := `
		SELECT
			n.id, n.tenant_id, n.audience, n.audience_id,
			n.notification_type, n.title, n.body, n.severity,
			n.resource_type, n.resource_id, n.url,
			n.actor_id, n.created_at,
			(nr.notification_id IS NOT NULL OR n.created_at <= COALESCE(ns.last_read_all_at, '-infinity'::timestamptz)) AS is_read,
			COUNT(*) OVER() AS total_count
		FROM notifications n
		LEFT JOIN notification_reads nr ON nr.notification_id = n.id AND nr.user_id = $2
		LEFT JOIN notification_state ns ON ns.tenant_id = $1 AND ns.user_id = $2
		` + where + `
		ORDER BY n.created_at DESC
		LIMIT $` + fmt.Sprintf("%d", len(args)+1) + ` OFFSET $` + fmt.Sprintf("%d", len(args)+2)

	args = append(args, page.PerPage, (page.Page-1)*page.PerPage)

	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return result, fmt.Errorf("failed to list notifications: %w", err)
	}
	defer rows.Close()

	var total int
	items := make([]*notification.Notification, 0, page.PerPage)
	for rows.Next() {
		n, totalCount, err := r.scanNotificationWithTotal(rows)
		if err != nil {
			return result, fmt.Errorf("failed to scan notification: %w", err)
		}
		items = append(items, n)
		total = totalCount
	}
	if err := rows.Err(); err != nil {
		return result, fmt.Errorf("notification rows error: %w", err)
	}

	if items == nil {
		items = make([]*notification.Notification, 0)
	}

	result.Data = items
	result.Total = int64(total)
	result.Page = page.Page
	result.PerPage = page.PerPage
	result.TotalPages = (total + page.PerPage - 1) / page.PerPage
	return result, nil
}

// UnreadCount returns the count of unread notifications for a user.
// Group membership is resolved via subquery to avoid an extra DB roundtrip.
func (r *NotificationRepository) UnreadCount(
	ctx context.Context,
	tenantID, userID shared.ID,
) (int, error) {
	audienceClause := r.buildAudienceClause()
	args := []any{tenantID, userID}

	query := `
		SELECT COUNT(*)
		FROM notifications n
		LEFT JOIN notification_reads nr ON nr.notification_id = n.id AND nr.user_id = $2
		LEFT JOIN notification_state ns ON ns.tenant_id = $1 AND ns.user_id = $2
		WHERE n.tenant_id = $1
		  AND n.created_at > COALESCE(ns.last_read_all_at, '-infinity'::timestamptz)
		  AND nr.notification_id IS NULL
		  AND n.created_at > NOW() - INTERVAL '30 days'
		  AND (` + audienceClause + `)`

	var count int
	if err := r.db.QueryRowContext(ctx, query, args...).Scan(&count); err != nil {
		return 0, fmt.Errorf("failed to count unread notifications: %w", err)
	}
	return count, nil
}

// MarkAsRead marks a single notification as read, verifying tenant ownership.
func (r *NotificationRepository) MarkAsRead(ctx context.Context, tenantID shared.ID, notificationID notification.ID, userID shared.ID) error {
	query := `
		INSERT INTO notification_reads (notification_id, user_id)
		SELECT $1, $2
		FROM notifications
		WHERE id = $1 AND tenant_id = $3
		ON CONFLICT DO NOTHING`

	result, err := r.db.ExecContext(ctx, query, notificationID.String(), userID.String(), tenantID.String())
	if err != nil {
		return fmt.Errorf("mark notification as read: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("get rows affected: %w", err)
	}
	if rows == 0 {
		return notification.ErrNotificationNotFound
	}
	return nil
}

// MarkAllAsRead updates the watermark for a user.
func (r *NotificationRepository) MarkAllAsRead(ctx context.Context, tenantID, userID shared.ID) error {
	query := `
		INSERT INTO notification_state (tenant_id, user_id, last_read_all_at)
		VALUES ($1, $2, NOW())
		ON CONFLICT (tenant_id, user_id)
		DO UPDATE SET last_read_all_at = NOW()`

	_, err := r.db.ExecContext(ctx, query, tenantID, userID)
	if err != nil {
		return fmt.Errorf("failed to mark all as read: %w", err)
	}
	return nil
}

// DeleteOlderThan removes old notifications.
func (r *NotificationRepository) DeleteOlderThan(ctx context.Context, age time.Duration) (int64, error) {
	query := `DELETE FROM notifications WHERE created_at < NOW() - $1::interval`

	res, err := r.db.ExecContext(ctx, query, fmt.Sprintf("%d seconds", int(age.Seconds())))
	if err != nil {
		return 0, fmt.Errorf("failed to delete old notifications: %w", err)
	}
	return res.RowsAffected()
}

// GetPreferences returns user notification preferences.
func (r *NotificationRepository) GetPreferences(ctx context.Context, tenantID, userID shared.ID) (*notification.Preferences, error) {
	query := `
		SELECT tenant_id, user_id, in_app_enabled, email_digest, muted_types, min_severity, updated_at
		FROM notification_preferences
		WHERE tenant_id = $1 AND user_id = $2`

	var (
		tID, uID       shared.ID
		inAppEnabled   bool
		emailDigest    string
		mutedTypesJSON sql.NullString
		minSeverity    sql.NullString
		updatedAt      time.Time
	)

	err := r.db.QueryRowContext(ctx, query, tenantID, userID).Scan(
		&tID, &uID, &inAppEnabled, &emailDigest, &mutedTypesJSON, &minSeverity, &updatedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return notification.DefaultPreferences(tenantID, userID), nil
		}
		return nil, fmt.Errorf("failed to get preferences: %w", err)
	}

	var mutedTypes []string
	if mutedTypesJSON.Valid && mutedTypesJSON.String != "" {
		if err := json.Unmarshal([]byte(mutedTypesJSON.String), &mutedTypes); err != nil {
			mutedTypes = nil
		}
	}

	return notification.ReconstitutePref(tID, uID, inAppEnabled, emailDigest, mutedTypes, minSeverity.String, updatedAt), nil
}

// UpsertPreferences creates or updates notification preferences.
func (r *NotificationRepository) UpsertPreferences(
	ctx context.Context,
	tenantID, userID shared.ID,
	params notification.PreferencesParams,
) (*notification.Preferences, error) {
	var mutedTypesJSON *string
	if params.MutedTypes != nil {
		b, err := json.Marshal(params.MutedTypes)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal muted_types: %w", err)
		}
		s := string(b)
		mutedTypesJSON = &s
	}

	var minSev *string
	if params.MinSeverity != "" {
		minSev = &params.MinSeverity
	}

	query := `
		INSERT INTO notification_preferences (tenant_id, user_id, in_app_enabled, email_digest, muted_types, min_severity, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, NOW())
		ON CONFLICT (tenant_id, user_id)
		DO UPDATE SET
			in_app_enabled = $3,
			email_digest = $4,
			muted_types = $5,
			min_severity = $6,
			updated_at = NOW()
		RETURNING tenant_id, user_id, in_app_enabled, email_digest, muted_types, min_severity, updated_at`

	var (
		tID, uID         shared.ID
		inAppEnabled     bool
		emailDigest      string
		retMutedTypesJSON sql.NullString
		retMinSeverity   sql.NullString
		updatedAt        time.Time
	)

	err := r.db.QueryRowContext(ctx, query, tenantID, userID, params.InAppEnabled, params.EmailDigest, mutedTypesJSON, minSev).Scan(
		&tID, &uID, &inAppEnabled, &emailDigest, &retMutedTypesJSON, &retMinSeverity, &updatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to upsert preferences: %w", err)
	}

	var retMutedTypes []string
	if retMutedTypesJSON.Valid && retMutedTypesJSON.String != "" {
		if jsonErr := json.Unmarshal([]byte(retMutedTypesJSON.String), &retMutedTypes); jsonErr != nil {
			retMutedTypes = nil
		}
	}

	return notification.ReconstitutePref(tID, uID, inAppEnabled, emailDigest, retMutedTypes, retMinSeverity.String, updatedAt), nil
}

// ============================================
// HELPERS
// ============================================

// buildAudienceClause returns the audience filtering SQL fragment using a subquery
// for group membership. This eliminates a separate DB roundtrip to fetch group IDs.
// Expects $1 = tenantID and $2 = userID in the query args.
func (r *NotificationRepository) buildAudienceClause() string {
	return `n.audience = 'all'` +
		` OR (n.audience = 'user' AND n.audience_id = $2)` +
		` OR (n.audience = 'group' AND n.audience_id IN (` +
		`SELECT g.id FROM groups g ` +
		`INNER JOIN group_members gm ON gm.group_id = g.id ` +
		`WHERE g.tenant_id = $1 AND gm.user_id = $2 AND g.is_active = true` +
		`))`
}

func (r *NotificationRepository) buildWhereClause(tenantID, userID shared.ID, filter notification.ListFilter) (string, []any) {
	args := []any{tenantID, userID}
	audienceClause := r.buildAudienceClause()

	where := `WHERE n.tenant_id = $1 AND n.created_at > NOW() - INTERVAL '30 days' AND (` + audienceClause + `)`

	if filter.Severity != "" {
		args = append(args, filter.Severity)
		where += fmt.Sprintf(" AND n.severity = $%d", len(args))
	}

	if filter.Type != "" {
		args = append(args, filter.Type)
		where += fmt.Sprintf(" AND n.notification_type = $%d", len(args))
	}

	if filter.IsRead != nil {
		if *filter.IsRead {
			where += " AND (nr.notification_id IS NOT NULL OR n.created_at <= COALESCE(ns.last_read_all_at, '-infinity'::timestamptz))"
		} else {
			where += " AND nr.notification_id IS NULL AND n.created_at > COALESCE(ns.last_read_all_at, '-infinity'::timestamptz)"
		}
	}

	return where, args
}

// rowScanner interface for scanning from both *sql.Row and *sql.Rows
type notifRowScanner interface {
	Scan(dest ...any) error
}

func (r *NotificationRepository) scanNotificationWithTotal(scanner notifRowScanner) (*notification.Notification, int, error) {
	var (
		id               shared.ID
		tenantID         shared.ID
		audience         string
		audienceIDStr    sql.NullString
		notificationType string
		title            string
		body             sql.NullString
		severity         string
		resourceType     sql.NullString
		resourceIDStr    sql.NullString
		url              sql.NullString
		actorIDStr       sql.NullString
		createdAt        time.Time
		isRead           bool
		totalCount       int
	)

	err := scanner.Scan(
		&id, &tenantID, &audience, &audienceIDStr,
		&notificationType, &title, &body, &severity,
		&resourceType, &resourceIDStr, &url,
		&actorIDStr, &createdAt, &isRead, &totalCount,
	)
	if err != nil {
		return nil, 0, err
	}

	var audienceID, resourceID, actorID *shared.ID
	if audienceIDStr.Valid {
		parsed, parseErr := shared.IDFromString(audienceIDStr.String)
		if parseErr == nil {
			audienceID = &parsed
		}
	}
	if resourceIDStr.Valid {
		parsed, parseErr := shared.IDFromString(resourceIDStr.String)
		if parseErr == nil {
			resourceID = &parsed
		}
	}
	if actorIDStr.Valid {
		parsed, parseErr := shared.IDFromString(actorIDStr.String)
		if parseErr == nil {
			actorID = &parsed
		}
	}

	return notification.Reconstitute(
		id, tenantID, audience, audienceID,
		notificationType, title, body.String, severity,
		resourceType.String, resourceID, url.String,
		actorID, createdAt, isRead,
	), totalCount, nil
}

