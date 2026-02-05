package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/openctemio/api/pkg/domain/admin"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/pagination"
)

// =============================================================================
// Admin User Repository
// =============================================================================

// AdminRepository implements admin.Repository using PostgreSQL.
type AdminRepository struct {
	db *DB
}

// NewAdminRepository creates a new AdminRepository.
func NewAdminRepository(db *DB) *AdminRepository {
	return &AdminRepository{db: db}
}

func (r *AdminRepository) selectQuery() string {
	return `
		SELECT id, email, name, api_key_hash, api_key_prefix,
		       role, is_active, last_used_at, last_used_ip,
		       failed_login_count, locked_until, last_failed_login_at, last_failed_login_ip,
		       created_at, created_by, updated_at
		FROM admin_users
	`
}

// Create creates a new admin user.
func (r *AdminRepository) Create(ctx context.Context, a *admin.AdminUser) error {
	query := `
		INSERT INTO admin_users (
			id, email, name, api_key_hash, api_key_prefix,
			role, is_active, created_at, created_by, updated_at
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
	`

	_, err := r.db.ExecContext(ctx, query,
		a.ID().String(),
		a.Email(),
		a.Name(),
		a.APIKeyHash(),
		a.APIKeyPrefix(),
		string(a.Role()),
		a.IsActive(),
		a.CreatedAt(),
		nullIDString(a.CreatedBy()),
		a.UpdatedAt(),
	)

	if err != nil {
		if isUniqueViolation(err) {
			return admin.ErrAdminAlreadyExists
		}
		return fmt.Errorf("failed to create admin user: %w", err)
	}

	return nil
}

// GetByID retrieves an admin user by ID.
func (r *AdminRepository) GetByID(ctx context.Context, id shared.ID) (*admin.AdminUser, error) {
	query := r.selectQuery() + " WHERE id = $1"
	row := r.db.QueryRowContext(ctx, query, id.String())
	return r.scanAdmin(row)
}

// GetByEmail retrieves an admin user by email.
func (r *AdminRepository) GetByEmail(ctx context.Context, email string) (*admin.AdminUser, error) {
	query := r.selectQuery() + " WHERE LOWER(email) = LOWER($1)"
	row := r.db.QueryRowContext(ctx, query, email)
	return r.scanAdmin(row)
}

// GetByAPIKeyPrefix retrieves an admin user by API key prefix.
func (r *AdminRepository) GetByAPIKeyPrefix(ctx context.Context, prefix string) (*admin.AdminUser, error) {
	query := r.selectQuery() + " WHERE api_key_prefix = $1 AND is_active = TRUE"
	row := r.db.QueryRowContext(ctx, query, prefix)
	return r.scanAdmin(row)
}

// List lists admin users with filters and pagination.
func (r *AdminRepository) List(ctx context.Context, filter admin.Filter, page pagination.Pagination) (pagination.Result[*admin.AdminUser], error) {
	var result pagination.Result[*admin.AdminUser]

	baseQuery := r.selectQuery()
	countQuery := "SELECT COUNT(*) FROM admin_users"
	whereClause, args := r.buildWhereClause(filter)

	if whereClause != "" {
		baseQuery += " WHERE " + whereClause
		countQuery += " WHERE " + whereClause
	}

	// Get total count
	var total int64
	err := r.db.QueryRowContext(ctx, countQuery, args...).Scan(&total)
	if err != nil {
		return result, fmt.Errorf("failed to count admin users: %w", err)
	}

	// Apply pagination
	offset := (page.Page - 1) * page.PerPage
	baseQuery += fmt.Sprintf(" ORDER BY created_at DESC LIMIT %d OFFSET %d", page.PerPage, offset)

	rows, err := r.db.QueryContext(ctx, baseQuery, args...)
	if err != nil {
		return result, fmt.Errorf("failed to list admin users: %w", err)
	}
	defer rows.Close()

	var admins []*admin.AdminUser
	for rows.Next() {
		a, err := r.scanAdminFromRows(rows)
		if err != nil {
			return result, err
		}
		admins = append(admins, a)
	}

	if err := rows.Err(); err != nil {
		return result, fmt.Errorf("error iterating admin users: %w", err)
	}

	return pagination.NewResult(admins, total, page), nil
}

// Update updates an admin user.
func (r *AdminRepository) Update(ctx context.Context, a *admin.AdminUser) error {
	query := `
		UPDATE admin_users
		SET email = $2, name = $3, api_key_hash = $4, api_key_prefix = $5,
		    role = $6, is_active = $7, last_used_at = $8, last_used_ip = $9,
		    failed_login_count = $10, locked_until = $11,
		    last_failed_login_at = $12, last_failed_login_ip = $13,
		    updated_at = $14
		WHERE id = $1
	`

	result, err := r.db.ExecContext(ctx, query,
		a.ID().String(),
		a.Email(),
		a.Name(),
		a.APIKeyHash(),
		a.APIKeyPrefix(),
		string(a.Role()),
		a.IsActive(),
		nullTime(a.LastUsedAt()),
		nullString(a.LastUsedIP()),
		a.FailedLoginCount(),
		nullTime(a.LockedUntil()),
		nullTime(a.LastFailedLoginAt()),
		nullString(a.LastFailedLoginIP()),
		time.Now(),
	)

	if err != nil {
		if isUniqueViolation(err) {
			return admin.ErrAdminAlreadyExists
		}
		return fmt.Errorf("failed to update admin user: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return admin.ErrAdminNotFound
	}

	return nil
}

// Delete deletes an admin user.
func (r *AdminRepository) Delete(ctx context.Context, id shared.ID) error {
	query := "DELETE FROM admin_users WHERE id = $1"

	result, err := r.db.ExecContext(ctx, query, id.String())
	if err != nil {
		return fmt.Errorf("failed to delete admin user: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return admin.ErrAdminNotFound
	}

	return nil
}

// =============================================================================
// Authentication
// =============================================================================

// ErrAccountLocked is returned when the admin account is locked due to too many failed login attempts.
var ErrAccountLocked = errors.New("account is locked due to too many failed login attempts")

// AuthenticateByAPIKey authenticates an admin user by raw API key.
// Implements SEC-H01: Rate limiting via account lockout after failed attempts.
func (r *AdminRepository) AuthenticateByAPIKey(ctx context.Context, rawKey string) (*admin.AdminUser, error) {
	// Extract prefix for lookup
	prefix := admin.ExtractAPIKeyPrefix(rawKey)
	if prefix == "" {
		return nil, admin.ErrInvalidAPIKey
	}

	// Look up admin by prefix (fast indexed lookup)
	// Note: GetByAPIKeyPrefix only returns active admins, but we need to check
	// locked status, so we use a modified query that includes locked accounts
	a, err := r.getByAPIKeyPrefixIncludingLocked(ctx, prefix)
	if err != nil {
		if admin.IsAdminNotFound(err) {
			return nil, admin.ErrInvalidAPIKey
		}
		return nil, err
	}

	// Check if account is locked before verifying password (prevents timing attacks)
	if a.IsLocked() {
		return nil, ErrAccountLocked
	}

	// Verify full hash using bcrypt (constant-time by design)
	if !a.VerifyAPIKey(rawKey) {
		// Record failed login attempt
		a.RecordFailedLogin("")
		// Update in database (async to not block response)
		go func() {
			// Use a new context since the original may be cancelled
			updateCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = r.Update(updateCtx, a)
		}()
		return nil, admin.ErrInvalidAPIKey
	}

	// Check if admin is active
	if !a.IsActive() {
		return nil, admin.ErrAdminInactive
	}

	// Reset failed login counter on successful auth
	if a.FailedLoginCount() > 0 {
		a.ResetFailedLogins()
		// Update in database (async)
		go func() {
			updateCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = r.Update(updateCtx, a)
		}()
	}

	return a, nil
}

// getByAPIKeyPrefixIncludingLocked retrieves an admin by API key prefix, including locked/inactive accounts.
// This is needed for proper lockout handling during authentication.
func (r *AdminRepository) getByAPIKeyPrefixIncludingLocked(ctx context.Context, prefix string) (*admin.AdminUser, error) {
	query := r.selectQuery() + " WHERE api_key_prefix = $1"
	row := r.db.QueryRowContext(ctx, query, prefix)
	return r.scanAdmin(row)
}

// RecordUsage records API key usage (IP and timestamp).
func (r *AdminRepository) RecordUsage(ctx context.Context, id shared.ID, ip string) error {
	query := `
		UPDATE admin_users
		SET last_used_at = NOW(), last_used_ip = $2, updated_at = NOW()
		WHERE id = $1
	`

	_, err := r.db.ExecContext(ctx, query, id.String(), ip)
	if err != nil {
		return fmt.Errorf("failed to record usage: %w", err)
	}

	return nil
}

// =============================================================================
// Statistics
// =============================================================================

// Count counts admin users with optional filter.
func (r *AdminRepository) Count(ctx context.Context, filter admin.Filter) (int, error) {
	query := "SELECT COUNT(*) FROM admin_users"
	whereClause, args := r.buildWhereClause(filter)

	if whereClause != "" {
		query += " WHERE " + whereClause
	}

	var count int
	err := r.db.QueryRowContext(ctx, query, args...).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("failed to count admin users: %w", err)
	}

	return count, nil
}

// CountByRole counts admin users by role.
func (r *AdminRepository) CountByRole(ctx context.Context, role admin.AdminRole) (int, error) {
	query := "SELECT COUNT(*) FROM admin_users WHERE role = $1"

	var count int
	err := r.db.QueryRowContext(ctx, query, string(role)).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("failed to count admin users by role: %w", err)
	}

	return count, nil
}

// =============================================================================
// Helpers
// =============================================================================

func (r *AdminRepository) buildWhereClause(filter admin.Filter) (string, []any) {
	var conditions []string
	var args []any
	argIndex := 1

	if filter.Role != nil {
		conditions = append(conditions, fmt.Sprintf("role = $%d", argIndex))
		args = append(args, string(*filter.Role))
		argIndex++
	}

	if filter.IsActive != nil {
		conditions = append(conditions, fmt.Sprintf("is_active = $%d", argIndex))
		args = append(args, *filter.IsActive)
		argIndex++
	}

	if filter.Email != "" {
		conditions = append(conditions, fmt.Sprintf("LOWER(email) LIKE LOWER($%d)", argIndex))
		args = append(args, "%"+filter.Email+"%")
		argIndex++
	}

	if filter.Search != "" {
		conditions = append(conditions, fmt.Sprintf(
			"(LOWER(email) LIKE LOWER($%d) OR LOWER(name) LIKE LOWER($%d))",
			argIndex, argIndex))
		args = append(args, "%"+filter.Search+"%")
		argIndex++
	}

	if len(conditions) == 0 {
		return "", nil
	}

	return strings.Join(conditions, " AND "), args
}

func (r *AdminRepository) scanAdmin(row *sql.Row) (*admin.AdminUser, error) {
	var (
		id                string
		email             string
		name              string
		apiKeyHash        string
		apiKeyPrefix      string
		role              string
		isActive          bool
		lastUsedAt        sql.NullTime
		lastUsedIP        sql.NullString
		failedLoginCount  int
		lockedUntil       sql.NullTime
		lastFailedLoginAt sql.NullTime
		lastFailedLoginIP sql.NullString
		createdAt         time.Time
		createdBy         sql.NullString
		updatedAt         time.Time
	)

	err := row.Scan(
		&id,
		&email,
		&name,
		&apiKeyHash,
		&apiKeyPrefix,
		&role,
		&isActive,
		&lastUsedAt,
		&lastUsedIP,
		&failedLoginCount,
		&lockedUntil,
		&lastFailedLoginAt,
		&lastFailedLoginIP,
		&createdAt,
		&createdBy,
		&updatedAt,
	)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, admin.ErrAdminNotFound
		}
		return nil, fmt.Errorf("failed to scan admin user: %w", err)
	}

	adminID, _ := shared.IDFromString(id)

	var lastUsed *time.Time
	if lastUsedAt.Valid {
		lastUsed = &lastUsedAt.Time
	}

	var locked *time.Time
	if lockedUntil.Valid {
		locked = &lockedUntil.Time
	}

	var lastFailed *time.Time
	if lastFailedLoginAt.Valid {
		lastFailed = &lastFailedLoginAt.Time
	}

	var createdByID *shared.ID
	if createdBy.Valid {
		cid, _ := shared.IDFromString(createdBy.String)
		createdByID = &cid
	}

	return admin.Reconstitute(
		adminID,
		email,
		name,
		apiKeyHash,
		apiKeyPrefix,
		admin.AdminRole(role),
		isActive,
		lastUsed,
		lastUsedIP.String,
		failedLoginCount,
		locked,
		lastFailed,
		lastFailedLoginIP.String,
		createdAt,
		createdByID,
		updatedAt,
	), nil
}

func (r *AdminRepository) scanAdminFromRows(rows *sql.Rows) (*admin.AdminUser, error) {
	var (
		id                string
		email             string
		name              string
		apiKeyHash        string
		apiKeyPrefix      string
		role              string
		isActive          bool
		lastUsedAt        sql.NullTime
		lastUsedIP        sql.NullString
		failedLoginCount  int
		lockedUntil       sql.NullTime
		lastFailedLoginAt sql.NullTime
		lastFailedLoginIP sql.NullString
		createdAt         time.Time
		createdBy         sql.NullString
		updatedAt         time.Time
	)

	err := rows.Scan(
		&id,
		&email,
		&name,
		&apiKeyHash,
		&apiKeyPrefix,
		&role,
		&isActive,
		&lastUsedAt,
		&lastUsedIP,
		&failedLoginCount,
		&lockedUntil,
		&lastFailedLoginAt,
		&lastFailedLoginIP,
		&createdAt,
		&createdBy,
		&updatedAt,
	)

	if err != nil {
		return nil, fmt.Errorf("failed to scan admin user row: %w", err)
	}

	adminID, _ := shared.IDFromString(id)

	var lastUsed *time.Time
	if lastUsedAt.Valid {
		lastUsed = &lastUsedAt.Time
	}

	var locked *time.Time
	if lockedUntil.Valid {
		locked = &lockedUntil.Time
	}

	var lastFailed *time.Time
	if lastFailedLoginAt.Valid {
		lastFailed = &lastFailedLoginAt.Time
	}

	var createdByID *shared.ID
	if createdBy.Valid {
		cid, _ := shared.IDFromString(createdBy.String)
		createdByID = &cid
	}

	return admin.Reconstitute(
		adminID,
		email,
		name,
		apiKeyHash,
		apiKeyPrefix,
		admin.AdminRole(role),
		isActive,
		lastUsed,
		lastUsedIP.String,
		failedLoginCount,
		locked,
		lastFailed,
		lastFailedLoginIP.String,
		createdAt,
		createdByID,
		updatedAt,
	), nil
}

// =============================================================================
// Audit Log Repository
// =============================================================================

// AuditLogRepository implements admin.AuditLogRepository using PostgreSQL.
type AuditLogRepository struct {
	db *DB
}

// NewAuditLogRepository creates a new AuditLogRepository.
func NewAuditLogRepository(db *DB) *AuditLogRepository {
	return &AuditLogRepository{db: db}
}

func (r *AuditLogRepository) selectQuery() string {
	return `
		SELECT id, admin_id, admin_email, action, resource_type, resource_id, resource_name,
		       request_method, request_path, request_body, response_status,
		       ip_address, user_agent, success, error_message, created_at
		FROM admin_audit_logs
	`
}

// Create creates a new audit log entry.
func (r *AuditLogRepository) Create(ctx context.Context, log *admin.AuditLog) error {
	query := `
		INSERT INTO admin_audit_logs (
			id, admin_id, admin_email, action, resource_type, resource_id, resource_name,
			request_method, request_path, request_body, response_status,
			ip_address, user_agent, success, error_message, created_at
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)
	`

	requestBody, err := json.Marshal(log.RequestBody)
	if err != nil {
		requestBody = []byte("{}")
	}

	_, err = r.db.ExecContext(ctx, query,
		log.ID.String(),
		nullIDString(log.AdminID),
		log.AdminEmail,
		log.Action,
		nullString(log.ResourceType),
		nullIDString(log.ResourceID),
		nullString(log.ResourceName),
		nullString(log.RequestMethod),
		nullString(log.RequestPath),
		requestBody,
		nullInt(log.ResponseStatus),
		nullString(log.IPAddress),
		nullString(log.UserAgent),
		log.Success,
		nullString(log.ErrorMessage),
		log.CreatedAt,
	)

	if err != nil {
		return fmt.Errorf("failed to create audit log: %w", err)
	}

	return nil
}

// GetByID retrieves an audit log by ID.
func (r *AuditLogRepository) GetByID(ctx context.Context, id shared.ID) (*admin.AuditLog, error) {
	query := r.selectQuery() + " WHERE id = $1"
	row := r.db.QueryRowContext(ctx, query, id.String())
	return r.scanAuditLog(row)
}

// List lists audit logs with filters and pagination.
func (r *AuditLogRepository) List(ctx context.Context, filter admin.AuditLogFilter, page pagination.Pagination) (pagination.Result[*admin.AuditLog], error) {
	var result pagination.Result[*admin.AuditLog]

	baseQuery := r.selectQuery()
	countQuery := "SELECT COUNT(*) FROM admin_audit_logs"
	whereClause, args := r.buildAuditWhereClause(filter)

	if whereClause != "" {
		baseQuery += " WHERE " + whereClause
		countQuery += " WHERE " + whereClause
	}

	// Get total count
	var total int64
	err := r.db.QueryRowContext(ctx, countQuery, args...).Scan(&total)
	if err != nil {
		return result, fmt.Errorf("failed to count audit logs: %w", err)
	}

	// Apply pagination
	offset := (page.Page - 1) * page.PerPage
	baseQuery += fmt.Sprintf(" ORDER BY created_at DESC LIMIT %d OFFSET %d", page.PerPage, offset)

	rows, err := r.db.QueryContext(ctx, baseQuery, args...)
	if err != nil {
		return result, fmt.Errorf("failed to list audit logs: %w", err)
	}
	defer rows.Close()

	var logs []*admin.AuditLog
	for rows.Next() {
		log, err := r.scanAuditLogFromRows(rows)
		if err != nil {
			return result, err
		}
		logs = append(logs, log)
	}

	if err := rows.Err(); err != nil {
		return result, fmt.Errorf("error iterating audit logs: %w", err)
	}

	return pagination.NewResult(logs, total, page), nil
}

// ListByAdmin lists audit logs for a specific admin.
func (r *AuditLogRepository) ListByAdmin(ctx context.Context, adminID shared.ID, page pagination.Pagination) (pagination.Result[*admin.AuditLog], error) {
	filter := admin.AuditLogFilter{AdminID: &adminID}
	return r.List(ctx, filter, page)
}

// ListByResource lists audit logs for a specific resource.
func (r *AuditLogRepository) ListByResource(ctx context.Context, resourceType string, resourceID shared.ID, page pagination.Pagination) (pagination.Result[*admin.AuditLog], error) {
	filter := admin.AuditLogFilter{
		ResourceType: resourceType,
		ResourceID:   &resourceID,
	}
	return r.List(ctx, filter, page)
}

// Count counts audit logs with optional filter.
func (r *AuditLogRepository) Count(ctx context.Context, filter admin.AuditLogFilter) (int64, error) {
	query := "SELECT COUNT(*) FROM admin_audit_logs"
	whereClause, args := r.buildAuditWhereClause(filter)

	if whereClause != "" {
		query += " WHERE " + whereClause
	}

	var count int64
	err := r.db.QueryRowContext(ctx, query, args...).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("failed to count audit logs: %w", err)
	}

	return count, nil
}

// GetRecentActions returns the most recent actions (for dashboard).
func (r *AuditLogRepository) GetRecentActions(ctx context.Context, limit int) ([]*admin.AuditLog, error) {
	query := r.selectQuery() + " ORDER BY created_at DESC LIMIT $1"

	rows, err := r.db.QueryContext(ctx, query, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to get recent actions: %w", err)
	}
	defer rows.Close()

	var logs []*admin.AuditLog
	for rows.Next() {
		log, err := r.scanAuditLogFromRows(rows)
		if err != nil {
			return nil, err
		}
		logs = append(logs, log)
	}

	return logs, nil
}

// GetFailedActions returns recent failed actions (for monitoring).
func (r *AuditLogRepository) GetFailedActions(ctx context.Context, since time.Duration, limit int) ([]*admin.AuditLog, error) {
	query := r.selectQuery() + `
		WHERE success = FALSE AND created_at > NOW() - $1::interval
		ORDER BY created_at DESC LIMIT $2
	`

	rows, err := r.db.QueryContext(ctx, query, since.String(), limit)
	if err != nil {
		return nil, fmt.Errorf("failed to get failed actions: %w", err)
	}
	defer rows.Close()

	var logs []*admin.AuditLog
	for rows.Next() {
		log, err := r.scanAuditLogFromRows(rows)
		if err != nil {
			return nil, err
		}
		logs = append(logs, log)
	}

	return logs, nil
}

func (r *AuditLogRepository) buildAuditWhereClause(filter admin.AuditLogFilter) (string, []any) {
	var conditions []string
	var args []any
	argIndex := 1

	if filter.AdminID != nil {
		conditions = append(conditions, fmt.Sprintf("admin_id = $%d", argIndex))
		args = append(args, filter.AdminID.String())
		argIndex++
	}

	if filter.AdminEmail != "" {
		conditions = append(conditions, fmt.Sprintf("LOWER(admin_email) LIKE LOWER($%d)", argIndex))
		args = append(args, "%"+filter.AdminEmail+"%")
		argIndex++
	}

	if filter.Action != "" {
		conditions = append(conditions, fmt.Sprintf("action = $%d", argIndex))
		args = append(args, filter.Action)
		argIndex++
	}

	if filter.ResourceType != "" {
		conditions = append(conditions, fmt.Sprintf("resource_type = $%d", argIndex))
		args = append(args, filter.ResourceType)
		argIndex++
	}

	if filter.ResourceID != nil {
		conditions = append(conditions, fmt.Sprintf("resource_id = $%d", argIndex))
		args = append(args, filter.ResourceID.String())
		argIndex++
	}

	if filter.Success != nil {
		conditions = append(conditions, fmt.Sprintf("success = $%d", argIndex))
		args = append(args, *filter.Success)
		argIndex++
	}

	if filter.StartTime != nil {
		conditions = append(conditions, fmt.Sprintf("created_at >= $%d", argIndex))
		args = append(args, *filter.StartTime)
		argIndex++
	}

	if filter.EndTime != nil {
		conditions = append(conditions, fmt.Sprintf("created_at <= $%d", argIndex))
		args = append(args, *filter.EndTime)
		argIndex++
	}

	if filter.Search != "" {
		conditions = append(conditions, fmt.Sprintf(
			"(action LIKE $%d OR resource_name LIKE $%d OR error_message LIKE $%d)",
			argIndex, argIndex, argIndex))
		args = append(args, "%"+filter.Search+"%")
		argIndex++
	}

	if len(conditions) == 0 {
		return "", nil
	}

	return strings.Join(conditions, " AND "), args
}

func (r *AuditLogRepository) scanAuditLog(row *sql.Row) (*admin.AuditLog, error) {
	log := &admin.AuditLog{}
	var (
		id             string
		adminID        sql.NullString
		resourceType   sql.NullString
		resourceID     sql.NullString
		resourceName   sql.NullString
		requestMethod  sql.NullString
		requestPath    sql.NullString
		requestBody    []byte
		responseStatus sql.NullInt32
		ipAddress      sql.NullString
		userAgent      sql.NullString
		errorMessage   sql.NullString
	)

	err := row.Scan(
		&id,
		&adminID,
		&log.AdminEmail,
		&log.Action,
		&resourceType,
		&resourceID,
		&resourceName,
		&requestMethod,
		&requestPath,
		&requestBody,
		&responseStatus,
		&ipAddress,
		&userAgent,
		&log.Success,
		&errorMessage,
		&log.CreatedAt,
	)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, admin.ErrAuditLogNotFound
		}
		return nil, fmt.Errorf("failed to scan audit log: %w", err)
	}

	log.ID, _ = shared.IDFromString(id)

	if adminID.Valid {
		aid, _ := shared.IDFromString(adminID.String)
		log.AdminID = &aid
	}

	log.ResourceType = resourceType.String
	if resourceID.Valid {
		rid, _ := shared.IDFromString(resourceID.String)
		log.ResourceID = &rid
	}
	log.ResourceName = resourceName.String
	log.RequestMethod = requestMethod.String
	log.RequestPath = requestPath.String
	log.ResponseStatus = int(responseStatus.Int32)
	log.IPAddress = ipAddress.String
	log.UserAgent = userAgent.String
	log.ErrorMessage = errorMessage.String

	if len(requestBody) > 0 {
		_ = json.Unmarshal(requestBody, &log.RequestBody)
	}

	return log, nil
}

func (r *AuditLogRepository) scanAuditLogFromRows(rows *sql.Rows) (*admin.AuditLog, error) {
	log := &admin.AuditLog{}
	var (
		id             string
		adminID        sql.NullString
		resourceType   sql.NullString
		resourceID     sql.NullString
		resourceName   sql.NullString
		requestMethod  sql.NullString
		requestPath    sql.NullString
		requestBody    []byte
		responseStatus sql.NullInt32
		ipAddress      sql.NullString
		userAgent      sql.NullString
		errorMessage   sql.NullString
	)

	err := rows.Scan(
		&id,
		&adminID,
		&log.AdminEmail,
		&log.Action,
		&resourceType,
		&resourceID,
		&resourceName,
		&requestMethod,
		&requestPath,
		&requestBody,
		&responseStatus,
		&ipAddress,
		&userAgent,
		&log.Success,
		&errorMessage,
		&log.CreatedAt,
	)

	if err != nil {
		return nil, fmt.Errorf("failed to scan audit log row: %w", err)
	}

	log.ID, _ = shared.IDFromString(id)

	if adminID.Valid {
		aid, _ := shared.IDFromString(adminID.String)
		log.AdminID = &aid
	}

	log.ResourceType = resourceType.String
	if resourceID.Valid {
		rid, _ := shared.IDFromString(resourceID.String)
		log.ResourceID = &rid
	}
	log.ResourceName = resourceName.String
	log.RequestMethod = requestMethod.String
	log.RequestPath = requestPath.String
	log.ResponseStatus = int(responseStatus.Int32)
	log.IPAddress = ipAddress.String
	log.UserAgent = userAgent.String
	log.ErrorMessage = errorMessage.String

	if len(requestBody) > 0 {
		_ = json.Unmarshal(requestBody, &log.RequestBody)
	}

	return log, nil
}

// =============================================================================
// Retention Management
// =============================================================================

// DeleteOlderThan deletes audit logs older than the specified time.
func (r *AuditLogRepository) DeleteOlderThan(ctx context.Context, olderThan time.Time) (int64, error) {
	query := `DELETE FROM admin_audit_logs WHERE created_at < $1`

	result, err := r.db.ExecContext(ctx, query, olderThan)
	if err != nil {
		return 0, fmt.Errorf("failed to delete old audit logs: %w", err)
	}

	count, err := result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("failed to get rows affected: %w", err)
	}

	return count, nil
}

// CountOlderThan counts audit logs older than the specified time.
func (r *AuditLogRepository) CountOlderThan(ctx context.Context, olderThan time.Time) (int64, error) {
	query := `SELECT COUNT(*) FROM admin_audit_logs WHERE created_at < $1`

	var count int64
	err := r.db.QueryRowContext(ctx, query, olderThan).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("failed to count old audit logs: %w", err)
	}

	return count, nil
}

// Note: nullInt is defined in command_repository.go (same package)
