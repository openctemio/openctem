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
		SELECT id, email, name,
		       role, is_active, user_id, last_used_at, last_used_ip,
		       failed_login_count, locked_until, last_failed_login_at, last_failed_login_ip,
		       created_at, created_by, updated_at,
		       is_break_glass, break_glass_tested_at, password_change_required,
		       COALESCE(idp_issuer, ''), COALESCE(idp_subject, ''), idp_bound_at
		FROM admin_users
	`
}

// Create creates a new admin user.
func (r *AdminRepository) Create(ctx context.Context, a *admin.AdminUser) error {
	query := `
		INSERT INTO admin_users (
			id, email, name,
			role, is_active, created_at, created_by, updated_at,
			is_break_glass, password_change_required
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
	`

	_, err := r.db.ExecContext(ctx, query,
		a.ID().String(),
		a.Email(),
		a.Name(),
		string(a.Role()),
		a.IsActive(),
		a.CreatedAt(),
		nullIDString(a.CreatedBy()),
		a.UpdatedAt(),
		a.IsBreakGlass(),
		a.PasswordChangeRequired(),
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
//
//getbyid:unsafe - Admin users are platform operators (not tenant users); no tenant_id column.
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
		SET email = $2, name = $3,
		    role = $4, is_active = $5, last_used_at = $6, last_used_ip = $7,
		    failed_login_count = $8, locked_until = $9,
		    last_failed_login_at = $10, last_failed_login_ip = $11,
		    updated_at = $12
		WHERE id = $1
	`

	result, err := r.db.ExecContext(ctx, query,
		a.ID().String(),
		a.Email(),
		a.Name(),
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
// Console usage
// =============================================================================

// RecordUsage records when and from where the administrator last opened the console.
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
		args = append(args, "%"+escapeLikePattern(filter.Email)+"%")
		argIndex++
	}

	if filter.Search != "" {
		conditions = append(conditions, fmt.Sprintf(
			"(LOWER(email) LIKE LOWER($%d) OR LOWER(name) LIKE LOWER($%d))",
			argIndex, argIndex))
		args = append(args, "%"+escapeLikePattern(filter.Search)+"%")
		// argIndex not incremented — this is the last condition.
	}

	if len(conditions) == 0 {
		return "", nil
	}

	return strings.Join(conditions, " AND "), args
}

func (r *AdminRepository) scanAdmin(row *sql.Row) (*admin.AdminUser, error) {
	a, err := scanAdminRow(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, admin.ErrAdminNotFound
	}
	return a, err
}

func (r *AdminRepository) scanAdminFromRows(rows *sql.Rows) (*admin.AdminUser, error) {
	return scanAdminRow(rows)
}

// scanAdminRow scans one selectQuery row (from *sql.Row or *sql.Rows).
func scanAdminRow(scanner interface{ Scan(dest ...any) error }) (*admin.AdminUser, error) {
	var (
		id                string
		email             string
		name              string
		role              string
		isActive          bool
		userID            sql.NullString
		lastUsedAt        sql.NullTime
		lastUsedIP        sql.NullString
		failedLoginCount  int
		lockedUntil       sql.NullTime
		lastFailedLoginAt sql.NullTime
		lastFailedLoginIP sql.NullString
		createdAt         time.Time
		createdBy         sql.NullString
		updatedAt         time.Time
		breakGlass        bool
		testedAt          sql.NullTime
		pwChange          bool
		idpIssuer         string
		idpSubject        string
		idpBoundAt        sql.NullTime
	)
	if err := scanner.Scan(
		&id, &email, &name, &role, &isActive, &userID,
		&lastUsedAt, &lastUsedIP,
		&failedLoginCount, &lockedUntil, &lastFailedLoginAt, &lastFailedLoginIP,
		&createdAt, &createdBy, &updatedAt,
		&breakGlass, &testedAt, &pwChange, &idpIssuer, &idpSubject, &idpBoundAt,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, err
		}
		return nil, fmt.Errorf("failed to scan admin user: %w", err)
	}

	adminID, _ := shared.IDFromString(id)
	optID := func(v sql.NullString) *shared.ID {
		if !v.Valid {
			return nil
		}
		parsed, err := shared.IDFromString(v.String)
		if err != nil {
			return nil
		}
		return &parsed
	}
	optTime := func(v sql.NullTime) *time.Time {
		if !v.Valid {
			return nil
		}
		t := v.Time
		return &t
	}

	return admin.Reconstitute(
		adminID,
		email,
		name,
		admin.AdminRole(role),
		isActive,
		optID(userID),
		optTime(lastUsedAt),
		lastUsedIP.String,
		failedLoginCount,
		optTime(lockedUntil),
		optTime(lastFailedLoginAt),
		lastFailedLoginIP.String,
		createdAt,
		optID(createdBy),
		updatedAt,
	).WithSignInState(admin.SignInState{
		BreakGlass:             breakGlass,
		BreakGlassTestedAt:     optTime(testedAt),
		PasswordChangeRequired: pwChange,
		IdPIssuer:              idpIssuer,
		IdPSubject:             idpSubject,
		IdPBoundAt:             optTime(idpBoundAt),
	}), nil
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
		       ip_address, user_agent, success, error_message, created_at, severity
		FROM admin_audit_logs
	`
}

// Create creates a new audit log entry.
func (r *AuditLogRepository) Create(ctx context.Context, log *admin.AuditLog) error {
	query := `
		INSERT INTO admin_audit_logs (
			id, admin_id, admin_email, action, resource_type, resource_id, resource_name,
			request_method, request_path, request_body, response_status,
			ip_address, user_agent, success, error_message, created_at, severity
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17)
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
		auditSeverity(log.Severity),
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
		args = append(args, "%"+escapeLikePattern(filter.AdminEmail)+"%")
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
		args = append(args, "%"+escapeLikePattern(filter.Search)+"%")
		// argIndex not incremented — this is the last condition.
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
		&log.Severity,
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
		&log.Severity,
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

// GetByUserID returns the administrator linked to a users row.
func (r *AdminRepository) GetByUserID(ctx context.Context, userID shared.ID) (*admin.AdminUser, error) {
	row := r.db.QueryRowContext(ctx, r.selectQuery()+" WHERE user_id = $1", userID.String())
	return r.scanAdmin(row)
}

// LinkUser links an administrator to a users row, refusing users that belong
// to an organization. The membership check and the update run in one
// statement; the tenant_members trigger (migration 000226) blocks the reverse
// order, so the two rules cannot race into an administrator with members.
func (r *AdminRepository) LinkUser(ctx context.Context, adminID, userID shared.ID) error {
	res, err := r.db.ExecContext(ctx, `
		UPDATE admin_users SET user_id = $2, updated_at = NOW()
		WHERE id = $1
		  AND NOT EXISTS (SELECT 1 FROM tenant_members WHERE user_id = $2)`,
		adminID.String(), userID.String())
	if err != nil {
		if isUniqueViolation(err) {
			return admin.ErrUserAlreadyAdmin
		}
		return fmt.Errorf("link admin user: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("link admin user: %w", err)
	}
	if n == 1 {
		return nil
	}
	// Nothing updated: either the admin does not exist or the user has members.
	var exists bool
	if err := r.db.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM admin_users WHERE id = $1)`, adminID.String()).Scan(&exists); err != nil {
		return fmt.Errorf("link admin user: %w", err)
	}
	if !exists {
		return admin.ErrAdminNotFound
	}
	return admin.ErrUserHasMemberships
}

// auditSeverity defaults an unset severity to info.
func auditSeverity(v string) string {
	if v == "" {
		return admin.SeverityInfo
	}
	return v
}
