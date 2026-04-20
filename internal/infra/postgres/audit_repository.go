package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/openctemio/api/pkg/domain/audit"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/pagination"
)

// AuditRepository implements audit.Repository using PostgreSQL.
type AuditRepository struct {
	db *DB
}

// NewAuditRepository creates a new AuditRepository.
func NewAuditRepository(db *DB) *AuditRepository {
	return &AuditRepository{db: db}
}

// Create persists a new audit log entry.
func (r *AuditRepository) Create(ctx context.Context, log *audit.AuditLog) error {
	var changesJSON any // Use any to allow nil for JSON column
	var err error
	if log.Changes() != nil {
		changesJSON, err = json.Marshal(log.Changes())
		if err != nil {
			return fmt.Errorf("failed to marshal changes: %w", err)
		}
	}
	// If changesJSON is still nil, that's fine - PostgreSQL will accept NULL for JSON column

	metadataJSON, err := json.Marshal(log.Metadata())
	if err != nil {
		return fmt.Errorf("failed to marshal metadata: %w", err)
	}

	query := `
		INSERT INTO audit_logs (
			id, tenant_id, actor_id, actor_email, actor_ip, actor_agent,
			action, resource_type, resource_id, resource_name,
			changes, result, severity, message, metadata,
			request_id, session_id, logged_at
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18)
	`

	_, err = r.db.ExecContext(ctx, query,
		log.ID().String(),
		nullableID(log.TenantID()),
		nullableID(log.ActorID()),
		nullString(log.ActorEmail()),
		nullString(log.ActorIP()),
		nullString(log.ActorAgent()),
		log.Action().String(),
		log.ResourceType().String(),
		nullString(log.ResourceID()),
		nullString(log.ResourceName()),
		changesJSON,
		log.Result().String(),
		log.Severity().String(),
		nullString(log.Message()),
		metadataJSON,
		nullString(log.RequestID()),
		nullString(log.SessionID()),
		log.Timestamp(),
	)

	if err != nil {
		return fmt.Errorf("failed to create audit log: %w", err)
	}

	return nil
}

// CreateBatch persists multiple audit log entries.
func (r *AuditRepository) CreateBatch(ctx context.Context, logs []*audit.AuditLog) error {
	if len(logs) == 0 {
		return nil
	}

	// Build batch insert query
	valueStrings := make([]string, 0, len(logs))
	valueArgs := make([]any, 0, len(logs)*18)
	argIndex := 1

	for _, log := range logs {
		var changesJSON any // Use any to allow nil for JSON column
		if log.Changes() != nil {
			var err error
			changesJSON, err = json.Marshal(log.Changes())
			if err != nil {
				return fmt.Errorf("failed to marshal changes: %w", err)
			}
		}

		metadataJSON, err := json.Marshal(log.Metadata())
		if err != nil {
			return fmt.Errorf("failed to marshal metadata: %w", err)
		}

		placeholders := make([]string, 18)
		for i := 0; i < 18; i++ {
			placeholders[i] = fmt.Sprintf("$%d", argIndex+i)
		}
		valueStrings = append(valueStrings, "("+strings.Join(placeholders, ", ")+")")

		valueArgs = append(valueArgs,
			log.ID().String(),
			nullableID(log.TenantID()),
			nullableID(log.ActorID()),
			nullString(log.ActorEmail()),
			nullString(log.ActorIP()),
			nullString(log.ActorAgent()),
			log.Action().String(),
			log.ResourceType().String(),
			nullString(log.ResourceID()),
			nullString(log.ResourceName()),
			changesJSON,
			log.Result().String(),
			log.Severity().String(),
			nullString(log.Message()),
			metadataJSON,
			nullString(log.RequestID()),
			nullString(log.SessionID()),
			log.Timestamp(),
		)

		argIndex += 18
	}

	query := `
		INSERT INTO audit_logs (
			id, tenant_id, actor_id, actor_email, actor_ip, actor_agent,
			action, resource_type, resource_id, resource_name,
			changes, result, severity, message, metadata,
			request_id, session_id, logged_at
		)
		VALUES ` + strings.Join(valueStrings, ", ")

	_, err := r.db.ExecContext(ctx, query, valueArgs...)
	if err != nil {
		return fmt.Errorf("failed to batch create audit logs: %w", err)
	}

	return nil
}

// GetByID retrieves an audit log by ID.
func (r *AuditRepository) GetByID(ctx context.Context, id shared.ID) (*audit.AuditLog, error) {
	query := r.selectQuery() + " WHERE id = $1"
	row := r.db.QueryRowContext(ctx, query, id.String())
	return r.scanAuditLog(row, audit.AuditLogNotFoundError(id))
}

// GetByTenantAndID retrieves an audit log by tenant and ID (tenant-scoped).
func (r *AuditRepository) GetByTenantAndID(ctx context.Context, tenantID, id shared.ID) (*audit.AuditLog, error) {
	query := r.selectQuery() + " WHERE tenant_id = $1 AND id = $2"
	row := r.db.QueryRowContext(ctx, query, tenantID.String(), id.String())
	return r.scanAuditLog(row, audit.AuditLogNotFoundError(id))
}

// List retrieves audit logs matching the filter with pagination.
func (r *AuditRepository) List(ctx context.Context, filter audit.Filter, page pagination.Pagination) (pagination.Result[*audit.AuditLog], error) {
	baseQuery := r.selectQuery()
	countQuery := `SELECT COUNT(*) FROM audit_logs`

	whereClause, args := r.buildWhereClause(filter)

	if whereClause != "" {
		baseQuery += " WHERE " + whereClause
		countQuery += " WHERE " + whereClause
	}

	baseQuery += " ORDER BY "
	if filter.SortBy != "" {
		// Prevent SQL injection by allowing only specific columns
		allowedSorts := map[string]string{
			"logged_at":     "logged_at",
			"action":        "action",
			"resource_type": "resource_type",
			"result":        "result",
			"severity":      "severity",
		}
		if col, ok := allowedSorts[filter.SortBy]; ok {
			baseQuery += col
		} else {
			baseQuery += "logged_at" // Default
		}

		if filter.SortOrder == sortOrderAscLower {
			baseQuery += " ASC"
		} else {
			baseQuery += " DESC"
		}
	} else {
		baseQuery += "logged_at DESC"
	}

	baseQuery += fmt.Sprintf(" LIMIT %d OFFSET %d", page.Limit(), page.Offset())

	var total int64
	err := r.db.QueryRowContext(ctx, countQuery, args...).Scan(&total)
	if err != nil {
		return pagination.Result[*audit.AuditLog]{}, fmt.Errorf("failed to count audit logs: %w", err)
	}

	rows, err := r.db.QueryContext(ctx, baseQuery, args...)
	if err != nil {
		return pagination.Result[*audit.AuditLog]{}, fmt.Errorf("failed to query audit logs: %w", err)
	}
	defer rows.Close()

	var logs []*audit.AuditLog
	for rows.Next() {
		log, err := r.scanAuditLogFromRows(rows)
		if err != nil {
			return pagination.Result[*audit.AuditLog]{}, err
		}
		logs = append(logs, log)
	}

	if err := rows.Err(); err != nil {
		return pagination.Result[*audit.AuditLog]{}, fmt.Errorf("failed to iterate audit logs: %w", err)
	}

	return pagination.NewResult(logs, total, page), nil
}

// Count returns the count of audit logs matching the filter.
func (r *AuditRepository) Count(ctx context.Context, filter audit.Filter) (int64, error) {
	query := `SELECT COUNT(*) FROM audit_logs`

	whereClause, args := r.buildWhereClause(filter)
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

// DeleteOlderThan deletes audit logs older than the specified time ACROSS ALL
// TENANTS. See the interface doc (F-3) — this is a platform-privileged
// operation, safe only from operator-driven background jobs.
func (r *AuditRepository) DeleteOlderThan(ctx context.Context, before time.Time) (int64, error) {
	query := `DELETE FROM audit_logs WHERE logged_at < $1 AND severity NOT IN ('high', 'critical')`

	result, err := r.db.ExecContext(ctx, query, before)
	if err != nil {
		return 0, fmt.Errorf("failed to delete old audit logs: %w", err)
	}

	count, err := result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("failed to get rows affected: %w", err)
	}

	return count, nil
}

// DeleteOlderThanForTenant deletes audit logs older than the specified time,
// scoped to a single tenant. High/critical severity entries are preserved
// (F-3 per-tenant retention variant).
func (r *AuditRepository) DeleteOlderThanForTenant(ctx context.Context, tenantID shared.ID, before time.Time) (int64, error) {
	query := `DELETE FROM audit_logs WHERE tenant_id = $1 AND logged_at < $2 AND severity NOT IN ('high', 'critical')`

	result, err := r.db.ExecContext(ctx, query, tenantID.String(), before)
	if err != nil {
		return 0, fmt.Errorf("failed to delete old audit logs: %w", err)
	}

	count, err := result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("failed to get rows affected: %w", err)
	}

	return count, nil
}

// GetLatestByResource retrieves the latest audit log for a resource within a tenant.
// tenantID is required to prevent cross-tenant reads (F-2).
func (r *AuditRepository) GetLatestByResource(ctx context.Context, tenantID shared.ID, resourceType audit.ResourceType, resourceID string) (*audit.AuditLog, error) {
	query := r.selectQuery() + ` WHERE tenant_id = $1 AND resource_type = $2 AND resource_id = $3 ORDER BY logged_at DESC LIMIT 1`
	row := r.db.QueryRowContext(ctx, query, tenantID.String(), resourceType.String(), resourceID)

	log, err := r.scanAuditLog(row, nil)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return log, nil
}

// ListByActor retrieves audit logs for a specific actor.
func (r *AuditRepository) ListByActor(ctx context.Context, actorID shared.ID, page pagination.Pagination) (pagination.Result[*audit.AuditLog], error) {
	filter := audit.NewFilter().WithActorID(actorID)
	return r.List(ctx, filter, page)
}

// ListByResource retrieves audit logs for a specific resource within a tenant.
// tenantID is required to prevent cross-tenant reads (F-2).
func (r *AuditRepository) ListByResource(ctx context.Context, tenantID shared.ID, resourceType audit.ResourceType, resourceID string, page pagination.Pagination) (pagination.Result[*audit.AuditLog], error) {
	filter := audit.NewFilter().
		WithTenantID(tenantID).
		WithResourceTypes(resourceType).
		WithResourceID(resourceID)
	return r.List(ctx, filter, page)
}

// CountByAction counts occurrences of an action within a time range.
func (r *AuditRepository) CountByAction(ctx context.Context, tenantID *shared.ID, action audit.Action, since time.Time) (int64, error) {
	var query string
	var args []any

	if tenantID != nil {
		query = `SELECT COUNT(*) FROM audit_logs WHERE tenant_id = $1 AND action = $2 AND logged_at >= $3`
		args = []any{tenantID.String(), action.String(), since}
	} else {
		query = `SELECT COUNT(*) FROM audit_logs WHERE action = $1 AND logged_at >= $2`
		args = []any{action.String(), since}
	}

	var count int64
	err := r.db.QueryRowContext(ctx, query, args...).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("failed to count by action: %w", err)
	}

	return count, nil
}

// Helper methods

func (r *AuditRepository) selectQuery() string {
	return `
		SELECT id, tenant_id, actor_id, actor_email, actor_ip, actor_agent,
			action, resource_type, resource_id, resource_name,
			changes, result, severity, message, metadata,
			request_id, session_id, logged_at
		FROM audit_logs
	`
}

func (r *AuditRepository) scanAuditLog(row *sql.Row, notFoundErr error) (*audit.AuditLog, error) {
	log, err := r.doScan(row.Scan)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			if notFoundErr != nil {
				return nil, notFoundErr
			}
			return nil, err
		}
		return nil, fmt.Errorf("failed to scan audit log: %w", err)
	}
	return log, nil
}

func (r *AuditRepository) scanAuditLogFromRows(rows *sql.Rows) (*audit.AuditLog, error) {
	return r.doScan(rows.Scan)
}

func (r *AuditRepository) doScan(scan func(dest ...any) error) (*audit.AuditLog, error) {
	var (
		idStr        string
		tenantIDStr  sql.NullString
		actorIDStr   sql.NullString
		actorEmail   sql.NullString
		actorIP      sql.NullString
		actorAgent   sql.NullString
		actionStr    string
		resourceType string
		resourceID   sql.NullString
		resourceName sql.NullString
		changesJSON  []byte
		resultStr    string
		severityStr  string
		message      sql.NullString
		metadataJSON []byte
		requestID    sql.NullString
		sessionID    sql.NullString
		logged_at    time.Time
	)

	err := scan(
		&idStr, &tenantIDStr, &actorIDStr, &actorEmail, &actorIP, &actorAgent,
		&actionStr, &resourceType, &resourceID, &resourceName,
		&changesJSON, &resultStr, &severityStr, &message, &metadataJSON,
		&requestID, &sessionID, &logged_at,
	)
	if err != nil {
		return nil, err
	}

	id, err := shared.IDFromString(idStr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse id: %w", err)
	}

	var tenantID *shared.ID
	if tenantIDStr.Valid {
		tid, err := shared.IDFromString(tenantIDStr.String)
		if err != nil {
			return nil, fmt.Errorf("failed to parse tenant id: %w", err)
		}
		tenantID = &tid
	}

	var actorID *shared.ID
	if actorIDStr.Valid {
		aid, err := shared.IDFromString(actorIDStr.String)
		if err != nil {
			return nil, fmt.Errorf("failed to parse actor id: %w", err)
		}
		actorID = &aid
	}

	var changes *audit.Changes
	if len(changesJSON) > 0 {
		changes = &audit.Changes{}
		if err := json.Unmarshal(changesJSON, changes); err != nil {
			return nil, fmt.Errorf("failed to unmarshal changes: %w", err)
		}
	}

	var metadata map[string]any
	if len(metadataJSON) > 0 {
		if err := json.Unmarshal(metadataJSON, &metadata); err != nil {
			return nil, fmt.Errorf("failed to unmarshal metadata: %w", err)
		}
	}

	return audit.Reconstitute(
		id,
		tenantID,
		actorID,
		nullStringValue(actorEmail),
		nullStringValue(actorIP),
		nullStringValue(actorAgent),
		audit.Action(actionStr),
		audit.ResourceType(resourceType),
		nullStringValue(resourceID),
		nullStringValue(resourceName),
		changes,
		audit.Result(resultStr),
		audit.Severity(severityStr),
		nullStringValue(message),
		metadata,
		nullStringValue(requestID),
		nullStringValue(sessionID),
		logged_at,
	), nil
}

func (r *AuditRepository) buildWhereClause(filter audit.Filter) (string, []any) {
	var conditions []string
	var args []any
	argIndex := 1

	if filter.TenantID != nil {
		conditions = append(conditions, fmt.Sprintf("tenant_id = $%d", argIndex))
		args = append(args, filter.TenantID.String())
		argIndex++
	}

	if filter.ActorID != nil {
		conditions = append(conditions, fmt.Sprintf("actor_id = $%d", argIndex))
		args = append(args, filter.ActorID.String())
		argIndex++
	}

	if len(filter.Actions) > 0 {
		placeholders := make([]string, len(filter.Actions))
		for i, action := range filter.Actions {
			placeholders[i] = fmt.Sprintf("$%d", argIndex)
			args = append(args, action.String())
			argIndex++
		}
		conditions = append(conditions, fmt.Sprintf("action IN (%s)", strings.Join(placeholders, ", ")))
	}

	if len(filter.ResourceTypes) > 0 {
		placeholders := make([]string, len(filter.ResourceTypes))
		for i, rt := range filter.ResourceTypes {
			placeholders[i] = fmt.Sprintf("$%d", argIndex)
			args = append(args, rt.String())
			argIndex++
		}
		conditions = append(conditions, fmt.Sprintf("resource_type IN (%s)", strings.Join(placeholders, ", ")))
	}

	if filter.ResourceID != nil {
		conditions = append(conditions, fmt.Sprintf("resource_id = $%d", argIndex))
		args = append(args, *filter.ResourceID)
		argIndex++
	}

	if len(filter.Results) > 0 {
		placeholders := make([]string, len(filter.Results))
		for i, r := range filter.Results {
			placeholders[i] = fmt.Sprintf("$%d", argIndex)
			args = append(args, r.String())
			argIndex++
		}
		conditions = append(conditions, fmt.Sprintf("result IN (%s)", strings.Join(placeholders, ", ")))
	}

	if len(filter.Severities) > 0 {
		placeholders := make([]string, len(filter.Severities))
		for i, sev := range filter.Severities {
			placeholders[i] = fmt.Sprintf("$%d", argIndex)
			args = append(args, sev.String())
			argIndex++
		}
		conditions = append(conditions, fmt.Sprintf("severity IN (%s)", strings.Join(placeholders, ", ")))
	}

	if filter.RequestID != nil {
		conditions = append(conditions, fmt.Sprintf("request_id = $%d", argIndex))
		args = append(args, *filter.RequestID)
		argIndex++
	}

	if filter.SessionID != nil {
		conditions = append(conditions, fmt.Sprintf("session_id = $%d", argIndex))
		args = append(args, *filter.SessionID)
		argIndex++
	}

	if filter.Since != nil {
		conditions = append(conditions, fmt.Sprintf("logged_at >= $%d", argIndex))
		args = append(args, *filter.Since)
		argIndex++
	}

	if filter.Until != nil {
		conditions = append(conditions, fmt.Sprintf("logged_at <= $%d", argIndex))
		args = append(args, *filter.Until)
		argIndex++
	}

	if filter.SearchTerm != nil && *filter.SearchTerm != "" {
		conditions = append(conditions, fmt.Sprintf(
			"to_tsvector('english', COALESCE(message, '') || ' ' || COALESCE(resource_name, '') || ' ' || COALESCE(actor_email, '')) @@ plainto_tsquery('english', $%d)",
			argIndex,
		))
		args = append(args, *filter.SearchTerm)
		argIndex++
	}

	if filter.ExcludeSystem {
		conditions = append(conditions, fmt.Sprintf("actor_email != $%d", argIndex))
		args = append(args, "System")
		argIndex++
	}

	return strings.Join(conditions, " AND "), args
}

// nullableID converts a *shared.ID to sql.NullString.
func nullableID(id *shared.ID) sql.NullString {
	if id == nil || id.IsZero() {
		return sql.NullString{}
	}
	return sql.NullString{String: id.String(), Valid: true}
}

// ────────────────────────────────────────────────────────────────────
// Audit hash-chain (migration 000154)
//
// These three methods back the tamper-evident audit_log_chain side
// table. Callers must ensure the audit_logs row exists before
// AppendChainEntry — the FK on audit_log_chain.audit_log_id enforces
// this at the database level too.
// ────────────────────────────────────────────────────────────────────

// LatestChainHash returns the newest chain hash for the tenant, or ""
// when the tenant has no chain entries yet.
func (r *AuditRepository) LatestChainHash(ctx context.Context, tenantID shared.ID) (string, error) {
	const q = `
		SELECT hash
		  FROM audit_log_chain
		 WHERE tenant_id = $1
		 ORDER BY chain_position DESC
		 LIMIT 1
	`
	var hash string
	err := r.db.QueryRowContext(ctx, q, tenantID.String()).Scan(&hash)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", nil
		}
		return "", fmt.Errorf("latest chain hash: %w", err)
	}
	return hash, nil
}

// AppendChainEntry inserts a new chain row. ON CONFLICT DO NOTHING so
// accidental retries don't duplicate the entry (the PK is
// audit_log_id).
func (r *AuditRepository) AppendChainEntry(ctx context.Context, e audit.ChainEntry) error {
	const q = `
		INSERT INTO audit_log_chain (audit_log_id, tenant_id, prev_hash, hash)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (audit_log_id) DO NOTHING
	`
	_, err := r.db.ExecContext(ctx, q,
		e.AuditLogID.String(),
		e.TenantID.String(),
		e.PrevHash,
		e.Hash,
	)
	if err != nil {
		return fmt.Errorf("append chain entry: %w", err)
	}
	return nil
}

// ListChainEntries returns chain rows ordered by position ASC. Used by
// the verify endpoint to walk the chain.
func (r *AuditRepository) ListChainEntries(ctx context.Context, tenantID shared.ID, limit int) ([]audit.ChainEntry, error) {
	if limit <= 0 {
		limit = 1000
	}
	const q = `
		SELECT audit_log_id, tenant_id, prev_hash, hash, chain_position, created_at
		  FROM audit_log_chain
		 WHERE tenant_id = $1
		 ORDER BY chain_position ASC
		 LIMIT $2
	`
	rows, err := r.db.QueryContext(ctx, q, tenantID.String(), limit)
	if err != nil {
		return nil, fmt.Errorf("list chain entries: %w", err)
	}
	defer func() { _ = rows.Close() }()

	out := make([]audit.ChainEntry, 0, limit)
	for rows.Next() {
		var (
			auditLogID, tid string
			e               audit.ChainEntry
		)
		if err := rows.Scan(&auditLogID, &tid, &e.PrevHash, &e.Hash, &e.ChainPosition, &e.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan chain entry: %w", err)
		}
		if id, err := shared.IDFromString(auditLogID); err == nil {
			e.AuditLogID = id
		}
		if id, err := shared.IDFromString(tid); err == nil {
			e.TenantID = id
		}
		out = append(out, e)
	}
	return out, rows.Err()
}
