package postgres

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/openctemio/api/pkg/domain/command"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/pagination"
)

// NullableJSON implements driver.Valuer for nullable JSON columns.
// When the underlying data is empty/nil, it returns NULL to the database.
type NullableJSON []byte

// Value implements driver.Valuer interface.
func (n NullableJSON) Value() (driver.Value, error) {
	if len(n) == 0 {
		return nil, nil
	}
	return []byte(n), nil
}

// CommandRepository implements command.Repository using PostgreSQL.
type CommandRepository struct {
	db *DB
}

// NewCommandRepository creates a new CommandRepository.
func NewCommandRepository(db *DB) *CommandRepository {
	return &CommandRepository{db: db}
}

// Create persists a new command.
func (r *CommandRepository) Create(ctx context.Context, cmd *command.Command) error {
	query := `
		INSERT INTO commands (
			id, tenant_id, agent_id, type, priority, payload,
			status, error_message,
			created_at, expires_at, acknowledged_at, started_at, completed_at,
			result, scheduled_at, schedule_id, step_run_id,
			is_platform_job, platform_agent_id,
			auth_token_hash, auth_token_prefix, auth_token_expires_at,
			queue_priority, queued_at, dispatch_attempts
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25)
	`

	_, err := r.db.ExecContext(ctx, query,
		cmd.ID.String(),
		cmd.TenantID.String(),
		nullIDString(cmd.AgentID),
		string(cmd.Type),
		string(cmd.Priority),
		cmd.Payload,
		string(cmd.Status),
		cmd.ErrorMessage,
		cmd.CreatedAt,
		nullTime(cmd.ExpiresAt),
		nullTime(cmd.AcknowledgedAt),
		nullTime(cmd.StartedAt),
		nullTime(cmd.CompletedAt),
		nullJSON(cmd.Result),
		nullTime(cmd.ScheduledAt),
		nullIDString(cmd.ScheduleID),
		nullIDString(cmd.StepRunID),
		cmd.IsPlatformJob,
		nullIDString(cmd.PlatformAgentID),
		nullString(cmd.AuthTokenHash),
		nullString(cmd.AuthTokenPrefix),
		nullTime(cmd.AuthTokenExpiresAt),
		cmd.QueuePriority,
		nullTime(cmd.QueuedAt),
		cmd.DispatchAttempts,
	)

	if err != nil {
		if isUniqueViolation(err) {
			return shared.NewDomainError("ALREADY_EXISTS", "command already exists", shared.ErrAlreadyExists)
		}
		return fmt.Errorf("failed to create command: %w", err)
	}

	return nil
}

// GetByID retrieves a command by its ID.
func (r *CommandRepository) GetByID(ctx context.Context, id shared.ID) (*command.Command, error) {
	query := r.selectQuery() + " WHERE id = $1"
	row := r.db.QueryRowContext(ctx, query, id.String())
	return r.scanCommand(row)
}

// GetByTenantAndID retrieves a command by tenant and ID.
func (r *CommandRepository) GetByTenantAndID(ctx context.Context, tenantID, id shared.ID) (*command.Command, error) {
	query := r.selectQuery() + " WHERE tenant_id = $1 AND id = $2"
	row := r.db.QueryRowContext(ctx, query, tenantID.String(), id.String())
	return r.scanCommand(row)
}

// GetPendingForAgent retrieves pending commands for an agent.
func (r *CommandRepository) GetPendingForAgent(ctx context.Context, tenantID shared.ID, agentID *shared.ID, limit int) ([]*command.Command, error) {
	query := r.selectQuery() + `
		WHERE tenant_id = $1
		AND status = 'pending'
		AND (expires_at IS NULL OR expires_at > NOW())
		AND (scheduled_at IS NULL OR scheduled_at <= NOW())
	`

	args := []any{tenantID.String()}
	argIndex := 2

	if agentID != nil {
		query += fmt.Sprintf(" AND (agent_id = $%d OR agent_id IS NULL)", argIndex)
		args = append(args, agentID.String())
		argIndex++
	} else {
		query += " AND agent_id IS NULL"
	}

	query += fmt.Sprintf(`
		ORDER BY
			CASE priority
				WHEN 'critical' THEN 1
				WHEN 'high' THEN 2
				WHEN 'normal' THEN 3
				WHEN 'low' THEN 4
			END,
			created_at ASC
		LIMIT %d
	`, limit)

	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to get pending commands: %w", err)
	}
	defer rows.Close()

	var commands []*command.Command
	for rows.Next() {
		cmd, err := r.scanCommandFromRows(rows)
		if err != nil {
			return nil, err
		}
		commands = append(commands, cmd)
	}

	return commands, nil
}

// List lists commands with filters and pagination.
func (r *CommandRepository) List(ctx context.Context, filter command.Filter, page pagination.Pagination) (pagination.Result[*command.Command], error) {
	var result pagination.Result[*command.Command]

	baseQuery := r.selectQuery()
	countQuery := "SELECT COUNT(*) FROM commands"
	whereClause, args := r.buildWhereClause(filter)

	if whereClause != "" {
		baseQuery += " WHERE " + whereClause
		countQuery += " WHERE " + whereClause
	}

	// Get total count
	var total int64
	err := r.db.QueryRowContext(ctx, countQuery, args...).Scan(&total)
	if err != nil {
		return result, fmt.Errorf("failed to count commands: %w", err)
	}

	// Apply pagination
	offset := (page.Page - 1) * page.PerPage
	baseQuery += fmt.Sprintf(" ORDER BY created_at DESC LIMIT %d OFFSET %d", page.PerPage, offset)

	rows, err := r.db.QueryContext(ctx, baseQuery, args...)
	if err != nil {
		return result, fmt.Errorf("failed to list commands: %w", err)
	}
	defer rows.Close()

	var commands []*command.Command
	for rows.Next() {
		cmd, err := r.scanCommandFromRows(rows)
		if err != nil {
			return result, err
		}
		commands = append(commands, cmd)
	}

	return pagination.NewResult(commands, total, page), nil
}

// Update updates a command.
func (r *CommandRepository) Update(ctx context.Context, cmd *command.Command) error {
	query := `
		UPDATE commands
		SET agent_id = $2, type = $3, priority = $4, payload = $5,
		    status = $6, error_message = $7,
		    expires_at = $8, acknowledged_at = $9, started_at = $10, completed_at = $11,
		    result = $12, scheduled_at = $13, schedule_id = $14,
		    is_platform_job = $15, platform_agent_id = $16,
		    auth_token_hash = $17, auth_token_prefix = $18, auth_token_expires_at = $19,
		    queue_priority = $20, queued_at = $21, dispatch_attempts = $22
		WHERE id = $1
	`

	result, err := r.db.ExecContext(ctx, query,
		cmd.ID.String(),
		nullIDString(cmd.AgentID),
		string(cmd.Type),
		string(cmd.Priority),
		cmd.Payload,
		string(cmd.Status),
		cmd.ErrorMessage,
		nullTime(cmd.ExpiresAt),
		nullTime(cmd.AcknowledgedAt),
		nullTime(cmd.StartedAt),
		nullTime(cmd.CompletedAt),
		nullJSON(cmd.Result),
		nullTime(cmd.ScheduledAt),
		nullIDString(cmd.ScheduleID),
		cmd.IsPlatformJob,
		nullIDString(cmd.PlatformAgentID),
		nullString(cmd.AuthTokenHash),
		nullString(cmd.AuthTokenPrefix),
		nullTime(cmd.AuthTokenExpiresAt),
		cmd.QueuePriority,
		nullTime(cmd.QueuedAt),
		cmd.DispatchAttempts,
	)

	if err != nil {
		return fmt.Errorf("failed to update command: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return shared.ErrNotFound
	}

	return nil
}

// Delete deletes a command.
func (r *CommandRepository) Delete(ctx context.Context, id shared.ID) error {
	query := "DELETE FROM commands WHERE id = $1"
	result, err := r.db.ExecContext(ctx, query, id.String())
	if err != nil {
		return fmt.Errorf("failed to delete command: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return shared.ErrNotFound
	}

	return nil
}

// ExpireOldCommands expires commands that have passed their expiration time.
func (r *CommandRepository) ExpireOldCommands(ctx context.Context) (int64, error) {
	query := `
		UPDATE commands
		SET status = 'expired'
		WHERE status = 'pending'
		AND expires_at IS NOT NULL
		AND expires_at < NOW()
	`

	result, err := r.db.ExecContext(ctx, query)
	if err != nil {
		return 0, fmt.Errorf("failed to expire commands: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	return rowsAffected, nil
}

func (r *CommandRepository) selectQuery() string {
	return `
		SELECT id, tenant_id, agent_id, type, priority, payload,
		       status, error_message,
		       created_at, expires_at, acknowledged_at, started_at, completed_at,
		       result, scheduled_at, schedule_id, step_run_id,
		       is_platform_job, platform_agent_id,
		       auth_token_hash, auth_token_prefix, auth_token_expires_at,
		       queue_priority, queued_at, dispatch_attempts
		FROM commands
	`
}

func (r *CommandRepository) buildWhereClause(filter command.Filter) (string, []any) {
	var conditions []string
	var args []any
	argIndex := 1

	if filter.TenantID != nil {
		conditions = append(conditions, fmt.Sprintf("tenant_id = $%d", argIndex))
		args = append(args, filter.TenantID.String())
		argIndex++
	}

	if filter.AgentID != nil {
		conditions = append(conditions, fmt.Sprintf("agent_id = $%d", argIndex))
		args = append(args, filter.AgentID.String())
		argIndex++
	}

	if filter.Type != nil {
		conditions = append(conditions, fmt.Sprintf("type = $%d", argIndex))
		args = append(args, string(*filter.Type))
		argIndex++
	}

	if filter.Status != nil {
		conditions = append(conditions, fmt.Sprintf("status = $%d", argIndex))
		args = append(args, string(*filter.Status))
		argIndex++
	}

	if filter.Priority != nil {
		conditions = append(conditions, fmt.Sprintf("priority = $%d", argIndex))
		args = append(args, string(*filter.Priority))
		argIndex++
	}

	// Platform job filters (v3.2)
	if filter.IsPlatformJob != nil {
		conditions = append(conditions, fmt.Sprintf("is_platform_job = $%d", argIndex))
		args = append(args, *filter.IsPlatformJob)
		argIndex++
	}

	// OSS Edition: PlatformAgentID filter not supported
	// if filter.PlatformAgentID != nil { ... }

	if len(conditions) == 0 {
		return "", nil
	}

	return strings.Join(conditions, " AND "), args
}

// scanCommand scans a command from a single row.
func (r *CommandRepository) scanCommand(row *sql.Row) (*command.Command, error) {
	cmd := &command.Command{}
	var (
		id                 string
		tenantID           string
		agentID            sql.NullString
		cmdType            string
		priority           string
		payload            []byte
		status             string
		expiresAt          sql.NullTime
		acknowledgedAt     sql.NullTime
		startedAt          sql.NullTime
		completedAt        sql.NullTime
		result             []byte
		scheduledAt        sql.NullTime
		scheduleID         sql.NullString
		stepRunID          sql.NullString
		isPlatformJob      bool
		platformAgentID    sql.NullString
		authTokenHash      sql.NullString
		authTokenPrefix    sql.NullString
		authTokenExpiresAt sql.NullTime
		queuePriority      int
		queuedAt           sql.NullTime
		dispatchAttempts   int
	)

	var errorMessage sql.NullString

	err := row.Scan(
		&id,
		&tenantID,
		&agentID,
		&cmdType,
		&priority,
		&payload,
		&status,
		&errorMessage,
		&cmd.CreatedAt,
		&expiresAt,
		&acknowledgedAt,
		&startedAt,
		&completedAt,
		&result,
		&scheduledAt,
		&scheduleID,
		&stepRunID,
		&isPlatformJob,
		&platformAgentID,
		&authTokenHash,
		&authTokenPrefix,
		&authTokenExpiresAt,
		&queuePriority,
		&queuedAt,
		&dispatchAttempts,
	)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, shared.ErrNotFound
		}
		return nil, fmt.Errorf("failed to scan command: %w", err)
	}

	cmd.ID, _ = shared.IDFromString(id)
	cmd.TenantID, _ = shared.IDFromString(tenantID)
	cmd.Type = command.CommandType(cmdType)
	cmd.Priority = command.CommandPriority(priority)
	cmd.Status = command.CommandStatus(status)
	cmd.Payload = payload
	cmd.ErrorMessage = errorMessage.String
	cmd.IsPlatformJob = isPlatformJob
	cmd.QueuePriority = queuePriority
	cmd.DispatchAttempts = dispatchAttempts

	if agentID.Valid {
		wid, _ := shared.IDFromString(agentID.String)
		cmd.AgentID = &wid
	}

	if expiresAt.Valid {
		cmd.ExpiresAt = &expiresAt.Time
	}

	if acknowledgedAt.Valid {
		cmd.AcknowledgedAt = &acknowledgedAt.Time
	}

	if startedAt.Valid {
		cmd.StartedAt = &startedAt.Time
	}

	if completedAt.Valid {
		cmd.CompletedAt = &completedAt.Time
	}

	if len(result) > 0 {
		cmd.Result = result
	}

	if scheduledAt.Valid {
		cmd.ScheduledAt = &scheduledAt.Time
	}

	if scheduleID.Valid {
		sid, _ := shared.IDFromString(scheduleID.String)
		cmd.ScheduleID = &sid
	}

	if stepRunID.Valid {
		srid, _ := shared.IDFromString(stepRunID.String)
		cmd.StepRunID = &srid
	}

	if platformAgentID.Valid {
		paid, _ := shared.IDFromString(platformAgentID.String)
		cmd.PlatformAgentID = &paid
	}

	if authTokenHash.Valid {
		cmd.AuthTokenHash = authTokenHash.String
	}

	if authTokenPrefix.Valid {
		cmd.AuthTokenPrefix = authTokenPrefix.String
	}

	if authTokenExpiresAt.Valid {
		cmd.AuthTokenExpiresAt = &authTokenExpiresAt.Time
	}

	if queuedAt.Valid {
		cmd.QueuedAt = &queuedAt.Time
	}

	return cmd, nil
}

// scanCommandFromRows scans a command from a result set row.
func (r *CommandRepository) scanCommandFromRows(rows *sql.Rows) (*command.Command, error) {
	cmd := &command.Command{}
	var (
		id                 string
		tenantID           string
		agentID            sql.NullString
		cmdType            string
		priority           string
		payload            []byte
		status             string
		expiresAt          sql.NullTime
		acknowledgedAt     sql.NullTime
		startedAt          sql.NullTime
		completedAt        sql.NullTime
		result             []byte
		scheduledAt        sql.NullTime
		scheduleID         sql.NullString
		stepRunID          sql.NullString
		isPlatformJob      bool
		platformAgentID    sql.NullString
		authTokenHash      sql.NullString
		authTokenPrefix    sql.NullString
		authTokenExpiresAt sql.NullTime
		queuePriority      int
		queuedAt           sql.NullTime
		dispatchAttempts   int
	)

	var errorMessage sql.NullString

	err := rows.Scan(
		&id,
		&tenantID,
		&agentID,
		&cmdType,
		&priority,
		&payload,
		&status,
		&errorMessage,
		&cmd.CreatedAt,
		&expiresAt,
		&acknowledgedAt,
		&startedAt,
		&completedAt,
		&result,
		&scheduledAt,
		&scheduleID,
		&stepRunID,
		&isPlatformJob,
		&platformAgentID,
		&authTokenHash,
		&authTokenPrefix,
		&authTokenExpiresAt,
		&queuePriority,
		&queuedAt,
		&dispatchAttempts,
	)

	if err != nil {
		return nil, fmt.Errorf("failed to scan command: %w", err)
	}

	cmd.ID, _ = shared.IDFromString(id)
	cmd.TenantID, _ = shared.IDFromString(tenantID)
	cmd.Type = command.CommandType(cmdType)
	cmd.Priority = command.CommandPriority(priority)
	cmd.Status = command.CommandStatus(status)
	cmd.Payload = payload
	cmd.ErrorMessage = errorMessage.String
	cmd.IsPlatformJob = isPlatformJob
	cmd.QueuePriority = queuePriority
	cmd.DispatchAttempts = dispatchAttempts

	if agentID.Valid {
		wid, _ := shared.IDFromString(agentID.String)
		cmd.AgentID = &wid
	}

	if expiresAt.Valid {
		cmd.ExpiresAt = &expiresAt.Time
	}

	if acknowledgedAt.Valid {
		cmd.AcknowledgedAt = &acknowledgedAt.Time
	}

	if startedAt.Valid {
		cmd.StartedAt = &startedAt.Time
	}

	if completedAt.Valid {
		cmd.CompletedAt = &completedAt.Time
	}

	if len(result) > 0 {
		cmd.Result = result
	}

	if scheduledAt.Valid {
		cmd.ScheduledAt = &scheduledAt.Time
	}

	if scheduleID.Valid {
		sid, _ := shared.IDFromString(scheduleID.String)
		cmd.ScheduleID = &sid
	}

	if stepRunID.Valid {
		srid, _ := shared.IDFromString(stepRunID.String)
		cmd.StepRunID = &srid
	}

	if platformAgentID.Valid {
		paid, _ := shared.IDFromString(platformAgentID.String)
		cmd.PlatformAgentID = &paid
	}

	if authTokenHash.Valid {
		cmd.AuthTokenHash = authTokenHash.String
	}

	if authTokenPrefix.Valid {
		cmd.AuthTokenPrefix = authTokenPrefix.String
	}

	if authTokenExpiresAt.Valid {
		cmd.AuthTokenExpiresAt = &authTokenExpiresAt.Time
	}

	if queuedAt.Valid {
		cmd.QueuedAt = &queuedAt.Time
	}

	return cmd, nil
}

// Helper functions for null handling
func nullIDString(id *shared.ID) sql.NullString {
	if id == nil {
		return sql.NullString{}
	}
	return sql.NullString{String: id.String(), Valid: true}
}

func nullJSON(data json.RawMessage) NullableJSON {
	return NullableJSON(data)
}

// FindExpired finds commands that have expired but not yet marked as expired.
func (r *CommandRepository) FindExpired(ctx context.Context) ([]*command.Command, error) {
	query := r.selectQuery() + `
		WHERE status IN ('pending', 'acknowledged')
		AND expires_at IS NOT NULL
		AND expires_at < NOW()
		ORDER BY expires_at ASC
		LIMIT 100
	`

	rows, err := r.db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to find expired commands: %w", err)
	}
	defer rows.Close()

	var commands []*command.Command
	for rows.Next() {
		cmd, err := r.scanCommandFromRows(rows)
		if err != nil {
			return nil, err
		}
		commands = append(commands, cmd)
	}

	return commands, nil
}

// =============================================================================
// Helper functions for platform job fields
// =============================================================================

func nullInt(i int) sql.NullInt32 {
	if i == 0 {
		return sql.NullInt32{}
	}
	//nolint:gosec // G115: used for HTTP status codes which are always within int32 range
	return sql.NullInt32{Int32: int32(i), Valid: true}
}

// =============================================================================
// Platform Job Queue Methods (v3.2)
// =============================================================================

// GetByAuthTokenHash retrieves a command by auth token hash.
func (r *CommandRepository) GetByAuthTokenHash(ctx context.Context, hash string) (*command.Command, error) {
	query := r.selectQuery() + " WHERE auth_token_hash = $1 AND is_platform_job = TRUE"
	row := r.db.QueryRowContext(ctx, query, hash)
	return r.scanCommand(row)
}

// CountActivePlatformJobsByTenant counts active platform jobs for a tenant.
func (r *CommandRepository) CountActivePlatformJobsByTenant(ctx context.Context, tenantID shared.ID) (int, error) {
	query := `
		SELECT COUNT(*)
		FROM commands
		WHERE tenant_id = $1
		AND is_platform_job = TRUE
		AND status IN ('acknowledged', 'running')
	`
	var count int
	err := r.db.QueryRowContext(ctx, query, tenantID.String()).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("failed to count active platform jobs: %w", err)
	}
	return count, nil
}

// CountQueuedPlatformJobsByTenant counts queued (pending, not dispatched) platform jobs for a tenant.
func (r *CommandRepository) CountQueuedPlatformJobsByTenant(ctx context.Context, tenantID shared.ID) (int, error) {
	query := `
		SELECT COUNT(*)
		FROM commands
		WHERE tenant_id = $1
		AND is_platform_job = TRUE
		AND status = 'pending'
		AND platform_agent_id IS NULL
	`
	var count int
	err := r.db.QueryRowContext(ctx, query, tenantID.String()).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("failed to count queued platform jobs: %w", err)
	}
	return count, nil
}

// CountQueuedPlatformJobs counts all queued platform jobs across all tenants.
func (r *CommandRepository) CountQueuedPlatformJobs(ctx context.Context) (int, error) {
	query := `
		SELECT COUNT(*)
		FROM commands
		WHERE is_platform_job = TRUE
		AND status = 'pending'
		AND platform_agent_id IS NULL
	`
	var count int
	err := r.db.QueryRowContext(ctx, query).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("failed to count queued platform jobs: %w", err)
	}
	return count, nil
}

// GetQueuedPlatformJobs retrieves queued platform jobs ordered by priority.
func (r *CommandRepository) GetQueuedPlatformJobs(ctx context.Context, limit int) ([]*command.Command, error) {
	query := r.selectQuery() + `
		WHERE is_platform_job = TRUE
		AND status = 'pending'
		AND platform_agent_id IS NULL
		ORDER BY queue_priority DESC, queued_at ASC
		LIMIT $1
	`

	rows, err := r.db.QueryContext(ctx, query, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to get queued platform jobs: %w", err)
	}
	defer rows.Close()

	var commands []*command.Command
	for rows.Next() {
		cmd, err := r.scanCommandFromRows(rows)
		if err != nil {
			return nil, err
		}
		commands = append(commands, cmd)
	}

	return commands, nil
}

// GetNextPlatformJob atomically claims the next job from the queue for an agent.
// Uses database function get_next_platform_job for atomic operation with FOR UPDATE SKIP LOCKED.
func (r *CommandRepository) GetNextPlatformJob(ctx context.Context, agentID shared.ID, capabilities []string, tools []string) (*command.Command, error) {
	query := `SELECT * FROM get_next_platform_job($1, $2, $3)`

	var (
		commandID    sql.NullString
		tenantID     sql.NullString
		commandType  sql.NullString
		payload      []byte
		queuedAt     sql.NullTime
		authTokenPfx sql.NullString
	)

	err := r.db.QueryRowContext(ctx, query,
		agentID.String(),
		capabilities,
		tools,
	).Scan(&commandID, &tenantID, &commandType, &payload, &queuedAt, &authTokenPfx)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil // No job available
		}
		return nil, fmt.Errorf("failed to get next platform job: %w", err)
	}

	// If no job found, database function returns NULL
	if !commandID.Valid {
		return nil, nil
	}

	// Fetch the full command object
	id, _ := shared.IDFromString(commandID.String)
	return r.GetByID(ctx, id)
}

// UpdateQueuePriorities recalculates queue priorities for all pending platform jobs.
func (r *CommandRepository) UpdateQueuePriorities(ctx context.Context) (int64, error) {
	query := `
		UPDATE commands
		SET queue_priority = calculate_queue_priority(priority, queued_at, tenant_id)
		WHERE is_platform_job = TRUE
		AND status = 'pending'
		AND platform_agent_id IS NULL
	`

	result, err := r.db.ExecContext(ctx, query)
	if err != nil {
		return 0, fmt.Errorf("failed to update queue priorities: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	return rowsAffected, nil
}

// RecoverStuckJobs returns stuck platform jobs to the queue.
// Uses a database function for atomic recovery.
func (r *CommandRepository) RecoverStuckJobs(ctx context.Context, stuckThresholdMinutes int, maxRetries int) (int64, error) {
	query := `SELECT recover_stuck_platform_jobs($1::INTEGER)`

	var recovered int64
	err := r.db.QueryRowContext(ctx, query, stuckThresholdMinutes).Scan(&recovered)
	if err != nil {
		return 0, fmt.Errorf("failed to recover stuck platform jobs: %w", err)
	}

	return recovered, nil
}

// ExpireOldPlatformJobs expires platform jobs that have been in queue too long.
func (r *CommandRepository) ExpireOldPlatformJobs(ctx context.Context, maxQueueMinutes int) (int64, error) {
	query := `
		UPDATE commands
		SET status = 'expired', error_message = 'Job expired in queue'
		WHERE is_platform_job = TRUE
		AND status = 'pending'
		AND queued_at IS NOT NULL
		AND queued_at < NOW() - ($1 || ' minutes')::INTERVAL
	`

	result, err := r.db.ExecContext(ctx, query, maxQueueMinutes)
	if err != nil {
		return 0, fmt.Errorf("failed to expire old platform jobs: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	return rowsAffected, nil
}

// GetQueuePosition gets the queue position for a specific command.
func (r *CommandRepository) GetQueuePosition(ctx context.Context, commandID shared.ID) (*command.QueuePosition, error) {
	query := `
		WITH ranked AS (
			SELECT id, queue_priority, queued_at,
				   ROW_NUMBER() OVER (ORDER BY queue_priority DESC, queued_at ASC) as position
			FROM commands
			WHERE is_platform_job = TRUE
			AND status = 'pending'
			AND platform_agent_id IS NULL
		),
		total AS (
			SELECT COUNT(*) as total_count
			FROM commands
			WHERE is_platform_job = TRUE
			AND status = 'pending'
			AND platform_agent_id IS NULL
		)
		SELECT r.position, t.total_count, r.queue_priority
		FROM ranked r, total t
		WHERE r.id = $1
	`

	var pos command.QueuePosition
	err := r.db.QueryRowContext(ctx, query, commandID.String()).Scan(
		&pos.Position,
		&pos.TotalQueued,
		&pos.Priority,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil // Not in queue
		}
		return nil, fmt.Errorf("failed to get queue position: %w", err)
	}

	return &pos, nil
}

// ListPlatformJobsByTenant lists platform jobs for a tenant with pagination.
func (r *CommandRepository) ListPlatformJobsByTenant(ctx context.Context, tenantID shared.ID, page pagination.Pagination) (pagination.Result[*command.Command], error) {
	var result pagination.Result[*command.Command]

	baseQuery := r.selectQuery() + " WHERE tenant_id = $1 AND is_platform_job = TRUE"
	countQuery := "SELECT COUNT(*) FROM commands WHERE tenant_id = $1 AND is_platform_job = TRUE"

	// Get total count
	var total int64
	err := r.db.QueryRowContext(ctx, countQuery, tenantID.String()).Scan(&total)
	if err != nil {
		return result, fmt.Errorf("failed to count platform jobs: %w", err)
	}

	// Apply pagination
	offset := (page.Page - 1) * page.PerPage
	baseQuery += fmt.Sprintf(" ORDER BY created_at DESC LIMIT %d OFFSET %d", page.PerPage, offset)

	rows, err := r.db.QueryContext(ctx, baseQuery, tenantID.String())
	if err != nil {
		return result, fmt.Errorf("failed to list platform jobs: %w", err)
	}
	defer rows.Close()

	var commands []*command.Command
	for rows.Next() {
		cmd, err := r.scanCommandFromRows(rows)
		if err != nil {
			return result, err
		}
		commands = append(commands, cmd)
	}

	return pagination.NewResult(commands, total, page), nil
}

// ListPlatformJobsAdmin lists platform jobs across all tenants (admin only).
func (r *CommandRepository) ListPlatformJobsAdmin(ctx context.Context, agentID, tenantID *shared.ID, status *command.CommandStatus, page pagination.Pagination) (pagination.Result[*command.Command], error) {
	var result pagination.Result[*command.Command]
	var conditions []string
	var args []any
	argIndex := 1

	conditions = append(conditions, "is_platform_job = TRUE")

	if agentID != nil {
		conditions = append(conditions, fmt.Sprintf("platform_agent_id = $%d", argIndex))
		args = append(args, agentID.String())
		argIndex++
	}

	if tenantID != nil {
		conditions = append(conditions, fmt.Sprintf("tenant_id = $%d", argIndex))
		args = append(args, tenantID.String())
		argIndex++
	}

	if status != nil {
		conditions = append(conditions, fmt.Sprintf("status = $%d", argIndex))
		args = append(args, string(*status))
		argIndex++
	}

	whereClause := strings.Join(conditions, " AND ")
	baseQuery := r.selectQuery() + " WHERE " + whereClause
	countQuery := "SELECT COUNT(*) FROM commands WHERE " + whereClause

	// Get total count
	var total int64
	err := r.db.QueryRowContext(ctx, countQuery, args...).Scan(&total)
	if err != nil {
		return result, fmt.Errorf("failed to count platform jobs: %w", err)
	}

	// Apply pagination
	offset := (page.Page - 1) * page.PerPage
	baseQuery += fmt.Sprintf(" ORDER BY created_at DESC LIMIT %d OFFSET %d", page.PerPage, offset)

	rows, err := r.db.QueryContext(ctx, baseQuery, args...)
	if err != nil {
		return result, fmt.Errorf("failed to list platform jobs: %w", err)
	}
	defer rows.Close()

	var commands []*command.Command
	for rows.Next() {
		cmd, err := r.scanCommandFromRows(rows)
		if err != nil {
			return result, err
		}
		commands = append(commands, cmd)
	}

	return pagination.NewResult(commands, total, page), nil
}

// GetPlatformJobsByAgent lists platform jobs assigned to an agent.
func (r *CommandRepository) GetPlatformJobsByAgent(ctx context.Context, agentID shared.ID, status *command.CommandStatus) ([]*command.Command, error) {
	query := r.selectQuery() + " WHERE platform_agent_id = $1 AND is_platform_job = TRUE"
	args := []any{agentID.String()}

	if status != nil {
		query += " AND status = $2"
		args = append(args, string(*status))
	}

	query += " ORDER BY created_at DESC"

	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to get platform jobs by agent: %w", err)
	}
	defer rows.Close()

	var commands []*command.Command
	for rows.Next() {
		cmd, err := r.scanCommandFromRows(rows)
		if err != nil {
			return nil, err
		}
		commands = append(commands, cmd)
	}

	return commands, nil
}

// =============================================================================
// Tenant Command Recovery Methods
// =============================================================================

// RecoverStuckTenantCommands returns stuck tenant commands to the pool.
// A command is stuck if it's assigned to an offline agent or hasn't been picked up.
// Uses a database function for atomic recovery.
// Returns the number of commands recovered.
func (r *CommandRepository) RecoverStuckTenantCommands(ctx context.Context, stuckThresholdMinutes int, maxRetries int) (int64, error) {
	query := `SELECT recover_stuck_tenant_commands($1::INTEGER, $2::INTEGER)`

	var recovered int64
	err := r.db.QueryRowContext(ctx, query, stuckThresholdMinutes, maxRetries).Scan(&recovered)
	if err != nil {
		return 0, fmt.Errorf("failed to recover stuck tenant commands: %w", err)
	}

	return recovered, nil
}

// FailExhaustedCommands marks commands that exceeded max retries as failed.
// Uses a database function for atomic operation.
// Returns the number of commands failed.
func (r *CommandRepository) FailExhaustedCommands(ctx context.Context, maxRetries int) (int64, error) {
	query := `SELECT fail_exhausted_commands($1::INTEGER)`

	var failed int64
	err := r.db.QueryRowContext(ctx, query, maxRetries).Scan(&failed)
	if err != nil {
		return 0, fmt.Errorf("failed to mark exhausted commands as failed: %w", err)
	}

	return failed, nil
}

// GetStatsByTenant returns aggregated command statistics for a tenant in a single query.
// This is optimized to avoid N queries when fetching stats.
func (r *CommandRepository) GetStatsByTenant(ctx context.Context, tenantID shared.ID) (command.CommandStats, error) {
	var stats command.CommandStats

	// Single aggregation query - much more efficient than N queries per status
	query := `
		SELECT
			COUNT(*) as total,
			COUNT(*) FILTER (WHERE status = 'pending') as pending,
			COUNT(*) FILTER (WHERE status IN ('running', 'acknowledged')) as running,
			COUNT(*) FILTER (WHERE status = 'completed') as completed,
			COUNT(*) FILTER (WHERE status IN ('failed', 'expired')) as failed,
			COUNT(*) FILTER (WHERE status = 'canceled') as canceled
		FROM commands
		WHERE tenant_id = $1
	`

	err := r.db.QueryRowContext(ctx, query, tenantID.String()).Scan(
		&stats.Total,
		&stats.Pending,
		&stats.Running,
		&stats.Completed,
		&stats.Failed,
		&stats.Canceled,
	)
	if err != nil {
		return stats, fmt.Errorf("failed to get command stats: %w", err)
	}

	return stats, nil
}
