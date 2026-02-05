package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/lib/pq"

	"github.com/openctemio/api/pkg/domain/agent"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/pagination"
)

// AgentRepository implements agent.Repository using PostgreSQL.
type AgentRepository struct {
	db *DB
}

// NewAgentRepository creates a new AgentRepository.
func NewAgentRepository(db *DB) *AgentRepository {
	return &AgentRepository{db: db}
}

// Create persists a new agent.
func (r *AgentRepository) Create(ctx context.Context, a *agent.Agent) error {
	metadata, err := json.Marshal(a.Metadata)
	if err != nil {
		return fmt.Errorf("failed to marshal metadata: %w", err)
	}

	labels, err := json.Marshal(a.Labels)
	if err != nil {
		return fmt.Errorf("failed to marshal labels: %w", err)
	}

	config, err := json.Marshal(a.Config)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	query := `
		INSERT INTO agents (
			id, tenant_id, name, type, description, capabilities, tools,
			execution_mode, status, health, status_message,
			is_platform_agent,
			api_key_hash, api_key_prefix, metadata, labels, config,
			version, hostname, ip_address,
			max_concurrent_jobs, current_jobs,
			last_seen_at, last_error_at, total_findings, total_scans, error_count,
			created_at, updated_at
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25, $26, $27, $28, $29)
	`

	var ipAddr sql.NullString
	if a.IPAddress != nil {
		ipAddr = sql.NullString{String: a.IPAddress.String(), Valid: true}
	}

	_, err = r.db.ExecContext(ctx, query,
		a.ID.String(),
		a.TenantID.String(),
		a.Name,
		string(a.Type),
		a.Description,
		pq.Array(a.Capabilities),
		pq.Array(a.Tools),
		string(a.ExecutionMode),
		string(a.Status),
		string(a.Health),
		a.StatusMessage,
		a.IsPlatformAgent,
		a.APIKeyHash,
		a.APIKeyPrefix,
		metadata,
		labels,
		config,
		nullString(a.Version),
		nullString(a.Hostname),
		ipAddr,
		a.MaxConcurrentJobs,
		a.CurrentJobs,
		nullTime(a.LastSeenAt),
		nullTime(a.LastErrorAt),
		a.TotalFindings,
		a.TotalScans,
		a.ErrorCount,
		a.CreatedAt,
		a.UpdatedAt,
	)

	if err != nil {
		if isUniqueViolation(err) {
			return shared.NewDomainError("ALREADY_EXISTS", "agent already exists", shared.ErrAlreadyExists)
		}
		return fmt.Errorf("failed to create agent: %w", err)
	}

	return nil
}

// CountByTenant counts the number of tenant-owned agents (excluding platform agents).
// Used for enforcing agent limits per plan.
func (r *AgentRepository) CountByTenant(ctx context.Context, tenantID shared.ID) (int, error) {
	query := `
		SELECT COUNT(*)
		FROM agents
		WHERE tenant_id = $1 AND is_platform_agent = FALSE
	`
	var count int
	err := r.db.QueryRowContext(ctx, query, tenantID.String()).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("failed to count agents: %w", err)
	}
	return count, nil
}

// GetByID retrieves an agent by its ID.
func (r *AgentRepository) GetByID(ctx context.Context, id shared.ID) (*agent.Agent, error) {
	query := r.selectQuery() + " WHERE id = $1"
	row := r.db.QueryRowContext(ctx, query, id.String())
	return r.scanAgent(row)
}

// GetByTenantAndID retrieves an agent by tenant and ID.
func (r *AgentRepository) GetByTenantAndID(ctx context.Context, tenantID, id shared.ID) (*agent.Agent, error) {
	query := r.selectQuery() + " WHERE tenant_id = $1 AND id = $2"
	row := r.db.QueryRowContext(ctx, query, tenantID.String(), id.String())
	return r.scanAgent(row)
}

// GetByAPIKeyHash retrieves an agent by API key hash.
func (r *AgentRepository) GetByAPIKeyHash(ctx context.Context, hash string) (*agent.Agent, error) {
	query := r.selectQuery() + " WHERE api_key_hash = $1"
	row := r.db.QueryRowContext(ctx, query, hash)
	return r.scanAgent(row)
}

// List lists agents with filters and pagination.
func (r *AgentRepository) List(ctx context.Context, filter agent.Filter, page pagination.Pagination) (pagination.Result[*agent.Agent], error) {
	var result pagination.Result[*agent.Agent]

	baseQuery := r.selectQuery()
	countQuery := "SELECT COUNT(*) FROM agents"
	whereClause, args := r.buildWhereClause(filter)

	if whereClause != "" {
		baseQuery += " WHERE " + whereClause
		countQuery += " WHERE " + whereClause
	}

	// Get total count
	var total int64
	err := r.db.QueryRowContext(ctx, countQuery, args...).Scan(&total)
	if err != nil {
		return result, fmt.Errorf("failed to count agents: %w", err)
	}

	// Apply pagination
	offset := (page.Page - 1) * page.PerPage
	baseQuery += fmt.Sprintf(" ORDER BY created_at DESC LIMIT %d OFFSET %d", page.PerPage, offset)

	rows, err := r.db.QueryContext(ctx, baseQuery, args...)
	if err != nil {
		return result, fmt.Errorf("failed to list agents: %w", err)
	}
	defer rows.Close()

	var agents []*agent.Agent
	for rows.Next() {
		a, err := r.scanAgentFromRows(rows)
		if err != nil {
			return result, err
		}
		agents = append(agents, a)
	}

	return pagination.NewResult(agents, total, page), nil
}

// Update updates an agent.
func (r *AgentRepository) Update(ctx context.Context, a *agent.Agent) error {
	metadata, err := json.Marshal(a.Metadata)
	if err != nil {
		return fmt.Errorf("failed to marshal metadata: %w", err)
	}

	labels, err := json.Marshal(a.Labels)
	if err != nil {
		return fmt.Errorf("failed to marshal labels: %w", err)
	}

	config, err := json.Marshal(a.Config)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	query := `
		UPDATE agents
		SET name = $2, type = $3, description = $4, capabilities = $5, tools = $6,
		    execution_mode = $7, status = $8, health = $9, status_message = $10,
		    api_key_hash = $11, api_key_prefix = $12, metadata = $13, labels = $14, config = $15,
		    version = $16, hostname = $17, ip_address = $18,
		    cpu_percent = $19, memory_percent = $20, max_concurrent_jobs = $21, current_jobs = $22, region = $23,
		    disk_read_mbps = $24, disk_write_mbps = $25, network_rx_mbps = $26, network_tx_mbps = $27,
		    load_score = $28, metrics_updated_at = $29,
		    last_seen_at = $30, last_error_at = $31, total_findings = $32, total_scans = $33, error_count = $34,
		    updated_at = $35
		WHERE id = $1
	`

	var ipAddr sql.NullString
	if a.IPAddress != nil {
		ipAddr = sql.NullString{String: a.IPAddress.String(), Valid: true}
	}

	result, err := r.db.ExecContext(ctx, query,
		a.ID.String(),
		a.Name,
		string(a.Type),
		a.Description,
		pq.Array(a.Capabilities),
		pq.Array(a.Tools),
		string(a.ExecutionMode),
		string(a.Status),
		string(a.Health),
		a.StatusMessage,
		a.APIKeyHash,
		a.APIKeyPrefix,
		metadata,
		labels,
		config,
		nullString(a.Version),
		nullString(a.Hostname),
		ipAddr,
		a.CPUPercent,
		a.MemoryPercent,
		a.MaxConcurrentJobs,
		a.CurrentJobs,
		nullString(a.Region),
		a.DiskReadMBPS,
		a.DiskWriteMBPS,
		a.NetworkRxMBPS,
		a.NetworkTxMBPS,
		a.LoadScore,
		nullTime(a.MetricsUpdatedAt),
		nullTime(a.LastSeenAt),
		nullTime(a.LastErrorAt),
		a.TotalFindings,
		a.TotalScans,
		a.ErrorCount,
		a.UpdatedAt,
	)

	if err != nil {
		return fmt.Errorf("failed to update agent: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return shared.ErrNotFound
	}

	return nil
}

// Delete deletes an agent.
func (r *AgentRepository) Delete(ctx context.Context, id shared.ID) error {
	query := "DELETE FROM agents WHERE id = $1"
	result, err := r.db.ExecContext(ctx, query, id.String())
	if err != nil {
		return fmt.Errorf("failed to delete agent: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return shared.ErrNotFound
	}

	return nil
}

// UpdateLastSeen updates the last seen timestamp and sets health to online.
// Note: This updates Health (automatic), not Status (admin-controlled).
func (r *AgentRepository) UpdateLastSeen(ctx context.Context, id shared.ID) error {
	query := `
		UPDATE agents
		SET last_seen_at = NOW(),
		    health = 'online',
		    updated_at = NOW()
		WHERE id = $1
	`
	_, err := r.db.ExecContext(ctx, query, id.String())
	return err
}

// IncrementStats increments agent statistics.
func (r *AgentRepository) IncrementStats(ctx context.Context, id shared.ID, findings, scans, errors int64) error {
	query := `
		UPDATE agents
		SET total_findings = total_findings + $2,
		    total_scans = total_scans + $3,
		    error_count = error_count + $4,
		    updated_at = NOW()
		WHERE id = $1
	`
	_, err := r.db.ExecContext(ctx, query, id.String(), findings, scans, errors)
	return err
}

// FindByCapabilities finds agents with the given capabilities.
func (r *AgentRepository) FindByCapabilities(ctx context.Context, tenantID shared.ID, capabilities []string, tool string) ([]*agent.Agent, error) {
	query := r.selectQuery() + " WHERE tenant_id = $1 AND status = 'active'"
	args := []any{tenantID.String()}
	argIndex := 2

	if len(capabilities) > 0 {
		query += fmt.Sprintf(" AND capabilities @> $%d", argIndex)
		args = append(args, pq.Array(capabilities))
		argIndex++
	}

	if tool != "" {
		query += fmt.Sprintf(" AND $%d = ANY(tools)", argIndex)
		args = append(args, tool)
	}

	query += " ORDER BY current_jobs ASC, total_scans ASC" // Load balance by least loaded

	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to find agents: %w", err)
	}
	defer rows.Close()

	var agents []*agent.Agent
	for rows.Next() {
		a, err := r.scanAgentFromRows(rows)
		if err != nil {
			return nil, err
		}
		agents = append(agents, a)
	}

	return agents, nil
}

// FindAvailable finds available agents for a task.
func (r *AgentRepository) FindAvailable(ctx context.Context, tenantID shared.ID, capabilities []string, tool string) ([]*agent.Agent, error) {
	return r.FindByCapabilities(ctx, tenantID, capabilities, tool)
}

// FindAvailableWithTool finds the best available agent for a tool.
// Returns the least-loaded agent that has the required tool.
func (r *AgentRepository) FindAvailableWithTool(ctx context.Context, tenantID shared.ID, tool string) (*agent.Agent, error) {
	if tool == "" {
		// No specific tool required, return least-loaded active agent
		// Only select agents with health='online' (have sent heartbeat recently)
		// Exclude health='unknown' as those agents have never sent a heartbeat
		query := r.selectQuery() + `
			WHERE tenant_id = $1
			  AND status = 'active'
			  AND health = 'online'
			  AND current_jobs < max_concurrent_jobs
			ORDER BY current_jobs ASC, total_scans ASC
			LIMIT 1
		`
		rows, err := r.db.QueryContext(ctx, query, tenantID.String())
		if err != nil {
			return nil, fmt.Errorf("failed to find available agent: %w", err)
		}
		defer rows.Close()

		if rows.Next() {
			return r.scanAgentFromRows(rows)
		}
		return nil, nil
	}

	// Find agent with specific tool
	// Only select agents with health='online' (have sent heartbeat recently)
	query := r.selectQuery() + `
		WHERE tenant_id = $1
		  AND status = 'active'
		  AND health = 'online'
		  AND $2 = ANY(tools)
		  AND current_jobs < max_concurrent_jobs
		ORDER BY current_jobs ASC, total_scans ASC
		LIMIT 1
	`
	rows, err := r.db.QueryContext(ctx, query, tenantID.String(), tool)
	if err != nil {
		return nil, fmt.Errorf("failed to find agent with tool: %w", err)
	}
	defer rows.Close()

	if rows.Next() {
		return r.scanAgentFromRows(rows)
	}
	return nil, nil // No agent found with required tool
}

// FindAvailableWithCapacity finds daemon agents with available job capacity.
// Used for load balancing - returns agents sorted by load factor (least loaded first).
// Only returns agents that can receive jobs from server (daemon mode or worker/collector type).
// Only considers agents with health='online' (have sent heartbeat recently).
// Agents with health='unknown' are excluded as they have never sent a heartbeat.
func (r *AgentRepository) FindAvailableWithCapacity(ctx context.Context, tenantID shared.ID, capabilities []string, tool string) ([]*agent.Agent, error) {
	query := r.selectQuery() + `
		WHERE tenant_id = $1
		  AND status = 'active'
		  AND health = 'online'
		  AND current_jobs < max_concurrent_jobs
		  AND (execution_mode = 'daemon' OR type IN ('worker', 'collector'))
	`
	args := []any{tenantID.String()}
	argIndex := 2

	if len(capabilities) > 0 {
		query += fmt.Sprintf(" AND capabilities @> $%d", argIndex)
		args = append(args, pq.Array(capabilities))
		argIndex++
	}

	if tool != "" {
		query += fmt.Sprintf(" AND $%d = ANY(tools)", argIndex)
		args = append(args, tool)
	}

	// Order by load factor (current_jobs / max_concurrent_jobs) ascending
	query += " ORDER BY (current_jobs::float / NULLIF(max_concurrent_jobs, 0)) ASC, total_scans ASC"

	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to find agents with capacity: %w", err)
	}
	defer rows.Close()

	var agents []*agent.Agent
	for rows.Next() {
		a, err := r.scanAgentFromRows(rows)
		if err != nil {
			return nil, err
		}
		agents = append(agents, a)
	}

	return agents, nil
}

// ClaimJob atomically increments the current_jobs counter for an agent.
// Returns error if the agent is at capacity or not available.
func (r *AgentRepository) ClaimJob(ctx context.Context, id shared.ID) error {
	query := `
		UPDATE agents
		SET current_jobs = current_jobs + 1,
		    updated_at = NOW()
		WHERE id = $1
		  AND status = 'active'
		  AND current_jobs < max_concurrent_jobs
	`
	result, err := r.db.ExecContext(ctx, query, id.String())
	if err != nil {
		return fmt.Errorf("failed to claim job: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return shared.NewDomainError("NO_CAPACITY", "agent has no available capacity", shared.ErrValidation)
	}

	return nil
}

// ReleaseJob atomically decrements the current_jobs counter for an agent.
func (r *AgentRepository) ReleaseJob(ctx context.Context, id shared.ID) error {
	query := `
		UPDATE agents
		SET current_jobs = GREATEST(current_jobs - 1, 0),
		    updated_at = NOW()
		WHERE id = $1
	`
	_, err := r.db.ExecContext(ctx, query, id.String())
	return err
}

// MarkStaleAsOffline marks agents as offline (health) if they haven't sent heartbeat within the timeout.
// Note: This updates Health (automatic), not Status (admin-controlled).
// Agents can still authenticate if their Status is 'active', regardless of Health.
// Returns the number of agents marked as offline.
func (r *AgentRepository) MarkStaleAsOffline(ctx context.Context, timeout time.Duration) (int64, error) {
	query := `
		UPDATE agents
		SET health = 'offline',
		    updated_at = NOW()
		WHERE health = 'online'
		  AND last_seen_at IS NOT NULL
		  AND last_seen_at < NOW() - $1::interval
	`

	result, err := r.db.ExecContext(ctx, query, timeout.String())
	if err != nil {
		return 0, fmt.Errorf("failed to mark stale agents as offline: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("failed to get rows affected: %w", err)
	}

	return rowsAffected, nil
}

func (r *AgentRepository) selectQuery() string {
	return `
		SELECT id, tenant_id, name, type, description, capabilities, tools,
		       execution_mode, status, health, status_message,
		       is_platform_agent, tier,
		       api_key_hash, api_key_prefix, metadata, labels, config,
		       version, hostname, ip_address,
		       cpu_percent, memory_percent, max_concurrent_jobs, current_jobs, region,
		       disk_read_mbps, disk_write_mbps, network_rx_mbps, network_tx_mbps,
		       load_score, metrics_updated_at,
		       last_seen_at, last_offline_at, last_error_at,
		       total_findings, total_scans, error_count,
		       created_at, updated_at
		FROM agents
	`
}

func (r *AgentRepository) buildWhereClause(filter agent.Filter) (string, []any) {
	var conditions []string
	var args []any
	argIndex := 1

	if filter.TenantID != nil {
		conditions = append(conditions, fmt.Sprintf("tenant_id = $%d", argIndex))
		args = append(args, filter.TenantID.String())
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

	if filter.Health != nil {
		conditions = append(conditions, fmt.Sprintf("health = $%d", argIndex))
		args = append(args, string(*filter.Health))
		argIndex++
	}

	if filter.ExecutionMode != nil {
		conditions = append(conditions, fmt.Sprintf("execution_mode = $%d", argIndex))
		args = append(args, string(*filter.ExecutionMode))
		argIndex++
	}

	if len(filter.Capabilities) > 0 {
		conditions = append(conditions, fmt.Sprintf("capabilities @> $%d", argIndex))
		args = append(args, pq.Array(filter.Capabilities))
		argIndex++
	}

	if len(filter.Tools) > 0 {
		conditions = append(conditions, fmt.Sprintf("tools && $%d", argIndex))
		args = append(args, pq.Array(filter.Tools))
		argIndex++
	}

	if filter.Search != "" {
		conditions = append(conditions, fmt.Sprintf("(name ILIKE $%d OR description ILIKE $%d)", argIndex, argIndex))
		args = append(args, wrapLikePattern(filter.Search))
		argIndex++
	}

	if filter.HasCapacity != nil && *filter.HasCapacity {
		conditions = append(conditions, "current_jobs < max_concurrent_jobs")
	}

	if len(conditions) == 0 {
		return "", nil
	}

	return strings.Join(conditions, " AND "), args
}

func (r *AgentRepository) scanAgent(row *sql.Row) (*agent.Agent, error) {
	a := &agent.Agent{}
	var (
		id               string
		tenantID         sql.NullString // Nullable for platform agents
		agentType        string
		executionMode    string
		status           string
		health           string
		capabilities     pq.StringArray
		tools            pq.StringArray
		metadata         []byte
		labels           []byte
		config           []byte
		description      sql.NullString
		statusMessage    sql.NullString
		isPlatformAgent  sql.NullBool
		tier             sql.NullString
		version          sql.NullString
		hostname         sql.NullString
		ipAddress        sql.NullString
		region           sql.NullString
		metricsUpdatedAt sql.NullTime
		lastSeenAt       sql.NullTime
		lastOfflineAt    sql.NullTime
		lastErrorAt      sql.NullTime
	)

	err := row.Scan(
		&id,
		&tenantID,
		&a.Name,
		&agentType,
		&description,
		&capabilities,
		&tools,
		&executionMode,
		&status,
		&health,
		&statusMessage,
		&isPlatformAgent,
		&tier,
		&a.APIKeyHash,
		&a.APIKeyPrefix,
		&metadata,
		&labels,
		&config,
		&version,
		&hostname,
		&ipAddress,
		&a.CPUPercent,
		&a.MemoryPercent,
		&a.MaxConcurrentJobs,
		&a.CurrentJobs,
		&region,
		&a.DiskReadMBPS,
		&a.DiskWriteMBPS,
		&a.NetworkRxMBPS,
		&a.NetworkTxMBPS,
		&a.LoadScore,
		&metricsUpdatedAt,
		&lastSeenAt,
		&lastOfflineAt,
		&lastErrorAt,
		&a.TotalFindings,
		&a.TotalScans,
		&a.ErrorCount,
		&a.CreatedAt,
		&a.UpdatedAt,
	)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, shared.ErrNotFound
		}
		return nil, fmt.Errorf("failed to scan agent: %w", err)
	}

	a.ID, _ = shared.IDFromString(id)
	if tenantID.Valid {
		tid, _ := shared.IDFromString(tenantID.String)
		a.TenantID = &tid
	}
	a.Type = agent.AgentType(agentType)
	a.ExecutionMode = agent.ExecutionMode(executionMode)
	a.Status = agent.AgentStatus(status)
	a.Health = agent.AgentHealth(health)
	a.Capabilities = capabilities
	a.Tools = tools

	if description.Valid {
		a.Description = description.String
	}
	if statusMessage.Valid {
		a.StatusMessage = statusMessage.String
	}
	if isPlatformAgent.Valid {
		a.IsPlatformAgent = isPlatformAgent.Bool
	}
	if version.Valid {
		a.Version = version.String
	}
	if hostname.Valid {
		a.Hostname = hostname.String
	}
	if ipAddress.Valid {
		a.IPAddress = parseIP(ipAddress.String)
	}
	if region.Valid {
		a.Region = region.String
	}
	if metricsUpdatedAt.Valid {
		a.MetricsUpdatedAt = &metricsUpdatedAt.Time
	}
	if lastSeenAt.Valid {
		a.LastSeenAt = &lastSeenAt.Time
	}
	if lastOfflineAt.Valid {
		a.LastOfflineAt = &lastOfflineAt.Time
	}
	if lastErrorAt.Valid {
		a.LastErrorAt = &lastErrorAt.Time
	}

	if len(metadata) > 0 {
		_ = json.Unmarshal(metadata, &a.Metadata)
	}
	if len(labels) > 0 {
		_ = json.Unmarshal(labels, &a.Labels)
	}
	if len(config) > 0 {
		_ = json.Unmarshal(config, &a.Config)
	}

	return a, nil
}

func (r *AgentRepository) scanAgentFromRows(rows *sql.Rows) (*agent.Agent, error) {
	a := &agent.Agent{}
	var (
		id               string
		tenantID         sql.NullString // Nullable for platform agents
		agentType        string
		executionMode    string
		status           string
		health           string
		capabilities     pq.StringArray
		tools            pq.StringArray
		metadata         []byte
		labels           []byte
		config           []byte
		description      sql.NullString
		statusMessage    sql.NullString
		isPlatformAgent  sql.NullBool
		tier             sql.NullString
		version          sql.NullString
		hostname         sql.NullString
		ipAddress        sql.NullString
		region           sql.NullString
		metricsUpdatedAt sql.NullTime
		lastSeenAt       sql.NullTime
		lastOfflineAt    sql.NullTime
		lastErrorAt      sql.NullTime
	)

	err := rows.Scan(
		&id,
		&tenantID,
		&a.Name,
		&agentType,
		&description,
		&capabilities,
		&tools,
		&executionMode,
		&status,
		&health,
		&statusMessage,
		&isPlatformAgent,
		&tier,
		&a.APIKeyHash,
		&a.APIKeyPrefix,
		&metadata,
		&labels,
		&config,
		&version,
		&hostname,
		&ipAddress,
		&a.CPUPercent,
		&a.MemoryPercent,
		&a.MaxConcurrentJobs,
		&a.CurrentJobs,
		&region,
		&a.DiskReadMBPS,
		&a.DiskWriteMBPS,
		&a.NetworkRxMBPS,
		&a.NetworkTxMBPS,
		&a.LoadScore,
		&metricsUpdatedAt,
		&lastSeenAt,
		&lastOfflineAt,
		&lastErrorAt,
		&a.TotalFindings,
		&a.TotalScans,
		&a.ErrorCount,
		&a.CreatedAt,
		&a.UpdatedAt,
	)

	if err != nil {
		return nil, fmt.Errorf("failed to scan agent: %w", err)
	}

	a.ID, _ = shared.IDFromString(id)
	if tenantID.Valid {
		tid, _ := shared.IDFromString(tenantID.String)
		a.TenantID = &tid
	}
	a.Type = agent.AgentType(agentType)
	a.ExecutionMode = agent.ExecutionMode(executionMode)
	a.Status = agent.AgentStatus(status)
	a.Health = agent.AgentHealth(health)
	a.Capabilities = capabilities
	a.Tools = tools

	if description.Valid {
		a.Description = description.String
	}
	if statusMessage.Valid {
		a.StatusMessage = statusMessage.String
	}
	if isPlatformAgent.Valid {
		a.IsPlatformAgent = isPlatformAgent.Bool
	}
	if version.Valid {
		a.Version = version.String
	}
	if hostname.Valid {
		a.Hostname = hostname.String
	}
	if ipAddress.Valid {
		a.IPAddress = parseIP(ipAddress.String)
	}
	if region.Valid {
		a.Region = region.String
	}
	if metricsUpdatedAt.Valid {
		a.MetricsUpdatedAt = &metricsUpdatedAt.Time
	}
	if lastSeenAt.Valid {
		a.LastSeenAt = &lastSeenAt.Time
	}
	if lastOfflineAt.Valid {
		a.LastOfflineAt = &lastOfflineAt.Time
	}
	if lastErrorAt.Valid {
		a.LastErrorAt = &lastErrorAt.Time
	}

	if len(metadata) > 0 {
		_ = json.Unmarshal(metadata, &a.Metadata)
	}
	if len(labels) > 0 {
		_ = json.Unmarshal(labels, &a.Labels)
	}
	if len(config) > 0 {
		_ = json.Unmarshal(config, &a.Config)
	}

	return a, nil
}
// ==========================================================================
// Tool Availability Methods
// ==========================================================================

// GetAvailableToolsForTenant returns all unique tool names that have at least one ONLINE agent.
// Only agents with health='online' are considered - meaning daemon is running and recently sent heartbeat.
func (r *AgentRepository) GetAvailableToolsForTenant(ctx context.Context, tenantID shared.ID) ([]string, error) {
	query := `
		SELECT DISTINCT unnest(tools) AS tool_name
		FROM agents
		WHERE tenant_id = $1
		  AND status = 'active'
		  AND health = 'online'
		ORDER BY tool_name
	`

	rows, err := r.db.QueryContext(ctx, query, tenantID.String())
	if err != nil {
		return nil, fmt.Errorf("failed to get available tools: %w", err)
	}
	defer rows.Close()

	var tools []string
	for rows.Next() {
		var tool string
		if err := rows.Scan(&tool); err != nil {
			return nil, fmt.Errorf("failed to scan tool: %w", err)
		}
		tools = append(tools, tool)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed to iterate tools: %w", err)
	}

	return tools, nil
}

// HasAgentForTool checks if there's at least one ONLINE agent that supports the given tool.
// Only agents with health='online' are considered - meaning daemon is running and recently sent heartbeat.
func (r *AgentRepository) HasAgentForTool(ctx context.Context, tenantID shared.ID, tool string) (bool, error) {
	query := `
		SELECT EXISTS (
			SELECT 1 FROM agents
			WHERE tenant_id = $1
			  AND status = 'active'
			  AND health = 'online'
			  AND $2 = ANY(tools)
		)
	`

	var exists bool
	err := r.db.QueryRowContext(ctx, query, tenantID.String(), tool).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("failed to check tool availability: %w", err)
	}

	return exists, nil
}

// GetAvailableCapabilitiesForTenant returns all unique capability names from all agents accessible to the tenant.
// Only agents with health='online' are considered.
func (r *AgentRepository) GetAvailableCapabilitiesForTenant(ctx context.Context, tenantID shared.ID) ([]string, error) {
	query := `
		SELECT DISTINCT unnest(capabilities) AS capability_name
		FROM agents
		WHERE tenant_id = $1
		  AND status = 'active'
		  AND health = 'online'
		ORDER BY capability_name
	`

	rows, err := r.db.QueryContext(ctx, query, tenantID.String())
	if err != nil {
		return nil, fmt.Errorf("failed to get available capabilities: %w", err)
	}
	defer rows.Close()

	var capabilities []string
	for rows.Next() {
		var cap string
		if err := rows.Scan(&cap); err != nil {
			return nil, fmt.Errorf("failed to scan capability: %w", err)
		}
		capabilities = append(capabilities, cap)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed to iterate capabilities: %w", err)
	}

	return capabilities, nil
}

// ==========================================================================
// Online/Offline Tracking Methods (Heartbeat Optimization)
// ==========================================================================

// UpdateOfflineTimestamp marks an agent as offline with the current timestamp.
// Called when a health monitor detects heartbeat timeout (agent hasn't sent heartbeat within threshold).
// Preserves last_seen_at as the time of the last successful heartbeat.
func (r *AgentRepository) UpdateOfflineTimestamp(ctx context.Context, id shared.ID) error {
	query := `
		UPDATE agents
		SET last_offline_at = NOW(),
		    health = 'offline',
		    updated_at = NOW()
		WHERE id = $1
	`
	_, err := r.db.ExecContext(ctx, query, id.String())
	if err != nil {
		return fmt.Errorf("failed to update offline timestamp: %w", err)
	}
	return nil
}

// MarkStaleAgentsOffline finds agents that haven't sent heartbeat within timeout and marks them offline.
// Returns the list of agent IDs that were marked offline (for audit logging).
// This is used by the health monitor worker.
func (r *AgentRepository) MarkStaleAgentsOffline(ctx context.Context, timeout time.Duration) ([]shared.ID, error) {
	query := `
		UPDATE agents
		SET last_offline_at = NOW(),
		    health = 'offline',
		    updated_at = NOW()
		WHERE health = 'online'
		  AND last_seen_at IS NOT NULL
		  AND last_seen_at < NOW() - $1::interval
		RETURNING id
	`

	rows, err := r.db.QueryContext(ctx, query, timeout.String())
	if err != nil {
		return nil, fmt.Errorf("failed to mark stale agents offline: %w", err)
	}
	defer rows.Close()

	var ids []shared.ID
	for rows.Next() {
		var idStr string
		if err := rows.Scan(&idStr); err != nil {
			return nil, fmt.Errorf("failed to scan agent id: %w", err)
		}
		id, err := shared.IDFromString(idStr)
		if err != nil {
			continue // Skip invalid IDs
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed to iterate stale agents: %w", err)
	}

	return ids, nil
}

// GetAgentsOfflineSince returns agents that went offline after the given timestamp.
// Used for historical queries like "which agents went offline in the last hour?"
func (r *AgentRepository) GetAgentsOfflineSince(ctx context.Context, since time.Time) ([]*agent.Agent, error) {
	query := r.selectQuery() + `
		WHERE last_offline_at IS NOT NULL
		  AND last_offline_at >= $1
		ORDER BY last_offline_at DESC
	`

	rows, err := r.db.QueryContext(ctx, query, since)
	if err != nil {
		return nil, fmt.Errorf("failed to get agents offline since: %w", err)
	}
	defer rows.Close()

	var agents []*agent.Agent
	for rows.Next() {
		a, err := r.scanAgentFromRows(rows)
		if err != nil {
			return nil, err
		}
		agents = append(agents, a)
	}

	return agents, nil
}

// HasAgentForCapability checks if there's at least one ONLINE agent that supports the given capability.
func (r *AgentRepository) HasAgentForCapability(ctx context.Context, tenantID shared.ID, capability string) (bool, error) {
	query := `
		SELECT EXISTS (
			SELECT 1 FROM agents
			WHERE tenant_id = $1
			  AND status = 'active'
			  AND health = 'online'
			  AND $2 = ANY(capabilities)
		)
	`

	var exists bool
	err := r.db.QueryRowContext(ctx, query, tenantID.String(), capability).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("failed to check capability availability: %w", err)
	}

	return exists, nil
}
