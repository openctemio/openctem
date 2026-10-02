package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"strings"
	"time"

	"github.com/lib/pq"

	"github.com/openctemio/api/pkg/domain/sensor"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/pagination"
)

// SensorRepository implements sensor.Repository using PostgreSQL.
type SensorRepository struct {
	db *DB
}

// NewSensorRepository creates a new SensorRepository.
func NewSensorRepository(db *DB) *SensorRepository {
	return &SensorRepository{db: db}
}

// Create persists a new sensor.
func (r *SensorRepository) Create(ctx context.Context, a *sensor.Sensor) error {
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
		INSERT INTO sensors (
			id, tenant_id, name, type, description, capabilities, tools,
			execution_mode, status, health, status_message,
			is_platform_sensor,
			api_key_hash, api_key_prefix, metadata, labels, config,
			version, hostname, ip_address,
			max_concurrent_jobs, current_jobs,
			last_seen_at, last_error_at, total_findings, total_scans, error_count,
			created_at, updated_at, key_expires_at
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25, $26, $27, $28, $29, $30)
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
		a.IsPlatformSensor,
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
		nullTime(a.KeyExpiresAt),
	)

	if err != nil {
		if isUniqueViolation(err) {
			return shared.NewDomainError("ALREADY_EXISTS", "sensor already exists", shared.ErrAlreadyExists)
		}
		return fmt.Errorf("failed to create sensor: %w", err)
	}

	return nil
}

// CountByTenant counts the number of tenant-owned sensors (excluding platform sensors).
// Used for enforcing sensor limits per plan.
func (r *SensorRepository) CountByTenant(ctx context.Context, tenantID shared.ID) (int, error) {
	query := `
		SELECT COUNT(*)
		FROM sensors
		WHERE tenant_id = $1 AND is_platform_sensor = FALSE
	`
	var count int
	err := r.db.QueryRowContext(ctx, query, tenantID.String()).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("failed to count sensors: %w", err)
	}
	return count, nil
}

// GetByID retrieves a sensor by its ID without tenant scoping.
//
// F-5: UNSAFE for user-facing handlers — see interface doc. Use
// GetByTenantAndID from handlers that authorize on a user JWT.
func (r *SensorRepository) GetByID(ctx context.Context, id shared.ID) (*sensor.Sensor, error) {
	query := r.selectQuery() + " WHERE id = $1"
	row := r.db.QueryRowContext(ctx, query, id.String())
	return r.scanSensor(row)
}

// GetByTenantAndID retrieves a sensor by tenant and ID.
func (r *SensorRepository) GetByTenantAndID(ctx context.Context, tenantID, id shared.ID) (*sensor.Sensor, error) {
	query := r.selectQuery() + " WHERE tenant_id = $1 AND id = $2"
	row := r.db.QueryRowContext(ctx, query, tenantID.String(), id.String())
	return r.scanSensor(row)
}

// GetByAPIKeyHash retrieves a sensor by API key hash.
//
// F-5: Tenant scope intentionally omitted — the hash IS the authentication
// material. Must only be used from the platform-auth middleware.
func (r *SensorRepository) GetByAPIKeyHash(ctx context.Context, hash string) (*sensor.Sensor, error) {
	query := r.selectQuery() + " WHERE api_key_hash = $1"
	row := r.db.QueryRowContext(ctx, query, hash)
	return r.scanSensor(row)
}

// List lists sensors with filters and pagination.
func (r *SensorRepository) List(ctx context.Context, filter sensor.Filter, page pagination.Pagination) (pagination.Result[*sensor.Sensor], error) {
	var result pagination.Result[*sensor.Sensor]

	baseQuery := r.selectQuery()
	countQuery := "SELECT COUNT(*) FROM sensors"
	whereClause, args := r.buildWhereClause(filter)

	if whereClause != "" {
		baseQuery += " WHERE " + whereClause
		countQuery += " WHERE " + whereClause
	}

	// Get total count
	var total int64
	err := r.db.QueryRowContext(ctx, countQuery, args...).Scan(&total)
	if err != nil {
		return result, fmt.Errorf("failed to count sensors: %w", err)
	}

	// Apply pagination
	offset := (page.Page - 1) * page.PerPage
	baseQuery += fmt.Sprintf(" ORDER BY created_at DESC LIMIT %d OFFSET %d", page.PerPage, offset)

	rows, err := r.db.QueryContext(ctx, baseQuery, args...)
	if err != nil {
		return result, fmt.Errorf("failed to list sensors: %w", err)
	}
	defer rows.Close()

	var sensors []*sensor.Sensor
	for rows.Next() {
		a, err := r.scanSensorFromRows(rows)
		if err != nil {
			return result, err
		}
		sensors = append(sensors, a)
	}
	if err := rows.Err(); err != nil {
		return result, err
	}

	return pagination.NewResult(sensors, total, page), nil
}

// Update updates a sensor.
func (r *SensorRepository) Update(ctx context.Context, a *sensor.Sensor) error {
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
		UPDATE sensors
		SET name = $2, type = $3, description = $4, capabilities = $5, tools = $6,
		    execution_mode = $7, status = $8, health = $9, status_message = $10,
		    api_key_hash = $11, api_key_prefix = $12, metadata = $13, labels = $14, config = $15,
		    version = $16, hostname = $17, ip_address = $18,
		    cpu_percent = $19, memory_percent = $20, max_concurrent_jobs = $21, current_jobs = $22, region = $23,
		    disk_read_mbps = $24, disk_write_mbps = $25, network_rx_mbps = $26, network_tx_mbps = $27,
		    load_score = $28, metrics_updated_at = $29,
		    last_seen_at = $30, last_error_at = $31, total_findings = $32, total_scans = $33, error_count = $34,
		    updated_at = $35, key_expires_at = $36
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
		nullTime(a.KeyExpiresAt),
	)

	if err != nil {
		return fmt.Errorf("failed to update sensor: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return shared.ErrNotFound
	}

	return nil
}

// Delete deletes a sensor.
func (r *SensorRepository) Delete(ctx context.Context, id shared.ID) error {
	query := "DELETE FROM sensors WHERE id = $1"
	result, err := r.db.ExecContext(ctx, query, id.String())
	if err != nil {
		return fmt.Errorf("failed to delete sensor: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return shared.ErrNotFound
	}

	return nil
}

// UpdateLastSeen updates the last seen timestamp and sets health to online.
// Note: This updates Health (automatic), not Status (admin-controlled).
func (r *SensorRepository) UpdateLastSeen(ctx context.Context, id shared.ID) error {
	query := `
		UPDATE sensors
		SET last_seen_at = NOW(),
		    health = 'online',
		    updated_at = NOW()
		WHERE id = $1
	`
	_, err := r.db.ExecContext(ctx, query, id.String())
	return err
}

// UpdateKeyExpiry sets only the inline API-key expiry. The status = 'active'
// guard means it is a no-op for a concurrently disabled/revoked sensor, so it can
// never revive one — unlike a full-row Update that would rewrite status.
func (r *SensorRepository) UpdateKeyExpiry(ctx context.Context, id shared.ID, expiresAt *time.Time) error {
	query := `
		UPDATE sensors
		SET key_expires_at = $2,
		    updated_at = NOW()
		WHERE id = $1 AND status = 'active'
	`
	_, err := r.db.ExecContext(ctx, query, id.String(), nullTime(expiresAt))
	return err
}

// UpdateHeartbeat writes only the heartbeat-owned columns. Unlike Update it
// never rewrites status / api_key_hash / key_expires_at, and the
// status = 'active' guard makes it a no-op for a sensor an admin revoked or
// disabled after the heartbeat's read — so a heartbeat can never undo a revoke
// or a key regeneration.
func (r *SensorRepository) UpdateHeartbeat(ctx context.Context, id shared.ID, hb sensor.HeartbeatUpdate) (bool, error) {
	var tenantID sql.NullString
	if hb.TenantID != nil {
		tenantID = sql.NullString{String: hb.TenantID.String(), Valid: true}
	}

	var outbox sql.NullString
	if hb.Outbox != nil {
		raw, err := json.Marshal(hb.Outbox)
		if err != nil {
			return false, fmt.Errorf("failed to marshal outbox stats: %w", err)
		}
		outbox = sql.NullString{String: string(raw), Valid: true}
	}

	rep, err := sensorReportArgsOf(hb.Report)
	if err != nil {
		return false, err
	}
	load, err := loadReportArgsOf(hb.Load)
	if err != nil {
		return false, err
	}

	query := `
		UPDATE sensors
		SET version = COALESCE(NULLIF($3, ''), version),
		    hostname = COALESCE(NULLIF($4, ''), hostname),
		    region = COALESCE(NULLIF($5, ''), region),
		    cpu_percent = $6, memory_percent = $7,
		    disk_read_mbps = $8, disk_write_mbps = $9,
		    network_rx_mbps = $10, network_tx_mbps = $11,
		    load_score = $12,
		    ip_address = COALESCE($13::inet, ip_address),
		    -- Outbox snapshot: a heartbeat without one ($14 NULL) leaves the
		    -- stored snapshot and its timestamp as they are.
		    outbox_stats = COALESCE($14::jsonb, outbox_stats),
		    outbox_reported_at = CASE WHEN $14::jsonb IS NULL THEN outbox_reported_at ELSE NOW() END,
		    -- Protocol telemetry (RFC-029 §5.3): $15 = 0 leaves it untouched.
		    protocol_version = CASE WHEN $15::smallint > 0 THEN $15::smallint ELSE protocol_version END,
		    protocol_client = CASE WHEN $15::smallint > 0 THEN NULLIF($16, '') ELSE protocol_client END,
		    protocol_seen_at = CASE WHEN $15::smallint > 0 THEN NOW() ELSE protocol_seen_at END,
		    -- Process start time from the reported uptime; 0 (not reported)
		    -- keeps the stored value.
		    process_started_at = CASE WHEN $17::bigint > 0
		        THEN NOW() - make_interval(secs => $17::bigint::double precision)
		        ELSE process_started_at END,
		    -- Capability report: each part NULL ($18..$23) leaves it as it is;
		    -- $24 says the heartbeat carried a report at all.
		    reported_tools = COALESCE($18::jsonb, reported_tools),
		    reported_tool_names = COALESCE($19::text[], reported_tool_names),
		    reported_capabilities = COALESCE($20::text[], reported_capabilities),
		    reported_max_jobs = COALESCE($21::integer, reported_max_jobs),
		    reported_os = COALESCE($22::varchar, reported_os),
		    reported_arch = COALESCE($23::varchar, reported_arch),
		    reported_at = CASE WHEN $24::boolean THEN NOW() ELSE reported_at END,
		    -- Load report (RFC-030 §5.8): each part NULL ($25..$27) leaves it
		    -- as it is; $28 says the heartbeat carried one at all.
		    reported_resources = COALESCE($25::jsonb, reported_resources),
		    reported_capacity = COALESCE($26::jsonb, reported_capacity),
		    reported_queue = COALESCE($27::jsonb, reported_queue),
		    load_reported_at = CASE WHEN $28::boolean THEN NOW() ELSE load_reported_at END,
		    -- Build information: an empty part leaves the stored value.
		    sdk_name = COALESCE(NULLIF($29, ''), sdk_name),
		    sdk_version = COALESCE(NULLIF($30, ''), sdk_version),
		    sensor_product = COALESCE(NULLIF($31, ''), sensor_product),
		    sensor_commit = COALESCE(NULLIF($32, ''), sensor_commit),
		    sensor_build_time = COALESCE($33::timestamptz, sensor_build_time),
		    metrics_updated_at = NOW(),
		    last_seen_at = NOW(),
		    health = 'online',
		    updated_at = NOW()
		WHERE id = $1
		  AND tenant_id IS NOT DISTINCT FROM $2::uuid
		  AND status = 'active'
	`
	result, err := r.db.ExecContext(ctx, query,
		id.String(), tenantID,
		hb.Version, hb.Hostname, hb.Region,
		hb.CPUPercent, hb.MemoryPercent,
		hb.DiskReadMBPS, hb.DiskWriteMBPS,
		hb.NetworkRxMBPS, hb.NetworkTxMBPS,
		hb.LoadScore,
		heartbeatIP(hb.IPAddress),
		outbox,
		heartbeatProtocol(hb.Protocol), hb.UserAgent,
		sensor.ClampUptime(hb.UptimeSeconds),
		rep.tools, rep.toolNames, rep.capabilities, rep.maxJobs, rep.os, rep.arch, rep.present,
		load.resources, load.capacity, load.queue, load.present,
		hb.Build.SDKName, hb.Build.SDKVersion, hb.Build.Product, hb.Build.Commit, nullTime(hb.Build.BuildTime),
	)
	if err != nil {
		return false, fmt.Errorf("failed to update sensor heartbeat: %w", err)
	}
	n, _ := result.RowsAffected()
	return n > 0, nil
}

// UpdateAPIKey writes only the inline API-key columns. With requireActive the
// write is guarded by status = 'active' so a self-renewal racing an admin
// revoke cannot install a fresh key on a revoked sensor.
func (r *SensorRepository) UpdateAPIKey(ctx context.Context, id shared.ID, hash, prefix string, expiresAt *time.Time, requireActive bool) (bool, error) {
	query := `
		UPDATE sensors
		SET api_key_hash = $2,
		    api_key_prefix = $3,
		    key_expires_at = $4,
		    updated_at = NOW()
		WHERE id = $1
	`
	if requireActive {
		query += " AND status = 'active'"
	}
	result, err := r.db.ExecContext(ctx, query, id.String(), hash, prefix, nullTime(expiresAt))
	if err != nil {
		return false, fmt.Errorf("failed to update sensor api key: %w", err)
	}
	n, _ := result.RowsAffected()
	return n > 0, nil
}

// IncrementStats increments sensor statistics.
func (r *SensorRepository) IncrementStats(ctx context.Context, id shared.ID, findings, scans, errors int64) error {
	query := `
		UPDATE sensors
		SET total_findings = total_findings + $2,
		    total_scans = total_scans + $3,
		    error_count = error_count + $4,
		    updated_at = NOW()
		WHERE id = $1
	`
	_, err := r.db.ExecContext(ctx, query, id.String(), findings, scans, errors)
	return err
}

// FindByCapabilities finds sensors with the given capabilities.
func (r *SensorRepository) FindByCapabilities(ctx context.Context, tenantID shared.ID, capabilities []string, tool string) ([]*sensor.Sensor, error) {
	query := r.selectQuery() + " WHERE tenant_id = $1 AND status = 'active'"
	args := []any{tenantID.String()}
	argIndex := 2

	if len(capabilities) > 0 {
		query += fmt.Sprintf(" AND effective_capabilities @> $%d", argIndex)
		args = append(args, pq.Array(capabilities))
		argIndex++
	}

	if tool != "" {
		query += fmt.Sprintf(" AND $%d = ANY(effective_tools)", argIndex)
		args = append(args, tool)
	}

	query += " ORDER BY " + sensorActiveCommandsSQL("sensors") + " ASC, total_scans ASC" // Load balance by least loaded

	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to find sensors: %w", err)
	}
	defer rows.Close()

	var sensors []*sensor.Sensor
	for rows.Next() {
		a, err := r.scanSensorFromRows(rows)
		if err != nil {
			return nil, err
		}
		sensors = append(sensors, a)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	return sensors, nil
}

// FindAvailable finds available sensors for a task.
func (r *SensorRepository) FindAvailable(ctx context.Context, tenantID shared.ID, capabilities []string, tool string) ([]*sensor.Sensor, error) {
	return r.FindByCapabilities(ctx, tenantID, capabilities, tool)
}

// FindAvailableWithTool finds the best available sensor for a tool.
// Returns the least-loaded sensor that has the required tool.
func (r *SensorRepository) FindAvailableWithTool(ctx context.Context, tenantID shared.ID, tool string) (*sensor.Sensor, error) {
	if tool == "" {
		// No specific tool required, return least-loaded active sensor
		// Only select sensors with health='online' (have sent heartbeat recently)
		// Exclude health='unknown' as those sensors have never sent a heartbeat
		query := r.selectQuery() + `
			WHERE tenant_id = $1
			  AND status = 'active'
			  AND health = 'online'
			  AND last_seen_at IS NOT NULL
			  AND ` + sensorFreeSlotsSQL("sensors") + ` > 0
			ORDER BY ` + sensorActiveCommandsSQL("sensors") + ` ASC, total_scans ASC
			LIMIT 1
		`
		rows, err := r.db.QueryContext(ctx, query, tenantID.String())
		if err != nil {
			return nil, fmt.Errorf("failed to find available sensor: %w", err)
		}
		defer rows.Close()

		if rows.Next() {
			return r.scanSensorFromRows(rows)
		}
		return nil, nil
	}

	// Find sensor with specific tool
	// Only select sensors with health='online' (have sent heartbeat recently)
	query := r.selectQuery() + `
		WHERE tenant_id = $1
		  AND status = 'active'
		  AND health = 'online'
		  AND last_seen_at IS NOT NULL
		  AND $2 = ANY(effective_tools)
		  AND ` + sensorFreeSlotsSQL("sensors") + ` > 0
		ORDER BY ` + sensorFreeSlotsSQL("sensors") + ` DESC,
		         ` + sensorToolThroughputSQL("sensors", "$2") + ` DESC NULLS LAST,
		         total_scans ASC
		LIMIT 1
	`
	rows, err := r.db.QueryContext(ctx, query, tenantID.String(), tool)
	if err != nil {
		return nil, fmt.Errorf("failed to find sensor with tool: %w", err)
	}
	defer rows.Close()

	if rows.Next() {
		return r.scanSensorFromRows(rows)
	}
	return nil, nil // No sensor found with required tool
}

// FindAvailableWithCapacity finds daemon sensors with available job capacity.
// Used for load balancing - returns sensors sorted by load factor (least loaded first).
// Only returns sensors that can receive jobs from server (daemon mode or worker/collector type).
// Only considers sensors with health='online' (have sent heartbeat recently).
// Sensors with health='unknown' are excluded as they have never sent a heartbeat.
func (r *SensorRepository) FindAvailableWithCapacity(ctx context.Context, tenantID shared.ID, capabilities []string, tool string) ([]*sensor.Sensor, error) {
	query := r.selectQuery() + `
		WHERE tenant_id = $1
		  AND status = 'active'
		  AND health = 'online'
		  AND last_seen_at IS NOT NULL
		  AND (execution_mode = 'daemon' OR type IN ('worker', 'collector'))
	`
	args := []any{tenantID.String()}
	argIndex := 2

	if len(capabilities) > 0 {
		query += fmt.Sprintf(" AND effective_capabilities @> $%d", argIndex)
		args = append(args, pq.Array(capabilities))
		argIndex++
	}

	if tool != "" {
		query += fmt.Sprintf(" AND $%d = ANY(effective_tools)", argIndex)
		args = append(args, tool)
	}

	// Most free slots first (server count, narrowed by a fresh load report),
	// then load factor, then the fewest scans run.
	query += " ORDER BY " + sensorFreeSlotsSQL("sensors") + " DESC, (" + sensorActiveCommandsSQL("sensors") +
		"::float / NULLIF(effective_max_jobs, 0)) ASC, total_scans ASC"

	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to find sensors with capacity: %w", err)
	}
	defer rows.Close()

	var sensors []*sensor.Sensor
	for rows.Next() {
		a, err := r.scanSensorFromRows(rows)
		if err != nil {
			return nil, err
		}
		sensors = append(sensors, a)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	return sensors, nil
}

// MarkStaleAsOffline marks sensors as offline (health) if they haven't sent heartbeat within the timeout.
// Note: This updates Health (automatic), not Status (admin-controlled).
// Sensors can still authenticate if their Status is 'active', regardless of Health.
// Returns the number of sensors marked as offline.
//
// A NULL last_seen_at counts as stale. It means "online but never once
// heartbeated", which the app cannot produce — UpdateLastSeen is the only writer
// of health='online' and it always sets last_seen_at in the same statement — but
// a fixture, a restore or a manual UPDATE can, and such a row was previously
// unreachable by this sweep forever.
func (r *SensorRepository) MarkStaleAsOffline(ctx context.Context, timeout time.Duration) (int64, error) {
	query := `
		UPDATE sensors
		SET health = 'offline',
		    updated_at = NOW()
		WHERE health = 'online'
		  AND (last_seen_at IS NULL OR last_seen_at < NOW() - $1::interval)
	`

	result, err := r.db.ExecContext(ctx, query, timeout.String())
	if err != nil {
		return 0, fmt.Errorf("failed to mark stale sensors as offline: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("failed to get rows affected: %w", err)
	}

	return rowsAffected, nil
}

// heartbeatProtocol bounds the protocol telemetry value to a smallint; an
// out-of-range value records nothing.
func heartbeatProtocol(p int) int16 {
	if p < 0 || p > 32767 {
		return 0
	}
	return int16(p)
}

// heartbeatIP is the inet parameter for a heartbeat's client address: NULL
// (keep the stored value) when the address is unknown.
func heartbeatIP(ip net.IP) sql.NullString {
	if ip == nil {
		return sql.NullString{}
	}
	return sql.NullString{String: ip.String(), Valid: true}
}

func (r *SensorRepository) selectQuery() string {
	return `
		SELECT id, tenant_id, name, type, description, capabilities, tools,
		       execution_mode, status, health, status_message,
		       is_platform_sensor, tier,
		       api_key_hash, api_key_prefix, metadata, labels, config,
		       version, hostname, ip_address,
		       cpu_percent, memory_percent, max_concurrent_jobs, ` + sensorActiveCommandsSQL("sensors") + ` AS current_jobs, region,
		       disk_read_mbps, disk_write_mbps, network_rx_mbps, network_tx_mbps,
		       load_score, metrics_updated_at,
		       last_seen_at, last_offline_at, last_error_at,
		       total_findings, total_scans, error_count,
		       created_at, updated_at, key_expires_at,
		       outbox_stats, outbox_reported_at,
		       protocol_version, protocol_client, protocol_seen_at,
		       process_started_at,
		       reported_tools, reported_capabilities, reported_max_jobs,
		       reported_os, reported_arch, reported_at,
		       reported_resources, reported_capacity, reported_queue, load_reported_at,
		       sdk_name, sdk_version, sensor_product, sensor_commit, sensor_build_time
		FROM sensors
	`
}

func (r *SensorRepository) buildWhereClause(filter sensor.Filter) (string, []any) {
	var conditions []string
	var args []any
	argIndex := 1

	if filter.TenantID != nil {
		conditions = append(conditions, fmt.Sprintf("tenant_id = $%d", argIndex))
		args = append(args, filter.TenantID.String())
		argIndex++
	}

	if filter.ExcludePlatform {
		conditions = append(conditions, "is_platform_sensor = FALSE")
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
		conditions = append(conditions, fmt.Sprintf("effective_capabilities @> $%d", argIndex))
		args = append(args, pq.Array(filter.Capabilities))
		argIndex++
	}

	if len(filter.Tools) > 0 {
		conditions = append(conditions, fmt.Sprintf("effective_tools && $%d", argIndex))
		args = append(args, pq.Array(filter.Tools))
		argIndex++
	}

	if filter.SDKVersion != nil {
		if *filter.SDKVersion == "" {
			conditions = append(conditions, "(sdk_version IS NULL OR sdk_version = '')")
		} else {
			conditions = append(conditions, fmt.Sprintf("sdk_version = $%d", argIndex))
			args = append(args, *filter.SDKVersion)
			argIndex++
		}
	}

	if filter.Search != "" {
		conditions = append(conditions, fmt.Sprintf("(name ILIKE $%d OR description ILIKE $%d)", argIndex, argIndex))
		args = append(args, wrapLikePattern(filter.Search))
		// argIndex not incremented — this is the last condition.
	}

	if filter.HasCapacity != nil && *filter.HasCapacity {
		conditions = append(conditions, sensorFreeSlotsSQL("sensors")+" > 0")
	}

	if len(conditions) == 0 {
		return "", nil
	}

	return strings.Join(conditions, " AND "), args
}

// sensorRowScanner is satisfied by *sql.Row and *sql.Rows.
type sensorRowScanner interface {
	Scan(dest ...any) error
}

func (r *SensorRepository) scanSensor(row *sql.Row) (*sensor.Sensor, error) {
	return r.scanSensorRow(row)
}

func (r *SensorRepository) scanSensorFromRows(rows *sql.Rows) (*sensor.Sensor, error) {
	return r.scanSensorRow(rows)
}

// scanSensorRow reads one row of selectQuery. sql.ErrNoRows maps to
// shared.ErrNotFound (only a *sql.Row can return it).
func (r *SensorRepository) scanSensorRow(row sensorRowScanner) (*sensor.Sensor, error) {
	a := &sensor.Sensor{}
	var (
		id               string
		tenantID         sql.NullString // Nullable for platform sensors
		sensorType       string
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
		isPlatformSensor sql.NullBool
		tier             sql.NullString
		version          sql.NullString
		hostname         sql.NullString
		ipAddress        sql.NullString
		region           sql.NullString
		diskReadMBPS     sql.NullFloat64
		diskWriteMBPS    sql.NullFloat64
		networkRxMBPS    sql.NullFloat64
		networkTxMBPS    sql.NullFloat64
		loadScore        sql.NullFloat64
		metricsUpdatedAt sql.NullTime
		lastSeenAt       sql.NullTime
		lastOfflineAt    sql.NullTime
		lastErrorAt      sql.NullTime
		keyExpiresAt     sql.NullTime
		outboxStats      []byte
		outboxReportedAt sql.NullTime
		protocolVersion  sql.NullInt16
		protocolUA       sql.NullString
		protocolSeenAt   sql.NullTime
		processStarted   sql.NullTime
		reportedTools    []byte
		reportedCaps     pq.StringArray
		reportedMaxJobs  sql.NullInt32
		reportedOS       sql.NullString
		reportedArch     sql.NullString
		reportedAt       sql.NullTime
		loadResources    []byte
		loadCapacity     []byte
		loadQueue        []byte
		loadReportedAt   sql.NullTime
		sdkName          sql.NullString
		sdkVersion       sql.NullString
		sensorProduct    sql.NullString
		sensorCommit     sql.NullString
		sensorBuildTime  sql.NullTime
	)

	err := row.Scan(
		&id,
		&tenantID,
		&a.Name,
		&sensorType,
		&description,
		&capabilities,
		&tools,
		&executionMode,
		&status,
		&health,
		&statusMessage,
		&isPlatformSensor,
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
		&diskReadMBPS,
		&diskWriteMBPS,
		&networkRxMBPS,
		&networkTxMBPS,
		&loadScore,
		&metricsUpdatedAt,
		&lastSeenAt,
		&lastOfflineAt,
		&lastErrorAt,
		&a.TotalFindings,
		&a.TotalScans,
		&a.ErrorCount,
		&a.CreatedAt,
		&a.UpdatedAt,
		&keyExpiresAt,
		&outboxStats,
		&outboxReportedAt,
		&protocolVersion,
		&protocolUA,
		&protocolSeenAt,
		&processStarted,
		&reportedTools,
		&reportedCaps,
		&reportedMaxJobs,
		&reportedOS,
		&reportedArch,
		&reportedAt,
		&loadResources,
		&loadCapacity,
		&loadQueue,
		&loadReportedAt,
		&sdkName,
		&sdkVersion,
		&sensorProduct,
		&sensorCommit,
		&sensorBuildTime,
	)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, shared.ErrNotFound
		}
		return nil, fmt.Errorf("failed to scan sensor: %w", err)
	}

	a.ID, _ = shared.IDFromString(id)
	if tenantID.Valid {
		tid, _ := shared.IDFromString(tenantID.String)
		a.TenantID = &tid
	}
	a.Type = sensor.SensorType(sensorType)
	a.ExecutionMode = sensor.ExecutionMode(executionMode)
	a.Status = sensor.SensorStatus(status)
	a.Health = sensor.SensorHealth(health)
	a.Capabilities = capabilities
	a.Tools = tools

	if description.Valid {
		a.Description = description.String
	}
	if statusMessage.Valid {
		a.StatusMessage = statusMessage.String
	}
	if isPlatformSensor.Valid {
		a.IsPlatformSensor = isPlatformSensor.Bool
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
	if diskReadMBPS.Valid {
		a.DiskReadMBPS = diskReadMBPS.Float64
	}
	if diskWriteMBPS.Valid {
		a.DiskWriteMBPS = diskWriteMBPS.Float64
	}
	if networkRxMBPS.Valid {
		a.NetworkRxMBPS = networkRxMBPS.Float64
	}
	if networkTxMBPS.Valid {
		a.NetworkTxMBPS = networkTxMBPS.Float64
	}
	if loadScore.Valid {
		a.LoadScore = loadScore.Float64
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
	if keyExpiresAt.Valid {
		a.KeyExpiresAt = &keyExpiresAt.Time
	}
	if processStarted.Valid {
		a.StartedAt = &processStarted.Time
	}

	if len(outboxStats) > 0 {
		var ob sensor.OutboxStats
		if err := json.Unmarshal(outboxStats, &ob); err != nil {
			log.Printf("[DEBUG] failed to unmarshal sensor outbox stats (id=%s): %v", a.ID, err)
		} else {
			if outboxReportedAt.Valid {
				ob.ReportedAt = outboxReportedAt.Time
			}
			a.Outbox = &ob
		}
	}

	if protocolVersion.Valid && protocolVersion.Int16 > 0 {
		a.Protocol = &sensor.ProtocolInfo{Version: int(protocolVersion.Int16), UserAgent: protocolUA.String}
		if protocolSeenAt.Valid {
			a.Protocol.SeenAt = protocolSeenAt.Time
		}
	}

	a.Build = sensor.BuildInfo{SDKName: sdkName.String, SDKVersion: sdkVersion.String,
		Product: sensorProduct.String, Commit: sensorCommit.String}
	if sensorBuildTime.Valid {
		a.Build.BuildTime = &sensorBuildTime.Time
	}

	a.Reported = scanReported(a.ID, reportedTools, reportedCaps, reportedMaxJobs, reportedOS, reportedArch, reportedAt)
	a.Load = scanLoadReport(a.ID, loadResources, loadCapacity, loadQueue, loadReportedAt)

	if len(metadata) > 0 {
		if err := json.Unmarshal(metadata, &a.Metadata); err != nil {
			log.Printf("[DEBUG] failed to unmarshal sensor metadata (id=%s): %v", a.ID, err)
		}
	}
	if len(labels) > 0 {
		if err := json.Unmarshal(labels, &a.Labels); err != nil {
			log.Printf("[DEBUG] failed to unmarshal sensor labels (id=%s): %v", a.ID, err)
		}
	}
	if len(config) > 0 {
		if err := json.Unmarshal(config, &a.Config); err != nil {
			log.Printf("[DEBUG] failed to unmarshal sensor config (id=%s): %v", a.ID, err)
		}
	}

	return a, nil
}

// ==========================================================================
// Tool Availability Methods
// ==========================================================================

// GetAvailableToolsForTenant returns all unique tool names that have at least one ONLINE sensor.
// Only sensors with health='online' are considered - meaning daemon is running and recently sent heartbeat.
func (r *SensorRepository) GetAvailableToolsForTenant(ctx context.Context, tenantID shared.ID) ([]string, error) {
	query := `
		SELECT DISTINCT unnest(effective_tools) AS tool_name
		FROM sensors
		WHERE tenant_id = $1
		  AND status = 'active'
		  AND health = 'online'
		  AND last_seen_at IS NOT NULL
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

// HasSensorForTool checks if there's at least one ONLINE sensor that supports the given tool.
// Only sensors with health='online' are considered - meaning daemon is running and recently sent heartbeat.
func (r *SensorRepository) HasSensorForTool(ctx context.Context, tenantID shared.ID, tool string) (bool, error) {
	query := `
		SELECT EXISTS (
			SELECT 1 FROM sensors
			WHERE tenant_id = $1
			  AND status = 'active'
			  AND health = 'online'
			  AND last_seen_at IS NOT NULL
			  AND $2 = ANY(effective_tools)
		)
	`

	var exists bool
	err := r.db.QueryRowContext(ctx, query, tenantID.String(), tool).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("failed to check tool availability: %w", err)
	}

	return exists, nil
}

// GetAvailableCapabilitiesForTenant returns all unique capability names from all sensors accessible to the tenant.
// Only sensors with health='online' are considered.
func (r *SensorRepository) GetAvailableCapabilitiesForTenant(ctx context.Context, tenantID shared.ID) ([]string, error) {
	query := `
		SELECT DISTINCT unnest(effective_capabilities) AS capability_name
		FROM sensors
		WHERE tenant_id = $1
		  AND status = 'active'
		  AND health = 'online'
		  AND last_seen_at IS NOT NULL
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

// UpdateOfflineTimestamp marks a sensor as offline with the current timestamp.
// Called when a health monitor detects heartbeat timeout (sensor hasn't sent heartbeat within threshold).
// Preserves last_seen_at as the time of the last successful heartbeat.
func (r *SensorRepository) UpdateOfflineTimestamp(ctx context.Context, id shared.ID) error {
	query := `
		UPDATE sensors
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

// MarkStaleSensorsOffline finds sensors that haven't sent heartbeat within timeout and marks them offline.
// Returns the list of sensor IDs that were marked offline (for audit logging).
// This is used by the health monitor worker.
//
// NULL last_seen_at counts as stale — see MarkStaleAsOffline for why.
func (r *SensorRepository) MarkStaleSensorsOffline(ctx context.Context, timeout time.Duration) ([]shared.ID, error) {
	query := `
		UPDATE sensors
		SET last_offline_at = NOW(),
		    health = 'offline',
		    updated_at = NOW()
		WHERE health = 'online'
		  AND (last_seen_at IS NULL OR last_seen_at < NOW() - $1::interval)
		RETURNING id
	`

	rows, err := r.db.QueryContext(ctx, query, timeout.String())
	if err != nil {
		return nil, fmt.Errorf("failed to mark stale sensors offline: %w", err)
	}
	defer rows.Close()

	var ids []shared.ID
	for rows.Next() {
		var idStr string
		if err := rows.Scan(&idStr); err != nil {
			return nil, fmt.Errorf("failed to scan sensor id: %w", err)
		}
		id, err := shared.IDFromString(idStr)
		if err != nil {
			continue // Skip invalid IDs
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed to iterate stale sensors: %w", err)
	}

	return ids, nil
}

// GetSensorsOfflineSince returns sensors that went offline after the given timestamp.
// Used for historical queries like "which sensors went offline in the last hour?"
func (r *SensorRepository) GetSensorsOfflineSince(ctx context.Context, since time.Time) ([]*sensor.Sensor, error) {
	query := r.selectQuery() + `
		WHERE last_offline_at IS NOT NULL
		  AND last_offline_at >= $1
		ORDER BY last_offline_at DESC
	`

	rows, err := r.db.QueryContext(ctx, query, since)
	if err != nil {
		return nil, fmt.Errorf("failed to get sensors offline since: %w", err)
	}
	defer rows.Close()

	var sensors []*sensor.Sensor
	for rows.Next() {
		a, err := r.scanSensorFromRows(rows)
		if err != nil {
			return nil, err
		}
		sensors = append(sensors, a)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	return sensors, nil
}

// GetPlatformSensorStats returns aggregate statistics for platform sensors.
// NOTE: Cross-tenant access is intentional — platform sensors are shared infrastructure
// managed by OpenCTEM, not scoped to individual tenants. The queued jobs count is
// tenant-scoped via the tenantID parameter.
func (r *SensorRepository) GetPlatformSensorStats(ctx context.Context, tenantID shared.ID) (*sensor.PlatformSensorStatsResult, error) {
	// Single CTE query combining sensor stats and queued job count to avoid N+1
	query := `
		WITH sensor_stats AS (
			SELECT
				COALESCE(labels->>'tier', 'shared') AS tier,
				COUNT(*) AS total_sensors,
				COUNT(*) FILTER (WHERE health = 'online') AS online_sensors,
				COALESCE(SUM(effective_max_jobs), 0) AS total_capacity,
				COALESCE(SUM(` + sensorActiveCommandsSQL("sensors") + `), 0) AS current_load
			FROM sensors
			WHERE is_platform_sensor = TRUE AND status = 'active'
			GROUP BY COALESCE(labels->>'tier', 'shared')
		), queued AS (
			SELECT COUNT(*) AS cnt FROM commands
			WHERE is_platform_job = TRUE AND status IN ('pending', 'queued') AND tenant_id = $1
		)
		SELECT q.cnt, a.tier, a.total_sensors, a.online_sensors, a.total_capacity, a.current_load
		FROM sensor_stats a, queued q
	`

	rows, err := r.db.QueryContext(ctx, query, tenantID.String())
	if err != nil {
		return nil, fmt.Errorf("failed to query platform sensor stats: %w", err)
	}
	defer rows.Close()

	result := &sensor.PlatformSensorStatsResult{
		TierBreakdown: make(map[string]sensor.TierBreakdown),
	}

	for rows.Next() {
		var tier string
		var tb sensor.TierBreakdown
		if err := rows.Scan(&result.CurrentQueuedJobs, &tier, &tb.TotalSensors, &tb.OnlineSensors, &tb.TotalCapacity, &tb.CurrentLoad); err != nil {
			return nil, fmt.Errorf("failed to scan platform sensor stats: %w", err)
		}
		result.TierBreakdown[tier] = tb
		result.TotalSensors += tb.TotalSensors
		result.OnlineSensors += tb.OnlineSensors
		result.TotalCapacity += tb.TotalCapacity
		result.CurrentActiveJobs += tb.CurrentLoad
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed to iterate platform sensor stats: %w", err)
	}

	// Handle case where no sensors exist but we still need queued count
	if len(result.TierBreakdown) == 0 {
		queueQuery := `SELECT COUNT(*) FROM commands WHERE is_platform_job = TRUE AND status IN ('pending', 'queued') AND tenant_id = $1`
		if err := r.db.QueryRowContext(ctx, queueQuery, tenantID.String()).Scan(&result.CurrentQueuedJobs); err != nil {
			return nil, fmt.Errorf("failed to query queued platform jobs: %w", err)
		}
	}

	return result, nil
}

// GetTenantSensorStats returns aggregate statistics for a tenant's sensors.
// Computes status / health / type / execution_mode breakdowns plus active job
// count in a SINGLE query using UNION ALL of grouped subqueries — replaces
// client-side .filter().length over a paginated list.
func (r *SensorRepository) GetTenantSensorStats(ctx context.Context, tenantID shared.ID) (*sensor.TenantSensorStats, error) {
	stats := &sensor.TenantSensorStats{
		ByStatus: make(map[string]int),
		ByHealth: make(map[string]int),
		ByType:   make(map[string]int),
		ByMode:   make(map[string]int),
	}

	query := `
WITH tenant_sensors AS (
  SELECT id, status, health, type, execution_mode, ` + sensorActiveCommandsSQL("sensors") + ` AS current_jobs, last_seen_at
  FROM sensors
  -- The same rows GET /sensors lists: the tenant's own sensors, without
  -- shared platform sensors (those have their own page).
  WHERE tenant_id = $1 AND is_platform_sensor = FALSE
)
SELECT category, key, value FROM (
  SELECT 'total'::text         AS category, ''::text       AS key, COUNT(*)::float8 AS value FROM tenant_sensors
  UNION ALL
  SELECT 'online_active',        '',                                COUNT(*)::float8 FROM tenant_sensors WHERE status = 'active' AND health = 'online'
  AND last_seen_at IS NOT NULL
  UNION ALL
  SELECT 'active_jobs',          '',                                COALESCE(SUM(current_jobs), 0)::float8 FROM tenant_sensors WHERE status = 'active' AND health = 'online'
  AND last_seen_at IS NOT NULL AND execution_mode = 'daemon'
  UNION ALL
  SELECT 'status',               status,                            COUNT(*)::float8 FROM tenant_sensors GROUP BY status
  UNION ALL
  SELECT 'health',               health,                            COUNT(*)::float8 FROM tenant_sensors GROUP BY health
  UNION ALL
  SELECT 'type',                 type,                              COUNT(*)::float8 FROM tenant_sensors GROUP BY type
  UNION ALL
  SELECT 'execution_mode',       execution_mode,                    COUNT(*)::float8 FROM tenant_sensors GROUP BY execution_mode
) sub
`

	rows, err := r.db.QueryContext(ctx, query, tenantID.String())
	if err != nil {
		return nil, fmt.Errorf("failed to query tenant sensor stats: %w", err)
	}
	defer func() { _ = rows.Close() }()

	for rows.Next() {
		var category, key string
		var value float64
		if err := rows.Scan(&category, &key, &value); err != nil {
			return nil, fmt.Errorf("failed to scan tenant sensor stats row: %w", err)
		}
		switch category {
		case "total":
			stats.Total = int(value)
		case "online_active":
			stats.OnlineActive = int(value)
		case "active_jobs":
			stats.ActiveJobs = int(value)
		case "status":
			stats.ByStatus[key] = int(value)
		case "health":
			stats.ByHealth[key] = int(value)
		case "type":
			stats.ByType[key] = int(value)
		case "execution_mode":
			stats.ByMode[key] = int(value)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating tenant sensor stats: %w", err)
	}

	return stats, nil
}

// HasSensorForCapability checks if there's at least one ONLINE sensor that supports the given capability.
func (r *SensorRepository) HasSensorForCapability(ctx context.Context, tenantID shared.ID, capability string) (bool, error) {
	query := `
		SELECT EXISTS (
			SELECT 1 FROM sensors
			WHERE tenant_id = $1
			  AND status = 'active'
			  AND health = 'online'
			  AND last_seen_at IS NOT NULL
			  AND $2 = ANY(effective_capabilities)
		)
	`

	var exists bool
	err := r.db.QueryRowContext(ctx, query, tenantID.String(), capability).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("failed to check capability availability: %w", err)
	}

	return exists, nil
}
