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

	"github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/pagination"
)

// SensorRepository implements sensor.Repository using PostgreSQL.
type SensorRepository struct {
	db *DB
	tokenPepper
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
			created_at, updated_at, key_expires_at, key_pepper_id
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25, $26, $27, $28, $29, $30, $31)
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
		a.InlineKeyPrefix,
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
		nullTime(a.InlineKeyExpiresAt),
		r.value(),
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

// Update writes a sensor's mutable fields from a. It deliberately does NOT
// write the key columns (api_key_hash, api_key_prefix, key_expires_at): those
// change only through Create, UpdateAPIKey and UpdateKeyExpiry. Writing them
// here from a copy read at the start of an admin request (rename, activate,
// disable, revoke) let that request put back a key an admin had just
// regenerated, or clear the expiry that retires a superseded key.
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
		    metadata = $11, labels = $12, config = $13,
		    version = $14, hostname = $15, ip_address = $16,
		    cpu_percent = $17, memory_percent = $18, max_concurrent_jobs = $19, current_jobs = $20, region = $21,
		    disk_read_mbps = $22, disk_write_mbps = $23, network_rx_mbps = $24, network_tx_mbps = $25,
		    load_score = $26, metrics_updated_at = $27,
		    last_seen_at = $28, last_error_at = $29, total_findings = $30, total_scans = $31, error_count = $32,
		    updated_at = $33
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

// RecordKeyUse marks the sensor seen and records the client address of the
// key use (sensor.KeyUseRecorder). The address and its time only move
// forward: key uses are recorded asynchronously and can arrive out of order,
// and an older observation must not overwrite a newer address.
//
// The previous address is read in the same statement under the row lock
// (FOR NO KEY UPDATE, what the UPDATE takes anyway). Without the lock, a use
// that waited for a concurrent one to commit compared against the row as it
// was when its own statement started: an older use then put its address back
// over the newer one and reported an address change that did not happen.
func (r *SensorRepository) RecordKeyUse(ctx context.Context, id shared.ID, ip net.IP, at time.Time) (net.IP, error) {
	query := `
		WITH prev AS (
			SELECT id, host(api_key_last_used_ip) AS ip, api_key_last_used_at AS at
			FROM sensors WHERE id = $1
			FOR NO KEY UPDATE
		)
		UPDATE sensors s
		SET last_seen_at = NOW(),
		    health = 'online',
		    updated_at = NOW(),
		    api_key_last_used_at = GREATEST(s.api_key_last_used_at, $3),
		    api_key_last_used_ip = CASE
		        WHEN prev.at IS NULL OR prev.at <= $3
		        THEN COALESCE($2::inet, s.api_key_last_used_ip)
		        ELSE s.api_key_last_used_ip
		    END
		FROM prev
		WHERE s.id = prev.id
		RETURNING prev.ip, (prev.at IS NULL OR prev.at <= $3)
	`
	var (
		prev  sql.NullString
		fresh bool
	)
	err := r.db.QueryRowContext(ctx, query, id.String(), heartbeatIP(ip), at.UTC()).Scan(&prev, &fresh)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("record sensor key use: %w", err)
	}
	if !fresh || !prev.Valid {
		return nil, nil
	}
	return parseIP(prev.String), nil
}

// ObserveInstance applies the clone-detection observation to an active
// sensor under a row lock (sensor.InstanceObserver).
func (r *SensorRepository) ObserveInstance(ctx context.Context, id shared.ID, instance string, now, currentLastSeen time.Time) (sensor.InstanceVerdict, bool, error) {
	var verdict sensor.InstanceVerdict
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return verdict, false, fmt.Errorf("observe sensor instance: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var (
		raw    []byte
		cloned sql.NullTime
	)
	err = tx.QueryRowContext(ctx, `
		SELECT instance_state, identity_cloned_at FROM sensors
		WHERE id = $1 AND status = 'active'
		FOR UPDATE`, id.String()).Scan(&raw, &cloned)
	if errors.Is(err, sql.ErrNoRows) {
		return verdict, false, nil
	}
	if err != nil {
		return verdict, false, fmt.Errorf("observe sensor instance: %w", err)
	}
	var st sensor.InstanceState
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &st); err != nil {
			st = sensor.InstanceState{} // a corrupt state starts over
		}
	}
	next, verdict := st.Observe(instance, now, currentLastSeen)
	flag := verdict.Cloned && !cloned.Valid
	data, err := json.Marshal(next)
	if err != nil {
		return verdict, false, fmt.Errorf("observe sensor instance: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE sensors
		SET instance_state = $2,
		    instance_id = $3,
		    identity_cloned_at = CASE WHEN $4 THEN $5 ELSE identity_cloned_at END
		WHERE id = $1`, id.String(), data, instance, flag, now); err != nil {
		return verdict, false, fmt.Errorf("observe sensor instance: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return verdict, false, fmt.Errorf("observe sensor instance: %w", err)
	}
	return verdict, flag, nil
}

// ClearIdentityCloned removes the cloned-identity flag and the instance
// memory (sensor.InstanceObserver).
func (r *SensorRepository) ClearIdentityCloned(ctx context.Context, id shared.ID) error {
	_, err := r.db.ExecContext(ctx, `
		UPDATE sensors
		SET identity_cloned_at = NULL, instance_state = '{}'::jsonb, instance_id = NULL, updated_at = NOW()
		WHERE id = $1`, id.String())
	if err != nil {
		return fmt.Errorf("clear sensor identity flag: %w", err)
	}
	return nil
}

var (
	_ sensor.KeyUseRecorder   = (*SensorRepository)(nil)
	_ sensor.InstanceObserver = (*SensorRepository)(nil)
)

// RetireInlineKey brings the inline key's expiry forward to at, only while
// the inline key's stored hash is one of keyHashes (an admin regeneration in
// the meantime installs another key's hash and is left alone) and only when that moves
// the expiry earlier. It writes key_expires_at alone, so it cannot revive a
// revoked sensor or put back a replaced key.
func (r *SensorRepository) RetireInlineKey(ctx context.Context, id shared.ID, keyHashes []string, at time.Time) (bool, error) {
	return retireInlineKey(ctx, r.db, id, keyHashes, at)
}

// retireInlineKey is RetireInlineKey on exec (the pool or a transaction).
func retireInlineKey(ctx context.Context, exec executor, id shared.ID, keyHashes []string, at time.Time) (bool, error) {
	query := `
		UPDATE sensors
		SET key_expires_at = $3,
		    updated_at = NOW()
		WHERE id = $1
		  AND api_key_hash = ANY($2)
		  AND (key_expires_at IS NULL OR key_expires_at > $3)
	`
	res, err := exec.ExecContext(ctx, query, id.String(), pq.Array(keyHashes), at)
	if err != nil {
		return false, fmt.Errorf("retire inline sensor key: %w", err)
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
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
	control, err := controlArg(hb.Control)
	if err != nil {
		return false, err
	}
	localPolicy, err := localPolicyArg(hb.LocalPolicy)
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
		    reported_max_jobs = CASE WHEN $34::boolean THEN NULL ELSE COALESCE($21::integer, reported_max_jobs) END,
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
		    -- Deadline of the next heartbeat (RFC-035 §5.6): the interval the
		    -- sensor follows from now on.
		    heartbeat_interval_seconds = $35::integer,
		    heartbeat_due_at = NOW() + make_interval(secs => $35::integer),
		    -- Control report: NULL ($36) leaves the stored one as it is.
		    reported_control = COALESCE($36::jsonb, reported_control),
		    control_reported_at = CASE WHEN $36::jsonb IS NULL THEN control_reported_at ELSE NOW() END,
		    -- Local policy report (RFC-040 §5.7): NULL ($37) leaves it as it is.
		    reported_local_policy = COALESCE($37::jsonb, reported_local_policy),
		    local_policy_reported_at = CASE WHEN $37::jsonb IS NULL THEN local_policy_reported_at ELSE NOW() END,
		    -- The config report digest this heartbeat echoed (research/26);
		    -- NULL when it echoed none, so a stale stored report shows.
		    config_heartbeat_digest = NULLIF($38, ''),
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
		rep.clearMaxJobs,
		heartbeatIntervalSeconds(hb.Interval), control, localPolicy,
		hb.ConfigReportDigest,
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
	return updateInlineKey(ctx, r.db, r.value(), id, hash, prefix, expiresAt, requireActive)
}

// updateInlineKey is UpdateAPIKey on exec (the pool or a transaction),
// stamping pepperID as the key's pepper.
func updateInlineKey(ctx context.Context, exec executor, pepperID sql.NullString, id shared.ID, hash, prefix string, expiresAt *time.Time, requireActive bool) (bool, error) {
	query := `
		UPDATE sensors
		SET api_key_hash = $2,
		    api_key_prefix = $3,
		    key_expires_at = $4,
		    key_pepper_id = $5,
		    updated_at = NOW()
		WHERE id = $1
	`
	if requireActive {
		query += " AND status = 'active'"
	}
	result, err := exec.ExecContext(ctx, query, id.String(), hash, prefix, nullTime(expiresAt), pepperID)
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
		query += fmt.Sprintf(" AND $%d = ANY("+sensorDispatchTools("sensors")+")", argIndex)
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
			  AND health IN ` + sensorDispatchableHealthSQL + `
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
		  AND health IN ` + sensorDispatchableHealthSQL + `
		  AND last_seen_at IS NOT NULL
		  AND $2 = ANY(` + sensorDispatchTools("sensors") + `)
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
		  AND health IN ` + sensorDispatchableHealthSQL + `
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
		query += fmt.Sprintf(" AND $%d = ANY("+sensorDispatchTools("sensors")+")", argIndex)
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

// MarkStaleAsOffline is the worker's backstop (jobs.SensorHealthChecker,
// WORKER_HEARTBEAT_TIMEOUT): it marks offline the sensors still stored
// online that the heartbeat ladder (pkg/domain/sensor/liveness.go) puts past
// its offline step and that were last seen more than timeout ago. In normal
// operation the health controller has moved such a sensor to late and stale
// long before, so this only acts when the controller does not run. It never
// convicts a sensor the controller holds at stale while the platform is slow.
// Note: This updates Health (automatic), not Status (admin-controlled).
//
// A NULL last_seen_at counts as stale. It means "online but never once
// heartbeated", which the app cannot produce, but a fixture, a restore or a
// manual UPDATE can, and such a row was previously unreachable by this sweep
// forever.
func (r *SensorRepository) MarkStaleAsOffline(ctx context.Context, timeout time.Duration) (int64, error) {
	ids, err := r.convictOffline(ctx, []sensor.SensorHealth{sensor.SensorHealthOnline}, timeout)
	if err != nil {
		return 0, fmt.Errorf("failed to mark stale sensors as offline: %w", err)
	}
	return int64(len(ids)), nil
}

// CountLegacyKeySensors counts the non-revoked sensors whose effective key
// (the current rotating key when there is one, else the inline key; the same
// choice as sensor.Sensor.KeyState) is a legacy rda_ key.
func (r *SensorRepository) CountLegacyKeySensors(ctx context.Context) (int64, error) {
	query := `SELECT COUNT(*) FROM sensors s WHERE s.status <> 'revoked' AND ` + sensorLegacyKeySQL("s")
	var n int64
	if err := r.db.QueryRowContext(ctx, query).Scan(&n); err != nil {
		return 0, fmt.Errorf("count legacy-key sensors: %w", err)
	}
	return n, nil
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
		       sdk_name, sdk_version, sensor_product, sensor_commit, sensor_build_time,
		       api_key_last_used_at, host(api_key_last_used_ip),
		       instance_id, instance_state, identity_cloned_at,
		       manifest_digest, manifest_at, manifest_source,
		       heartbeat_interval_seconds, heartbeat_due_at, reported_control, control_reported_at,
		       reported_local_policy, local_policy_reported_at,
		       config_report_digest, config_health, config_heartbeat_digest,
		       ` + sensorActiveKeySQL("sensors") + ` AS active_key
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
		keyLastUsedAt    sql.NullTime
		keyLastUsedIP    sql.NullString
		instanceID       sql.NullString
		instanceState    []byte
		identityCloned   sql.NullTime
		manifestDigest   sql.NullString
		manifestAt       sql.NullTime
		manifestSource   sql.NullString
		hbInterval       sql.NullInt32
		hbDueAt          sql.NullTime
		control          []byte
		controlAt        sql.NullTime
		localPolicy      []byte
		localPolicyAt    sql.NullTime
		configDigest     sql.NullString
		configHealth     sql.NullString
		configHBDigest   sql.NullString
		activeKey        []byte
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
		&a.InlineKeyPrefix,
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
		&keyLastUsedAt,
		&keyLastUsedIP,
		&instanceID,
		&instanceState,
		&identityCloned,
		&manifestDigest,
		&manifestAt,
		&manifestSource,
		&hbInterval,
		&hbDueAt,
		&control,
		&controlAt,
		&localPolicy,
		&localPolicyAt,
		&configDigest,
		&configHealth,
		&configHBDigest,
		&activeKey,
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
		a.InlineKeyExpiresAt = &keyExpiresAt.Time
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

	if keyLastUsedAt.Valid {
		a.KeyLastUsedAt = &keyLastUsedAt.Time
	}
	if keyLastUsedIP.Valid {
		a.KeyLastUsedIP = parseIP(keyLastUsedIP.String)
	}
	a.InstanceID = instanceID.String
	if len(instanceState) > 0 {
		if err := json.Unmarshal(instanceState, &a.InstanceState); err != nil {
			log.Printf("[DEBUG] failed to unmarshal sensor instance state (id=%s): %v", a.ID, err)
		}
	}
	if identityCloned.Valid {
		a.IdentityClonedAt = &identityCloned.Time
	}
	a.ManifestDigest, a.ManifestSource = manifestDigest.String, manifestSource.String
	a.ActiveKey = parseActiveKey(activeKey)
	if manifestAt.Valid {
		a.ManifestAt = &manifestAt.Time
	}

	a.Reported = scanReported(a.ID, reportedTools, reportedCaps, reportedMaxJobs, reportedOS, reportedArch, reportedAt)
	a.Load = scanLoadReport(a.ID, loadResources, loadCapacity, loadQueue, loadReportedAt)
	if hbInterval.Valid {
		a.HeartbeatInterval = time.Duration(hbInterval.Int32) * time.Second
	}
	if hbDueAt.Valid {
		a.HeartbeatDueAt = &hbDueAt.Time
	}
	a.Control = scanControl(a.ID, control, controlAt)
	a.LocalPolicy, a.LocalPolicyReportedAt = scanLocalPolicy(a.ID, localPolicy, localPolicyAt)
	a.ConfigReportDigest, a.ConfigHealth, a.ConfigHeartbeatDigest = configDigest.String, configHealth.String, configHBDigest.String

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
		SELECT DISTINCT unnest(` + sensorDispatchTools("sensors") + `) AS tool_name
		FROM sensors
		WHERE tenant_id = $1
		  AND status = 'active'
		  AND health IN ` + sensorDispatchableHealthSQL + `
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
			  AND health IN ` + sensorDispatchableHealthSQL + `
			  AND last_seen_at IS NOT NULL
			  AND $2 = ANY(` + sensorDispatchTools("sensors") + `)
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
		  AND health IN ` + sensorDispatchableHealthSQL + `
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

// MarkStaleSensorsOffline marks offline the sensors (online, late or stale)
// that the heartbeat ladder puts past its offline step, judged against each
// sensor's stored deadline and interval (pkg/domain/sensor/liveness.go), and
// that were last seen more than minAge ago (0: no floor). Returns the ids it
// moved. The health controller walks the whole ladder itself
// (ListLivenessCandidates / ApplyLiveness); this is the same offline step in
// one call.
//
// NULL last_seen_at counts as stale — see MarkStaleAsOffline for why.
func (r *SensorRepository) MarkStaleSensorsOffline(ctx context.Context, minAge time.Duration) ([]shared.ID, error) {
	ids, err := r.convictOffline(ctx, liveHealths, minAge)
	if err != nil {
		return nil, fmt.Errorf("failed to mark stale sensors offline: %w", err)
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
				COUNT(*) FILTER (WHERE health IN ` + sensorDispatchableHealthSQL + `) AS online_sensors,
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
  SELECT 'online_active',        '',                                COUNT(*)::float8 FROM tenant_sensors WHERE status = 'active' AND health IN ` + sensorDispatchableHealthSQL + `
  AND last_seen_at IS NOT NULL
  UNION ALL
  SELECT 'active_jobs',          '',                                COALESCE(SUM(current_jobs), 0)::float8 FROM tenant_sensors WHERE status = 'active' AND health IN ` + sensorDispatchableHealthSQL + `
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
			  AND health IN ` + sensorDispatchableHealthSQL + `
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

// RehashKey replaces the stored hash of a sensor's inline key made with an earlier pepper
// by its hash under the current pepper, only while the stored hash is still
// oldHash. Reports whether the row changed.
func (r *SensorRepository) RehashKey(ctx context.Context, id shared.ID, oldHash, newHash string) (bool, error) {
	return r.rehash(ctx, r.db, sensorInlineTokens, id, oldHash, newHash)
}

// CountKeysNotUnderPepper counts active tokens not hashed with the current
// pepper (they still need APP_ENCRYPTION_KEY_PREVIOUS).
func (r *SensorRepository) CountKeysNotUnderPepper(ctx context.Context) (int, error) {
	return r.countNotCurrent(ctx, r.db, sensorInlineTokens)
}
