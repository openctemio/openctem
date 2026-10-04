package postgres

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/pkg/domain/command"
	sensordom "github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/pagination"
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
	// lease is how long a claim holds without renewal (command_lease.go).
	lease time.Duration
}

// NewCommandRepository creates a new CommandRepository.
func NewCommandRepository(db *DB) *CommandRepository {
	return &CommandRepository{db: db, lease: command.DefaultLeaseDuration}
}

// Create persists a new command.
func (r *CommandRepository) Create(ctx context.Context, cmd *command.Command) error {
	query := `
		INSERT INTO commands (
			id, tenant_id, sensor_id, type, priority, payload,
			status, error_message,
			created_at, expires_at, acknowledged_at, started_at, completed_at,
			result, scheduled_at, schedule_id, step_run_id,
			is_platform_job, platform_sensor_id,
			auth_token_hash, auth_token_prefix, auth_token_expires_at,
			queue_priority, queued_at, dispatch_attempts, scan_zone_id
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25, $26)
	`

	_, err := r.db.ExecContext(ctx, query,
		cmd.ID.String(),
		cmd.TenantID.String(),
		nullIDString(cmd.SensorID),
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
		nullIDString(cmd.PlatformSensorID),
		nullString(cmd.AuthTokenHash),
		nullString(cmd.AuthTokenPrefix),
		nullTime(cmd.AuthTokenExpiresAt),
		cmd.QueuePriority,
		nullTime(cmd.QueuedAt),
		cmd.DispatchAttempts,
		nullIDString(cmd.ScanZoneID),
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

// GetPendingForSensor retrieves pending commands for a sensor.
//
// A command that names a tool (payload "scanner", else "preferred_tool") is
// only returned to a sensor that has that tool (toolClaimPredicate), zoned or
// not: a sensor never receives a scan it would fail with "scanner not found"
// (RFC-030 B5).
//
// A command whose payload carries a non-empty required_capabilities array is
// only returned when every one of those capabilities is present in the polling
// sensor's capabilities. This is the claim-time mirror of the dispatch-time
// capability the validation dispatcher stamps onto a validate command
// (payload.required_capabilities = ["validate"] or ["validate:nuclei"]): it
// stops a non-nuclei sensor race-claiming a nuclei validate job it cannot run.
// A command with no (or an empty) required_capabilities is returned to any
// sensor, preserving the pre-existing behavior for every scan/collect command.
func (r *CommandRepository) GetPendingForSensor(ctx context.Context, tenantID shared.ID, sensorID *shared.ID, capabilities []string, limit int) ([]*command.Command, error) {
	where, args := pendingForSensorWhere(tenantID, sensorID, capabilities)
	query := fairPendingQuery(r.selectQuery(), where, limit)

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
	if err := rows.Err(); err != nil {
		return nil, err
	}

	return commands, nil
}

// pendingForSensorWhere is the poll's predicate for sensorID in tenantID:
// pending and due, pinned to the sensor or unpinned, the zone claim
// predicate, the tool gate and the capability gate. Arguments: $1 tenant,
// $2 sensor (when given), then the capabilities.
func pendingForSensorWhere(tenantID shared.ID, sensorID *shared.ID, capabilities []string) (string, []any) {
	where := `commands.tenant_id = $1 AND ` + pendingReadyPredicate
	args := []any{tenantID.String()}
	if sensorID != nil {
		where += " AND (commands.sensor_id = $2 OR commands.sensor_id IS NULL) AND " + zoneClaimPredicate("$2") +
			" AND " + toolClaimPredicate("$2")
		args = append(args, sensorID.String())
	} else {
		// No sensor identity: nothing pinned, no zone membership and no tools
		// to prove.
		where += " AND commands.sensor_id IS NULL AND commands.scan_zone_id IS NULL AND " + commandToolSQL + " IS NULL"
	}
	where += " AND " + capabilityClaimPredicate(fmt.Sprintf("$%d", len(args)+1))
	args = append(args, pq.Array(capabilities))
	return where, args
}

// claimAgingSeconds is how long a command waits before it moves up one
// priority class (RFC-046 §11, RFC-030 §5.3: +1 class per 30 minutes).
const claimAgingSeconds = 1800

// fairCandidateWindow bounds the candidates ranked for fairness on one poll:
// the oldest pending commands of each class, so the ranking stays cheap on a
// deep queue.
const fairCandidateWindow = 1000

// claimClassSQL is a command's priority class for dispatch, 1 (critical)
// to 4 (low), raised one class per claimAgingSeconds waited. Aging never
// lifts a command into the critical class, which stays for verification
// work, and a created_at slightly in the future (clock skew between API
// replicas) never lowers one.
var claimClassSQL = fmt.Sprintf(`(CASE commands.priority
		WHEN 'critical' THEN 1
		ELSE GREATEST(2,
			(CASE commands.priority WHEN 'high' THEN 2 WHEN 'normal' THEN 3 ELSE 4 END)
			- LEAST(2, GREATEST(0, FLOOR(EXTRACT(EPOCH FROM (NOW() - commands.created_at)) / %d)::int)))
	END)`, claimAgingSeconds)

// fairPendingQuery orders the commands matching where for dispatch (RFC-046
// §11): by priority class (with aging), then round-robin across runs (the
// first pending command of every run before the second of any), then age.
// One large run therefore no longer starves a small run queued after it.
// selectSQL is the repository's column list FROM commands.
func fairPendingQuery(selectSQL, where string, limit int) string {
	return `
		WITH cand AS (
			SELECT commands.id AS c_id, ` + claimClassSQL + ` AS c_cls, commands.created_at AS c_at,
			       COALESCE(commands.payload->>'pipeline_run_id', commands.id::text) AS c_run
			FROM commands
			WHERE ` + where + `
			ORDER BY c_cls, c_at
			LIMIT ` + fmt.Sprint(fairCandidateWindow) + `
		), ranked AS (
			SELECT c_id, c_cls, c_at,
			       ROW_NUMBER() OVER (PARTITION BY c_cls, c_run ORDER BY c_at, c_id) AS c_rn
			FROM cand
		)
		` + selectSQL + `
		JOIN ranked ON ranked.c_id = commands.id
		ORDER BY ranked.c_cls, ranked.c_rn, ranked.c_at, commands.id
		LIMIT ` + fmt.Sprint(limit)
}

// pendingReadyPredicate keeps a command that is waiting and due: pending, not
// expired, and not scheduled for later.
const pendingReadyPredicate = `commands.status = 'pending'
		AND (commands.expires_at IS NULL OR commands.expires_at > NOW())
		AND (commands.scheduled_at IS NULL OR commands.scheduled_at <= NOW())`

// capabilityClaimPredicate is the capability gate: keep a command only if it
// declares no required capabilities, or every required capability is one the
// sensor (bound to capsParam, a text[]) advertises.
// jsonb_typeof(...) IS DISTINCT FROM 'array' covers a missing key (SQL NULL)
// and any malformed value, so those always pass through as unscoped.
func capabilityClaimPredicate(capsParam string) string {
	return `(
			jsonb_typeof(commands.payload->'required_capabilities') IS DISTINCT FROM 'array'
			OR NOT EXISTS (
				SELECT 1
				FROM jsonb_array_elements_text(commands.payload->'required_capabilities') AS rc(cap)
				WHERE rc.cap <> ALL(COALESCE(` + capsParam + `::text[], ARRAY[]::text[]))
			)
		)`
}

// PendingWorkForSensor is the heartbeat doorbell's read (RFC-023 §9.2a): how
// many commands the sensor could claim right now (capped at limit), and a
// fingerprint of its zone assignments, in one statement.
//
// "Could claim" is exactly what the poll (GetPendingForSensor) would offer:
// pinned to the sensor or unpinned, ready, zone claim predicate, tool gate,
// capability gate. The query only splits the poll's (sensor_id = $2 OR sensor_id IS NULL)
// into two counts so each half is an index range on idx_commands_pending_poll
// / idx_commands_pending_unassigned instead of a filter over every pending row
// of the tenant, and pre-filters unpinned zone commands to the sensor's zones
// once (a condition the zone claim predicate implies) instead of running that
// predicate's subquery per row. The predicate itself is still applied as-is.
func (r *CommandRepository) PendingWorkForSensor(ctx context.Context, tenantID, sensorID shared.ID, capabilities []string, limit int) (sensordom.PendingWork, error) {
	if limit <= 0 {
		limit = 1
	}
	claimable := pendingReadyPredicate + `
		AND ` + zoneClaimPredicate("$2") + `
		AND ` + toolClaimPredicate("$2") + `
		AND ` + capabilityClaimPredicate("$3")
	query := `
		SELECT
			LEAST($4::int,
				(SELECT count(*) FROM (
					SELECT 1 FROM commands
					WHERE commands.tenant_id = $1 AND commands.sensor_id = $2
					  AND ` + claimable + `
					LIMIT $4) pinned)
				+
				(SELECT count(*) FROM (
					SELECT 1 FROM commands
					WHERE commands.tenant_id = $1 AND commands.sensor_id IS NULL
					  AND (commands.scan_zone_id IS NULL OR commands.scan_zone_id = ANY(ARRAY(
						SELECT m.zone_id FROM scan_zone_sensors m
						WHERE m.tenant_id = $1 AND m.sensor_id = $2)))
					  AND ` + claimable + `
					LIMIT $4) unpinned)
			) AS pending,
			(SELECT count(*) FROM (
				SELECT 1 FROM commands
				WHERE commands.tenant_id = $1 AND commands.sensor_id = $2
				  AND commands.status = 'canceled'
				  AND commands.acknowledged_at IS NOT NULL
				  AND COALESCE(commands.completed_at, commands.acknowledged_at) > NOW() - make_interval(secs => $5)
				LIMIT $4) canceled) AS recently_canceled,
			COALESCE((
				SELECT string_agg(z.id::text || '@' || to_char(z.updated_at AT TIME ZONE 'UTC', 'YYYYMMDDHH24MISSUS'), ',' ORDER BY z.id)
				FROM scan_zone_sensors zs
				JOIN scan_zones z ON z.id = zs.zone_id AND z.tenant_id = zs.tenant_id
				WHERE zs.tenant_id = $1 AND zs.sensor_id = $2
			), '') AS zones`

	var out sensordom.PendingWork
	err := r.db.QueryRowContext(ctx, query, tenantID.String(), sensorID.String(), pq.Array(capabilities), limit, r.leaseSeconds()).
		Scan(&out.Count, &out.RecentlyCanceled, &out.ZoneFingerprint)
	if err != nil {
		return sensordom.PendingWork{}, fmt.Errorf("failed to read pending work: %w", err)
	}
	return out, nil
}

// zoneClaimPredicate is the claim-time zone check (RFC-023 D7 layer 2) for
// the sensor bound to sensorParam. A command with no zone keeps the pre-zone
// behavior. A zone-stamped command, pinned or not, is offered only to a
// sensor that is assigned to that zone (same tenant, enforced again here) and
// that has the command's tool: the reaper unpins stuck commands and an
// unassignment unpins pending ones, and neither may release a zone's job to a
// sensor outside the zone.
func zoneClaimPredicate(sensorParam string) string {
	return `(
		commands.scan_zone_id IS NULL
		OR EXISTS (
			SELECT 1
			FROM scan_zone_sensors zs
			JOIN sensors zsn ON zsn.id = zs.sensor_id AND zsn.tenant_id = zs.tenant_id
			WHERE zs.zone_id = commands.scan_zone_id
			  AND zs.tenant_id = commands.tenant_id
			  AND zs.sensor_id = ` + sensorParam + `
			  AND (` + commandToolSQL + ` IS NULL OR ` + commandToolSQL + ` = ANY(` + sensorDispatchTools("zsn") + `))
		)
	)`
}

// commandToolSQL is the tool a command asks for: payload "scanner", else
// "preferred_tool" (a workflow step), NULL when it names none (collect,
// validate and other tool-less commands). The v2 results receiver reads the
// same keys (ingest commandTool).
const commandToolSQL = `COALESCE(NULLIF(commands.payload->>'scanner', ''), NULLIF(commands.payload->>'preferred_tool', ''))`

// sensorDispatchTools is the SQL for the tools dispatch may send the sensor
// aliased alias work for. It is the one place that decides it, for the poll,
// the claim, the heartbeat doorbell and the zone predicate.
//
// It is the tools the sensor VERIFIED: the ones its own probe reported
// installed (heartbeat tools[] or the RFC-033 manifest), narrowed by its tool
// limit (sensors.tools; an empty limit allows every reported tool). That is
// effective_tools (RFC-029 §4.3.1, migration 000253) for a sensor that
// reported. A sensor that never reported has no verified tool: its
// effective_tools fall back to the tools the administrator declared, which
// nothing checked, so dispatch reads none from it (live: a declared-only
// sensor failed 24 trivy commands with "scanner not found: trivy"). The
// trigger's availability check (HasSensorForTool), the selector and the zone
// router use this same expression.
func sensorDispatchTools(alias string) string {
	return `(CASE WHEN ` + alias + `.reported_tool_names IS NULL THEN ARRAY[]::text[] ELSE ` + alias + `.effective_tools END)`
}

// toolClaimPredicate is the tool gate (RFC-030 B5): keep a command only if it
// names no tool, or the sensor bound to sensorParam (same tenant as the
// command) has that tool. Unlike the zone predicate it applies to every
// command, so an unzoned nuclei scan is never offered to a sensor without
// nuclei, and a sensor cannot claim one by id either.
func toolClaimPredicate(sensorParam string) string {
	return `(
		` + commandToolSQL + ` IS NULL
		OR EXISTS (
			SELECT 1 FROM sensors ts
			WHERE ts.id = ` + sensorParam + `
			  AND ts.tenant_id = commands.tenant_id
			  AND ` + commandToolSQL + ` = ANY(` + sensorDispatchTools("ts") + `)
		)
	)`
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
	if err := rows.Err(); err != nil {
		return result, err
	}

	return pagination.NewResult(commands, total, page), nil
}

// ClaimForSensor atomically acknowledges a still-pending command for the given
// sensor. The status='pending' guard makes the claim a no-op (0 rows) if another
// poller already acknowledged it, so two sensors polling the same unassigned
// command can't both proceed (double dispatch).
//
// The zone predicate and the tool gate are the same as the poll's (RFC-023
// layer 2, RFC-030 B5): a sensor cannot acknowledge, by id, a command it would
// never have been offered.
func (r *CommandRepository) ClaimForSensor(ctx context.Context, tenantID, commandID shared.ID, sensorID string) (bool, error) {
	query := `
		UPDATE commands
		SET status = 'acknowledged', sensor_id = $3, acknowledged_at = NOW(),
		    lease_epoch = lease_epoch + 1,
		    lease_expires_at = NOW() + make_interval(secs => $4)
		WHERE id = $1 AND tenant_id = $2 AND status = 'pending'
		  AND (sensor_id IS NULL OR sensor_id = $3)
		  AND ` + zoneClaimPredicate("$3") + `
		  AND ` + toolClaimPredicate("$3") + `
	`
	result, err := r.db.ExecContext(ctx, query, commandID.String(), tenantID.String(), sensorID, r.leaseSeconds())
	if err != nil {
		return false, fmt.Errorf("failed to claim command: %w", err)
	}
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("failed to read rows affected: %w", err)
	}
	return rowsAffected > 0, nil
}

var _ command.BatchClaimer = (*CommandRepository)(nil)

// ClaimManyForSensor acknowledges for sensorID those of ids that are still
// claimable by it, in one statement. The candidate rows are locked with FOR
// UPDATE SKIP LOCKED, so two sensors claiming at once take disjoint sets and
// never wait on each other; the gates are the poll's (tenant, pinning, zone,
// tool, capability), re-checked at claim time because the ids came from an
// earlier read. A command of another tenant is never claimed, whatever id is
// passed.
func (r *CommandRepository) ClaimManyForSensor(ctx context.Context, tenantID, sensorID shared.ID, capabilities []string, ids []shared.ID) ([]shared.ID, error) {
	if len(ids) == 0 {
		return nil, nil
	}
	want := make([]string, len(ids))
	for i, id := range ids {
		want[i] = id.String()
	}
	where, args := pendingForSensorWhere(tenantID, &sensorID, capabilities)
	args = append(args, pq.Array(want), r.leaseSeconds())
	idsParam, leaseParam := fmt.Sprintf("$%d", len(args)-1), fmt.Sprintf("$%d", len(args))
	query := `
		UPDATE commands c
		SET status = 'acknowledged', sensor_id = $2, acknowledged_at = NOW(),
		    lease_epoch = c.lease_epoch + 1,
		    lease_expires_at = NOW() + make_interval(secs => ` + leaseParam + `)
		WHERE c.id IN (
			SELECT commands.id FROM commands
			WHERE ` + where + `
			  AND commands.id = ANY(` + idsParam + `::uuid[])
			FOR UPDATE SKIP LOCKED
		)
		  AND c.tenant_id = $1 AND c.status = 'pending'
		RETURNING c.id`
	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to claim commands: %w", err)
	}
	defer rows.Close()
	out := make([]shared.ID, 0, len(ids))
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("failed to scan claimed command: %w", err)
		}
		if cid, err := shared.IDFromString(id); err == nil {
			out = append(out, cid)
		}
	}
	return out, rows.Err()
}

// CountHeldScans counts the scan commands sensorID holds in tenantID.
func (r *CommandRepository) CountHeldScans(ctx context.Context, tenantID, sensorID shared.ID) (int, error) {
	var n int
	err := r.db.QueryRowContext(ctx, `
		SELECT count(*) FROM commands
		WHERE tenant_id = $1 AND sensor_id = $2 AND type = 'scan'
		  AND status IN ('acknowledged', 'running')`,
		tenantID.String(), sensorID.String()).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("failed to count held commands: %w", err)
	}
	return n, nil
}

// Update updates a command.
func (r *CommandRepository) Update(ctx context.Context, cmd *command.Command) error {
	query := `
		UPDATE commands
		SET sensor_id = $2, type = $3, priority = $4, payload = $5,
		    status = $6, error_message = $7,
		    expires_at = $8, acknowledged_at = $9, started_at = $10, completed_at = $11,
		    result = $12, scheduled_at = $13, schedule_id = $14,
		    is_platform_job = $15, platform_sensor_id = $16,
		    auth_token_hash = $17, auth_token_prefix = $18, auth_token_expires_at = $19,
		    queue_priority = $20, queued_at = $21, dispatch_attempts = $22
		WHERE id = $1 AND tenant_id = $23
	`

	result, err := r.db.ExecContext(ctx, query,
		cmd.ID.String(),
		nullIDString(cmd.SensorID),
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
		nullIDString(cmd.PlatformSensorID),
		nullString(cmd.AuthTokenHash),
		nullString(cmd.AuthTokenPrefix),
		nullTime(cmd.AuthTokenExpiresAt),
		cmd.QueuePriority,
		nullTime(cmd.QueuedAt),
		cmd.DispatchAttempts,
		cmd.TenantID.String(),
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

func (r *CommandRepository) selectQuery() string {
	return `
		SELECT id, tenant_id, sensor_id, type, priority, payload,
		       status, error_message,
		       created_at, expires_at, acknowledged_at, started_at, completed_at,
		       result, scheduled_at, schedule_id, step_run_id,
		       is_platform_job, platform_sensor_id,
		       auth_token_hash, auth_token_prefix, auth_token_expires_at,
		       queue_priority, queued_at, dispatch_attempts, scan_zone_id,
		       lease_epoch, lease_expires_at
		FROM commands
	`
}

func (r *CommandRepository) buildWhereClause(filter command.Filter) (string, []any) {
	var conditions []string
	var args []any

	if filter.TenantID != nil {
		args = append(args, filter.TenantID.String())
		conditions = append(conditions, fmt.Sprintf("tenant_id = $%d", len(args)))
	}

	if filter.SensorID != nil {
		args = append(args, filter.SensorID.String())
		conditions = append(conditions, fmt.Sprintf("sensor_id = $%d", len(args)))
	}

	if filter.Type != nil {
		args = append(args, string(*filter.Type))
		conditions = append(conditions, fmt.Sprintf("type = $%d", len(args)))
	}

	if filter.Status != nil {
		args = append(args, string(*filter.Status))
		conditions = append(conditions, fmt.Sprintf("status = $%d", len(args)))
	}

	if filter.Priority != nil {
		args = append(args, string(*filter.Priority))
		conditions = append(conditions, fmt.Sprintf("priority = $%d", len(args)))
	}

	// Platform job filters (v3.2)
	if filter.IsPlatformJob != nil {
		args = append(args, *filter.IsPlatformJob)
		conditions = append(conditions, fmt.Sprintf("is_platform_job = $%d", len(args)))
	}

	// OSS Edition: PlatformSensorID filter not supported
	// if filter.PlatformSensorID != nil { ... }

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
		sensorID           sql.NullString
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
		platformSensorID   sql.NullString
		authTokenHash      sql.NullString
		authTokenPrefix    sql.NullString
		authTokenExpiresAt sql.NullTime
		queuePriority      int
		queuedAt           sql.NullTime
		dispatchAttempts   int
		scanZoneID         sql.NullString
		leaseExpiresAt     sql.NullTime
	)

	var errorMessage sql.NullString

	err := row.Scan(
		&id,
		&tenantID,
		&sensorID,
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
		&platformSensorID,
		&authTokenHash,
		&authTokenPrefix,
		&authTokenExpiresAt,
		&queuePriority,
		&queuedAt,
		&dispatchAttempts,
		&scanZoneID,
		&cmd.LeaseEpoch,
		&leaseExpiresAt,
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

	if sensorID.Valid {
		wid, _ := shared.IDFromString(sensorID.String)
		cmd.SensorID = &wid
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

	if platformSensorID.Valid {
		paid, _ := shared.IDFromString(platformSensorID.String)
		cmd.PlatformSensorID = &paid
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

	if leaseExpiresAt.Valid {
		cmd.LeaseExpiresAt = &leaseExpiresAt.Time
	}
	if scanZoneID.Valid {
		zid, _ := shared.IDFromString(scanZoneID.String)
		cmd.ScanZoneID = &zid
	}

	return cmd, nil
}

// scanCommandFromRows scans a command from a result set row.
func (r *CommandRepository) scanCommandFromRows(rows *sql.Rows) (*command.Command, error) {
	cmd := &command.Command{}
	var (
		id                 string
		tenantID           string
		sensorID           sql.NullString
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
		platformSensorID   sql.NullString
		authTokenHash      sql.NullString
		authTokenPrefix    sql.NullString
		authTokenExpiresAt sql.NullTime
		queuePriority      int
		queuedAt           sql.NullTime
		dispatchAttempts   int
		scanZoneID         sql.NullString
		leaseExpiresAt     sql.NullTime
	)

	var errorMessage sql.NullString

	err := rows.Scan(
		&id,
		&tenantID,
		&sensorID,
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
		&platformSensorID,
		&authTokenHash,
		&authTokenPrefix,
		&authTokenExpiresAt,
		&queuePriority,
		&queuedAt,
		&dispatchAttempts,
		&scanZoneID,
		&cmd.LeaseEpoch,
		&leaseExpiresAt,
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

	if sensorID.Valid {
		wid, _ := shared.IDFromString(sensorID.String)
		cmd.SensorID = &wid
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

	if platformSensorID.Valid {
		paid, _ := shared.IDFromString(platformSensorID.String)
		cmd.PlatformSensorID = &paid
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

	if leaseExpiresAt.Valid {
		cmd.LeaseExpiresAt = &leaseExpiresAt.Time
	}
	if scanZoneID.Valid {
		zid, _ := shared.IDFromString(scanZoneID.String)
		cmd.ScanZoneID = &zid
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
	if err := rows.Err(); err != nil {
		return nil, err
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
		AND platform_sensor_id IS NULL
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
		AND platform_sensor_id IS NULL
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
		AND platform_sensor_id IS NULL
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
	if err := rows.Err(); err != nil {
		return nil, err
	}

	return commands, nil
}

// GetNextPlatformJob atomically claims the next job from the queue for a sensor.
// Uses database function get_next_platform_job for atomic operation with FOR UPDATE SKIP LOCKED.
func (r *CommandRepository) GetNextPlatformJob(ctx context.Context, sensorID shared.ID, capabilities []string, tools []string) (*command.Command, error) {
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
		sensorID.String(),
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
		AND platform_sensor_id IS NULL
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
//
// maxRetries used to be accepted and dropped on the floor: only the threshold
// was bound and the SQL hardcoded `dispatch_attempts < 3`. See migration
// 000200, which also fixes the WHERE clause that made the function unable to
// match any row at all.
func (r *CommandRepository) RecoverStuckJobs(ctx context.Context, stuckThresholdMinutes int, maxRetries int) (int64, error) {
	query := `SELECT recover_stuck_platform_jobs($1::INTEGER, $2::INTEGER)`

	var recovered int64
	err := r.db.QueryRowContext(ctx, query, stuckThresholdMinutes, maxRetries).Scan(&recovered)
	if err != nil {
		return 0, fmt.Errorf("failed to recover stuck platform jobs: %w", err)
	}

	return recovered, nil
}

// FindQueueExpiredPlatformJobs returns platform jobs still waiting in the queue
// past maxQueueMinutes, so the caller can expire them *and* tell the owning
// pipeline run why.
//
// This deliberately returns rows instead of expiring them. The previous
// ExpireOldPlatformJobs was a raw UPDATE flipping the rows to 'expired'
// in place — the same silent-expiry mistake ExpireOldCommands made for tenant
// commands. Platform jobs are created by scan/pipeline dispatch with a
// pipeline_run_id + step_key payload and no expires_at, so FindExpired never
// sees them; the raw UPDATE was the only thing that ever reaped them, and it
// notified nobody. The step stayed 'queued' until ScanTimeoutController
// eventually reported a generic timeout instead of "expired in queue".
// app/command.ExpirationChecker owns the expiry now and calls
// pipeline.OnStepFailed.
func (r *CommandRepository) FindQueueExpiredPlatformJobs(ctx context.Context, maxQueueMinutes int) ([]*command.Command, error) {
	query := r.selectQuery() + `
		WHERE is_platform_job = TRUE
		AND status = 'pending'
		AND queued_at IS NOT NULL
		AND queued_at < NOW() - ($1 || ' minutes')::INTERVAL
		ORDER BY queued_at ASC
		LIMIT 100
	`

	rows, err := r.db.QueryContext(ctx, query, maxQueueMinutes)
	if err != nil {
		return nil, fmt.Errorf("failed to find queue-expired platform jobs: %w", err)
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
	if err := rows.Err(); err != nil {
		return nil, err
	}

	return commands, nil
}

// ExpireIfUnchanged expires a command the expiration checker read earlier, but
// only if the row has not moved since: the status, sensor assignments, expiry
// and queue time must still be the ones in the snapshot. Without the condition
// the checker wrote its stale snapshot back over a command a sensor had just
// started or completed, and two replicas both expired the same row and both
// failed its pipeline step.
func (r *CommandRepository) ExpireIfUnchanged(ctx context.Context, cmd *command.Command, errorMessage string) (bool, error) {
	res, err := r.db.ExecContext(ctx, `
		UPDATE commands
		SET status = 'expired', error_message = $3
		WHERE id = $1 AND tenant_id = $2
		  AND status = $4
		  AND sensor_id IS NOT DISTINCT FROM $5
		  AND platform_sensor_id IS NOT DISTINCT FROM $6
		  AND expires_at IS NOT DISTINCT FROM $7
		  AND queued_at IS NOT DISTINCT FROM $8`,
		cmd.ID.String(), cmd.TenantID.String(), errorMessage,
		string(cmd.Status),
		nullIDString(cmd.SensorID),
		nullIDString(cmd.PlatformSensorID),
		nullTime(cmd.ExpiresAt),
		nullTime(cmd.QueuedAt),
	)
	if err != nil {
		return false, fmt.Errorf("expire command: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("expire command: %w", err)
	}
	return n == 1, nil
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
			AND platform_sensor_id IS NULL
		),
		total AS (
			SELECT COUNT(*) as total_count
			FROM commands
			WHERE is_platform_job = TRUE
			AND status = 'pending'
			AND platform_sensor_id IS NULL
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
	if err := rows.Err(); err != nil {
		return result, err
	}

	return pagination.NewResult(commands, total, page), nil
}

// ListPlatformJobsAdmin lists platform jobs across all tenants (admin only).
func (r *CommandRepository) ListPlatformJobsAdmin(ctx context.Context, sensorID, tenantID *shared.ID, status *command.CommandStatus, page pagination.Pagination) (pagination.Result[*command.Command], error) {
	var result pagination.Result[*command.Command]
	var conditions []string
	var args []any

	conditions = append(conditions, "is_platform_job = TRUE")

	if sensorID != nil {
		args = append(args, sensorID.String())
		conditions = append(conditions, fmt.Sprintf("platform_sensor_id = $%d", len(args)))
	}

	if tenantID != nil {
		args = append(args, tenantID.String())
		conditions = append(conditions, fmt.Sprintf("tenant_id = $%d", len(args)))
	}

	if status != nil {
		args = append(args, string(*status))
		conditions = append(conditions, fmt.Sprintf("status = $%d", len(args)))
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
	if err := rows.Err(); err != nil {
		return result, err
	}

	return pagination.NewResult(commands, total, page), nil
}

// GetPlatformJobsBySensor lists platform jobs assigned to a sensor.
func (r *CommandRepository) GetPlatformJobsBySensor(ctx context.Context, sensorID shared.ID, status *command.CommandStatus) ([]*command.Command, error) {
	query := r.selectQuery() + " WHERE platform_sensor_id = $1 AND is_platform_job = TRUE"
	args := []any{sensorID.String()}

	if status != nil {
		query += " AND status = $2"
		args = append(args, string(*status))
	}

	query += orderByCreatedAtDesc

	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to get platform jobs by sensor: %w", err)
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
	if err := rows.Err(); err != nil {
		return nil, err
	}

	return commands, nil
}

// =============================================================================
// Tenant Command Recovery Methods
// =============================================================================

// ReleasePendingFromUnavailableSensors unpins pending scan commands that the
// platform routed to a sensor which has since gone stale or offline (the
// health controller walks it down the heartbeat ladder after missed
// heartbeats; a late sensor keeps its pins) or stopped being active
// (disabled, revoked). Before this, such a command waited for the run timeout:
// only a zone unassignment ever unpinned pending work (RFC-030 B7).
//
// Only routed scan work is released: type 'scan' with a pipeline_run_id in the
// payload, i.e. what trigger-time zone pinning and pipeline step routing pin.
// A command an operator addressed to one sensor on purpose (config_update,
// health_check, a scan coverage job pinned to one Tenable runner) keeps its
// sensor. scan_zone_id is untouched, so the zone claim predicate still limits
// the released command to the zone's sensors, and the tool gate to sensors
// with the tool.
func (r *CommandRepository) ReleasePendingFromUnavailableSensors(ctx context.Context) (int64, error) {
	res, err := r.db.ExecContext(ctx, `
		UPDATE commands c
		SET sensor_id = NULL
		FROM sensors s
		WHERE c.sensor_id = s.id
		  AND c.status = 'pending'
		  AND `+routedScanWork("c")+`
		  AND (s.health IN ('stale', 'offline') OR s.status <> 'active')`)
	if err != nil {
		return 0, fmt.Errorf("failed to release pending commands of unavailable sensors: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("failed to read rows affected: %w", err)
	}
	return n, nil
}

// routedScanWork is the SQL predicate for scan work the platform routed to a
// sensor (trigger-time zone pinning, pipeline step routing): type 'scan'
// with a pipeline_run_id in the payload. Such a command may be handed to
// another sensor; any other command addressed to a sensor is for that
// sensor only.
func routedScanWork(alias string) string {
	return alias + ".type = 'scan' AND " + alias + ".payload ? 'pipeline_run_id'"
}

// RecoverStuckTenantCommands returns stuck tenant commands to the pool.
// A command is stuck if it's assigned to an offline sensor or hasn't been picked up.
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

// FailExhaustedCommandsReturning is FailExhaustedCommands (the same rows and
// the same change as the fail_exhausted_commands() function) returning the
// failed commands, so the caller can notify their pipeline runs.
func (r *CommandRepository) FailExhaustedCommandsReturning(ctx context.Context, maxRetries int) ([]*command.Command, error) {
	const query = `
		UPDATE commands
		SET status = 'failed',
		    error_message = 'Max dispatch attempts exceeded',
		    completed_at = NOW()
		WHERE status IN ('pending', 'acknowledged')
		  AND dispatch_attempts >= $1
		RETURNING id, tenant_id, payload, dispatch_attempts
	`
	rows, err := r.db.QueryContext(ctx, query, maxRetries)
	if err != nil {
		return nil, fmt.Errorf("failed to mark exhausted commands as failed: %w", err)
	}
	defer rows.Close()
	var out []*command.Command
	for rows.Next() {
		var (
			id, tenantID string
			payload      []byte
			attempts     int
		)
		if err := rows.Scan(&id, &tenantID, &payload, &attempts); err != nil {
			return nil, fmt.Errorf("failed to scan exhausted command: %w", err)
		}
		cid, _ := shared.IDFromString(id)
		tid, _ := shared.IDFromString(tenantID)
		out = append(out, &command.Command{
			ID: cid, TenantID: tid, Payload: payload, DispatchAttempts: attempts,
			Status: command.CommandStatusFailed, ErrorMessage: "Max dispatch attempts exceeded",
		})
	}
	return out, rows.Err()
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

// CancelByPipelineRunID marks all non-terminal commands for a pipeline run as canceled.
// A command is "non-terminal" if its status is one of: pending, acknowledged, running.
// Terminal statuses (completed, failed, canceled, expired) are left untouched.
//
// Tenant scoping is enforced — only commands belonging to the given tenant are affected.
// Returns the number of commands canceled.
func (r *CommandRepository) CancelByPipelineRunID(ctx context.Context, tenantID, runID shared.ID) (int64, error) {
	// A command belongs to the run either through commands.step_run_id or
	// through the pipeline_run_id the dispatcher writes into its payload. The
	// scan dispatcher only writes the payload key (step_run_id stays NULL), so
	// matching on step_runs alone canceled nothing for a scan: the run read
	// "canceled" while the sensor kept scanning.
	query := `
		UPDATE commands c
		SET status = 'canceled',
		    -- NOTE: commands has no updated_at column (no migration adds one), so
		    -- assigning it made every pipeline cancel fail with 42703.
		    completed_at = NOW(),
		    lease_expires_at = NULL
		WHERE c.tenant_id = $1
		  AND c.status IN ('pending', 'acknowledged', 'running')
		  AND (
		        c.payload->>'pipeline_run_id' = $3
		        OR c.step_run_id IN (SELECT sr.id FROM step_runs sr WHERE sr.pipeline_run_id = $2)
		  )
	`
	result, err := r.db.ExecContext(ctx, query, tenantID.String(), runID.String(), runID.String())
	if err != nil {
		return 0, fmt.Errorf("failed to cancel commands by pipeline run: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("failed to read rows affected: %w", err)
	}
	return rows, nil
}

var _ command.StepBatchGate = (*CommandRepository)(nil)

// The expiration checker asserts this; without it, it refuses to expire.
var _ command.ConditionalExpirer = (*CommandRepository)(nil)

// StepBatchState reports the zone batches that share one step run.
func (r *CommandRepository) StepBatchState(ctx context.Context, tenantID, stepRunID shared.ID) (command.StepBatch, error) {
	var b command.StepBatch
	err := r.db.QueryRowContext(ctx, `
		SELECT count(*),
		       count(*) FILTER (WHERE status IN ('pending', 'acknowledged', 'running')),
		       count(*) FILTER (WHERE status IN ('failed', 'expired', 'canceled')),
		       COALESCE(sum(CASE WHEN jsonb_typeof(result->'findings_count') = 'number'
		                         THEN (result->>'findings_count')::numeric END), 0)::bigint,
		       COALESCE((array_agg(error_message ORDER BY completed_at NULLS LAST, id)
		                 FILTER (WHERE status IN ('failed', 'expired', 'canceled')
		                           AND COALESCE(error_message, '') <> ''))[1], '')
		FROM commands
		WHERE tenant_id = $1 AND step_run_id = $2`,
		tenantID.String(), stepRunID.String()).Scan(&b.Total, &b.Active, &b.Failed, &b.Findings, &b.FirstError)
	if err != nil {
		return b, fmt.Errorf("step batch state: %w", err)
	}
	return b, nil
}

// ClaimStepFinalization stamps completed_at on a step run that has none yet.
// Two batches finishing at the same moment both see "no batch active"; only
// the one whose UPDATE matches records the outcome.
func (r *CommandRepository) ClaimStepFinalization(ctx context.Context, stepRunID shared.ID) (bool, error) {
	res, err := r.db.ExecContext(ctx,
		`UPDATE step_runs SET completed_at = NOW() WHERE id = $1 AND completed_at IS NULL`,
		stepRunID.String())
	if err != nil {
		return false, fmt.Errorf("claim step finalization: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("claim step finalization: %w", err)
	}
	return n == 1, nil
}

// ReleaseForSensor hands a command the sensor holds back to the queue
// (RFC-030 §5.12): pending, unpinned, acknowledged/started times cleared, the
// reason kept in error_message, scan_zone_id untouched. Only an acknowledged
// or running command held by sensorID is released; a voluntary release does
// not count as a dispatch attempt.
func (r *CommandRepository) ReleaseForSensor(ctx context.Context, tenantID, commandID shared.ID, sensorID, reason string) (bool, error) {
	res, err := r.db.ExecContext(ctx, `
		UPDATE commands
		SET status = 'pending', sensor_id = NULL,
		    acknowledged_at = NULL, started_at = NULL,
		    lease_expires_at = NULL,
		    error_message = $4
		WHERE id = $1 AND tenant_id = $2 AND sensor_id = $3
		  AND status IN ('acknowledged', 'running')`,
		commandID.String(), tenantID.String(), sensorID, reason)
	if err != nil {
		return false, fmt.Errorf("failed to release command: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("failed to read rows affected: %w", err)
	}
	return n > 0, nil
}
