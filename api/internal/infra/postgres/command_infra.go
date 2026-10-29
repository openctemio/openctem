package postgres

// Infrastructure failures of a command (research/302; migration
// command_infra_failure): the failures recorded on a command, the re-queue
// that excludes the failing sensor, and the fleet stop rule.

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/pkg/domain/command"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

var _ command.InfraStore = (*CommandRepository)(nil)

// failedOnPredicate keeps a sensor from claiming a command it failed.
func failedOnPredicate(sensorParam string) string {
	return "NOT (commands.failed_on @> ARRAY[" + sensorParam + "::uuid])"
}

// CommandAttempts returns the failures recorded on a command of the tenant.
func (r *CommandRepository) CommandAttempts(ctx context.Context, tenantID, commandID shared.ID) ([]command.InfraAttempt, error) {
	var raw []byte
	err := r.db.QueryRowContext(ctx,
		`SELECT attempts FROM commands WHERE id = $1 AND tenant_id = $2`,
		commandID.String(), tenantID.String()).Scan(&raw)
	if err != nil {
		return nil, fmt.Errorf("read command attempts: %w", err)
	}
	var out []command.InfraAttempt
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &out); err != nil {
			return nil, fmt.Errorf("decode command attempts: %w", err)
		}
	}
	return out, nil
}

// RequeueFailed puts a command the fenced sensor holds back to pending,
// unpinned with its zone kept, records the failure and excludes the sensor
// from later claims. One more dispatch attempt is counted, as for a lease
// re-queue; the return is counted without a delay because another sensor
// may take it at once (the failing sensor is excluded).
func (r *CommandRepository) RequeueFailed(ctx context.Context, tenantID, commandID shared.ID, fence command.Fence, att command.InfraAttempt, message string) (bool, error) {
	attJSON, err := json.Marshal(att)
	if err != nil {
		return false, err
	}
	res, err := r.db.ExecContext(ctx, `
		UPDATE commands
		SET status = 'pending', sensor_id = NULL,
		    acknowledged_at = NULL, started_at = NULL,
		    lease_expires_at = NULL,
		    dispatch_attempts = dispatch_attempts + 1,
		    `+requeueCountSQL("")+`,
		    error_message = $6,
		    failed_on = CASE WHEN failed_on @> ARRAY[$3::uuid] THEN failed_on ELSE array_append(failed_on, $3::uuid) END,
		    attempts = attempts || jsonb_build_array($7::jsonb)
		WHERE id = $1 AND tenant_id = $2 AND sensor_id = $3
		  AND status = $4::text AND lease_epoch = $5
		  AND `+routedScanWork("commands")+`
		  AND is_platform_job = FALSE
		  AND jsonb_array_length(attempts) < `+fmt.Sprint(command.MaxInfraAttempts),
		commandID.String(), tenantID.String(), fence.SensorID, string(fence.Status), fence.Epoch, message, string(attJSON))
	if err != nil {
		return false, fmt.Errorf("re-queue failed command: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("failed to read rows affected: %w", err)
	}
	if n > 0 {
		r.changedTenant(tenantID)
	}
	return n > 0, nil
}

// RecordFailedAttempt records att and its class on a command the fenced
// sensor holds and is about to fail; the status change that follows
// writes the failure event with the class.
func (r *CommandRepository) RecordFailedAttempt(ctx context.Context, tenantID, commandID shared.ID, fence command.Fence, att command.InfraAttempt) error {
	attJSON, err := json.Marshal(att)
	if err != nil {
		return err
	}
	_, err = r.db.ExecContext(ctx, `
		UPDATE commands
		SET failed_on = CASE WHEN failed_on @> ARRAY[$3::uuid] OR cardinality(failed_on) >= 16 THEN failed_on ELSE array_append(failed_on, $3::uuid) END,
		    attempts = CASE WHEN jsonb_array_length(attempts) >= `+fmt.Sprint(command.MaxInfraAttempts)+` THEN attempts ELSE attempts || jsonb_build_array($6::jsonb) END,
		    failure_class = $7
		WHERE id = $1 AND tenant_id = $2 AND sensor_id = $3
		  AND status = $4::text AND lease_epoch = $5`,
		commandID.String(), tenantID.String(), fence.SensorID, string(fence.Status), fence.Epoch, string(attJSON), string(att.Class))
	if err != nil {
		return fmt.Errorf("record command failure: %w", err)
	}
	return nil
}

// fleetKeyHash is the stored key of a tool and content version.
func fleetKeyHash(k command.FleetKey) string {
	sum := sha256.Sum256([]byte(k.String()))
	return hex.EncodeToString(sum[:16])
}

// RecordFleetFailure notes that sensorID failed key and reports whether the
// stop rule is in force: this failure made FleetBreakerSensors different
// sensors fail it within FleetBreakerWindow (the rule trips and holds for
// FleetBreakerHold), or it was already tripped and the hold has not ended.
// A hold is not extended by further failures. Tenant-scoped.
func (r *CommandRepository) RecordFleetFailure(ctx context.Context, tenantID shared.ID, key command.FleetKey, sensorID shared.ID, class command.FailureClass, now time.Time) (bool, error) {
	if !key.Valid() {
		return false, nil
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return false, fmt.Errorf("begin fleet breaker: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	hash := fleetKeyHash(key)
	var sensors pq.StringArray
	var started time.Time
	var until sql.NullTime
	err = tx.QueryRowContext(ctx, `
		SELECT sensors, window_started_at, until FROM failure_breakers
		WHERE tenant_id = $1 AND key_hash = $2 FOR UPDATE`,
		tenantID.String(), hash).Scan(&sensors, &started, &until)
	exists := err == nil
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return false, fmt.Errorf("read fleet breaker: %w", err)
	}
	if exists && until.Valid && until.Time.After(now) {
		return true, nil
	}
	if !exists || now.Sub(started) > command.FleetBreakerWindow || (until.Valid && !until.Time.After(now)) {
		sensors, started = pq.StringArray{}, now
	}
	have := false
	for _, s := range sensors {
		if s == sensorID.String() {
			have = true
		}
	}
	if !have && len(sensors) < 16 {
		sensors = append(sensors, sensorID.String())
	}
	var newUntil, tripped any
	trip := len(sensors) >= command.FleetBreakerSensors
	if trip {
		newUntil, tripped = now.Add(command.FleetBreakerHold), now
	}
	_, err = tx.ExecContext(ctx, `
		INSERT INTO failure_breakers (tenant_id, key_hash, tool, tool_digest, content_digest, class, sensors, window_started_at, tripped_at, until)
		VALUES ($1, $2, $3, $4, $5, $6, $7::uuid[], $8, $9, $10)
		ON CONFLICT (tenant_id, key_hash) DO UPDATE
		SET class = EXCLUDED.class, sensors = EXCLUDED.sensors,
		    window_started_at = EXCLUDED.window_started_at,
		    tripped_at = EXCLUDED.tripped_at, until = EXCLUDED.until`,
		tenantID.String(), hash, key.Tool, key.ToolDigest, key.ContentDigest, string(class), pq.Array([]string(sensors)), started, tripped, newUntil)
	if err != nil {
		return false, fmt.Errorf("write fleet breaker: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return false, fmt.Errorf("commit fleet breaker: %w", err)
	}
	return trip, nil
}
