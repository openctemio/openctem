package postgres

// Sensor refusals of a command (research/25 §3.6, D8; migration 000950):
// the refusals recorded on a command, the re-queue that excludes the
// refuser, and the sensors that could still take the command.

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/pkg/domain/command"
	"github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

var _ command.RefusalStore = (*CommandRepository)(nil)

// refusedByPredicate keeps a sensor from claiming a command it refused.
func refusedByPredicate(sensorParam string) string {
	return "NOT (commands.refused_by @> ARRAY[" + sensorParam + "::uuid])"
}

// CommandRefusals returns the refusals recorded on a command of the tenant.
func (r *CommandRepository) CommandRefusals(ctx context.Context, tenantID, commandID shared.ID) ([]command.RefusalRecord, error) {
	var raw []byte
	err := r.db.QueryRowContext(ctx,
		`SELECT refusals FROM commands WHERE id = $1 AND tenant_id = $2`,
		commandID.String(), tenantID.String()).Scan(&raw)
	if err != nil {
		return nil, fmt.Errorf("read command refusals: %w", err)
	}
	var out []command.RefusalRecord
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &out); err != nil {
			return nil, fmt.Errorf("decode command refusals: %w", err)
		}
	}
	return out, nil
}

// RequeueRefused puts a command the fenced sensor holds back to pending,
// unpinned with its zone kept, records the refusal and excludes the sensor
// from later claims. One more dispatch attempt is counted, as for a lease
// re-queue.
func (r *CommandRepository) RequeueRefused(ctx context.Context, tenantID, commandID shared.ID, fence command.Fence, rec command.RefusalRecord, message string) (bool, error) {
	recJSON, err := json.Marshal(rec)
	if err != nil {
		return false, err
	}
	res, err := r.db.ExecContext(ctx, `
		UPDATE commands
		SET status = 'pending', sensor_id = NULL,
		    acknowledged_at = NULL, started_at = NULL,
		    lease_expires_at = NULL,
		    dispatch_attempts = dispatch_attempts + 1,
		    error_message = $6,
		    refused_by = array_append(refused_by, $3::uuid),
		    refusals = refusals || jsonb_build_array($7::jsonb)
		WHERE id = $1 AND tenant_id = $2 AND sensor_id = $3
		  AND status = $4::text AND lease_epoch = $5
		  AND NOT (refused_by @> ARRAY[$3::uuid])
		  AND cardinality(refused_by) < 16`,
		commandID.String(), tenantID.String(), fence.SensorID, string(fence.Status), fence.Epoch, message, string(recJSON))
	if err != nil {
		return false, fmt.Errorf("re-queue refused command: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("failed to read rows affected: %w", err)
	}
	return n > 0, nil
}

// AppendRefusal records a refusal on a failed command of the tenant.
func (r *CommandRepository) AppendRefusal(ctx context.Context, tenantID, commandID shared.ID, rec command.RefusalRecord) error {
	recJSON, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	_, err = r.db.ExecContext(ctx, `
		UPDATE commands
		SET refused_by = CASE WHEN refused_by @> ARRAY[$3::uuid] THEN refused_by ELSE array_append(refused_by, $3::uuid) END,
		    refusals = refusals || jsonb_build_array($4::jsonb)
		WHERE id = $1 AND tenant_id = $2 AND status = 'failed'
		  AND cardinality(refused_by) < 16`,
		commandID.String(), tenantID.String(), rec.SensorID, string(recJSON))
	if err != nil {
		return fmt.Errorf("record command refusal: %w", err)
	}
	return nil
}

// maxRequeueCandidates bounds the sensors read to decide a re-queue.
const maxRequeueCandidates = 200

// RequeueCandidates returns the local-policy reports of the tenant's
// sensors, other than exclude, that could claim the command now: active,
// dispatchable, with a usable key, in the command's zone when it has one,
// and with the command's tool. The caller judges the reports
// (sensor.Accepts).
func (r *CommandRepository) RequeueCandidates(ctx context.Context, tenantID, commandID shared.ID, exclude []shared.ID) ([]*sensor.LocalPolicyReport, error) {
	ex := make([]string, len(exclude))
	for i, id := range exclude {
		ex[i] = id.String()
	}
	rows, err := r.db.QueryContext(ctx, `
		SELECT s.id, s.reported_local_policy
		FROM commands
		JOIN sensors s ON s.tenant_id = commands.tenant_id
		WHERE commands.id = $1 AND commands.tenant_id = $2
		  AND s.status = 'active'
		  AND s.health IN `+sensorDispatchableHealthSQL+`
		  AND s.last_seen_at IS NOT NULL
		  AND `+sensorKeyUsableSQL("s")+`
		  AND (s.execution_mode = 'daemon' OR s.type IN ('worker', 'collector'))
		  AND NOT (s.id = ANY($3::uuid[]))
		  AND (commands.scan_zone_id IS NULL OR EXISTS (
		        SELECT 1 FROM scan_zone_sensors zs
		        WHERE zs.zone_id = commands.scan_zone_id AND zs.tenant_id = commands.tenant_id AND zs.sensor_id = s.id))
		  AND (`+commandToolSQL+` IS NULL OR `+commandToolSQL+` = ANY(`+sensorDispatchTools("s")+`))
		LIMIT $4`,
		commandID.String(), tenantID.String(), pq.Array(ex), maxRequeueCandidates)
	if err != nil {
		return nil, fmt.Errorf("re-queue candidates: %w", err)
	}
	defer rows.Close()
	var out []*sensor.LocalPolicyReport
	for rows.Next() {
		var id string
		var raw []byte
		if err := rows.Scan(&id, &raw); err != nil {
			return nil, fmt.Errorf("scan re-queue candidate: %w", err)
		}
		sid, err := shared.IDFromString(id)
		if err != nil {
			continue
		}
		rep, _ := scanLocalPolicy(sid, raw, sql.NullTime{})
		out = append(out, rep)
	}
	return out, rows.Err()
}
