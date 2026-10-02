package postgres

// Command leases: docs/rfcs/RFC-035-sensor-control-plane-under-load.md §5.7
// (owner decision D6) and docs/architecture/sensors.md "Command leases".

import (
	"context"
	"fmt"
	"time"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/pkg/domain/command"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// SetLeaseDuration sets how long a claim holds without renewal; d is
// clamped to [command.MinLeaseDuration, command.MaxLeaseDuration]. Call
// before use.
func (r *CommandRepository) SetLeaseDuration(d time.Duration) {
	r.lease = command.ClampLeaseDuration(d)
}

// leaseSeconds is the lease length in seconds, for make_interval.
func (r *CommandRepository) leaseSeconds() float64 {
	if r.lease <= 0 {
		return command.DefaultLeaseDuration.Seconds()
	}
	return r.lease.Seconds()
}

// RenewLeases extends the leases of the commands sensorID holds: those in
// ids, or every one it holds when all is set (a sensor that does not report
// what it runs). Only claimed or running commands still held by the sensor
// are touched; anything re-queued or claimed by another sensor is left
// alone. Returns the number of leases renewed.
func (r *CommandRepository) RenewLeases(ctx context.Context, tenantID, sensorID shared.ID, ids []string, all bool) (int64, error) {
	if !all && len(ids) == 0 {
		return 0, nil
	}
	query := `
		UPDATE commands
		SET lease_expires_at = NOW() + make_interval(secs => $3)
		WHERE tenant_id = $1 AND sensor_id = $2
		  AND status IN ('acknowledged', 'running')
		  AND ($4::boolean OR id::text = ANY($5::text[]))`
	res, err := r.db.ExecContext(ctx, query, tenantID.String(), sensorID.String(), r.leaseSeconds(), all, pq.Array(ids))
	if err != nil {
		return 0, fmt.Errorf("failed to renew command leases: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("failed to read rows affected: %w", err)
	}
	return n, nil
}

// RequeueExpiredLeases puts every tenant command whose lease ran out back
// to pending: unpinned, its zone kept, one more dispatch attempt (so
// fail_exhausted_commands ends a command that keeps killing its sensors).
// The holder can no longer change it: its start, complete or fail are
// guarded by the sensor, the state and the lease epoch (FencedUpdate).
func (r *CommandRepository) RequeueExpiredLeases(ctx context.Context) ([]command.RequeuedCommand, error) {
	rows, err := r.db.QueryContext(ctx, `
		UPDATE commands c
		SET status = 'pending', sensor_id = NULL,
		    acknowledged_at = NULL, started_at = NULL,
		    lease_expires_at = NULL,
		    dispatch_attempts = c.dispatch_attempts + 1,
		    error_message = $1
		FROM (
			SELECT id, sensor_id AS old_sensor_id, lease_epoch AS old_epoch
			FROM commands
			WHERE status IN ('acknowledged', 'running')
			  AND is_platform_job = FALSE
			  AND lease_expires_at IS NOT NULL
			  AND lease_expires_at < NOW()
			FOR UPDATE SKIP LOCKED
		) expired
		WHERE c.id = expired.id
		RETURNING c.id, c.tenant_id, expired.old_sensor_id, expired.old_epoch`,
		command.LeaseExpiredMessage)
	if err != nil {
		return nil, fmt.Errorf("failed to re-queue commands with an expired lease: %w", err)
	}
	defer rows.Close()
	var out []command.RequeuedCommand
	for rows.Next() {
		var id, tenant string
		var sensor *string
		var epoch int
		if err := rows.Scan(&id, &tenant, &sensor, &epoch); err != nil {
			return nil, fmt.Errorf("failed to scan re-queued command: %w", err)
		}
		rq := command.RequeuedCommand{Epoch: epoch}
		if rq.ID, err = shared.IDFromString(id); err != nil {
			continue
		}
		if rq.TenantID, err = shared.IDFromString(tenant); err != nil {
			continue
		}
		if sensor != nil {
			if sid, err := shared.IDFromString(*sensor); err == nil {
				rq.SensorID = &sid
			}
		}
		out = append(out, rq)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed to iterate re-queued commands: %w", err)
	}
	return out, nil
}

// FencedUpdate is Update for a sensor-side state change: it applies only if
// the command is still held by sensorID in the state and lease epoch the
// caller read (expect). A command that was re-queued, re-claimed or finished
// meanwhile is left untouched and false is returned. A started command's
// lease is renewed.
func (r *CommandRepository) FencedUpdate(ctx context.Context, cmd *command.Command, expect command.Fence) (bool, error) {
	res, err := r.db.ExecContext(ctx, `
		UPDATE commands
		SET status = $4::text, error_message = $5, started_at = $6, completed_at = $7,
		    result = $8,
		    lease_expires_at = CASE
		        WHEN $4::text = 'running' THEN NOW() + make_interval(secs => $9)
		        WHEN $4::text IN ('completed', 'failed') THEN NULL
		        ELSE lease_expires_at END
		WHERE id = $1 AND tenant_id = $2 AND sensor_id = $3
		  AND status = $10::text AND lease_epoch = $11`,
		cmd.ID.String(), cmd.TenantID.String(), expect.SensorID,
		string(cmd.Status), cmd.ErrorMessage, nullTime(cmd.StartedAt), nullTime(cmd.CompletedAt),
		nullJSON(cmd.Result), r.leaseSeconds(),
		string(expect.Status), expect.Epoch)
	if err != nil {
		return false, fmt.Errorf("failed to update command: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("failed to read rows affected: %w", err)
	}
	return n > 0, nil
}
