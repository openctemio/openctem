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

// CommandsToCancel returns the ids among ids (a heartbeat's running list,
// untrusted) that sensorID must stop: every well-formed id except the
// commands this sensor still holds (acknowledged or running, or pending and
// pinned to it: handed over, not claimed yet) and the ones it completed.
// A re-queued command is pending with no sensor, so it is returned. A command of another tenant is reported like an unknown one, so
// the answer says nothing about it. Malformed ids are dropped.
func (r *CommandRepository) CommandsToCancel(ctx context.Context, tenantID, sensorID shared.ID, ids []string) ([]string, error) {
	valid := make([]string, 0, len(ids))
	for _, id := range ids {
		if _, err := shared.IDFromString(id); err == nil {
			valid = append(valid, id)
		}
	}
	if len(valid) == 0 {
		return nil, nil
	}
	rows, err := r.db.QueryContext(ctx, `
		SELECT DISTINCT r.id
		FROM unnest($3::text[]) AS r(id)
		WHERE NOT EXISTS (
			SELECT 1 FROM commands c
			WHERE c.id = r.id::uuid AND c.tenant_id = $1 AND c.sensor_id = $2
			  AND c.status IN ('pending', 'acknowledged', 'running', 'completed'))`,
		tenantID.String(), sensorID.String(), pq.Array(valid))
	if err != nil {
		return nil, fmt.Errorf("failed to find commands to cancel: %w", err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("failed to scan command id: %w", err)
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// CancelIfOpen writes cmd's cancellation (status canceled, completed_at)
// only if the command is still pending, acknowledged or running, so a
// result a sensor got accepted between the read and this write is never
// overwritten. Returns whether it applied.
func (r *CommandRepository) CancelIfOpen(ctx context.Context, cmd *command.Command) (bool, error) {
	res, err := r.db.ExecContext(ctx, `
		UPDATE commands
		SET status = 'canceled', completed_at = $3, lease_expires_at = NULL
		WHERE id = $1 AND tenant_id = $2
		  AND status IN ('pending', 'acknowledged', 'running')`,
		cmd.ID.String(), cmd.TenantID.String(), nullTime(cmd.CompletedAt))
	if err != nil {
		return false, fmt.Errorf("failed to cancel command: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("failed to read rows affected: %w", err)
	}
	if n > 0 {
		// The holder (if any) is told to stop; the sensor is not known
		// here, so the tenant's streams re-check.
		r.changedTenant(cmd.TenantID)
	}
	return n > 0, nil
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
	woken := map[shared.ID]bool{}
	for _, rq := range out {
		if !woken[rq.TenantID] {
			woken[rq.TenantID] = true
			r.changedTenant(rq.TenantID)
		}
	}
	return out, nil
}

// ReleaseHeldBySensor takes back every tenant command sensorID holds under a
// lease (acknowledged or running), at once, for a sensor that was revoked or
// disabled (RFC-040 §5.2). Routed scan work goes back to pending, unpinned,
// its zone kept, with requeueMessage, and does not count as a dispatch
// attempt (the sensor was withdrawn, the command did nothing wrong). Any
// other command was addressed to that sensor only, so it is failed with
// failMessage. Both clear the lease, and neither is held by the sensor in
// the state it held it in any more, so whatever the old holder sends later
// fails the fence of FencedUpdate (sensor, state and lease epoch); the next
// claim starts a new epoch, as after a lease expiry.
func (r *CommandRepository) ReleaseHeldBySensor(ctx context.Context, tenantID, sensorID shared.ID, requeueMessage, failMessage string) ([]command.ReleasedCommand, error) {
	rows, err := r.db.QueryContext(ctx, `
		UPDATE commands c
		SET status = CASE WHEN held.routed THEN 'pending' ELSE 'failed' END,
		    sensor_id = CASE WHEN held.routed THEN NULL ELSE c.sensor_id END,
		    acknowledged_at = CASE WHEN held.routed THEN NULL ELSE c.acknowledged_at END,
		    started_at = CASE WHEN held.routed THEN NULL ELSE c.started_at END,
		    completed_at = CASE WHEN held.routed THEN NULL ELSE NOW() END,
		    error_message = CASE WHEN held.routed THEN $3 ELSE $4 END,
		    lease_expires_at = NULL
		FROM (
			SELECT id, status AS old_status, lease_epoch AS old_epoch,
			       (`+routedScanWork("commands")+`) AS routed
			FROM commands
			WHERE tenant_id = $1 AND sensor_id = $2
			  AND status IN ('acknowledged', 'running')
			  AND is_platform_job = FALSE
			FOR UPDATE
		) held
		WHERE c.id = held.id
		RETURNING c.id, c.type, held.old_status, held.old_epoch, held.routed`,
		tenantID.String(), sensorID.String(), requeueMessage, failMessage)
	if err != nil {
		return nil, fmt.Errorf("failed to release the commands of sensor: %w", err)
	}
	defer rows.Close()
	var out []command.ReleasedCommand
	for rows.Next() {
		var id, typ, status string
		var rc command.ReleasedCommand
		if err := rows.Scan(&id, &typ, &status, &rc.Epoch, &rc.Requeued); err != nil {
			return nil, fmt.Errorf("failed to scan released command: %w", err)
		}
		if rc.ID, err = shared.IDFromString(id); err != nil {
			continue
		}
		rc.Type, rc.PrevStatus = command.CommandType(typ), command.CommandStatus(status)
		out = append(out, rc)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed to iterate released commands: %w", err)
	}
	if len(out) > 0 {
		r.changedTenant(tenantID)
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
	if n > 0 {
		r.changed(cmd)
	}
	return n > 0, nil
}
