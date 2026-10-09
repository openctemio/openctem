package postgres

// Scan windows at dispatch (docs/architecture/scan-windows.md): the claim
// defers or splits jobs outside their windows; the closing-window controller
// returns running jobs to the queue once their grace has passed. Every write
// is tenant-scoped and conditional on the state that was read.

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/pkg/domain/command"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

var (
	_ command.WindowHoldStore    = (*CommandRepository)(nil)
	_ command.WindowClosingStore = (*CommandRepository)(nil)
)

// expiryAfterWait is expires_at moved by the wait until $until when $extend.
const expiryAfterWait = `CASE WHEN %[1]s AND expires_at IS NOT NULL
		THEN expires_at + GREATEST(interval '0', %[2]s::timestamptz - NOW()) ELSE expires_at END`

// moveRunDeadline moves the deadline of the run a command belongs to so it
// ends no earlier than opensAt plus the run's timeout.
func moveRunDeadline(ctx context.Context, tx *sql.Tx, tenantID shared.ID, payload json.RawMessage, opensAt *time.Time) error {
	if opensAt == nil {
		return nil
	}
	var p struct {
		RunID string `json:"scan_run_id"`
	}
	if json.Unmarshal(payload, &p) != nil || p.RunID == "" {
		return nil
	}
	if _, err := shared.IDFromString(p.RunID); err != nil {
		return nil
	}
	_, err := tx.ExecContext(ctx, `
		UPDATE scan_runs r
		SET deadline_at = GREATEST(r.deadline_at, `+runDeadlineSQL("$3::timestamptz", "r.scan_id", "r.scan_workflow_id")+`)
		WHERE r.tenant_id = $1 AND r.id = $2::uuid AND r.status IN ('pending', 'running')
		  AND r.deadline_at IS NOT NULL`,
		tenantID.String(), p.RunID, opensAt.UTC())
	if err != nil {
		return fmt.Errorf("move run deadline: %w", err)
	}
	return nil
}

// DeferPending defers a pending command to d.Until with its explanation.
func (r *CommandRepository) DeferPending(ctx context.Context, cmd *command.Command, d command.WindowDeferral) (bool, error) {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return false, fmt.Errorf("defer command: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	res, err := tx.ExecContext(ctx, `
		UPDATE commands
		SET scheduled_at = $3, window_hold = $4,
		    expires_at = `+fmt.Sprintf(expiryAfterWait, "$5", "$3")+`
		WHERE id = $1 AND tenant_id = $2 AND status = 'pending' AND payload = $6::jsonb`,
		cmd.ID.String(), cmd.TenantID.String(), d.Until.UTC(), []byte(d.Hold), d.ExtendExpiry, []byte(cmd.Payload))
	if err != nil {
		return false, fmt.Errorf("defer command: %w", err)
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return false, nil
	}
	if err := moveRunDeadline(ctx, tx, cmd.TenantID, cmd.Payload, d.RunOpensAt); err != nil {
		return false, err
	}
	if err := tx.Commit(); err != nil {
		return false, fmt.Errorf("defer command: %w", err)
	}
	return true, nil
}

// SplitPending narrows a pending command to keep and creates a sibling with
// wait, deferred by d (same step, zone, gate and host keys; never pinned to a
// platform sensor).
func (r *CommandRepository) SplitPending(ctx context.Context, cmd *command.Command, keep, wait json.RawMessage, d command.WindowDeferral) (shared.ID, bool, error) {
	sibling := shared.NewID()
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return sibling, false, fmt.Errorf("split command: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	res, err := tx.ExecContext(ctx, `
		UPDATE commands SET payload = $3
		WHERE id = $1 AND tenant_id = $2 AND status = 'pending' AND payload = $4::jsonb`,
		cmd.ID.String(), cmd.TenantID.String(), []byte(keep), []byte(cmd.Payload))
	if err != nil {
		return sibling, false, fmt.Errorf("split command: %w", err)
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return sibling, false, nil
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO commands (id, tenant_id, sensor_id, type, priority, payload, status, error_message,
			created_at, expires_at, scheduled_at, schedule_id, scan_run_step_id, is_platform_job,
			queue_priority, queued_at, dispatch_attempts, scan_zone_id, host_keys, dispatch_gate, window_hold)
		SELECT $3, tenant_id, sensor_id, type, priority, $4, 'pending', '',
			NOW(), `+fmt.Sprintf(expiryAfterWait, "$6", "$5")+`, $5, schedule_id, scan_run_step_id, FALSE,
			queue_priority, queued_at, 0, scan_zone_id, host_keys, dispatch_gate, $7
		FROM commands WHERE id = $1 AND tenant_id = $2`,
		cmd.ID.String(), cmd.TenantID.String(), sibling.String(), []byte(wait), d.Until.UTC(), d.ExtendExpiry,
		[]byte(d.Hold)); err != nil {
		return sibling, false, fmt.Errorf("split command: %w", err)
	}
	if err := moveRunDeadline(ctx, tx, cmd.TenantID, cmd.Payload, d.RunOpensAt); err != nil {
		return sibling, false, err
	}
	if err := tx.Commit(); err != nil {
		return sibling, false, fmt.Errorf("split command: %w", err)
	}
	return sibling, true, nil
}

// RecordWindowPolicies stores the allow policies a pending command runs
// under.
func (r *CommandRepository) RecordWindowPolicies(ctx context.Context, cmd *command.Command, policyIDs []string) (bool, error) {
	var ids any
	if len(policyIDs) > 0 {
		ids = pq.Array(policyIDs)
	}
	res, err := r.db.ExecContext(ctx, `
		UPDATE commands SET window_policy_ids = $3::uuid[]
		WHERE id = $1 AND tenant_id = $2 AND status = 'pending'
		  AND window_policy_ids IS DISTINCT FROM $3::uuid[]`,
		cmd.ID.String(), cmd.TenantID.String(), ids)
	if err != nil {
		return false, fmt.Errorf("record window policies: %w", err)
	}
	n, _ := res.RowsAffected()
	return n == 1, nil
}

// CountRunningUnderPolicies counts acknowledged and running commands of the
// tenant under each policy.
func (r *CommandRepository) CountRunningUnderPolicies(ctx context.Context, tenantID shared.ID, policyIDs []string) (map[string]int, error) {
	out := make(map[string]int, len(policyIDs))
	if len(policyIDs) == 0 {
		return out, nil
	}
	rows, err := r.db.QueryContext(ctx, `
		SELECT p.id::text, count(c.id)
		FROM unnest($2::uuid[]) AS p(id)
		LEFT JOIN commands c ON c.tenant_id = $1 AND c.status IN ('acknowledged', 'running')
			AND c.window_policy_ids IS NOT NULL AND c.window_policy_ids @> ARRAY[p.id]
		GROUP BY p.id`, tenantID.String(), pq.Array(policyIDs))
	if err != nil {
		return nil, fmt.Errorf("count commands under window policies: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var id string
		var n int
		if err := rows.Scan(&id, &n); err != nil {
			return nil, fmt.Errorf("count commands under window policies: %w", err)
		}
		out[id] = n
	}
	return out, rows.Err()
}

// ReleaseWindowHolds makes the tenant's deferred commands due now.
func (r *CommandRepository) ReleaseWindowHolds(ctx context.Context, tenantID shared.ID) (int64, error) {
	res, err := r.db.ExecContext(ctx, `
		UPDATE commands SET scheduled_at = NULL
		WHERE tenant_id = $1 AND status = 'pending' AND window_hold IS NOT NULL
		  AND scheduled_at IS NOT NULL AND scheduled_at > NOW()`, tenantID.String())
	if err != nil {
		return 0, fmt.Errorf("release window holds: %w", err)
	}
	n, _ := res.RowsAffected()
	if n > 0 {
		r.changedTenant(tenantID)
	}
	return n, nil
}

// probingTypes are the command types a scan window governs.
var probingTypes = pq.Array([]string{
	string(command.CommandTypeScan), string(command.CommandTypeValidate),
	string(command.CommandTypeRetest), string(command.CommandTypeConnectorScan),
})

// RunningProbing lists the tenant's acknowledged and running probing
// commands.
func (r *CommandRepository) RunningProbing(ctx context.Context, tenantID shared.ID, limit int) ([]*command.RunningCommand, error) {
	if limit <= 0 || limit > 1000 {
		limit = 1000
	}
	rows, err := r.db.QueryContext(ctx, r.selectQuery()+`
		WHERE tenant_id = $1 AND status IN ('acknowledged', 'running') AND type = ANY($2::text[])
		ORDER BY acknowledged_at NULLS LAST, id
		LIMIT $3`, tenantID.String(), probingTypes, limit)
	if err != nil {
		return nil, fmt.Errorf("list running commands: %w", err)
	}
	var cmds []*command.Command
	for rows.Next() {
		c, err := r.scanCommandFromRows(rows)
		if err != nil {
			rows.Close()
			return nil, err
		}
		cmds = append(cmds, c)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(cmds) == 0 {
		return nil, nil
	}
	ids := make([]string, len(cmds))
	for i, c := range cmds {
		ids[i] = c.ID.String()
	}
	closed := map[string]time.Time{}
	crow, err := r.db.QueryContext(ctx, `
		SELECT id::text, window_closed_at FROM commands
		WHERE tenant_id = $1 AND id = ANY($2::uuid[]) AND window_closed_at IS NOT NULL`,
		tenantID.String(), pq.Array(ids))
	if err != nil {
		return nil, fmt.Errorf("read window marks: %w", err)
	}
	defer crow.Close()
	for crow.Next() {
		var id string
		var at time.Time
		if err := crow.Scan(&id, &at); err != nil {
			return nil, err
		}
		closed[id] = at
	}
	if err := crow.Err(); err != nil {
		return nil, err
	}
	out := make([]*command.RunningCommand, 0, len(cmds))
	for _, c := range cmds {
		rc := &command.RunningCommand{Command: c, SensorID: c.SensorID, LeaseEpoch: c.LeaseEpoch}
		if at, ok := closed[c.ID.String()]; ok {
			at = at.UTC()
			rc.WindowClosedAt = &at
		}
		out = append(out, rc)
	}
	return out, nil
}

// MarkWindowClosed records the first time running commands were seen outside
// their windows.
func (r *CommandRepository) MarkWindowClosed(ctx context.Context, tenantID shared.ID, ids []shared.ID, at time.Time) error {
	if len(ids) == 0 {
		return nil
	}
	_, err := r.db.ExecContext(ctx, `
		UPDATE commands SET window_closed_at = $3
		WHERE tenant_id = $1 AND id = ANY($2::uuid[]) AND status IN ('acknowledged', 'running')
		  AND window_closed_at IS NULL`, tenantID.String(), pq.Array(windowIDStrings(ids)), at.UTC())
	if err != nil {
		return fmt.Errorf("mark window closed: %w", err)
	}
	return nil
}

// ClearWindowClosed forgets the mark of commands back inside their windows.
func (r *CommandRepository) ClearWindowClosed(ctx context.Context, tenantID shared.ID, ids []shared.ID) error {
	if len(ids) == 0 {
		return nil
	}
	_, err := r.db.ExecContext(ctx, `
		UPDATE commands SET window_closed_at = NULL
		WHERE tenant_id = $1 AND id = ANY($2::uuid[]) AND window_closed_at IS NOT NULL`,
		tenantID.String(), pq.Array(windowIDStrings(ids)))
	if err != nil {
		return fmt.Errorf("clear window closed: %w", err)
	}
	return nil
}

// RequeueForWindow returns a running command to pending under a new lease
// epoch at its next claim, deferred by d. The holder finds it in its
// heartbeat cancel list and its later reports fail the lease fence.
func (r *CommandRepository) RequeueForWindow(ctx context.Context, rc *command.RunningCommand, d command.WindowDeferral) (bool, error) {
	cmd := rc.Command
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return false, fmt.Errorf("requeue command: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	res, err := tx.ExecContext(ctx, `
		UPDATE commands
		SET status = 'pending', sensor_id = NULL, acknowledged_at = NULL, started_at = NULL,
		    lease_expires_at = NULL, window_closed_at = NULL, window_policy_ids = NULL,
		    scheduled_at = $5, window_hold = $6,
		    expires_at = `+fmt.Sprintf(expiryAfterWait, "$7", "$5")+`,
		    error_message = $8
		WHERE id = $1 AND tenant_id = $2 AND status IN ('acknowledged', 'running')
		  AND sensor_id IS NOT DISTINCT FROM $3::uuid AND lease_epoch = $4`,
		cmd.ID.String(), cmd.TenantID.String(), nullIDString(rc.SensorID), rc.LeaseEpoch,
		d.Until.UTC(), []byte(d.Hold), d.ExtendExpiry, command.WindowClosedMessage)
	if err != nil {
		return false, fmt.Errorf("requeue command: %w", err)
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return false, nil
	}
	if err := moveRunDeadline(ctx, tx, cmd.TenantID, cmd.Payload, d.RunOpensAt); err != nil {
		return false, err
	}
	if err := tx.Commit(); err != nil {
		return false, fmt.Errorf("requeue command: %w", err)
	}
	r.changedTenant(cmd.TenantID)
	return true, nil
}

func windowIDStrings(ids []shared.ID) []string {
	out := make([]string, len(ids))
	for i, id := range ids {
		out[i] = id.String()
	}
	return out
}
