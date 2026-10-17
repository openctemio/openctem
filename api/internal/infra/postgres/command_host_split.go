package postgres

// Partial admission at claim time: pkg/domain/command/host_split.go.

import (
	"context"
	"fmt"
	"strconv"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/pkg/domain/command"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

var _ command.HostSplitter = (*CommandRepository)(nil)

// hostBusyPredicate keeps a pending, due scan command of a run step that
// is not a platform job, was split fewer than command.MaxHostSplits times,
// and waits for its hosts (the negation of hostFreePredicate).
var hostBusyPredicate = `commands.status = 'pending'
		AND (commands.expires_at IS NULL OR commands.expires_at > NOW())
		AND ` + scheduledDuePredicate + `
		AND commands.type = 'scan'
		AND commands.scan_run_step_id IS NOT NULL
		AND ` + tenantJobPredicate + `
		AND commands.host_splits < ` + strconv.Itoa(command.MaxHostSplits) + `
		AND commands.host_keys IS NOT NULL
		AND NOT ` + hostFreePredicate

// HostSplitCandidates lists the tenant's pending scan commands of run steps
// that sensorID may take and that wait for their hosts, oldest first.
func (r *CommandRepository) HostSplitCandidates(ctx context.Context, tenantID shared.ID, sensorID *shared.ID, capabilities []string, limit int) ([]*command.Command, error) {
	if limit <= 0 {
		return nil, nil
	}
	where, args := sensorWhere(hostBusyPredicate, tenantID, sensorID, capabilities)
	args = append(args, min(limit, 100))
	rows, err := r.db.QueryContext(ctx, r.selectQuery()+` WHERE `+where+`
		ORDER BY COALESCE(commands.queued_at, commands.created_at), commands.id
		LIMIT $`+strconv.Itoa(len(args)), args...)
	if err != nil {
		return nil, fmt.Errorf("list commands waiting for hosts: %w", err)
	}
	defer rows.Close()
	var out []*command.Command
	for rows.Next() {
		cmd, err := r.scanCommandFromRows(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, cmd)
	}
	return out, rows.Err()
}

const (
	// narrowForHostsSQL narrows a pending command to the targets on free
	// hosts: only when it is unchanged since it was read ($5) and below
	// the split bound ($6). The row lock it takes orders it with a claim.
	narrowForHostsSQL = `
		UPDATE commands SET payload = $3, host_keys = $4, host_splits = host_splits + 1
		WHERE id = $1 AND tenant_id = $2 AND status = 'pending'
		  AND payload = $5::jsonb AND host_splits < $6`
	// waitForHostsSQL inserts the waiting part $3 of command $1: its
	// placement is the parent's (step, pin, zone, schedule, gate, window
	// policies, refusals, attempts, its place in the fair queue); payload
	// and host keys are its own; host_splits is the parent's new count.
	waitForHostsSQL = `
		INSERT INTO commands (id, tenant_id, sensor_id, type, priority, payload, status, error_message,
			created_at, expires_at, scheduled_at, schedule_id, scan_run_step_id, is_platform_job,
			queue_priority, queued_at, dispatch_attempts, scan_zone_id, host_keys, dispatch_gate,
			window_policy_ids, refused_by, refusals, host_splits)
		SELECT $3, p.tenant_id, p.sensor_id, p.type, p.priority, $4, 'pending', '',
			NOW(), p.expires_at, p.scheduled_at, p.schedule_id, p.scan_run_step_id, FALSE,
			p.queue_priority, COALESCE(p.queued_at, p.created_at), p.dispatch_attempts, p.scan_zone_id, $5, p.dispatch_gate,
			p.window_policy_ids, p.refused_by, p.refusals, p.host_splits
		FROM commands p WHERE p.id = $1 AND p.tenant_id = $2`
)

// SplitHostBusy narrows cmd to s.Keep and inserts s.Wait as a new pending
// command of the same step, in one transaction.
func (r *CommandRepository) SplitHostBusy(ctx context.Context, cmd *command.Command, s command.HostSplit) (shared.ID, bool, error) {
	sibling := shared.NewID()
	// The waiting part passes the create guard (the web scope of a web
	// job) like every created command.
	wait := *cmd
	wait.ID, wait.Payload, wait.HostKeys = sibling, s.Wait, s.WaitKeys
	if err := r.guardCreate(ctx, &wait); err != nil {
		return sibling, false, err
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return sibling, false, fmt.Errorf("split command for busy hosts: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	res, err := tx.ExecContext(ctx, narrowForHostsSQL, cmd.ID.String(), cmd.TenantID.String(),
		[]byte(s.Keep), pq.Array(s.KeepKeys), []byte(cmd.Payload), command.MaxHostSplits)
	if err != nil {
		return sibling, false, fmt.Errorf("split command for busy hosts: %w", err)
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return sibling, false, nil
	}
	if _, err := tx.ExecContext(ctx, waitForHostsSQL, cmd.ID.String(), cmd.TenantID.String(),
		sibling.String(), []byte(wait.Payload), pq.Array(s.WaitKeys)); err != nil {
		return sibling, false, fmt.Errorf("split command for busy hosts: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return sibling, false, fmt.Errorf("split command for busy hosts: %w", err)
	}
	r.changed(cmd)
	r.changedTenant(cmd.TenantID)
	return sibling, true, nil
}
