package postgres

// Follow-up commands for unfinished targets: pkg/domain/command/unfinished.go.

import (
	"context"
	"fmt"

	"github.com/openctemio/openctem/api/pkg/domain/command"
)

var _ command.FollowUpCompleter = (*CommandRepository)(nil)

// insertFollowUpSQL inserts a follow-up of the parent command $2 (same
// tenant, $3): its placement is the parent's (step, zone, schedule, dispatch
// gate, window policies, the sensors that refused or failed it and its place in the
// fair queue); id, payload, attempts, expiry and host keys ($7: those of its
// remaining targets; NULL keeps the parent's) are the follow-up's own. It is pending and held by no sensor, like a re-queued
// command.
const insertFollowUpSQL = `
	INSERT INTO commands (
		id, tenant_id, type, priority, payload, status, created_at, expires_at,
		scheduled_at, schedule_id, scan_run_step_id, is_platform_job,
		queue_priority, queued_at, dispatch_attempts, scan_zone_id,
		host_keys, dispatch_gate, window_policy_ids, refused_by, refusals, retry_of, failed_on
	)
	SELECT $1, p.tenant_id, p.type, p.priority, $4, 'pending', NOW(), LEAST($6::timestamptz, p.expires_at),
	       p.scheduled_at, p.schedule_id, p.scan_run_step_id, FALSE,
	       p.queue_priority, COALESCE(p.queued_at, p.created_at), $5, p.scan_zone_id,
	       COALESCE($7::text[], p.host_keys), p.dispatch_gate, p.window_policy_ids, p.refused_by, p.refusals, p.id,
	       CASE WHEN $8::boolean AND p.sensor_id IS NOT NULL AND NOT (p.failed_on @> ARRAY[p.sensor_id]) AND cardinality(p.failed_on) < 16
	            THEN array_append(p.failed_on, p.sensor_id) ELSE p.failed_on END
	FROM commands p
	WHERE p.id = $2 AND p.tenant_id = $3 AND p.is_platform_job = FALSE`

// CompleteWithFollowUp applies cmd's completion fenced like FencedUpdate
// and, in the same transaction, inserts followUp (when not nil) as the
// continuation of cmd. Nothing is written when the fence does not hold.
func (r *CommandRepository) CompleteWithFollowUp(ctx context.Context, cmd *command.Command, expect command.Fence, followUp *command.Command) (bool, error) {
	if followUp == nil {
		return r.FencedUpdate(ctx, cmd, expect)
	}
	if followUp.TenantID != cmd.TenantID {
		return false, fmt.Errorf("follow-up of another tenant's command")
	}
	// The parent's payload passed the web scope guard; the follow-up passes
	// it again, like every created command.
	if err := r.guardCreate(ctx, followUp); err != nil {
		return false, err
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return false, fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	res, err := tx.ExecContext(ctx, fencedUpdateSQL, r.fencedUpdateArgs(cmd, expect)...)
	if err != nil {
		return false, fmt.Errorf("failed to update command: %w", err)
	}
	if n, err := res.RowsAffected(); err != nil || n == 0 {
		return false, err
	}
	res, err = tx.ExecContext(ctx, insertFollowUpSQL, followUp.ID.String(), cmd.ID.String(), cmd.TenantID.String(),
		followUp.Payload, followUp.DispatchAttempts, nullTime(followUp.ExpiresAt), hostKeysArg(followUp.HostKeys), followUp.ExcludeParentSensor)
	if err != nil {
		return false, fmt.Errorf("failed to create follow-up command: %w", err)
	}
	if n, err := res.RowsAffected(); err != nil || n != 1 {
		return false, fmt.Errorf("follow-up command not created (rows %d): %w", n, err)
	}
	if err := tx.Commit(); err != nil {
		return false, fmt.Errorf("failed to commit: %w", err)
	}
	r.changed(cmd)
	r.changedTenant(cmd.TenantID)
	return true, nil
}
