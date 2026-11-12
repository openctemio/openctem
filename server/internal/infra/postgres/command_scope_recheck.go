package postgres

// Storage of the claim-time scope re-check (docs/architecture/active-probe-gate.md,
// "Re-check at claim"): the dispatch-gate record written with a command, and
// the two conditional writes of the re-check's outcome.

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/openctemio/openctem/api/pkg/domain/command"
)

// dispatchGateArg is the dispatch_gate column value of g (NULL for none).
func dispatchGateArg(g *command.DispatchGate) any {
	if g == nil {
		return nil
	}
	b, err := json.Marshal(g)
	if err != nil {
		return nil
	}
	return b
}

// strictDispatchGate re-checks a command whose record cannot be read: the
// full active gate at t1. The platform writes the record, so this is a
// damaged row; it is never re-checked more loosely than a dispatch.
var strictDispatchGate = command.DispatchGate{Tier: 1}

// decodeDispatchGate reads the dispatch_gate column (nil for NULL).
func decodeDispatchGate(b []byte) *command.DispatchGate {
	if len(b) == 0 {
		return nil
	}
	var g command.DispatchGate
	if err := json.Unmarshal(b, &g); err != nil {
		strict := strictDispatchGate
		return &strict
	}
	return &g
}

// NarrowPendingPayload replaces the payload of a pending command of its
// tenant with a narrower one, only while it is still pending with the
// payload the re-check read (no other writer narrowed or claimed it since).
func (r *CommandRepository) NarrowPendingPayload(ctx context.Context, cmd *command.Command, payload json.RawMessage) (bool, error) {
	res, err := r.db.ExecContext(ctx, `
		UPDATE commands SET payload = $3
		WHERE id = $1 AND tenant_id = $2 AND status = 'pending'
		  AND payload = $4::jsonb`,
		cmd.ID.String(), cmd.TenantID.String(), []byte(payload), []byte(cmd.Payload))
	if err != nil {
		return false, fmt.Errorf("narrow command payload: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("narrow command payload: %w", err)
	}
	return n == 1, nil
}

// FailPending fails a pending command of its tenant with message, only while
// it is still pending: of two concurrent re-checks one fails it, and only
// that one reports the failure to the run.
func (r *CommandRepository) FailPending(ctx context.Context, cmd *command.Command, message string) (bool, error) {
	res, err := r.db.ExecContext(ctx, `
		UPDATE commands
		SET status = 'failed', error_message = $3, completed_at = NOW()
		WHERE id = $1 AND tenant_id = $2 AND status = 'pending'`,
		cmd.ID.String(), cmd.TenantID.String(), message)
	if err != nil {
		return false, fmt.Errorf("fail pending command: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("fail pending command: %w", err)
	}
	return n == 1, nil
}
