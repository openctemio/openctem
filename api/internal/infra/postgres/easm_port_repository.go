package postgres

// Open-port asset status for port reconciliation (research/22 P0-6): set
// reconciliation (asset_attribute_set_repository.go, RFC-069) closes and
// reopens an address's open_port assets through these helpers. Every query
// is tenant-scoped. Architecture: docs/architecture/easm.md.

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// portClosedNote marks an exposure resolved because its port was closed.
const portClosedNote = "Resolved automatically: the port scan that had found the port open no longer sees it."

// closePortsTx marks the tenant's active open_port assets among ids
// inactive, records a "disappeared" entry for each and resolves their
// active port_open and service_detected exposures, inside tx. A port seen
// open at or after seenBefore is not closed. It returns the ids it closed.
func closePortsTx(ctx context.Context, tx *sql.Tx, tenantID shared.ID, ids []string, seenBefore time.Time, reason string) ([]string, error) {
	if len(ids) == 0 {
		return nil, nil
	}
	closed, err := portQueryIDs(ctx, tx, `
		UPDATE assets SET status = 'inactive', updated_at = now()
		WHERE tenant_id = $1 AND id = ANY($2::uuid[]) AND deleted_at IS NULL AND status = 'active'
		  AND asset_type = 'service' AND sub_type = 'open_port' AND last_seen < $3
		RETURNING id`, tenantID.String(), pq.Array(ids), seenBefore.UTC())
	if err != nil {
		return nil, fmt.Errorf("close ports: %w", err)
	}
	for _, id := range closed {
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO asset_state_history (id, tenant_id, asset_id, change_type, field, old_value, new_value,
				reason, metadata, source, changed_by, changed_at, created_at)
			VALUES ($1, $2, $3, 'disappeared', 'status', 'active', 'inactive', $4,
				'{"event":"port_closed"}'::jsonb, 'scan', NULL, now(), now())`,
			shared.NewID().String(), tenantID.String(), id, reason); err != nil {
			return nil, fmt.Errorf("record port closed: %w", err)
		}
	}
	if len(closed) > 0 {
		resolved, err := portQueryIDs(ctx, tx, `
			UPDATE exposure_events SET state = 'resolved', resolved_at = now(), resolved_by = NULL,
				resolution_notes = $3, updated_at = now()
			WHERE tenant_id = $1 AND asset_id = ANY($2::uuid[]) AND state = 'active'
			  AND event_type IN ('port_open', 'service_detected')
			RETURNING id`, tenantID.String(), pq.Array(closed), portClosedNote)
		if err != nil {
			return nil, fmt.Errorf("resolve exposures of closed ports: %w", err)
		}
		for _, id := range resolved {
			if _, err := tx.ExecContext(ctx, `
				INSERT INTO exposure_state_history (id, exposure_event_id, previous_state, new_state, changed_by, reason, created_at)
				VALUES ($1, $2, 'active', 'resolved', NULL, $3, now())`,
				shared.NewID().String(), id, portClosedNote); err != nil {
				return nil, fmt.Errorf("record exposure transition: %w", err)
			}
		}
	}
	return closed, nil
}

// reopenPortsTx marks the tenant's inactive open_port assets among ids
// active again, with a "recovered" history entry, inside tx.
func reopenPortsTx(ctx context.Context, tx *sql.Tx, tenantID shared.ID, ids []string, reason string) ([]string, error) {
	if len(ids) == 0 {
		return nil, nil
	}
	back, err := portQueryIDs(ctx, tx, `
		UPDATE assets SET status = 'active', updated_at = now()
		WHERE tenant_id = $1 AND id = ANY($2::uuid[]) AND deleted_at IS NULL AND status = 'inactive'
		  AND asset_type = 'service' AND sub_type = 'open_port'
		RETURNING id`, tenantID.String(), pq.Array(ids))
	if err != nil {
		return nil, fmt.Errorf("reopen ports: %w", err)
	}
	for _, id := range back {
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO asset_state_history (id, tenant_id, asset_id, change_type, field, old_value, new_value,
				reason, metadata, source, changed_by, changed_at, created_at)
			VALUES ($1, $2, $3, 'recovered', 'status', 'inactive', 'active', $4,
				'{"event":"port_opened"}'::jsonb, 'scan', NULL, now(), now())`,
			shared.NewID().String(), tenantID.String(), id, reason); err != nil {
			return nil, fmt.Errorf("record port reopened: %w", err)
		}
	}
	return back, nil
}

func portQueryIDs(ctx context.Context, tx *sql.Tx, q string, args ...any) ([]string, error) {
	rows, err := tx.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}
