package postgres

// Open-port assets for port reconciliation (research/22 P0-6). Every query
// is tenant-scoped. Architecture: docs/architecture/easm.md.

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/internal/app/ingest"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// EASMPortRepository implements ingest.PortReconciler.
type EASMPortRepository struct {
	db *DB
}

// NewEASMPortRepository creates the repository.
func NewEASMPortRepository(db *DB) *EASMPortRepository { return &EASMPortRepository{db: db} }

var _ ingest.PortReconciler = (*EASMPortRepository)(nil)

// portClosedNote marks an exposure resolved because its port was closed.
const portClosedNote = "Resolved automatically: the port was not seen open by the latest port scan."

// ActiveOpenPorts returns the tenant's active open_port assets of the given
// hosts (properties.host), by host.
func (r *EASMPortRepository) ActiveOpenPorts(ctx context.Context, tenantID shared.ID, hosts []string) (map[string][]ingest.OpenPortAsset, error) {
	out := map[string][]ingest.OpenPortAsset{}
	if len(hosts) == 0 {
		return out, nil
	}
	rows, err := r.db.QueryContext(ctx, `
		SELECT id, name, properties->>'host'
		FROM assets
		WHERE tenant_id = $1 AND deleted_at IS NULL AND status = 'active'
		  AND asset_type = 'service' AND sub_type = 'open_port'
		  AND properties->>'host' = ANY($2)`,
		tenantID.String(), pq.Array(hosts))
	if err != nil {
		return nil, fmt.Errorf("list open ports: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var id, name, host string
		if err := rows.Scan(&id, &name, &host); err != nil {
			return nil, err
		}
		aid, err := shared.IDFromString(id)
		if err != nil {
			continue
		}
		out[host] = append(out[host], ingest.OpenPortAsset{ID: aid, Name: name})
	}
	return out, rows.Err()
}

// ClosePorts marks the tenant's active open_port assets inactive, records a
// "disappeared" entry for each and resolves their active port_open and
// service_detected exposures, in one transaction.
func (r *EASMPortRepository) ClosePorts(ctx context.Context, tenantID shared.ID, ids []shared.ID, seenBefore time.Time, reason string) ([]shared.ID, error) {
	if len(ids) == 0 {
		return nil, nil
	}
	raw := make([]string, 0, len(ids))
	for _, id := range ids {
		raw = append(raw, id.String())
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()

	closed, err := portQueryIDs(ctx, tx, `
		UPDATE assets SET status = 'inactive', updated_at = now()
		WHERE tenant_id = $1 AND id = ANY($2::uuid[]) AND deleted_at IS NULL AND status = 'active'
		  AND asset_type = 'service' AND sub_type = 'open_port' AND last_seen < $3
		RETURNING id`, tenantID.String(), pq.Array(raw), seenBefore.UTC())
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
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	out := make([]shared.ID, 0, len(closed))
	for _, s := range closed {
		if id, err := shared.IDFromString(s); err == nil {
			out = append(out, id)
		}
	}
	return out, nil
}

// ReopenPorts marks the tenant's inactive open_port assets with the given
// (normalized) names active again, with a "recovered" history entry.
func (r *EASMPortRepository) ReopenPorts(ctx context.Context, tenantID shared.ID, names []string, reason string) ([]shared.ID, error) {
	if len(names) == 0 {
		return nil, nil
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()
	back, err := portQueryIDs(ctx, tx, `
		UPDATE assets SET status = 'active', updated_at = now()
		WHERE tenant_id = $1 AND name = ANY($2) AND deleted_at IS NULL AND status = 'inactive'
		  AND asset_type = 'service' AND sub_type = 'open_port'
		RETURNING id`, tenantID.String(), pq.Array(names))
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
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	out := make([]shared.ID, 0, len(back))
	for _, s := range back {
		if id, err := shared.IDFromString(s); err == nil {
			out = append(out, id)
		}
	}
	return out, nil
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
