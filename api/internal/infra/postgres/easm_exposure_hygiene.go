package postgres

// EASM exposure hygiene (research/22 P0-9, bug 22c B2): relinking CT
// exposures to their host's asset, and resolving the EASM exposures of names
// a person rejected. Architecture: docs/architecture/easm.md.

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// RejectedResolutionNote marks an exposure resolved because a person said the
// name is not the tenant's.
const RejectedResolutionNote = "Resolved automatically: the name was marked not ours (rejected)."

// easmExposureSources are the sources whose exposures follow the name's
// ownership: the CT monitor and the DNS checks.
var easmExposureSources = []string{"cert_transparency", "easm_dns"}

// RelinkExposures moves the tenant's exposures of one source, by
// fingerprint, onto the given asset when they point elsewhere (or nowhere).
// The asset must be the tenant's: the update selects it with the tenant id.
func (r *ExposureRepository) RelinkExposures(ctx context.Context, tenantID shared.ID, source string, links map[string]shared.ID) (int, error) {
	if len(links) == 0 {
		return 0, nil
	}
	fps := make([]string, 0, len(links))
	ids := make([]string, 0, len(links))
	for fp, id := range links {
		fps = append(fps, fp)
		ids = append(ids, id.String())
	}
	res, err := r.db.ExecContext(ctx, `
		UPDATE exposure_events e SET asset_id = l.asset_id, updated_at = now()
		FROM unnest($3::text[], $4::uuid[]) AS l(fingerprint, asset_id)
		JOIN assets a ON a.id = l.asset_id AND a.tenant_id = $1 AND a.deleted_at IS NULL
		WHERE e.tenant_id = $1 AND e.source = $2 AND e.fingerprint = l.fingerprint
		  AND e.asset_id IS DISTINCT FROM l.asset_id`,
		tenantID.String(), source, pq.Array(fps), pq.Array(ids))
	if err != nil {
		return 0, fmt.Errorf("relink exposures: %w", err)
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}

// ResolveRejectedNames resolves the tenant's active EASM exposures (CT and
// DNS checks) on the given assets' names and every name under them, and on
// exposures linked to those assets, recording the transition. A person's
// own resolution, acceptance or false-positive mark is left alone (only
// active rows move). Returns how many were resolved.
func (r *ExposureRepository) ResolveRejectedNames(ctx context.Context, tenantID shared.ID, assetIDs []shared.ID) (int, error) {
	if len(assetIDs) == 0 {
		return 0, nil
	}
	ids := make([]string, 0, len(assetIDs))
	for _, id := range assetIDs {
		ids = append(ids, id.String())
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }()
	resolved, err := queryIDs(ctx, tx, `
		WITH rejected AS (
			SELECT a.id, lower(trim(trailing '.' from a.name)) AS name
			FROM assets a WHERE a.tenant_id = $1 AND a.id = ANY($2::uuid[])
		)
		UPDATE exposure_events e SET state = 'resolved', resolved_at = now(), resolved_by = NULL,
			resolution_notes = $4, updated_at = now()
		WHERE e.tenant_id = $1 AND e.state = 'active' AND e.source = ANY($3)
		  AND EXISTS (
			SELECT 1 FROM rejected x
			WHERE e.asset_id = x.id
			   OR lower(e.details->>'domain') = x.name
			   OR right(lower(e.details->>'domain'), length(x.name) + 1) = '.' || x.name)
		RETURNING e.id`,
		tenantID.String(), pq.Array(ids), pq.Array(easmExposureSources), RejectedResolutionNote)
	if err != nil {
		return 0, fmt.Errorf("resolve exposures of rejected names: %w", err)
	}
	for _, id := range resolved {
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO exposure_state_history (id, exposure_event_id, previous_state, new_state, changed_by, reason, created_at)
			VALUES ($1, $2, 'active', 'resolved', NULL, $3, now())`,
			shared.NewID().String(), id, RejectedResolutionNote); err != nil {
			return 0, fmt.Errorf("record exposure transition: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return len(resolved), nil
}

// queryIDs runs a statement returning one id column and collects the ids.
func queryIDs(ctx context.Context, tx *sql.Tx, q string, args ...any) ([]string, error) {
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
