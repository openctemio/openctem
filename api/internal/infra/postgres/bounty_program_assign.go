package postgres

// Program data scope (RFC-065 §7): the assets a program's active entries
// cover are assigned to the program's group (asset_owners rows with
// assignment_source 'program', ownership 'informed'), and assignments the
// entries no longer cover are removed. The asset_owners trigger keeps
// user_accessible_assets current, so the group's members see exactly those
// assets and their findings. Names a program exclusion matches are left
// out. Every statement is tenant-scoped.

import (
	"context"
	"fmt"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// programCoveredAssets selects the tenant's assets one program's in-effect
// entries cover ($1 tenant, $2 program): domain entries by name (a wildcard
// covers the apex and every name below it), address entries by containment.
const programCoveredAssets = `
	WITH entries AS (
		SELECT target_type, lower(pattern) AS p
		FROM scope_targets
		WHERE tenant_id = $1 AND program_id = $2 AND status = 'active'
		  AND (expires_at IS NULL OR expires_at > now())
	), excl AS (
		SELECT lower(pattern) AS p
		FROM bounty_program_exclusions
		WHERE tenant_id = $1 AND target_type = 'domain'
	)
	SELECT a.id
	FROM assets a
	WHERE a.tenant_id = $1
	  AND (EXISTS (
		SELECT 1 FROM bounty_program_target_assets ta
		WHERE ta.tenant_id = $1 AND ta.program_id = $2 AND ta.asset_id = a.id
		  AND EXISTS (SELECT 1 FROM bounty_programs bp WHERE bp.tenant_id = $1 AND bp.id = $2 AND bp.status <> 'ended'))
	  OR EXISTS (
		SELECT 1 FROM entries e
		WHERE (e.target_type = 'domain' AND e.p LIKE '*.%'
		       AND (lower(a.name) = substr(e.p, 3) OR right(lower(a.name), length(e.p) - 1) = substr(e.p, 2)))
		   OR (e.target_type = 'domain' AND e.p NOT LIKE '*%' AND lower(a.name) = e.p)
		   OR (e.target_type IN ('ip_address', 'cidr') AND pg_input_is_valid(a.name, 'inet')
		       AND pg_input_is_valid(e.p, 'inet') AND a.name::inet <<= e.p::inet)))
	  AND NOT EXISTS (
		SELECT 1 FROM excl x
		WHERE (x.p LIKE '*.%' AND (lower(a.name) = substr(x.p, 3) OR right(lower(a.name), length(x.p) - 1) = substr(x.p, 2)))
		   OR lower(a.name) = x.p)`

// AssignProgramAssets reconciles one program's group assignments with what
// its entries cover now. A program without a group assigns nothing. It
// returns the number of assignments added and removed.
func (r *BountyProgramRepository) AssignProgramAssets(ctx context.Context, tenantID, programID shared.ID) (added, removed int64, err error) {
	var groupID *string
	if err := r.db.QueryRowContext(ctx, `SELECT group_id::text FROM bounty_programs WHERE tenant_id = $1 AND id = $2`,
		tenantID.String(), programID.String()).Scan(&groupID); err != nil {
		return 0, 0, fmt.Errorf("program group: %w", err)
	}
	if groupID == nil {
		return 0, 0, nil
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, 0, err
	}
	defer func() { _ = tx.Rollback() }()
	res, err := tx.ExecContext(ctx, `
		INSERT INTO asset_owners (asset_id, group_id, ownership_type, assignment_source)
		SELECT c.id, $3, 'informed', 'program' FROM (`+programCoveredAssets+`) c
		ON CONFLICT DO NOTHING`, tenantID.String(), programID.String(), *groupID)
	if err != nil {
		return 0, 0, fmt.Errorf("assign program assets: %w", err)
	}
	added, _ = res.RowsAffected()
	res, err = tx.ExecContext(ctx, `
		DELETE FROM asset_owners ao
		USING assets a
		WHERE ao.asset_id = a.id AND a.tenant_id = $1
		  AND ao.group_id = $3 AND ao.assignment_source = 'program'
		  AND ao.asset_id NOT IN (`+programCoveredAssets+`)`, tenantID.String(), programID.String(), *groupID)
	if err != nil {
		return 0, 0, fmt.Errorf("unassign program assets: %w", err)
	}
	removed, _ = res.RowsAffected()
	// Program asset provenance and the derived system tags (RFC-065 §16.5).
	if err := syncProgramAssetLinks(ctx, tx, tenantID.String(), programID.String()); err != nil {
		return 0, 0, err
	}
	return added, removed, tx.Commit()
}

// AssignTenantPrograms reconciles every program of one tenant.
func (r *BountyProgramRepository) AssignTenantPrograms(ctx context.Context, tenantID shared.ID) (int64, error) {
	return r.assignWhere(ctx, `tenant_id = $1`, tenantID.String())
}

// AssignAllPrograms reconciles every program of every tenant (the periodic
// safety net).
func (r *BountyProgramRepository) AssignAllPrograms(ctx context.Context) (int64, error) {
	return r.assignWhere(ctx, `true`)
}

type programRef struct{ tenant, program shared.ID }

func (r *BountyProgramRepository) programRefs(ctx context.Context, where string, args ...any) ([]programRef, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT tenant_id::text, id::text FROM bounty_programs
		WHERE group_id IS NOT NULL AND `+where+` ORDER BY tenant_id, id LIMIT 10000`, args...)
	if err != nil {
		return nil, fmt.Errorf("list programs: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []programRef
	for rows.Next() {
		var t, p string
		if err := rows.Scan(&t, &p); err != nil {
			return nil, err
		}
		tid, e1 := shared.IDFromString(t)
		pid, e2 := shared.IDFromString(p)
		if e1 == nil && e2 == nil {
			out = append(out, programRef{tid, pid})
		}
	}
	return out, rows.Err()
}

func (r *BountyProgramRepository) assignWhere(ctx context.Context, where string, args ...any) (int64, error) {
	todo, err := r.programRefs(ctx, where, args...)
	if err != nil {
		return 0, err
	}
	var changed int64
	for _, x := range todo {
		a, d, err := r.AssignProgramAssets(ctx, x.tenant, x.program)
		if err != nil {
			return changed, err
		}
		changed += a + d
	}
	return changed, nil
}
