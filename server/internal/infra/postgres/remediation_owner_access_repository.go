package postgres

import (
	"context"
	"fmt"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/pkg/domain/remediation"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/filterspec"
)

// RemediationOwnerAccessRepository reads what the task owner picker needs:
// the findings an owner would have to see, and the people and teams to offer.
// Every query is tenant-scoped.
type RemediationOwnerAccessRepository struct {
	db *DB
}

// NewRemediationOwnerAccessRepository creates the repository.
func NewRemediationOwnerAccessRepository(db *DB) *RemediationOwnerAccessRepository {
	return &RemediationOwnerAccessRepository{db: db}
}

const ownerAccessMaxRefs = 5000

func scanFindingRefs(rows interface {
	Next() bool
	Scan(...any) error
	Err() error
}) ([]remediation.OwnerFindingRef, error) {
	var out []remediation.OwnerFindingRef
	for rows.Next() {
		var ref remediation.OwnerFindingRef
		var assignee *string
		if err := rows.Scan(&ref.FindingID, &ref.AssetID, &assignee); err != nil {
			return nil, err
		}
		if assignee != nil {
			if id, err := shared.IDFromString(*assignee); err == nil {
				ref.AssignedTo = &id
			}
		}
		out = append(out, ref)
	}
	return out, rows.Err()
}

// OpenFindingRefs returns the asset and assignee of each open finding among
// ids (closed findings never give an owner a view). Ids of another tenant
// are absent.
func (r *RemediationOwnerAccessRepository) OpenFindingRefs(ctx context.Context, tenantID shared.ID, ids []shared.ID) ([]remediation.OwnerFindingRef, error) {
	if len(ids) == 0 {
		return nil, nil
	}
	rows, err := r.db.QueryContext(ctx, `
		SELECT f.id, f.asset_id, f.assigned_to::text FROM findings f
		WHERE f.tenant_id = $1 AND f.id = ANY($2::uuid[]) AND NOT (f.status = ANY($3))`,
		tenantID.String(), pq.Array(rtIDStrings(ids)), closedStatusArray())
	if err != nil {
		return nil, fmt.Errorf("read finding refs: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out, err := scanFindingRefs(rows)
	if err == nil {
		err = rows.Err()
	}
	if err != nil {
		return nil, fmt.Errorf("read finding refs: %w", err)
	}
	return out, nil
}

// TaskOpenPrimaryRefs is OpenFindingRefs for the active primary members of a
// task of the tenant.
func (r *RemediationOwnerAccessRepository) TaskOpenPrimaryRefs(ctx context.Context, tenantID, taskID shared.ID) ([]remediation.OwnerFindingRef, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT f.id, f.asset_id, f.assigned_to::text
		FROM remediation_task_members m
		JOIN findings f ON f.tenant_id = m.tenant_id AND f.id = m.finding_id
		WHERE m.tenant_id = $1 AND m.task_id = $2 AND m.left_at IS NULL AND m.role = 'primary'
		  AND NOT (f.status = ANY($3))
		LIMIT $4`,
		tenantID.String(), taskID.String(), closedStatusArray(), ownerAccessMaxRefs)
	if err != nil {
		return nil, fmt.Errorf("read task finding refs: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out, err := scanFindingRefs(rows)
	if err == nil {
		err = rows.Err()
	}
	if err != nil {
		return nil, fmt.Errorf("read task finding refs: %w", err)
	}
	return out, nil
}

// SearchOwnerUsers returns active members of the tenant whose name or email
// contains q (all when empty), by name.
func (r *RemediationOwnerAccessRepository) SearchOwnerUsers(ctx context.Context, tenantID shared.ID, q string, limit int) ([]remediation.OwnerUser, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT u.id, u.name, u.email
		FROM tenant_members m JOIN users u ON u.id = m.user_id
		WHERE m.tenant_id = $1 AND m.status = 'active' AND u.status = 'active'
		  AND ($2 = '' OR u.name ILIKE $3 ESCAPE '\' OR u.email ILIKE $3 ESCAPE '\')
		ORDER BY lower(u.name), u.id LIMIT $4`,
		tenantID.String(), q, "%"+filterspec.EscapeLike(q)+"%", limit)
	if err != nil {
		return nil, fmt.Errorf("search owner users: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []remediation.OwnerUser
	for rows.Next() {
		var u remediation.OwnerUser
		if err := rows.Scan(&u.ID, &u.Name, &u.Email); err != nil {
			return nil, fmt.Errorf("search owner users: %w", err)
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// SearchOwnerGroups returns active teams of the tenant whose name contains q.
func (r *RemediationOwnerAccessRepository) SearchOwnerGroups(ctx context.Context, tenantID shared.ID, q string, limit int) ([]remediation.OwnerGroup, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT g.id, g.name FROM groups g
		WHERE g.tenant_id = $1 AND g.is_active AND ($2 = '' OR g.name ILIKE $3 ESCAPE '\')
		ORDER BY lower(g.name), g.id LIMIT $4`,
		tenantID.String(), q, "%"+filterspec.EscapeLike(q)+"%", limit)
	if err != nil {
		return nil, fmt.Errorf("search owner groups: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []remediation.OwnerGroup
	for rows.Next() {
		var g remediation.OwnerGroup
		if err := rows.Scan(&g.ID, &g.Name); err != nil {
			return nil, fmt.Errorf("search owner groups: %w", err)
		}
		out = append(out, g)
	}
	return out, rows.Err()
}

// GroupActiveMembers returns the active, unexpired members of a team of the
// tenant (at most limit) and how many there are in all.
func (r *RemediationOwnerAccessRepository) GroupActiveMembers(ctx context.Context, tenantID, groupID shared.ID, limit int) ([]shared.ID, int, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT gm.user_id, count(*) OVER ()
		FROM group_members gm JOIN groups g ON g.id = gm.group_id
		WHERE g.tenant_id = $1 AND g.id = $2 AND g.is_active
		  AND (gm.expires_at IS NULL OR gm.expires_at > now())
		  AND principal_is_active(g.tenant_id, gm.user_id)
		ORDER BY gm.user_id LIMIT $3`,
		tenantID.String(), groupID.String(), limit)
	if err != nil {
		return nil, 0, fmt.Errorf("read team members: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var ids []shared.ID
	total := 0
	for rows.Next() {
		var id shared.ID
		if err := rows.Scan(&id, &total); err != nil {
			return nil, 0, fmt.Errorf("read team members: %w", err)
		}
		ids = append(ids, id)
	}
	return ids, total, rows.Err()
}
