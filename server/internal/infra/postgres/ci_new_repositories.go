package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/openctemio/openctem/server/pkg/domain/cirun"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
)

var _ cirun.NewRepositoryStore = (*CIRunRepository)(nil)

// NewRepositoryBlocked reports whether the project or its group is blocked
// for the configuration.
func (r *CIRunRepository) NewRepositoryBlocked(ctx context.Context, tenantID, configID shared.ID, group, project string) (bool, error) {
	var blocked bool
	err := r.db.QueryRowContext(ctx, `
		SELECT EXISTS (SELECT 1 FROM ci_trust_new_repositories
			WHERE tenant_id = $1 AND config_id = $2 AND state = 'blocked'
			AND ((kind = 'group' AND name = $3) OR (kind = 'project' AND name = $4)))`,
		tenantID.String(), configID.String(), group, project).Scan(&blocked)
	if err != nil {
		return false, fmt.Errorf("check blocked ci repository: %w", err)
	}
	return blocked, nil
}

// RecordPendingRepository records a sighting of a new project with the
// verified ids of its first sighting. firstOfGroup is true when the
// project's group had no row of the configuration before (a new group asks).
// At most cirun.MaxPendingPerGroup pending rows per group and
// cirun.MaxPendingRepositories per configuration: past either nothing is
// recorded and the outcome says which list is full. An approved row of a
// project the configuration no longer lists becomes pending again with the
// new sighting's ids.
func (r *CIRunRepository) RecordPendingRepository(ctx context.Context, tenantID, configID shared.ID, sg cirun.Sighting, at time.Time) (string, bool, error) {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return "", false, err
	}
	defer func() { _ = tx.Rollback() }()
	tid, cid := tenantID.String(), configID.String()
	// One writer per configuration at a time, so the bounds and the
	// first-of-group answer hold under concurrent exchanges.
	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtext('ci_new_repo:' || $1))`, cid); err != nil {
		return "", false, err
	}
	var groupSeen bool
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM ci_trust_new_repositories
		WHERE tenant_id = $1 AND config_id = $2 AND group_name = $3)`, tid, cid, sg.Group).Scan(&groupSeen); err != nil {
		return "", false, err
	}
	res, err := tx.ExecContext(ctx, `
		UPDATE ci_trust_new_repositories SET last_seen = GREATEST(last_seen, $5), count = count + 1
		WHERE tenant_id = $1 AND config_id = $2 AND kind = 'project' AND name = $3 AND group_name = $4 AND state <> 'approved'`,
		tid, cid, sg.Project, sg.Group, at.UTC())
	if err != nil {
		return "", false, err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		var inGroup, total int
		if err := tx.QueryRowContext(ctx, `SELECT count(*) FILTER (WHERE group_name = $3), count(*)
			FROM ci_trust_new_repositories WHERE tenant_id = $1 AND config_id = $2 AND state = 'pending'`,
			tid, cid, sg.Group).Scan(&inGroup, &total); err != nil {
			return "", false, err
		}
		if inGroup >= cirun.MaxPendingPerGroup {
			return cirun.SightingGroupFull, false, nil
		}
		if total >= cirun.MaxPendingRepositories {
			return cirun.SightingListFull, false, nil
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO ci_trust_new_repositories (tenant_id, config_id, kind, name, group_name, state, first_seen, last_seen, count,
				project_id, namespace_path, namespace_id)
			SELECT $1, $2, 'project', $3, $4, 'pending', $5, $5, 1, $6, $7, $8
			WHERE EXISTS (SELECT 1 FROM ci_trust_configs WHERE id = $2 AND tenant_id = $1)
			ON CONFLICT (config_id, kind, name) DO UPDATE
			SET state = 'pending', first_seen = EXCLUDED.first_seen, last_seen = EXCLUDED.last_seen, count = 1,
				project_id = EXCLUDED.project_id, namespace_path = EXCLUDED.namespace_path, namespace_id = EXCLUDED.namespace_id,
				decided_by = '', decided_at = NULL
			WHERE ci_trust_new_repositories.state = 'approved' AND ci_trust_new_repositories.tenant_id = EXCLUDED.tenant_id`,
			tid, cid, sg.Project, sg.Group, at.UTC(), sg.ProjectID, sg.NamespacePath, sg.NamespaceID); err != nil {
			return "", false, err
		}
	}
	if err := tx.Commit(); err != nil {
		return "", false, err
	}
	return cirun.SightingRecorded, !groupSeen, nil
}

// ApprovedProjectID returns the project id an approved project was seen with.
func (r *CIRunRepository) ApprovedProjectID(ctx context.Context, tenantID, configID shared.ID, project string) (string, bool, error) {
	var id string
	err := r.db.QueryRowContext(ctx, `SELECT project_id FROM ci_trust_new_repositories
		WHERE tenant_id = $1 AND config_id = $2 AND kind = 'project' AND name = $3 AND state = 'approved'`,
		tenantID.String(), configID.String(), project).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("read approved ci repository: %w", err)
	}
	return id, true, nil
}

// ListNewRepositories lists the configuration's pending and blocked rows,
// by group then name.
func (r *CIRunRepository) ListNewRepositories(ctx context.Context, tenantID, configID shared.ID) ([]cirun.NewRepository, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT kind, name, group_name, state, first_seen, last_seen, count, decided_by, decided_at,
			project_id, namespace_path, namespace_id
		FROM ci_trust_new_repositories WHERE tenant_id = $1 AND config_id = $2 AND state IN ('pending', 'blocked')
		ORDER BY state, group_name, kind DESC, name LIMIT $3`,
		tenantID.String(), configID.String(), cirun.MaxPendingRepositories*2)
	if err != nil {
		return nil, fmt.Errorf("list ci new repositories: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := []cirun.NewRepository{}
	for rows.Next() {
		var n cirun.NewRepository
		if err := rows.Scan(&n.Kind, &n.Name, &n.Group, &n.State, &n.FirstSeen, &n.LastSeen, &n.Count, &n.DecidedBy, &n.DecidedAt,
			&n.ProjectID, &n.NamespacePath, &n.NamespaceID); err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, rows.Err()
}

// ApplyNewRepositoryDecision records a decision in one transaction:
// approving removes the rows it covers (a group: its pending projects and
// its block), blocking upserts a blocked row (a group: also removes its
// pending projects), unblocking removes the block.
func (r *CIRunRepository) ApplyNewRepositoryDecision(ctx context.Context, tenantID, configID shared.ID, d cirun.NewRepositoryDecision, by string, at time.Time) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	tid, cid := tenantID.String(), configID.String()
	for _, it := range d.Items {
		switch {
		case d.Action == cirun.DecisionApprove && it.Kind == cirun.NewRepoGroup,
			d.Action == cirun.DecisionBlock && it.Kind == cirun.NewRepoGroup:
			if _, err := tx.ExecContext(ctx, `DELETE FROM ci_trust_new_repositories
				WHERE tenant_id = $1 AND config_id = $2 AND kind = 'project' AND group_name = $3 AND state = 'pending'`, tid, cid, it.Name); err != nil {
				return err
			}
		}
		if d.Action == cirun.DecisionApprove && it.Kind == cirun.NewRepoProject {
			// Keep the pending row as approved: the first admitted run must
			// carry the project id that was seen and approved.
			if _, err := tx.ExecContext(ctx, `UPDATE ci_trust_new_repositories
				SET state = 'approved', decided_by = $4, decided_at = $5
				WHERE tenant_id = $1 AND config_id = $2 AND kind = 'project' AND name = $3 AND state = 'pending'`,
				tid, cid, it.Name, by, at.UTC()); err != nil {
				return err
			}
		}
		switch d.Action {
		case cirun.DecisionApprove, cirun.DecisionUnblock:
			if _, err := tx.ExecContext(ctx, `DELETE FROM ci_trust_new_repositories
				WHERE tenant_id = $1 AND config_id = $2 AND kind = $3 AND name = $4 AND state <> 'approved'`, tid, cid, it.Kind, it.Name); err != nil {
				return err
			}
		case cirun.DecisionBlock:
			if _, err := tx.ExecContext(ctx, `
				INSERT INTO ci_trust_new_repositories (tenant_id, config_id, kind, name, group_name, state, first_seen, last_seen, count, decided_by, decided_at)
				SELECT $1, $2, $3, $4, $5, 'blocked', $6, $6, 0, $7, $6
				WHERE EXISTS (SELECT 1 FROM ci_trust_configs WHERE id = $2 AND tenant_id = $1)
				ON CONFLICT (config_id, kind, name) DO UPDATE
				SET state = 'blocked', decided_by = EXCLUDED.decided_by, decided_at = EXCLUDED.decided_at,
					project_id = '', namespace_path = '', namespace_id = ''
				WHERE ci_trust_new_repositories.tenant_id = EXCLUDED.tenant_id`,
				tid, cid, it.Kind, it.Name, it.Group(), at.UTC(), by); err != nil {
				return err
			}
		}
	}
	return tx.Commit()
}
