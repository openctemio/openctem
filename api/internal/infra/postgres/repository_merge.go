package postgres

import (
	"context"
	"database/sql"
	"fmt"
	"sort"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/pkg/domain/cirun"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Duplicate repository assets: one repository can be two assets of a tenant
// when repository import named it "org/repo" and CI named it
// "github.com/org/repo", or when a rename or transfer made CI create a new
// asset while the old one kept the findings, branches, gate policy and
// coverage expectation. MergeDuplicateRepositories finds such groups and
// merges each into its oldest asset through the asset merge
// (mergeAssetReferences: every reference moves, findings are re-keyed and
// folded, branches with the same name are joined). It is tenant-scoped,
// idempotent (a merged group is one asset and is not found again) and a dry
// run only reads.

// RepositoryMergeGroup is one repository that is several assets.
type RepositoryMergeGroup struct {
	KeepAssetID   string   `json:"keep_asset_id"`
	MergeAssetIDs []string `json:"merge_asset_ids"`
	// Name is the name the kept asset ends with ("" keeps its own).
	Name string `json:"name,omitempty"`
	// GatePolicies counts the repository gate policies on the group's
	// assets. More than one is a conflict: a repository has one policy, and
	// keeping the wrong one would loosen its gate. The group is merged only
	// with resolve, keeping a policy at least as strict as every other
	// (cirun.StrictestPolicy); without one, it is never merged.
	GatePolicies int `json:"gate_policies,omitempty"`
	// Refused says why the group was not merged ("" when it was, or would be).
	Refused string `json:"refused,omitempty"`
}

// Reasons a duplicate group is not merged.
const (
	RefusedPolicyConflict     = "gate_policy_conflict"
	RefusedPolicyIncomparable = "gate_policies_incomparable"
)

// RepositoryMergeReport counts what a merge moved (or a dry run would).
type RepositoryMergeReport struct {
	TenantID     string                 `json:"tenant_id"`
	Applied      bool                   `json:"applied"`
	Groups       int                    `json:"groups"`
	AssetsMerged int                    `json:"assets_merged"`
	Findings     int                    `json:"findings"`
	Branches     int                    `json:"branches"`
	Pipelines    int                    `json:"pipelines"`
	Runs         int                    `json:"runs"`
	GatePolicies int                    `json:"gate_policies"`
	Expectations int                    `json:"coverage_expectations"`
	MergeDetails []RepositoryMergeGroup `json:"merges,omitempty"`
	FailedGroups int                    `json:"failed_groups,omitempty"`
	// RefusedGroups were left alone: their assets carry several gate
	// policies (see RepositoryMergeGroup.GatePolicies).
	RefusedGroups int      `json:"refused_groups,omitempty"`
	FailureDetail []string `json:"failures,omitempty"`
}

// RepositoryMergeRepository finds and merges duplicate repository assets.
type RepositoryMergeRepository struct {
	db *DB
}

// NewRepositoryMergeRepository creates the repository.
func NewRepositoryMergeRepository(db *DB) *RepositoryMergeRepository {
	return &RepositoryMergeRepository{db: db}
}

// TenantsWithRepositories lists the tenants that have repository assets.
func (r *RepositoryMergeRepository) TenantsWithRepositories(ctx context.Context) ([]shared.ID, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT DISTINCT tenant_id FROM assets WHERE asset_type = 'repository' ORDER BY tenant_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []shared.ID
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			return nil, err
		}
		id, err := shared.IDFromString(s)
		if err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// mergeRepoHostSQL is the lower-case host of a repository extension (r)'s
// web URL, else clone URL; "" when neither is an absolute URL.
const mergeRepoHostSQL = `lower(COALESCE(substring(COALESCE(NULLIF(r.web_url, ''), r.clone_url, '') from '^[a-zA-Z][a-zA-Z0-9+.-]*://(?:[^@/]*@)?([^/]+)'), ''))`

// duplicatePairsSQL lists pairs of a tenant's repository assets that are one
// repository, with the name the pair should end with ("" for no preference):
//   - the same repository id on the same host (repository extensions);
//   - "host/path" (CI) and "path" whose extension's web address is on that
//     host (repository import);
//   - a CI pipeline keyed by the code host's repository id (GitHub, GitLab,
//     Bitbucket) whose runs are on another asset than the pipeline now (a
//     rename or transfer); the pipeline's current name wins.
const duplicatePairsSQL = `
WITH repo AS (
	SELECT a.id, a.name, a.created_at, r.repo_id, ` + mergeRepoHostSQL + ` AS host
	FROM assets a JOIN asset_repositories r ON r.asset_id = a.id
	WHERE a.tenant_id = $1 AND a.asset_type = 'repository'
)
SELECT x.id::text, y.id::text, '' FROM repo x JOIN repo y
	ON x.id < y.id AND COALESCE(x.repo_id, '') <> '' AND x.repo_id = y.repo_id AND x.host <> '' AND x.host = y.host
UNION
SELECT c.id::text, i.id::text, c.name FROM assets c JOIN repo i
	ON i.host <> '' AND lower(i.name) NOT LIKE i.host || '/%' AND c.name = i.host || '/' || lower(i.name)
WHERE c.tenant_id = $1 AND c.asset_type = 'repository' AND c.id <> i.id
UNION
SELECT DISTINCT p.repository_asset_id::text, ru.repository_asset_id::text, p.repository_name
	FROM ci_pipelines p
	JOIN ci_runs ru ON ru.tenant_id = p.tenant_id AND ru.pipeline_id = p.id
	JOIN assets a ON a.tenant_id = p.tenant_id AND a.id = ru.repository_asset_id AND a.asset_type = 'repository'
	WHERE p.tenant_id = $1 AND p.provider IN ('github', 'gitlab', 'bitbucket')
	  AND p.external_repo_id NOT LIKE 'legacy:%'
	  AND ru.repository_asset_id <> p.repository_asset_id`

// FindDuplicateRepositories groups the tenant's duplicate repository assets;
// the oldest asset of each group is kept.
func (r *RepositoryMergeRepository) FindDuplicateRepositories(ctx context.Context, tenantID shared.ID) ([]RepositoryMergeGroup, error) {
	rows, err := r.db.QueryContext(ctx, duplicatePairsSQL, tenantID.String())
	if err != nil {
		return nil, fmt.Errorf("find duplicate repositories: %w", err)
	}
	defer rows.Close()
	parent := map[string]string{}
	var find func(string) string
	find = func(x string) string {
		if p, ok := parent[x]; ok && p != x {
			parent[x] = find(p)
			return parent[x]
		}
		parent[x] = x
		return x
	}
	preferred := map[string]string{}
	for rows.Next() {
		var a, b, name string
		if err := rows.Scan(&a, &b, &name); err != nil {
			return nil, err
		}
		ra, rb := find(a), find(b)
		if ra != rb {
			parent[ra] = rb
		}
		if name != "" {
			preferred[a] = name
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	members := map[string][]string{}
	for x := range parent {
		root := find(x)
		members[root] = append(members[root], x)
	}
	groups := make([]RepositoryMergeGroup, 0, len(members))
	for _, ids := range members {
		if len(ids) < 2 {
			continue
		}
		ordered, err := r.oldestFirst(ctx, tenantID, ids)
		if err != nil {
			return nil, err
		}
		if len(ordered) < 2 {
			continue
		}
		g := RepositoryMergeGroup{KeepAssetID: ordered[0], MergeAssetIDs: ordered[1:]}
		for _, id := range ordered {
			if n := preferred[id]; n != "" {
				g.Name = n
			}
		}
		groups = append(groups, g)
	}
	sort.Slice(groups, func(i, j int) bool { return groups[i].KeepAssetID < groups[j].KeepAssetID })
	return groups, nil
}

// oldestFirst returns the tenant's repository assets among ids, oldest first.
func (r *RepositoryMergeRepository) oldestFirst(ctx context.Context, tenantID shared.ID, ids []string) ([]string, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT id::text FROM assets
		WHERE tenant_id = $1 AND id = ANY($2::uuid[]) AND asset_type = 'repository'
		ORDER BY created_at, id`, tenantID.String(), pq.Array(ids))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// countMoved adds to rep what merging ids would move.
func (r *RepositoryMergeRepository) countMoved(ctx context.Context, tenantID shared.ID, ids []string, rep *RepositoryMergeReport) error {
	var f, b, p, ru, gp, ce int
	err := r.db.QueryRowContext(ctx, `SELECT
		(SELECT count(*) FROM findings WHERE tenant_id = $1 AND asset_id = ANY($2::uuid[])),
		(SELECT count(*) FROM repository_branches WHERE repository_id = ANY($2::uuid[])),
		(SELECT count(*) FROM ci_pipelines WHERE tenant_id = $1 AND repository_asset_id = ANY($2::uuid[])),
		(SELECT count(*) FROM ci_runs WHERE tenant_id = $1 AND repository_asset_id = ANY($2::uuid[])),
		(SELECT count(*) FROM ci_gate_policies WHERE tenant_id = $1 AND repository_asset_id = ANY($2::uuid[])),
		(SELECT count(*) FROM ci_coverage_expectations WHERE tenant_id = $1 AND repository_asset_id = ANY($2::uuid[]))`,
		tenantID.String(), pq.Array(ids)).Scan(&f, &b, &p, &ru, &gp, &ce)
	if err != nil {
		return fmt.Errorf("count merge: %w", err)
	}
	rep.Findings += f
	rep.Branches += b
	rep.Pipelines += p
	rep.Runs += ru
	rep.GatePolicies += gp
	rep.Expectations += ce
	return nil
}

// noReview is the review id mergeAssetReferences is given for a merge that
// no review asked for.
const noReview = "00000000-0000-0000-0000-000000000000"

// MergeDuplicateRepositories finds the tenant's duplicate repository assets
// and, with apply, merges each group in its own transaction. Without apply
// it changes nothing and reports what it would move. A group whose assets
// carry several gate policies is merged only with resolve, keeping the
// strictest one; otherwise (or when none is the strictest) it is refused.
func (r *RepositoryMergeRepository) MergeDuplicateRepositories(ctx context.Context, tenantID shared.ID, apply, resolve bool) (*RepositoryMergeReport, error) {
	groups, err := r.FindDuplicateRepositories(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	rep := &RepositoryMergeReport{TenantID: tenantID.String(), Applied: apply}
	for i := range groups {
		g := &groups[i]
		policies, err := r.groupPolicies(ctx, r.db, tenantID, g.ids())
		if err != nil {
			return nil, err
		}
		g.GatePolicies = len(policies)
		if len(policies) > 1 {
			if _, ok := cirun.StrictestPolicy(policies); !ok {
				g.Refused = RefusedPolicyIncomparable
			} else if !resolve {
				g.Refused = RefusedPolicyConflict
			}
		}
		if g.Refused != "" {
			rep.RefusedGroups++
			continue
		}
		if err := r.countMoved(ctx, tenantID, g.MergeAssetIDs, rep); err != nil {
			return nil, err
		}
		if apply {
			if err := r.mergeGroup(ctx, tenantID, *g); err != nil {
				rep.FailedGroups++
				rep.FailureDetail = append(rep.FailureDetail, fmt.Sprintf("keep %s: %v", g.KeepAssetID, err))
				continue
			}
		}
		rep.Groups++
		rep.AssetsMerged += len(g.MergeAssetIDs)
	}
	rep.MergeDetails = groups
	return rep, nil
}

// ids is every asset of the group, the kept one first.
func (g RepositoryMergeGroup) ids() []string {
	return append([]string{g.KeepAssetID}, g.MergeAssetIDs...)
}

type policyQueryer interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
}

// groupPolicies reads the repository gate policies on the given assets.
func (r *RepositoryMergeRepository) groupPolicies(ctx context.Context, q policyQueryer, tenantID shared.ID, ids []string) ([]cirun.GatePolicy, error) {
	rows, err := q.QueryContext(ctx, `SELECT `+ciPolicyColumns+` FROM ci_gate_policies
		WHERE tenant_id = $1 AND scope_type = 'repository' AND repository_asset_id = ANY($2::uuid[])
		ORDER BY created_at, id`, tenantID.String(), pq.Array(ids))
	if err != nil {
		return nil, fmt.Errorf("read gate policies: %w", err)
	}
	defer rows.Close()
	var out []cirun.GatePolicy
	for rows.Next() {
		p, err := scanCIPolicy(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// keepStrictestPolicy leaves, among the group's gate policies, only the
// strictest; the asset merge then moves it to the kept asset. It refuses when
// none is at least as strict as every other.
func (r *RepositoryMergeRepository) keepStrictestPolicy(ctx context.Context, tx *sql.Tx, tenantID shared.ID, g RepositoryMergeGroup) error {
	policies, err := r.groupPolicies(ctx, tx, tenantID, g.ids())
	if err != nil || len(policies) < 2 {
		return err
	}
	keep, ok := cirun.StrictestPolicy(policies)
	if !ok {
		return fmt.Errorf("the group's gate policies are stricter on different settings")
	}
	drop := make([]string, 0, len(policies)-1)
	for i, p := range policies {
		if i != keep {
			drop = append(drop, p.ID.String())
		}
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM ci_gate_policies WHERE tenant_id = $1 AND id = ANY($2::uuid[])`,
		tenantID.String(), pq.Array(drop)); err != nil {
		return fmt.Errorf("drop looser gate policies: %w", err)
	}
	return nil
}

func (r *RepositoryMergeRepository) mergeGroup(ctx context.Context, tenantID shared.ID, g RepositoryMergeGroup) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if err := setLocalStatementTimeout(ctx, tx, timeoutHeavy); err != nil {
		return err
	}
	tid := tenantID.String()
	// Lock every asset of the group first. A CI run, finding or branch
	// written meanwhile holds a key-share lock on the asset it references,
	// so it either commits before the merge reads (and moves with the rest)
	// or waits and then fails its foreign key; it is never written onto a
	// merged asset after the move and lost to the delete's cascade.
	var locked int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM (SELECT id FROM assets
		WHERE tenant_id = $1 AND id = ANY($2::uuid[]) AND asset_type = 'repository' ORDER BY id FOR UPDATE) l`,
		tid, pq.Array(g.ids())).Scan(&locked); err != nil {
		return fmt.Errorf("lock assets: %w", err)
	}
	if locked != len(g.ids()) {
		return fmt.Errorf("the group changed since it was found")
	}
	if err := r.keepStrictestPolicy(ctx, tx, tenantID, g); err != nil {
		return err
	}
	if err := mergeAssetReferences(ctx, tx, tid, noReview, g.KeepAssetID, g.MergeAssetIDs); err != nil {
		return err
	}
	for _, id := range g.MergeAssetIDs {
		if _, err := tx.ExecContext(ctx, `INSERT INTO asset_merge_log (tenant_id, kept_asset_id, kept_asset_name,
				merged_asset_id, merged_asset_name, correlation_type, action, source, created_at)
			SELECT $1, $2, (SELECT name FROM assets WHERE tenant_id = $1 AND id = $2),
				$3, (SELECT name FROM assets WHERE tenant_id = $1 AND id = $3),
				'repository_identity', 'merge', 'system', NOW()`, tid, g.KeepAssetID, id); err != nil {
			return fmt.Errorf("log merge: %w", err)
		}
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM assets WHERE tenant_id = $1 AND id = ANY($2::uuid[])`,
		tid, pq.Array(g.MergeAssetIDs)); err != nil {
		return fmt.Errorf("delete merged assets: %w", err)
	}
	if g.Name != "" {
		if err := renameKept(ctx, tx, tid, g.KeepAssetID, g.Name); err != nil {
			return err
		}
	}
	if _, err := tx.ExecContext(ctx, `UPDATE assets SET updated_at = NOW() WHERE tenant_id = $1 AND id = $2`, tid, g.KeepAssetID); err != nil {
		return fmt.Errorf("touch kept asset: %w", err)
	}
	return tx.Commit()
}

// renameKept gives the kept asset the group's name when no other asset of the
// tenant holds it (the merged ones are gone by now), logging the rename.
func renameKept(ctx context.Context, tx *sql.Tx, tenantID, keepID, name string) error {
	res, err := tx.ExecContext(ctx, `UPDATE assets SET name = $3
		WHERE tenant_id = $1 AND id = $2 AND name <> $3
		  AND NOT EXISTS (SELECT 1 FROM assets o WHERE o.tenant_id = $1 AND o.name = $3)`, tenantID, keepID, name)
	if err != nil {
		return fmt.Errorf("rename kept asset: %w", err)
	}
	if n, _ := res.RowsAffected(); n > 0 {
		if _, err := tx.ExecContext(ctx, `INSERT INTO asset_merge_log (tenant_id, kept_asset_id, kept_asset_name,
				correlation_type, action, new_name, source, created_at)
			VALUES ($1, $2, $3, 'repository_identity', 'rename', $3, 'system', NOW())`, tenantID, keepID, name); err != nil {
			return fmt.Errorf("log rename: %w", err)
		}
	}
	return nil
}
