package postgres

import (
	"context"
	"fmt"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

// ListFindingBranches returns the branches a finding was seen on, the
// default branch first, then the most recently seen. Tenant-scoped.
func (r *FindingRepository) ListFindingBranches(ctx context.Context, tenantID, findingID shared.ID, limit int) ([]vulnerability.BranchSighting, error) {
	const query = `
		SELECT b.name, b.is_default, o.status, o.first_seen_at, o.last_seen_at,
			COALESCE(o.first_commit_sha, ''), COALESCE(o.last_commit_sha, '')
		FROM finding_branch_occurrences o
		JOIN repository_branches b ON b.id = o.branch_id
		WHERE o.tenant_id = $1 AND o.finding_id = $2
		ORDER BY b.is_default DESC, o.last_seen_at DESC
		LIMIT $3`
	rows, err := r.db.QueryContext(ctx, query, tenantID.String(), findingID.String(), limit)
	if err != nil {
		return nil, fmt.Errorf("list finding branches: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := make([]vulnerability.BranchSighting, 0, 4)
	for rows.Next() {
		var b vulnerability.BranchSighting
		if err := rows.Scan(&b.Name, &b.IsDefault, &b.Status, &b.FirstSeenAt, &b.LastSeenAt, &b.FirstCommit, &b.LastCommit); err != nil {
			return nil, fmt.Errorf("scan finding branch: %w", err)
		}
		out = append(out, b)
	}
	return out, rows.Err()
}

// ListFindingRuns returns the CI runs that reported a finding (matched on
// its fingerprint), newest first, and the first one. Tenant-scoped.
func (r *FindingRepository) ListFindingRuns(ctx context.Context, tenantID shared.ID, fingerprint string, limit int) (latest []vulnerability.RunSighting, first *vulnerability.RunSighting, err error) {
	const cols = `r.id, r.provider, COALESCE(r.external_run_id, ''), COALESCE(r.pipeline_url, ''),
			COALESCE(r.branch, ''), COALESCE(r.commit_sha, ''), COALESCE(r.pull_request, ''),
			r.is_default_branch, COALESCE(r.event, ''), r.created_at`
	const from = `FROM ci_run_findings c
		JOIN ci_runs r ON r.tenant_id = c.tenant_id AND r.id = c.run_id
		WHERE c.tenant_id = $1 AND c.fingerprint = $2`
	scan := func(sc interface{ Scan(...any) error }) (vulnerability.RunSighting, error) {
		var s vulnerability.RunSighting
		err := sc.Scan(&s.ID, &s.Provider, &s.ExternalRunID, &s.PipelineURL, &s.Branch, &s.CommitSHA,
			&s.PullRequest, &s.IsDefaultBranch, &s.Event, &s.CreatedAt)
		return s, err
	}
	rows, err := r.db.QueryContext(ctx, `SELECT `+cols+` `+from+` ORDER BY r.created_at DESC LIMIT $3`,
		tenantID.String(), fingerprint, limit)
	if err != nil {
		return nil, nil, fmt.Errorf("list finding runs: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		s, err := scan(rows)
		if err != nil {
			return nil, nil, fmt.Errorf("scan finding run: %w", err)
		}
		latest = append(latest, s)
	}
	if err := rows.Err(); err != nil {
		return nil, nil, fmt.Errorf("iterate finding runs: %w", err)
	}
	if len(latest) == 0 {
		return nil, nil, nil
	}
	f, err := scan(r.db.QueryRowContext(ctx, `SELECT `+cols+` `+from+` ORDER BY r.created_at ASC LIMIT 1`,
		tenantID.String(), fingerprint))
	if err != nil {
		return nil, nil, fmt.Errorf("first finding run: %w", err)
	}
	return latest, &f, nil
}
