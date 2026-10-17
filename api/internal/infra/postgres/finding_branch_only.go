package postgres

// Branch-only findings (docs/architecture/branch-only-findings.md): a
// finding seen only on branches that do not count as exposure. The database
// marks it on insert and clears it (migration 001138); these are the reads
// and writes the ingest path and the lifecycle job need.

import (
	"context"
	"fmt"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// BranchOnlyIDs returns which of the tenant's findings among ids are
// branch-only.
func (r *FindingRepository) BranchOnlyIDs(ctx context.Context, tenantID shared.ID, ids []shared.ID) (map[shared.ID]bool, error) {
	out := make(map[shared.ID]bool)
	if len(ids) == 0 {
		return out, nil
	}
	strs := make([]string, 0, len(ids))
	for _, id := range ids {
		strs = append(strs, id.String())
	}
	rows, err := r.db.QueryContext(ctx,
		`SELECT id FROM findings WHERE tenant_id = $1 AND id = ANY($2::uuid[]) AND branch_only`,
		tenantID.String(), pq.Array(strs))
	if err != nil {
		return nil, fmt.Errorf("query branch-only findings: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			return nil, fmt.Errorf("scan branch-only finding: %w", err)
		}
		if id, err := shared.IDFromString(s); err == nil {
			out[id] = true
		}
	}
	return out, rows.Err()
}

// PromoteBranchOnlyByFingerprints clears the branch-only mark on the
// tenant's findings among fingerprints that now have an occurrence on a
// counting branch, and starts their SLA clock now. It returns the promoted
// finding ids.
func (r *FindingRepository) PromoteBranchOnlyByFingerprints(ctx context.Context, tenantID shared.ID, fingerprints []string) ([]shared.ID, error) {
	if len(fingerprints) == 0 {
		return nil, nil
	}
	rows, err := r.db.QueryContext(ctx, `
		SELECT promote_branch_only_findings($1, ARRAY(
			SELECT f.id FROM findings f
			WHERE f.tenant_id = $1 AND f.fingerprint = ANY($2) AND f.branch_only))`,
		tenantID.String(), pq.Array(fingerprints))
	if err != nil {
		return nil, fmt.Errorf("promote branch-only findings: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []shared.ID
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			return nil, fmt.Errorf("scan promoted finding: %w", err)
		}
		if id, err := shared.IDFromString(s); err == nil {
			out = append(out, id)
		}
	}
	return out, rows.Err()
}

// expireBranchOnlyFindings marks the tenant's open branch-only findings
// that no branch still shows as stale (observation_state; the status stays,
// it is never a fix). A branch still shows a finding while its occurrence
// there is open and was seen within the branch's retention (or
// defaultExpiryDays). A merged or deleted branch stops showing it: a deleted
// branch takes its occurrences with it, and a merged one is no longer
// scanned. The finding itself must also be unseen for defaultExpiryDays, so
// a missed occurrence write never expires a fresh finding. keep_when_inactive
// is not consulted: it keeps findings of a branch that counts, and a
// branch-only finding counts nowhere.
func (r *FindingRepository) expireBranchOnlyFindings(ctx context.Context, tenantID shared.ID, defaultExpiryDays int) (int64, error) {
	query := `
		UPDATE findings f
		SET observation_state = 'stale', updated_at = NOW()
		WHERE f.tenant_id = $1
		  AND f.branch_only
		  AND f.status IN ` + branchOnlyExpiryFromSQL + `
		  AND f.observation_state = 'present'
		  AND f.last_seen_at < NOW() - make_interval(days => $2)
		  AND NOT EXISTS (
			SELECT 1 FROM finding_branch_occurrences o
			JOIN repository_branches b ON b.id = o.branch_id
			WHERE o.tenant_id = $1 AND o.finding_id = f.id AND o.status = 'open'
			  AND o.last_seen_at >= NOW() - make_interval(days => COALESCE(b.retention_days, $2)))`
	res, err := r.db.ExecContext(ctx, query, tenantID.String(), defaultExpiryDays)
	if err != nil {
		return 0, fmt.Errorf("expire branch-only findings: %w", err)
	}
	n, _ := res.RowsAffected()
	return n, nil
}
