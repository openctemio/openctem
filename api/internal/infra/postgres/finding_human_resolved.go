package postgres

import (
	"context"
	"fmt"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// HumanResolvedFingerprints returns the fingerprints, among the given ones,
// whose finding is closed as fixed (resolved or verified) by a person: any
// resolution method except scan_verified, which only auto-resolve sets. These
// are the findings AutoReopenByFingerprintsBatch would reopen that a sensor
// report without a command covering their asset must leave closed. A closure
// recorded as mitigated is left out: detection never reopens it, so it needs
// no guard.
// (docs/rfcs/RFC-040-platform-sensor-mutual-distrust.md §5.3).
func (r *FindingRepository) HumanResolvedFingerprints(ctx context.Context, tenantID shared.ID, fingerprints []string) (map[string]bool, error) {
	out := make(map[string]bool)
	if len(fingerprints) == 0 {
		return out, nil
	}
	rows, err := r.db.QueryContext(ctx, `
		SELECT fingerprint
		FROM findings
		WHERE tenant_id = $1
			AND fingerprint = ANY($2)
			AND status = 'resolved'
			AND closure_reason IS DISTINCT FROM 'mitigated'
			AND verification IS DISTINCT FROM 'covered_scan'`,
		tenantID.String(), pq.Array(fingerprints))
	if err != nil {
		return nil, fmt.Errorf("failed to find human-resolved findings: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var fp string
		if err := rows.Scan(&fp); err != nil {
			return nil, fmt.Errorf("failed to scan human-resolved finding: %w", err)
		}
		out[fp] = true
	}
	return out, rows.Err()
}

// DefaultBranchResolvedFingerprints returns the fingerprints, among the given
// ones, whose finding is closed as fixed and counts on the default branch (it
// is not branch-only). A run on another branch must not reopen these: it
// records a branch occurrence and leaves the status to a default-branch run.
func (r *FindingRepository) DefaultBranchResolvedFingerprints(ctx context.Context, tenantID shared.ID, fingerprints []string) (map[string]bool, error) {
	out := make(map[string]bool)
	if len(fingerprints) == 0 {
		return out, nil
	}
	rows, err := r.db.QueryContext(ctx, `
		SELECT fingerprint
		FROM findings
		WHERE tenant_id = $1
			AND fingerprint = ANY($2)
			AND status IN `+regressionReopenFromSQL+`
			AND NOT branch_only`,
		tenantID.String(), pq.Array(fingerprints))
	if err != nil {
		return nil, fmt.Errorf("failed to find default-branch resolved findings: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var fp string
		if err := rows.Scan(&fp); err != nil {
			return nil, fmt.Errorf("failed to scan default-branch resolved finding: %w", err)
		}
		out[fp] = true
	}
	return out, rows.Err()
}
