package postgres

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/lib/pq"

	"github.com/openctemio/api/internal/app/finding"
	"github.com/openctemio/api/pkg/domain/shared"
)

// AITriagePriorityLookupRepo resolves the latest COMPLETED AI-triage
// false-positive verdict per finding for priority classification. It implements
// finding.AITriageVerdictLookup with ONE batch, tenant-scoped query (DISTINCT ON
// finding_id, latest first) — no per-finding N+1.
//
// Only high-confidence verdicts are returned: a completed triage whose
// false_positive_likelihood is at or above finding.AITriageFPThreshold. That is
// the only signal permitted to DE-ESCALATE a finding, so a missing / pending /
// low-confidence verdict simply yields no entry (fail-safe: no effect).
type AITriagePriorityLookupRepo struct {
	db        *sql.DB
	threshold float64
}

// NewAITriagePriorityLookupRepo creates the lookup adapter.
func NewAITriagePriorityLookupRepo(db *sql.DB) *AITriagePriorityLookupRepo {
	return &AITriagePriorityLookupRepo{db: db, threshold: finding.AITriageFPThreshold}
}

var _ finding.AITriageVerdictLookup = (*AITriagePriorityLookupRepo)(nil)

// GetFalsePositiveVerdicts returns, for each finding whose latest COMPLETED
// triage flagged it as a high-confidence false positive, the verdict. Findings
// with no completed triage, or a below-threshold likelihood, are absent from the
// map. Tenant-scoped.
func (r *AITriagePriorityLookupRepo) GetFalsePositiveVerdicts(
	ctx context.Context,
	tenantID shared.ID,
	findingIDs []shared.ID,
) (map[shared.ID]finding.AIFalsePositiveVerdict, error) {
	result := make(map[shared.ID]finding.AIFalsePositiveVerdict)
	if len(findingIDs) == 0 {
		return result, nil
	}

	idStrings := make([]string, len(findingIDs))
	for i, id := range findingIDs {
		idStrings[i] = id.String()
	}

	// Pick the LATEST completed triage per finding FIRST (DISTINCT ON), THEN apply
	// the threshold — so a newer, below-threshold verdict correctly supersedes an
	// older high-confidence one (the de-escalation is reversible). Filtering by
	// threshold before DISTINCT ON would wrongly resurrect a stale FP verdict.
	// tenant_id scoping guarantees cross-tenant isolation; a NULL likelihood
	// (never scored) fails the >= comparison and is treated as not-a-false-positive.
	query := `
		SELECT finding_id, false_positive_likelihood
		FROM (
			SELECT DISTINCT ON (finding_id) finding_id, false_positive_likelihood
			FROM ai_triage_results
			WHERE tenant_id = $1
			  AND finding_id = ANY($2)
			  AND status = 'completed'
			ORDER BY finding_id, created_at DESC
		) latest
		WHERE false_positive_likelihood >= $3
	`

	rows, err := r.db.QueryContext(ctx, query, tenantID.String(), pq.Array(idStrings), r.threshold)
	if err != nil {
		return nil, fmt.Errorf("ai triage false-positive lookup: %w", err)
	}
	defer func() { _ = rows.Close() }()

	for rows.Next() {
		var fidStr string
		var likelihood float64
		if err := rows.Scan(&fidStr, &likelihood); err != nil {
			continue
		}
		fid, err := shared.IDFromString(fidStr)
		if err != nil {
			continue
		}
		result[fid] = finding.AIFalsePositiveVerdict{Likely: true, Likelihood: likelihood}
	}
	return result, rows.Err()
}
