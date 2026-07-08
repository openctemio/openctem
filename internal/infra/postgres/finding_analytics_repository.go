package postgres

import (
	"context"
	"fmt"

	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/domain/vulnerability"
)

// SourceBreakdown returns per-(source, tool) finding counts for a tenant. It
// powers Tool Insights (which scanner/source contributes what) and the
// DefectDojo-dependency ratio (RFC-013's measure-to-phase-out guardrail).
//
// Pentest findings are excluded (they are a manual workflow, not a scanner
// source) to match ListFindingGroups.
func (r *FindingRepository) SourceBreakdown(ctx context.Context, tenantID shared.ID) ([]vulnerability.SourceStat, error) {
	const q = `
		SELECT
			COALESCE(NULLIF(source, ''), 'unknown')     AS source,
			COALESCE(NULLIF(tool_name, ''), 'unknown')  AS tool_name,
			COUNT(*)                                     AS total,
			COUNT(*) FILTER (
				WHERE status NOT IN ('resolved', 'false_positive', 'accepted', 'duplicate')
			)                                            AS open
		FROM findings
		WHERE tenant_id = $1 AND source != 'pentest'
		GROUP BY source, tool_name
		ORDER BY total DESC, tool_name ASC
	`
	rows, err := r.db.QueryContext(ctx, q, tenantID.String())
	if err != nil {
		return nil, fmt.Errorf("source breakdown: %w", err)
	}
	defer func() { _ = rows.Close() }()

	stats := make([]vulnerability.SourceStat, 0)
	for rows.Next() {
		var s vulnerability.SourceStat
		if err := rows.Scan(&s.Source, &s.ToolName, &s.Total, &s.Open); err != nil {
			return nil, fmt.Errorf("scan source stat: %w", err)
		}
		stats = append(stats, s)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return stats, nil
}
