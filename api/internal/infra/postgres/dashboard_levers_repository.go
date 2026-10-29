package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/openctemio/openctem/api/pkg/domain/dashboard"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// topFixCandidates is how many proposed suggestions, by their stored risk
// points, are re-counted in the read's scope.
const topFixCandidates = 50

// TopFix implements dashboard.FactReader.
//
// The tenant's proposed suggestions are re-counted over their members that
// are open now and pass findingWhere (tenant, asset rule, data scope,
// campaign rule). Pentest findings are left out entirely: a suggestion's
// title describes a fix, and a fix found only on pentest findings must not
// reach a reader outside the campaign. A suggestion with no counted member
// is skipped, so a reader only sees a fix for findings they can read.
func (r *DashboardWidgetRepository) TopFix(ctx context.Context, scope dashboard.ReadScope) (*dashboard.FixLever, error) {
	b := findingWhere(scope)
	b.add("dash_finding_lens(f.status) = 'open'")
	b.add("f.source IS DISTINCT FROM 'pentest'")
	limit := b.arg(topFixCandidates)
	//nolint:gosec // G202: fixed SQL, values bound
	q := `WITH top AS (
			SELECT rs.id, rs.title, rs.finding_ids FROM remediation_suggestions rs
			WHERE rs.tenant_id = $1 AND rs.state = 'proposed'
			ORDER BY rs.risk_points DESC, rs.id
			LIMIT ` + limit + `)
		SELECT t.id, t.title, COUNT(*), COUNT(DISTINCT f.asset_id),
			COUNT(*) FILTER (WHERE f.priority_class IN ('P0', 'P1')),
			COALESCE(SUM(` + FindingRiskPointsSQL + `), 0) AS points
		FROM top t
		JOIN findings f ON f.id = ANY(t.finding_ids)
		WHERE ` + b.sql() + `
		GROUP BY t.id, t.title
		ORDER BY points DESC, COUNT(*) DESC, t.id
		LIMIT 1`
	qctx, cancel := context.WithTimeout(ctx, widgetQueryTimeout)
	defer cancel()
	var (
		id  string
		out dashboard.FixLever
	)
	err := r.db.QueryRowContext(qctx, q, b.args...).Scan(&id, &out.Title, &out.Findings, &out.Assets, &out.PriorityOpen, &out.Points)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("top fix: %w", err)
	}
	sid, err := shared.IDFromString(id)
	if err != nil {
		return nil, fmt.Errorf("top fix id: %w", err)
	}
	out.SuggestionID = sid
	return &out, nil
}
