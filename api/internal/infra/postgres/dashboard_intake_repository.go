package postgres

// The exposure-flow and intake reads of the dashboards
// (docs/architecture/dashboards.md, "Exposure flow and intake"): where the
// findings in scope went, and what each source sent. Outcomes follow the
// CTEM reads' rules (findingWhere); the intake reads the receipts with the
// same grouping expressions as the receipt list filters, so a figure equals
// the list it opens.

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/dashboard"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// maxIntakeSources bounds the sources one intake read returns (the busiest
// first); the totals of the widget are computed over every row returned.
const maxIntakeSources = 200

// Outcomes implements dashboard.FactReader.
func (r *DashboardWidgetRepository) Outcomes(ctx context.Context, scope dashboard.ReadScope, since time.Time) (dashboard.OutcomeCounts, error) {
	b := findingWhere(scope)
	where := b.sql()
	sinceArg := b.arg(since.UTC())
	//nolint:gosec // G202: fixed SQL, values bound
	q := `SELECT COUNT(*) FILTER (WHERE f.status = 'in_progress'),
		COUNT(*) FILTER (WHERE f.status = 'resolved' AND f.resolved_at >= ` + sinceArg + `),
		COUNT(*) FILTER (WHERE f.status = 'accepted' AND f.resolved_at >= ` + sinceArg + `),
		COUNT(*) FILTER (WHERE f.status = 'false_positive' AND f.resolved_at >= ` + sinceArg + `)
		FROM findings f WHERE (f.status = 'in_progress' OR f.resolved_at >= ` + sinceArg + `) AND ` + where
	qctx, cancel := context.WithTimeout(ctx, widgetQueryTimeout)
	defer cancel()
	var out dashboard.OutcomeCounts
	if err := r.db.QueryRowContext(qctx, q, b.args...).Scan(&out.InProgress, &out.Fixed, &out.Accepted, &out.FalsePositive); err != nil {
		return out, fmt.Errorf("outcomes: %w", err)
	}
	return out, nil
}

// OrgIntake implements dashboard.FactReader.
func (r *DashboardWidgetRepository) OrgIntake(ctx context.Context, tenantID shared.ID, since time.Time) ([]dashboard.IntakeRow, error) {
	//nolint:gosec // G202: fixed SQL (constant expressions), values bound
	q := `WITH rc AS (
			SELECT ` + receiptOriginSQL + ` AS origin, ` + receiptToolSQL + ` AS tool, id, status, created_at, updated_at,
				findings_received, findings_created, findings_updated, findings_reopened, findings_closed,
				skipped, findings_failed, findings_suppressed
			FROM ingest_receipts WHERE tenant_id = $1 AND updated_at >= $2
		), gaps AS (
			SELECT origin, tool, EXTRACT(EPOCH FROM created_at - lag(created_at) OVER (PARTITION BY origin, tool ORDER BY created_at)) AS gap
			FROM rc
		), med AS (
			SELECT origin, tool, percentile_cont(0.5) WITHIN GROUP (ORDER BY gap) AS gap, COUNT(*) AS n
			FROM gaps WHERE gap IS NOT NULL GROUP BY origin, tool
		)
		SELECT rc.origin, rc.tool, COUNT(*), COALESCE(SUM(findings_received), 0), COALESCE(SUM(findings_created), 0),
			COALESCE(SUM(findings_updated), 0), COALESCE(SUM(findings_reopened), 0), COALESCE(SUM(findings_closed), 0),
			COALESCE(SUM(skipped), 0), COALESCE(SUM(findings_failed), 0), COALESCE(SUM(findings_suppressed), 0),
			MAX(updated_at), (array_agg(status ORDER BY updated_at DESC, id DESC))[1],
			(array_agg(id::text ORDER BY updated_at DESC, id DESC))[1],
			CASE WHEN MAX(med.n) >= 2 THEN MAX(med.gap) END
		FROM rc LEFT JOIN med ON med.origin = rc.origin AND med.tool = rc.tool
		GROUP BY rc.origin, rc.tool
		ORDER BY SUM(findings_received) DESC, rc.origin, rc.tool
		LIMIT ` + fmt.Sprint(maxIntakeSources)
	qctx, cancel := context.WithTimeout(ctx, widgetQueryTimeout)
	defer cancel()
	rows, err := r.db.QueryContext(qctx, q, tenantID.String(), since.UTC())
	if err != nil {
		return nil, fmt.Errorf("intake: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := make([]dashboard.IntakeRow, 0, 8)
	for rows.Next() {
		var row dashboard.IntakeRow
		var id string
		var gap sql.NullFloat64
		if err := rows.Scan(&row.Origin, &row.Tool, &row.Receipts, &row.Received, &row.Created, &row.StillDetected,
			&row.Reopened, &row.Closed, &row.Skipped, &row.Failed, &row.Suppressed, &row.LastAt, &row.LastStatus, &id, &gap); err != nil {
			return nil, fmt.Errorf("scan intake: %w", err)
		}
		if sid, perr := shared.IDFromString(id); perr == nil {
			row.LastReceiptID = sid
		}
		if gap.Valid {
			d := time.Duration(gap.Float64 * float64(time.Second))
			row.MedianGap = &d
		}
		out = append(out, row)
	}
	return out, rows.Err()
}
