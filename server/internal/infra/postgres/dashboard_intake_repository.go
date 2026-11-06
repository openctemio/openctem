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
	"github.com/openctemio/openctem/api/pkg/domain/ingestreceipt"
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

// intakeBaseSQL is one row per receipt, tool and sender in the window: the
// receipt's source group and status with the counts the tool's reports by
// that sender added (ingest_receipt_tools), so a source is the tool that
// reported, never the first tool of a multi-tool run. The receipt list
// filters by the same rows (receiptWhere), so a figure equals its list.
const intakeBaseSQL = `SELECT ` + receiptOriginSQL + ` AS origin, t.tool, t.instance_kind AS ikind, t.instance_id AS iid,
		t.instance_name AS iname, r.id, r.status, r.created_at, r.updated_at,
		t.received, t.created, t.still_detected, t.reopened, t.closed, t.skipped, t.failed, t.suppressed,
		t.assets_created + t.assets_updated AS assets
	FROM ingest_receipt_tools t
	JOIN ingest_receipts r ON r.tenant_id = t.tenant_id AND r.id = t.receipt_id
	WHERE r.tenant_id = $1 AND t.tenant_id = $1 AND r.updated_at >= $2`

// OrgIntake implements dashboard.FactReader.
func (r *DashboardWidgetRepository) OrgIntake(ctx context.Context, tenantID shared.ID, since time.Time) ([]dashboard.IntakeRow, error) {
	//nolint:gosec // G202: fixed SQL (constant expressions), values bound
	q := `WITH rc AS (` + intakeBaseSQL + `
		), rr AS (
			SELECT DISTINCT ON (origin, tool, id) origin, tool, id, created_at FROM rc
		), gaps AS (
			SELECT origin, tool, EXTRACT(EPOCH FROM created_at - lag(created_at) OVER (PARTITION BY origin, tool ORDER BY created_at)) AS gap
			FROM rr
		), med AS (
			SELECT origin, tool, percentile_cont(0.5) WITHIN GROUP (ORDER BY gap) AS gap, COUNT(*) AS n
			FROM gaps WHERE gap IS NOT NULL GROUP BY origin, tool
		)
		SELECT rc.origin, rc.tool, COUNT(DISTINCT rc.id), COALESCE(SUM(received), 0), COALESCE(SUM(created), 0),
			COALESCE(SUM(still_detected), 0), COALESCE(SUM(reopened), 0), COALESCE(SUM(closed), 0),
			COALESCE(SUM(skipped), 0), COALESCE(SUM(failed), 0), COALESCE(SUM(suppressed), 0),
			MAX(updated_at), (array_agg(status ORDER BY updated_at DESC, rc.id DESC))[1],
			(array_agg(rc.id::text ORDER BY updated_at DESC, rc.id DESC))[1],
			CASE WHEN MAX(med.n) >= 2 THEN MAX(med.gap) END, COALESCE(SUM(assets), 0)
		FROM rc LEFT JOIN med ON med.origin = rc.origin AND med.tool = rc.tool
		GROUP BY rc.origin, rc.tool
		ORDER BY SUM(received) DESC, SUM(assets) DESC, rc.origin, rc.tool
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
			&row.Reopened, &row.Closed, &row.Skipped, &row.Failed, &row.Suppressed, &row.LastAt, &row.LastStatus, &id, &gap,
			&row.Assets); err != nil {
			return nil, fmt.Errorf("scan intake: %w", err)
		}
		if sid, perr := shared.IDFromString(id); perr == nil {
			row.LastReceiptID = sid
		}
		row.MedianGap = gapDuration(gap)
		out = append(out, row)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return out, nil
	}
	if err := r.intakeInstances(qctx, tenantID, since, out); err != nil {
		return nil, err
	}
	return out, nil
}

// maxIntakeInstances bounds the senders one intake read returns.
const maxIntakeInstances = 1000

// intakeInstances fills each source's senders. A sensor is named from the
// tenant's own sensors only (another tenant's or a platform sensor stays
// unnamed and has no page to open).
func (r *DashboardWidgetRepository) intakeInstances(ctx context.Context, tenantID shared.ID, since time.Time, srcs []dashboard.IntakeRow) error {
	//nolint:gosec // G202: fixed SQL (constant expressions), values bound
	q := `WITH rc AS (` + intakeBaseSQL + `
		), rr AS (
			SELECT DISTINCT ON (origin, tool, ikind, iid, id) origin, tool, ikind, iid, id, created_at FROM rc
		), gaps AS (
			SELECT origin, tool, ikind, iid,
				EXTRACT(EPOCH FROM created_at - lag(created_at) OVER (PARTITION BY origin, tool, ikind, iid ORDER BY created_at)) AS gap
			FROM rr
		), med AS (
			SELECT origin, tool, ikind, iid, percentile_cont(0.5) WITHIN GROUP (ORDER BY gap) AS gap, COUNT(*) AS n
			FROM gaps WHERE gap IS NOT NULL GROUP BY origin, tool, ikind, iid
		), agg AS (
			SELECT rc.origin, rc.tool, rc.ikind, rc.iid, MAX(rc.iname) AS iname, COUNT(DISTINCT rc.id) AS receipts,
				COALESCE(SUM(received), 0) AS received, COALESCE(SUM(assets), 0) AS assets, MAX(updated_at) AS last_at,
				(array_agg(status ORDER BY updated_at DESC, rc.id DESC))[1] AS last_status,
				CASE WHEN MAX(med.n) >= 2 THEN MAX(med.gap) END AS gap
			FROM rc LEFT JOIN med ON med.origin = rc.origin AND med.tool = rc.tool AND med.ikind = rc.ikind AND med.iid = rc.iid
			GROUP BY rc.origin, rc.tool, rc.ikind, rc.iid
		)
		SELECT agg.origin, agg.tool, agg.ikind, agg.iid, COALESCE(s.name, agg.iname, ''), s.id IS NOT NULL,
			agg.receipts, agg.received, agg.assets, agg.last_at, agg.last_status, agg.gap
		FROM agg
		LEFT JOIN sensors s ON agg.ikind = '` + ingestreceipt.InstanceSensor + `' AND s.tenant_id = $1 AND s.id::text = agg.iid
		ORDER BY agg.received DESC, agg.assets DESC, agg.ikind, agg.iid
		LIMIT ` + fmt.Sprint(maxIntakeInstances)
	rows, err := r.db.QueryContext(ctx, q, tenantID.String(), since.UTC())
	if err != nil {
		return fmt.Errorf("intake instances: %w", err)
	}
	defer func() { _ = rows.Close() }()
	idx := make(map[[2]string]int, len(srcs))
	for i := range srcs {
		idx[[2]string{srcs[i].Origin, srcs[i].Tool}] = i
	}
	for rows.Next() {
		var origin, tool string
		var in dashboard.IntakeInstanceRow
		var gap sql.NullFloat64
		if err := rows.Scan(&origin, &tool, &in.Kind, &in.ID, &in.Name, &in.Owned, &in.Receipts, &in.Received,
			&in.Assets, &in.LastAt, &in.LastStatus, &gap); err != nil {
			return fmt.Errorf("scan intake instance: %w", err)
		}
		in.MedianGap = gapDuration(gap)
		if i, ok := idx[[2]string{origin, tool}]; ok {
			srcs[i].Instances = append(srcs[i].Instances, in)
		}
	}
	return rows.Err()
}

// gapDuration is a median gap in seconds as a duration (nil when unknown).
func gapDuration(gap sql.NullFloat64) *time.Duration {
	if !gap.Valid {
		return nil
	}
	d := time.Duration(gap.Float64 * float64(time.Second))
	return &d
}
