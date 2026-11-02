package postgres

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/dashboard"
	"github.com/openctemio/openctem/api/pkg/domain/remediation"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

// The closure quality, campaign progress and false-positive breakdowns of
// the dashboard (docs/architecture/dashboards.md, "Closure quality,
// campaigns and detection quality"). Each figure is read with the predicate
// of the list it opens, tenant first, values bound:
//   - finding figures start from findingWhere (data scope, campaign rule);
//   - Ready to close uses the Ready to close list's own statement
//     (proposalFromSQL, proposalEligibleSQL, proposalScope);
//   - campaigns use the campaign list's visibility (campaignVisibleCond) and
//     summary (RemediationCampaignRepository.Summaries).

// maxDashboardCampaigns bounds the active campaigns one read summarizes.
const maxDashboardCampaigns = 500

// ClosureQuality implements dashboard.FactReader. The fixes are the findings
// list's status=resolved with resolved_at_gte and resolved_by_null; a reopen
// is its last_reopened_at_gte.
func (r *DashboardWidgetRepository) ClosureQuality(ctx context.Context, scope dashboard.ReadScope, from, prevFrom time.Time) (dashboard.ClosureQualityCounts, error) {
	var out dashboard.ClosureQualityCounts
	b := findingWhere(scope)
	prev := b.arg(prevFrom.UTC())
	cur := b.arg(from.UTC())
	fixed := func(lo, hi, person string) string {
		c := "f.status = 'resolved' AND f.resolved_at >= " + lo + " AND f.resolved_by " + person
		if hi != "" {
			c += " AND f.resolved_at < " + hi
		}
		return "COUNT(*) FILTER (WHERE " + c + ")"
	}
	reopened := func(lo, hi string) string {
		c := "f.last_reopened_at >= " + lo
		if hi != "" {
			c += " AND f.last_reopened_at < " + hi
		}
		return "COUNT(*) FILTER (WHERE " + c + ")"
	}
	b.add("(f.resolved_at >= " + prev + " OR f.last_reopened_at >= " + prev + ")")
	//nolint:gosec // G202: fixed SQL (constant expressions), values bound
	q := "SELECT " + fixed(cur, "", "IS NOT NULL") + ", " + fixed(cur, "", "IS NULL") + ", " + reopened(cur, "") + ", " +
		fixed(prev, cur, "IS NOT NULL") + ", " + fixed(prev, cur, "IS NULL") + ", " + reopened(prev, cur) +
		" FROM findings f WHERE " + b.sql()
	qctx, cancel := context.WithTimeout(ctx, widgetQueryTimeout)
	defer cancel()
	if err := r.db.QueryRowContext(qctx, q, b.args...).Scan(&out.Current.ByPerson, &out.Current.Automatic, &out.Current.Reopened,
		&out.Previous.ByPerson, &out.Previous.Automatic, &out.Previous.Reopened); err != nil {
		return out, fmt.Errorf("closure quality: %w", err)
	}

	// Ready to close: the list's count (CountClosureProposals) for the
	// reader's data scope; an organization read counts the whole tenant.
	cond, args := proposalScope(scope.Assets, 2)
	args = append([]any{scope.TenantID.String()}, args...)
	//nolint:gosec // G202: fixed SQL (constant expressions), values bound
	rq := "SELECT COUNT(*)" + proposalFromSQL + proposalEligibleSQL + " AND " + cond
	if err := r.db.QueryRowContext(qctx, rq, args...).Scan(&out.ReadyToClose); err != nil {
		return out, fmt.Errorf("closure quality ready to close: %w", err)
	}
	return out, nil
}

// ActiveCampaigns implements dashboard.FactReader. Visibility and summary are
// the campaign list's: a restricted reader sees the campaigns they created or
// own or with a task holding a finding in their scope, counted over their
// scope, except a campaign they own, counted whole.
func (r *DashboardWidgetRepository) ActiveCampaigns(ctx context.Context, scope dashboard.ReadScope) ([]dashboard.CampaignProgressRow, error) {
	viewer := remediation.CampaignViewer{Scope: scope.Assets}
	if scope.Assets != nil {
		uid := scope.Assets.UserID
		viewer.UserID = &uid
	}
	args := []any{scope.TenantID.String()}
	vis, args := campaignVisibleCond(viewer, args)
	//nolint:gosec // G202: fixed SQL (constant expressions), values bound
	q := `SELECT c.id, c.name, c.due_date, c.assigned_to FROM remediation_campaigns c
		WHERE c.tenant_id = $1 AND c.status = 'active' AND ` + vis + `
		ORDER BY c.due_date ASC NULLS LAST, c.created_at, c.id LIMIT ` + fmt.Sprint(maxDashboardCampaigns)
	rows, cancel, err := r.query(ctx, q, args)
	if err != nil {
		return nil, fmt.Errorf("active campaigns: %w", err)
	}
	defer cancel()
	defer rows.Close()
	var (
		out          []dashboard.CampaignProgressRow
		mine, others []shared.ID
	)
	for rows.Next() {
		var (
			row      dashboard.CampaignProgressRow
			due      sql.NullTime
			assignee sql.NullString
		)
		if err := rows.Scan(&row.ID, &row.Name, &due, &assignee); err != nil {
			return nil, fmt.Errorf("scan active campaign: %w", err)
		}
		if due.Valid {
			d := due.Time
			row.DueDate = &d
		}
		if viewer.Restricted() && assignee.Valid && assignee.String == viewer.UserID.String() {
			mine = append(mine, row.ID)
		} else {
			others = append(others, row.ID)
		}
		out = append(out, row)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("active campaigns: %w", err)
	}
	campaigns := &RemediationCampaignRepository{db: r.db}
	sums, err := campaigns.Summaries(ctx, scope.TenantID, others, scope.Assets)
	if err != nil {
		return nil, err
	}
	if len(mine) > 0 {
		whole := &shared.DataScope{TenantID: scope.TenantID, UserID: viewer.Scope.UserID, Unrestricted: true}
		own, err := campaigns.Summaries(ctx, scope.TenantID, mine, whole)
		if err != nil {
			return nil, err
		}
		for id, s := range own {
			sums[id] = s
		}
	}
	for i := range out {
		s := sums[out[i].ID]
		out[i].Tasks, out[i].Done, out[i].Overdue = int64(s.Tasks), int64(s.DoneTasks), int64(s.OverdueTasks)
	}
	return out, nil
}

// ClosedByTool implements dashboard.FactReader. Closed is the findings
// list's state=closed with resolved_at_gte; false positive its
// status=false_positive with resolved_at_gte; both per tool_name.
func (r *DashboardWidgetRepository) ClosedByTool(ctx context.Context, scope dashboard.ReadScope, from time.Time) ([]dashboard.ToolClosedRow, error) {
	b := findingWhere(scope)
	since := b.arg(from.UTC())
	b.add("f.resolved_at >= " + since)
	b.add(vulnerability.ClosedStatusSQL("f.status"))
	//nolint:gosec // G202: fixed SQL (constant expressions), values bound
	q := `SELECT f.tool_name, COUNT(*), COUNT(*) FILTER (WHERE f.status = 'false_positive')
		FROM findings f WHERE ` + b.sql() + ` GROUP BY f.tool_name ORDER BY f.tool_name`
	rows, cancel, err := r.query(ctx, q, b.args)
	if err != nil {
		return nil, fmt.Errorf("closed by tool: %w", err)
	}
	defer cancel()
	defer rows.Close()
	out := make([]dashboard.ToolClosedRow, 0)
	for rows.Next() {
		var row dashboard.ToolClosedRow
		if err := rows.Scan(&row.Tool, &row.Closed, &row.FalsePositive); err != nil {
			return nil, fmt.Errorf("scan closed by tool: %w", err)
		}
		out = append(out, row)
	}
	return out, rows.Err()
}
