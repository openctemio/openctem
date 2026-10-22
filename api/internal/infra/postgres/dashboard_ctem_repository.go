package postgres

import (
	"context"
	"fmt"
	"time"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/pkg/domain/dashboard"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/filterspec"
)

// The CTEM widget reads (docs/architecture/dashboards.md, "CTEM metrics"):
// crown jewels, the coverage ledger and validation. They follow the fact
// reads' rules: tenant first, assets that are not deleted and not
// program-only, the ReadScope asset scope, and the pentest campaign rule for
// anything counted from findings.

// coverageTrackedSQL / coverageCoveredSQL are the ledger predicates for one
// asset (alias a): tracked = the ledger has a capability that applies to it;
// covered = a run of any capability succeeded since {since}. The asset list
// filter coverage=covered|uncovered uses the same predicates, so the
// Discovery figure equals the list it opens.
const (
	coverageTrackedSQL = `EXISTS (SELECT 1 FROM asset_coverage act
		WHERE act.tenant_id = a.tenant_id AND act.asset_id = a.id AND act.state <> 'not_applicable')`
	coverageCoveredFmt = `EXISTS (SELECT 1 FROM asset_coverage acs
		WHERE acs.tenant_id = a.tenant_id AND acs.asset_id = a.id AND acs.state <> 'not_applicable'
		AND acs.last_success_at >= %s)`
)

// CoverageCondition is the asset list predicate for coverage=covered or
// uncovered (alias a), with since as the bound placeholder. Unknown values
// give "".
func CoverageCondition(value, sincePlaceholder string) string {
	covered := fmt.Sprintf(coverageCoveredFmt, sincePlaceholder)
	switch value {
	case "covered":
		return covered
	case "uncovered":
		return coverageTrackedSQL + " AND NOT " + covered
	}
	return ""
}

// assetWhere is the asset predicate set for a query over assets (alias a).
func assetWhere(scope dashboard.ReadScope) *whereBuilder {
	b := &whereBuilder{args: []any{scope.TenantID.String()}}
	b.add("a.tenant_id = $1")
	b.add("a.deleted_at IS NULL")
	b.add("NOT a.program_only")
	if scope.Assets != nil {
		cond, args := filterspec.ScopeSQL("a.id", scope.Assets, len(b.args)+1)
		b.args = append(b.args, args...)
		b.add(cond)
	}
	return b
}

// findingWhere is the predicate set for open, published findings (alias f)
// in scope: the fact lens, not branch-only, the asset rule and the campaign
// rule. A finding without an asset counts only in an organization read (no
// asset scope), as in the facts.
func findingWhere(scope dashboard.ReadScope) *whereBuilder {
	b := &whereBuilder{args: []any{scope.TenantID.String()}}
	b.add("f.tenant_id = $1")
	b.add("NOT f.branch_only")
	b.add(`(f.asset_id IS NULL OR EXISTS (SELECT 1 FROM assets wa
		WHERE wa.tenant_id = $1 AND wa.id = f.asset_id AND wa.deleted_at IS NULL AND NOT wa.program_only))`)
	if scope.Assets != nil {
		cond, args := filterspec.ScopeSQL("f.asset_id", scope.Assets, len(b.args)+1)
		b.args = append(b.args, args...)
		b.add(cond)
	}
	if scope.CampaignViewer != nil {
		user := b.arg(scope.CampaignViewer.String())
		b.add(fmt.Sprintf(`(f.source <> 'pentest' OR f.pentest_campaign_id IN (SELECT pcm.campaign_id
			FROM pentest_campaign_members pcm WHERE pcm.user_id = %s AND pcm.tenant_id = $1))`, user))
	}
	return b
}

// CrownJewels implements dashboard.FactReader.
func (r *DashboardWidgetRepository) CrownJewels(ctx context.Context, scope dashboard.ReadScope, priorities []string) (dashboard.CrownJewelCounts, error) {
	b := assetWhere(scope)
	b.add("a.is_crown_jewel")
	// Exposed: an open fact row (F1) of the priorities on the asset, with
	// the fact reads' campaign rule. The asset rule and the scope are the
	// outer query's (s.asset_id = a.id).
	exposed := "FALSE"
	if len(priorities) > 0 {
		cond := fmt.Sprintf("s.tenant_id = $1 AND s.asset_id = a.id AND s.lens = 'open' AND s.priority_class = ANY(%s::text[])", b.arg(pq.Array(priorities)))
		if scope.CampaignViewer != nil {
			user := b.arg(scope.CampaignViewer.String())
			cond += fmt.Sprintf(` AND (s.source <> 'pentest' OR s.pentest_campaign_id IN (SELECT pcm.campaign_id
				FROM pentest_campaign_members pcm WHERE pcm.user_id = %s AND pcm.tenant_id = $1))`, user)
		}
		exposed = "EXISTS (SELECT 1 FROM dash_asset_state s WHERE " + cond + ")"
	}
	//nolint:gosec // G202: fixed SQL, values bound
	q := "SELECT COUNT(*), COUNT(*) FILTER (WHERE " + exposed + ") FROM assets a WHERE " + b.sql()
	qctx, cancel := context.WithTimeout(ctx, widgetQueryTimeout)
	defer cancel()
	var out dashboard.CrownJewelCounts
	if err := r.db.QueryRowContext(qctx, q, b.args...).Scan(&out.Designated, &out.Exposed); err != nil {
		return out, fmt.Errorf("crown jewels: %w", err)
	}
	return out, nil
}

// Discovery implements dashboard.FactReader.
func (r *DashboardWidgetRepository) Discovery(ctx context.Context, scope dashboard.ReadScope, since time.Time) (dashboard.DiscoveryCounts, error) {
	b := assetWhere(scope)
	b.add(coverageTrackedSQL)
	covered := fmt.Sprintf(coverageCoveredFmt, b.arg(since.UTC()))
	//nolint:gosec // G202: fixed SQL, values bound
	q := "SELECT COUNT(*), COUNT(*) FILTER (WHERE " + covered + ") FROM assets a WHERE " + b.sql()
	qctx, cancel := context.WithTimeout(ctx, widgetQueryTimeout)
	defer cancel()
	var out dashboard.DiscoveryCounts
	if err := r.db.QueryRowContext(qctx, q, b.args...).Scan(&out.Tracked, &out.Covered); err != nil {
		return out, fmt.Errorf("discovery coverage: %w", err)
	}
	return out, nil
}

// Validation implements dashboard.FactReader. Validated follows the
// validation coverage read (a finding with at least one validation
// evidence row); retests are those completed in the window, on findings in
// scope.
func (r *DashboardWidgetRepository) Validation(ctx context.Context, scope dashboard.ReadScope, since time.Time) (dashboard.ValidationCounts, error) {
	b := findingWhere(scope)
	where := b.sql()
	sinceArg := b.arg(since.UTC())
	//nolint:gosec // G202: fixed SQL, values bound
	q := `SELECT o.n_open, o.n_validated, (SELECT COUNT(*) FROM finding_retests fr
			JOIN findings f ON f.tenant_id = $1 AND f.id = fr.finding_id
			WHERE fr.tenant_id = $1 AND fr.status = 'completed' AND fr.completed_at >= ` + sinceArg + `
			AND dash_finding_lens(f.status) IS NOT NULL AND ` + where + `)
		FROM (SELECT COUNT(*) AS n_open, COUNT(*) FILTER (WHERE EXISTS (SELECT 1 FROM validation_evidence ve
			WHERE ve.tenant_id = $1 AND ve.finding_id = f.id)) AS n_validated
			FROM findings f WHERE dash_finding_lens(f.status) = 'open' AND ` + where + `) o`
	qctx, cancel := context.WithTimeout(ctx, widgetQueryTimeout)
	defer cancel()
	var out dashboard.ValidationCounts
	if err := r.db.QueryRowContext(qctx, q, b.args...).Scan(&out.Open, &out.Validated, &out.RetestsRun); err != nil {
		return out, fmt.Errorf("validation: %w", err)
	}
	return out, nil
}

// VisibleAssets implements dashboard.FactReader.
func (r *DashboardWidgetRepository) VisibleAssets(ctx context.Context, scope dashboard.ReadScope, ids []shared.ID) (map[shared.ID]bool, error) {
	out := map[shared.ID]bool{}
	if len(ids) == 0 {
		return out, nil
	}
	strs := make([]string, 0, len(ids))
	for _, id := range ids {
		strs = append(strs, id.String())
	}
	b := assetWhere(scope)
	b.add(fmt.Sprintf("a.id = ANY(%s::uuid[])", b.arg(pq.Array(strs))))
	//nolint:gosec // G202: fixed SQL, values bound
	rows, cancel, err := r.query(ctx, "SELECT a.id FROM assets a WHERE "+b.sql(), b.args)
	if err != nil {
		return nil, fmt.Errorf("visible assets: %w", err)
	}
	defer cancel()
	defer rows.Close()
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("scan visible asset: %w", err)
		}
		if sid, perr := shared.IDFromString(id); perr == nil {
			out[sid] = true
		}
	}
	return out, rows.Err()
}
