package postgres

import (
	"context"
	"fmt"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/dashboard"
)

// The attack surface and accepted-risk breakdowns of the dashboard
// (docs/architecture/dashboards.md, "Attack surface and accepted risk").
// Every read starts from the scope predicates the other widget reads use
// (assetWhere, findingWhere): the caller's tenant first, deleted and
// program-only assets left out, the data scope and the campaign rule from
// the server-built ReadScope. Each band is written with the same comparison
// as the list it opens, so a figure equals its list for the same viewer.

// NewAssets implements dashboard.FactReader. The asset list's
// first_seen_after filter is created_at >= the day, so the current window is
// counted the same way.
func (r *DashboardWidgetRepository) NewAssets(ctx context.Context, scope dashboard.ReadScope, from, prevFrom time.Time) ([]dashboard.NewAssetRow, error) {
	b := assetWhere(scope)
	prev := b.arg(prevFrom.UTC())
	cur := b.arg(from.UTC())
	b.add("a.created_at >= " + prev)
	//nolint:gosec // G202: fixed SQL, values bound
	q := `SELECT a.asset_type, COUNT(*) FILTER (WHERE a.created_at >= ` + cur + `),
		COUNT(*) FILTER (WHERE a.created_at < ` + cur + `)
		FROM assets a WHERE ` + b.sql() + ` GROUP BY a.asset_type ORDER BY a.asset_type`
	rows, cancel, err := r.query(ctx, q, b.args)
	if err != nil {
		return nil, fmt.Errorf("new assets: %w", err)
	}
	defer cancel()
	defer rows.Close()
	out := make([]dashboard.NewAssetRow, 0)
	for rows.Next() {
		var row dashboard.NewAssetRow
		if err := rows.Scan(&row.AssetType, &row.Current, &row.Previous); err != nil {
			return nil, fmt.Errorf("scan new assets: %w", err)
		}
		out = append(out, row)
	}
	return out, rows.Err()
}

// CertificateExpiry implements dashboard.FactReader. The expiry is the asset
// list's expiry expression (expirySQL) and the bands use its strict
// expires_after (>) and expires_before (<) comparisons.
func (r *DashboardWidgetRepository) CertificateExpiry(ctx context.Context, scope dashboard.ReadScope, now time.Time) (dashboard.CertificateExpiryCounts, error) {
	b := assetWhere(scope)
	b.add("a.asset_type = 'certificate'")
	n := now.UTC()
	t0 := b.arg(n)
	t7 := b.arg(n.Add(7 * 24 * time.Hour))
	t30 := b.arg(n.Add(30 * 24 * time.Hour))
	t90 := b.arg(n.Add(90 * 24 * time.Hour))
	band := func(after, before string) string {
		if after == "" {
			return "COUNT(*) FILTER (WHERE " + expirySQL + " < " + before + ")"
		}
		return "COUNT(*) FILTER (WHERE " + expirySQL + " > " + after + " AND " + expirySQL + " < " + before + ")"
	}
	//nolint:gosec // G202: fixed SQL (constant expressions), values bound
	q := "SELECT COUNT(*), " + band("", t0) + ", " + band(t0, t7) + ", " + band(t7, t30) + ", " + band(t30, t90) +
		" FROM assets a WHERE " + b.sql()
	qctx, cancel := context.WithTimeout(ctx, widgetQueryTimeout)
	defer cancel()
	var out dashboard.CertificateExpiryCounts
	if err := r.db.QueryRowContext(qctx, q, b.args...).Scan(&out.Total, &out.Expired, &out.Within7d, &out.Within30d, &out.Within90d); err != nil {
		return out, fmt.Errorf("certificate expiry: %w", err)
	}
	return out, nil
}

// AcceptanceExpiry implements dashboard.FactReader. The bands use the
// findings list's acceptance_expires_at_lte / _gt filters.
func (r *DashboardWidgetRepository) AcceptanceExpiry(ctx context.Context, scope dashboard.ReadScope, now time.Time) (dashboard.AcceptanceExpiryCounts, error) {
	b := findingWhere(scope)
	b.add("f.status = 'accepted'")
	n := now.UTC()
	t7 := b.arg(n.Add(7 * 24 * time.Hour))
	t30 := b.arg(n.Add(30 * 24 * time.Hour))
	//nolint:gosec // G202: fixed SQL, values bound
	q := `SELECT COUNT(*),
		COUNT(*) FILTER (WHERE f.acceptance_expires_at <= ` + t7 + `),
		COUNT(*) FILTER (WHERE f.acceptance_expires_at > ` + t7 + ` AND f.acceptance_expires_at <= ` + t30 + `),
		COUNT(*) FILTER (WHERE f.acceptance_expires_at > ` + t30 + `)
		FROM findings f WHERE ` + b.sql()
	qctx, cancel := context.WithTimeout(ctx, widgetQueryTimeout)
	defer cancel()
	var out dashboard.AcceptanceExpiryCounts
	if err := r.db.QueryRowContext(qctx, q, b.args...).Scan(&out.Accepted, &out.Within7d, &out.Within30d, &out.Later); err != nil {
		return out, fmt.Errorf("acceptance expiry: %w", err)
	}
	return out, nil
}
