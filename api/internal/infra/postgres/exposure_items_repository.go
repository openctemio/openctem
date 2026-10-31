package postgres

// The Exposure Items view (docs/architecture/exposure-taxonomy.md, "Exposure
// Items view"). Every read takes a filter compiled for exposure.ItemFields
// from placeholder $2 (checked below), so the tenant and the caller's data
// scope are always in the WHERE; $1 is the tenant's unclassified-scans mode,
// an input of the asset's monitoring state.

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/exposure"
	"github.com/openctemio/openctem/api/pkg/filterspec"
	"github.com/openctemio/openctem/api/pkg/pagination"
)

const (
	exposureItemsListTimeout  = "3s"
	exposureItemsStatsTimeout = "2s"
)

var errUncompiledExposureItemFilter = errors.New("exposure item filter was not compiled for a tenant")

const exposureItemColumns = `e.id, e.tenant_id, e.asset_id, e.event_type, e.severity,
	e.state, e.title, e.description, e.details, e.fingerprint, e.source,
	e.first_seen_at, e.last_seen_at, e.resolved_at, e.resolved_by, e.resolution_notes,
	e.created_at, e.updated_at, e.peak_severity,
	e.source_severity, e.severity_override_reason, e.severity_overridden_by, e.severity_overridden_at`

// exposureItemsFrom is the FROM of every read: the exposure, its live asset
// (same tenant) and the parameter row p. The monitoring state lateral is
// added only when the filter or the order reads it (exposureItemsFromFor):
// it costs a scope-exclusion match per row.
func exposureItemsFrom(withState bool) string {
	from := ` FROM exposure_events e
	CROSS JOIN (SELECT $1::boolean AS scanned) p
	LEFT JOIN assets a ON a.tenant_id = e.tenant_id AND a.id = e.asset_id AND a.deleted_at IS NULL`
	if withState {
		from += `
	LEFT JOIN LATERAL (SELECT ` + assetMonitoringStateSQL("a", "p.scanned") + ` AS state WHERE a.id IS NOT NULL) ms ON true`
	}
	return from
}

func exposureItemsFromFor(w *filterspec.Where) string {
	return exposureItemsFrom(strings.Contains(w.SQL, exposure.MonitoringStateSQL) ||
		strings.Contains(w.OrderBy, exposure.MonitoringStateSQL))
}

func checkExposureItemWhere(w *filterspec.Where) error {
	if w == nil || w.First != exposure.ItemFilterFirstArg ||
		!strings.HasPrefix(w.SQL, exposure.ItemFields.TenantSQL+" = $") || w.OrderBy == "" {
		return errUncompiledExposureItemFilter
	}
	return nil
}

func exposureItemArgs(w *filterspec.Where, scanned bool) []any {
	return append([]any{scanned}, w.Args...)
}

// readOnlyTx opens a read-only transaction with a statement timeout.
func (r *ExposureRepository) readOnlyTx(ctx context.Context, timeout string) (*sql.Tx, error) {
	tx, err := r.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, fmt.Errorf("begin exposure items read: %w", err)
	}
	if _, err := tx.ExecContext(ctx, "SET LOCAL statement_timeout = '"+timeout+"'"); err != nil {
		_ = tx.Rollback()
		return nil, fmt.Errorf("set exposure items timeout: %w", err)
	}
	return tx, nil
}

// ListItems lists one page of exposures matching a compiled filter, with the
// total. The monitoring state of the page's assets is read for those rows
// only.
func (r *ExposureRepository) ListItems(ctx context.Context, w *filterspec.Where, scanned bool,
	page pagination.Pagination) (pagination.Result[*exposure.Item], error) {
	var empty pagination.Result[*exposure.Item]
	if err := checkExposureItemWhere(w); err != nil {
		return empty, err
	}
	tx, err := r.readOnlyTx(ctx, exposureItemsListTimeout)
	if err != nil {
		return empty, err
	}
	defer func() { _ = tx.Rollback() }()
	from := exposureItemsFromFor(w)
	args := exposureItemArgs(w, scanned)
	var total int64
	if err := tx.QueryRowContext(ctx, "SELECT COUNT(*)"+from+" WHERE "+w.SQL, args...).Scan(&total); err != nil {
		return empty, fmt.Errorf("count exposure items: %w", err)
	}
	// w.SQL and w.OrderBy come from filterspec.Compile (checked above):
	// registry constants and bound placeholders only.
	q := fmt.Sprintf(`SELECT %s, COALESCE(a.name, ''), COALESCE(a.asset_type, ''),
		CASE WHEN a.id IS NULL THEN false ELSE %s END,
		CASE WHEN a.id IS NULL THEN '' ELSE %s END
		%s WHERE %s ORDER BY %s LIMIT %d OFFSET %d`, //nolint:gosec // G201: compiled filter
		exposureItemColumns, asset.PrimarySQL("a"), assetMonitoringStateSQL("a", "p.scanned"),
		from, w.SQL, w.OrderBy, page.Limit(), page.Offset())
	rows, err := tx.QueryContext(ctx, q, args...)
	if err != nil {
		return empty, fmt.Errorf("list exposure items: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := make([]*exposure.Item, 0, page.Limit())
	for rows.Next() {
		it := &exposure.Item{}
		ev, err := r.doScan(func(dest ...any) error {
			return rows.Scan(append(dest, &it.AssetName, &it.AssetType, &it.Primary, &it.MonitoringState)...)
		})
		if err != nil {
			return empty, fmt.Errorf("scan exposure item: %w", err)
		}
		it.Event = ev
		out = append(out, it)
	}
	if err := rows.Err(); err != nil {
		return empty, fmt.Errorf("list exposure items: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return empty, fmt.Errorf("commit exposure items: %w", err)
	}
	return pagination.NewResult(out, total, page), nil
}

// ItemStats counts the exposures of a compiled filter by severity, display
// category and state: the same WHERE as the list.
func (r *ExposureRepository) ItemStats(ctx context.Context, w *filterspec.Where, scanned bool) (*exposure.ItemStats, error) {
	if err := checkExposureItemWhere(w); err != nil {
		return nil, err
	}
	tx, err := r.readOnlyTx(ctx, exposureItemsStatsTimeout)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()
	q := "SELECT e.severity, e.event_type, e.state, count(*)" + exposureItemsFromFor(w) + //nolint:gosec // G202: compiled filter
		" WHERE " + w.SQL + " GROUP BY 1, 2, 3"
	rows, err := tx.QueryContext(ctx, q, exposureItemArgs(w, scanned)...)
	if err != nil {
		return nil, fmt.Errorf("exposure item stats: %w", err)
	}
	defer func() { _ = rows.Close() }()
	st := &exposure.ItemStats{BySeverity: map[string]int64{}, ByCategory: map[string]int64{}, ByState: map[string]int64{}}
	for rows.Next() {
		var sev, typ, state string
		var n int64
		if err := rows.Scan(&sev, &typ, &state, &n); err != nil {
			return nil, fmt.Errorf("scan exposure item stats: %w", err)
		}
		st.Total += n
		st.BySeverity[sev] += n
		st.ByCategory[string(exposure.EventType(typ).Category())] += n
		st.ByState[state] += n
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("exposure item stats: %w", err)
	}
	return st, tx.Commit()
}

// ItemsByAsset folds the exposures of a compiled filter into one row per
// asset (exposures without an asset are left out), most severe first.
func (r *ExposureRepository) ItemsByAsset(ctx context.Context, w *filterspec.Where, scanned bool,
	page pagination.Pagination) (pagination.Result[*exposure.AssetGroup], error) {
	var empty pagination.Result[*exposure.AssetGroup]
	if err := checkExposureItemWhere(w); err != nil {
		return empty, err
	}
	tx, err := r.readOnlyTx(ctx, exposureItemsListTimeout)
	if err != nil {
		return empty, err
	}
	defer func() { _ = tx.Rollback() }()
	from := exposureItemsFromFor(w)
	args := exposureItemArgs(w, scanned)
	where := w.SQL + " AND a.id IS NOT NULL"
	var total int64
	if err := tx.QueryRowContext(ctx, "SELECT COUNT(DISTINCT a.id)"+from+" WHERE "+where, args...).Scan(&total); err != nil {
		return empty, fmt.Errorf("count exposure item assets: %w", err)
	}
	q := fmt.Sprintf(`WITH g AS (
		SELECT a.id, a.tenant_id, max(a.name) AS name, max(a.asset_type) AS asset_type, count(*) AS total,
		       count(*) FILTER (WHERE e.severity = 'critical') AS critical,
		       count(*) FILTER (WHERE e.severity = 'high') AS high,
		       count(*) FILTER (WHERE e.severity = 'medium') AS medium,
		       count(*) FILTER (WHERE e.severity = 'low') AS low,
		       count(*) FILTER (WHERE e.severity = 'info') AS info,
		       max(%s) AS top_rank, min(e.first_seen_at) AS first_seen, max(e.last_seen_at) AS last_seen,
		       bool_or(p.scanned) AS scanned
		%s WHERE %s GROUP BY a.id, a.tenant_id
		ORDER BY top_rank DESC NULLS LAST, total DESC, a.id LIMIT %d OFFSET %d)
	SELECT g.id, g.name, g.asset_type, g.total, g.critical, g.high, g.medium, g.low, g.info, g.top_rank,
	       g.first_seen, g.last_seen, %s, %s
	FROM g JOIN assets a ON a.tenant_id = g.tenant_id AND a.id = g.id
	ORDER BY g.top_rank DESC NULLS LAST, g.total DESC, g.id`, //nolint:gosec // G201: compiled filter and constants
		exposure.SeverityRankSQL, from, where, page.Limit(), page.Offset(),
		asset.PrimarySQL("a"), assetMonitoringStateSQL("a", "g.scanned"))
	rows, err := tx.QueryContext(ctx, q, args...)
	if err != nil {
		return empty, fmt.Errorf("list exposure item assets: %w", err)
	}
	defer func() { _ = rows.Close() }()
	ranks := exposure.AllSeverities() // critical .. info
	out := make([]*exposure.AssetGroup, 0, page.Limit())
	for rows.Next() {
		var (
			g                          exposure.AssetGroup
			crit, high, med, low, info int64
			rank                       sql.NullInt64
			firstSeen, lastSeen        time.Time
		)
		if err := rows.Scan(&g.AssetID, &g.AssetName, &g.AssetType, &g.Total, &crit, &high, &med, &low, &info, &rank,
			&firstSeen, &lastSeen, &g.Primary, &g.MonitoringState); err != nil {
			return empty, fmt.Errorf("scan exposure item asset: %w", err)
		}
		g.FirstSeenAt, g.LastSeenAt = firstSeen, lastSeen
		g.BySeverity = map[string]int64{"critical": crit, "high": high, "medium": med, "low": low, "info": info}
		if rank.Valid && rank.Int64 >= 1 && int(rank.Int64) <= len(ranks) {
			g.TopSeverity = string(ranks[len(ranks)-int(rank.Int64)])
		}
		out = append(out, &g)
	}
	if err := rows.Err(); err != nil {
		return empty, fmt.Errorf("list exposure item assets: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return empty, fmt.Errorf("commit exposure item assets: %w", err)
	}
	return pagination.NewResult(out, total, page), nil
}
