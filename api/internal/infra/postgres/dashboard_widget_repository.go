package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/pkg/domain/dashboard"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/filterspec"
)

// DashboardWidgetRepository reads the dashboard fact tables for typed
// widgets (docs/architecture/dashboards.md, "Widget data").
//
// Every query starts with tenant_id = $1 and adds, in this order:
//   - the asset rule: findings without an asset (the all-zero id) or on an
//     asset that is not soft-deleted and not program-only (program assets
//     stay out of dashboards, as in every dashboard read);
//   - the asset scope of ReadScope (user_accessible_assets for a restricted
//     member, the hidden private program assets for an unrestricted one;
//     the all-zero asset is in nobody's scope);
//   - the pentest campaign rule when ReadScope names a viewer;
//   - the widget filter, as fixed column predicates with bound values.
//
// No caller text reaches the SQL: dimensions are mapped to column names
// from a fixed table and values are bound parameters.
type DashboardWidgetRepository struct {
	db *DB
}

// NewDashboardWidgetRepository creates the repository.
func NewDashboardWidgetRepository(db *DB) *DashboardWidgetRepository {
	return &DashboardWidgetRepository{db: db}
}

var _ dashboard.FactReader = (*DashboardWidgetRepository)(nil)

const zeroAssetID = "00000000-0000-0000-0000-000000000000"

// widgetQueryTimeout bounds one widget read.
const widgetQueryTimeout = 5 * time.Second

// factDimColumn maps a dimension to its fact column (same name in F1 and F2
// where both carry it).
var factDimColumn = map[dashboard.Dimension]string{
	dashboard.DimSeverity:      "severity",
	dashboard.DimPriorityClass: "priority_class",
	dashboard.DimSource:        "source",
	dashboard.DimSLAState:      "sla_state",
	dashboard.DimAgeBand:       "age_band",
	dashboard.DimKEV:           "kev",
	dashboard.DimReachable:     "reachable",
}

// factTable says which campaign rule form a table needs.
type factTable int

const (
	tableState factTable = iota // F1: has source
	tableDay                    // F2: campaign id only
	tableRank                   // F3: is_pentest
)

// whereBuilder accumulates predicates and bound arguments ($1 is the tenant).
type whereBuilder struct {
	conds []string
	args  []any
}

func (b *whereBuilder) arg(v any) string {
	b.args = append(b.args, v)
	return fmt.Sprintf("$%d", len(b.args))
}

func (b *whereBuilder) add(c string) { b.conds = append(b.conds, c) }

func (b *whereBuilder) sql() string { return strings.Join(b.conds, " AND ") }

// base builds the tenant, asset, scope and campaign predicates for alias.
func baseWhere(alias string, t factTable, scope dashboard.ReadScope) *whereBuilder {
	b := &whereBuilder{args: []any{scope.TenantID.String()}}
	b.add(alias + ".tenant_id = $1")
	b.add(fmt.Sprintf(`(%[1]s.asset_id = '%[2]s'::uuid OR EXISTS (SELECT 1 FROM assets wa
		WHERE wa.tenant_id = $1 AND wa.id = %[1]s.asset_id AND wa.deleted_at IS NULL AND NOT wa.program_only))`, alias, zeroAssetID))
	if scope.Assets != nil {
		cond, args := filterspec.ScopeSQL(alias+".asset_id", scope.Assets, len(b.args)+1)
		b.args = append(b.args, args...)
		b.add(cond)
	}
	if scope.CampaignViewer != nil {
		user := b.arg(scope.CampaignViewer.String())
		member := fmt.Sprintf(`%s.pentest_campaign_id IN (SELECT pcm.campaign_id FROM pentest_campaign_members pcm
			WHERE pcm.user_id = %s AND pcm.tenant_id = $1)`, alias, user)
		switch t {
		case tableState:
			b.add(fmt.Sprintf("(%s.source <> 'pentest' OR %s)", alias, member))
		case tableRank:
			b.add(fmt.Sprintf("(NOT %s.is_pentest OR %s)", alias, member))
		default:
			// F2 has no source: a non-pentest row carries the all-zero campaign.
			b.add(fmt.Sprintf("(%s.pentest_campaign_id = '%s'::uuid OR %s)", alias, zeroAssetID, member))
		}
	}
	return b
}

// applyFilter adds the widget filter. Dimensions the table does not carry
// never reach here (the catalog allows only carried ones).
func applyFilter(b *whereBuilder, alias string, f dashboard.WidgetFilter) {
	in := func(col string, vals []string) {
		if len(vals) > 0 {
			b.add(fmt.Sprintf("%s.%s = ANY(%s::text[])", alias, col, b.arg(pq.Array(vals))))
		}
	}
	in("severity", f.Severity)
	in("priority_class", f.PriorityClass)
	in("source", f.Source)
	in("sla_state", f.SLAState)
	in("age_band", f.AgeBand)
	if f.KEV != nil {
		b.add(fmt.Sprintf("%s.kev = %s", alias, b.arg(*f.KEV)))
	}
	if f.Reachable != nil {
		b.add(fmt.Sprintf("%s.reachable = %s", alias, b.arg(*f.Reachable)))
	}
	if len(f.AssetGroupIDs) > 0 {
		// Groups resolve inside the tenant: an id of another tenant matches nothing.
		b.add(fmt.Sprintf(`%s.asset_id IN (SELECT agm.asset_id FROM asset_group_members agm
			JOIN asset_groups ag ON ag.id = agm.asset_group_id AND ag.tenant_id = $1
			WHERE agm.asset_group_id = ANY(%s::uuid[]))`, alias, b.arg(pq.Array(f.AssetGroupIDs))))
	}
}

func dimColumns(alias string, groupBy []dashboard.Dimension) ([]string, error) {
	cols := make([]string, 0, len(groupBy))
	for _, d := range groupBy {
		c, ok := factDimColumn[d]
		if !ok {
			return nil, fmt.Errorf("%w: cannot group by %q", shared.ErrValidation, d)
		}
		cols = append(cols, alias+"."+c+"::text")
	}
	return cols, nil
}

func (r *DashboardWidgetRepository) query(ctx context.Context, q string, args []any) (*sql.Rows, context.CancelFunc, error) {
	qctx, cancel := context.WithTimeout(ctx, widgetQueryTimeout)
	rows, err := r.db.QueryContext(qctx, q, args...)
	if err != nil {
		cancel()
		return nil, nil, err
	}
	return rows, cancel, nil
}

// FactsBuiltAt implements dashboard.FactReader.
func (r *DashboardWidgetRepository) FactsBuiltAt(ctx context.Context, tenantID shared.ID) (*time.Time, error) {
	var at sql.NullTime
	err := r.db.QueryRowContext(ctx, `SELECT rebuilt_at FROM dash_fact_status WHERE tenant_id = $1`, tenantID.String()).Scan(&at)
	if errors.Is(err, sql.ErrNoRows) || (err == nil && !at.Valid) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read dashboard fact status: %w", err)
	}
	return &at.Time, nil
}

// CountOpen implements dashboard.FactReader.
func (r *DashboardWidgetRepository) CountOpen(ctx context.Context, scope dashboard.ReadScope, f dashboard.WidgetFilter, groupBy []dashboard.Dimension) ([]dashboard.CountRow, error) {
	cols, err := dimColumns("s", groupBy)
	if err != nil {
		return nil, err
	}
	b := baseWhere("s", tableState, scope)
	b.add("s.lens = 'open'")
	applyFilter(b, "s", f)
	sel := "COALESCE(SUM(s.finding_count), 0)"
	group := ""
	if len(cols) > 0 {
		sel = strings.Join(cols, ", ") + ", SUM(s.finding_count)"
		group = " GROUP BY " + strings.Join(cols, ", ")
	}
	//nolint:gosec // G202: columns come from factDimColumn, values are bound
	q := "SELECT " + sel + " FROM dash_asset_state s WHERE " + b.sql() + group
	rows, cancel, err := r.query(ctx, q, b.args)
	if err != nil {
		return nil, fmt.Errorf("count open findings: %w", err)
	}
	defer cancel()
	defer rows.Close()
	out := []dashboard.CountRow{}
	for rows.Next() {
		keys := make([]string, len(cols))
		dest := make([]any, 0, len(cols)+1)
		for i := range keys {
			dest = append(dest, &keys[i])
		}
		var n int64
		dest = append(dest, &n)
		if err := rows.Scan(dest...); err != nil {
			return nil, fmt.Errorf("scan open count: %w", err)
		}
		out = append(out, dashboard.CountRow{Keys: keys, Count: n})
	}
	return out, rows.Err()
}

// SLAWithin implements dashboard.FactReader.
func (r *DashboardWidgetRepository) SLAWithin(ctx context.Context, scope dashboard.ReadScope, f dashboard.WidgetFilter) (int64, int64, error) {
	b := baseWhere("s", tableState, scope)
	b.add("s.lens = 'open'")
	applyFilter(b, "s", f)
	//nolint:gosec // G202: fixed SQL, values bound
	q := `SELECT COALESCE(SUM(s.finding_count) FILTER (WHERE s.sla_state IN ('ok', 'warning')), 0),
		COALESCE(SUM(s.finding_count) FILTER (WHERE s.sla_state IN ('ok', 'warning', 'breached')), 0)
		FROM dash_asset_state s WHERE ` + b.sql()
	qctx, cancel := context.WithTimeout(ctx, widgetQueryTimeout)
	defer cancel()
	var num, den int64
	if err := r.db.QueryRowContext(qctx, q, b.args...).Scan(&num, &den); err != nil {
		return 0, 0, fmt.Errorf("sla within: %w", err)
	}
	return num, den, nil
}

func dayKey(groupBy dashboard.Dimension) (string, error) {
	if groupBy == "" {
		return "''::text", nil
	}
	cols, err := dimColumns("d", []dashboard.Dimension{groupBy})
	if err != nil {
		return "", err
	}
	return cols[0], nil
}

// Days implements dashboard.FactReader.
func (r *DashboardWidgetRepository) Days(ctx context.Context, scope dashboard.ReadScope, f dashboard.WidgetFilter, groupBy dashboard.Dimension, from, to time.Time) ([]dashboard.DayRow, error) {
	key, err := dayKey(groupBy)
	if err != nil {
		return nil, err
	}
	b := baseWhere("d", tableDay, scope)
	b.add("d.day BETWEEN " + b.arg(from.Format(time.DateOnly)) + "::date AND " + b.arg(to.Format(time.DateOnly)) + "::date")
	applyFilter(b, "d", f)
	//nolint:gosec // G202: key comes from factDimColumn, values are bound
	q := "SELECT d.day, " + key + ", SUM(d.opened), SUM(d.fixed), SUM(d.net_open_delta) FROM dash_asset_day d WHERE " +
		b.sql() + " GROUP BY 1, 2 ORDER BY 1"
	rows, cancel, err := r.query(ctx, q, b.args)
	if err != nil {
		return nil, fmt.Errorf("read daily flows: %w", err)
	}
	defer cancel()
	defer rows.Close()
	out := []dashboard.DayRow{}
	for rows.Next() {
		var d dashboard.DayRow
		if err := rows.Scan(&d.Day, &d.Key, &d.Opened, &d.Fixed, &d.NetDelta); err != nil {
			return nil, fmt.Errorf("scan daily flow: %w", err)
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// FixHist implements dashboard.FactReader.
func (r *DashboardWidgetRepository) FixHist(ctx context.Context, scope dashboard.ReadScope, f dashboard.WidgetFilter, groupBy dashboard.Dimension, from, to time.Time) ([]dashboard.FixHistRow, error) {
	key, err := dayKey(groupBy)
	if err != nil {
		return nil, err
	}
	b := baseWhere("d", tableDay, scope)
	b.add("d.day BETWEEN " + b.arg(from.Format(time.DateOnly)) + "::date AND " + b.arg(to.Format(time.DateOnly)) + "::date")
	b.add("d.fixed > 0")
	applyFilter(b, "d", f)
	//nolint:gosec // G202: key comes from factDimColumn, values are bound
	q := "SELECT " + key + " AS k, h.i, SUM(h.n) FROM dash_asset_day d, unnest(d.fix_hours_hist) WITH ORDINALITY AS h(n, i) WHERE " +
		b.sql() + " GROUP BY 1, 2"
	rows, cancel, err := r.query(ctx, q, b.args)
	if err != nil {
		return nil, fmt.Errorf("read fix histogram: %w", err)
	}
	defer cancel()
	defer rows.Close()
	byKey := map[string]*dashboard.FixHistRow{}
	order := []string{}
	for rows.Next() {
		var k string
		var i, n int64
		if err := rows.Scan(&k, &i, &n); err != nil {
			return nil, fmt.Errorf("scan fix histogram: %w", err)
		}
		row, ok := byKey[k]
		if !ok {
			row = &dashboard.FixHistRow{Key: k}
			byKey[k] = row
			order = append(order, k)
		}
		if i >= 1 && i <= 12 {
			row.Hist[i-1] += n
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	out := make([]dashboard.FixHistRow, 0, len(order))
	for _, k := range order {
		out = append(out, *byKey[k])
	}
	return out, nil
}

// Rank implements dashboard.FactReader. The rank fact holds finding ids
// only; the list fields are read from the findings by id, inside the tenant,
// and a finding no longer open (the facts lag by seconds) is left out.
func (r *DashboardWidgetRepository) Rank(ctx context.Context, scope dashboard.ReadScope, kind dashboard.RankKind, f dashboard.WidgetFilter, limit int) ([]dashboard.RankItem, error) {
	order := ""
	switch kind {
	case dashboard.RankFixNext:
		order = `r.priority_class, CASE r.severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3
			WHEN 'low' THEN 4 WHEN 'info' THEN 5 ELSE 6 END, r.sort_at DESC NULLS LAST, r.finding_id`
	case dashboard.RankSLADue:
		order = "r.sort_at ASC NULLS LAST, r.finding_id"
	default:
		return nil, fmt.Errorf("%w: unknown rank list", shared.ErrValidation)
	}
	if limit < 1 || limit > 10 {
		limit = 10
	}
	b := baseWhere("r", tableRank, scope)
	b.add("r.kind = " + b.arg(string(kind)))
	applyFilter(b, "r", f)
	lim := b.arg(limit)
	//nolint:gosec // G202: fixed SQL, values bound
	q := `WITH ranked AS (
			SELECT r.finding_id, r.priority_class, r.severity, r.sort_at, r.is_pentest, r.pentest_campaign_id,
			       row_number() OVER (ORDER BY ` + order + `) AS pos
			FROM dash_asset_rank r WHERE ` + b.sql() + `
		)
		SELECT f.id, f.title, k.severity, k.priority_class, f.asset_id, COALESCE(a.name, ''), k.sort_at, f.sla_deadline,
		       COALESCE(f.is_in_kev, false), k.is_pentest, k.pentest_campaign_id
		FROM ranked k
		JOIN findings f ON f.tenant_id = $1 AND f.id = k.finding_id AND ` + openFindingStatusClause + `
		LEFT JOIN assets a ON a.tenant_id = $1 AND a.id = f.asset_id
		ORDER BY k.pos LIMIT ` + lim
	rows, cancel, err := r.query(ctx, q, b.args)
	if err != nil {
		return nil, fmt.Errorf("read rank list: %w", err)
	}
	defer cancel()
	defer rows.Close()
	out := []dashboard.RankItem{}
	for rows.Next() {
		var it dashboard.RankItem
		var asset sql.NullString
		var sortAt, due sql.NullTime
		if err := rows.Scan(&it.FindingID, &it.Title, &it.Severity, &it.PriorityClass, &asset, &it.AssetName, &sortAt, &due, &it.KEV, &it.Pentest, &it.CampaignID); err != nil {
			return nil, fmt.Errorf("scan rank item: %w", err)
		}
		if asset.Valid {
			if id, perr := shared.IDFromString(asset.String); perr == nil {
				it.AssetID = &id
			}
		}
		if sortAt.Valid {
			it.SortAt = &sortAt.Time
		}
		if due.Valid {
			it.SLADeadline = &due.Time
		}
		out = append(out, it)
	}
	return out, rows.Err()
}

// CampaignsOf implements dashboard.FactReader.
func (r *DashboardWidgetRepository) CampaignsOf(ctx context.Context, tenantID, userID shared.ID) ([]shared.ID, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT campaign_id FROM pentest_campaign_members WHERE tenant_id = $1 AND user_id = $2`,
		tenantID.String(), userID.String())
	if err != nil {
		return nil, fmt.Errorf("list campaign memberships: %w", err)
	}
	defer rows.Close()
	var out []shared.ID
	for rows.Next() {
		var id shared.ID
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("scan campaign membership: %w", err)
		}
		out = append(out, id)
	}
	return out, rows.Err()
}
