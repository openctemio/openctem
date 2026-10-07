package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/webendpoint"
	"github.com/openctemio/openctem/api/pkg/filterspec"
	"github.com/openctemio/openctem/api/pkg/pagination"
)

// The read side of the web surface sub-inventory: lists, stats and by-id
// reads compiled through the list query contract (RFC-048), so the tenant
// and the caller's data scope (on the origin asset) are always in the WHERE.

const (
	webEndpointListTimeout  = "3s"
	webEndpointStatsTimeout = "1500ms"
)

var errUncompiledWebEndpointFilter = errors.New("web endpoint filter was not compiled for a tenant")

// webEndpointFrom joins the live origin asset: an endpoint of a deleted
// origin is never listed.
const webEndpointFrom = ` FROM web_endpoints e
	JOIN assets a ON a.id = e.origin_asset_id AND a.tenant_id = e.tenant_id AND a.deleted_at IS NULL`

const webEndpointColumns = `e.id, e.tenant_id, e.origin_asset_id, a.name, e.method, e.path_template, e.template_hash,
	e.path_hash, e.kind, e.sources, COALESCE(e.example_path, ''), COALESCE(e.last_status, 0), COALESCE(e.content_type, ''),
	e.auth_state, e.technologies, e.labels, e.state, e.in_scope, COALESCE(e.catalog_key, ''), e.param_count,
	e.first_seen_at, e.last_seen_at, e.last_changed_at, COALESCE(e.last_tool, '')`

func checkWebEndpointWhere(w *filterspec.Where) error {
	if w == nil || !strings.HasPrefix(w.SQL, webendpoint.Fields.TenantSQL+" = $") || w.OrderBy == "" {
		return errUncompiledWebEndpointFilter
	}
	return nil
}

func scanWebEndpoint(s interface{ Scan(...any) error }) (*webendpoint.Endpoint, error) {
	var (
		e                    webendpoint.Endpoint
		id, tenant, origin   string
		sources, techs, labs pq.StringArray
		changed              sql.NullTime
		state                string
	)
	if err := s.Scan(&id, &tenant, &origin, &e.Origin, &e.Method, &e.PathTemplate, &e.TemplateHash,
		&e.PathHash, &e.Kind, &sources, &e.ExamplePath, &e.LastStatus, &e.ContentType,
		&e.AuthState, &techs, &labs, &state, &e.InScope, &e.CatalogKey, &e.ParamCount,
		&e.FirstSeenAt, &e.LastSeenAt, &changed, &e.LastTool); err != nil {
		return nil, err
	}
	e.ID, e.TenantID, e.OriginAssetID = shared.MustIDFromString(id), shared.MustIDFromString(tenant), shared.MustIDFromString(origin)
	e.TemplateHash, e.PathHash = strings.TrimSpace(e.TemplateHash), strings.TrimSpace(e.PathHash)
	e.Sources, e.Technologies, e.Labels = []string(sources), []string(techs), []string(labs)
	e.State = webendpoint.State(state)
	if changed.Valid {
		t := changed.Time
		e.LastChangedAt = &t
	}
	return &e, nil
}

// ListWhere lists one page of endpoints matching a compiled filter, with the
// total, in one read-only transaction with a statement timeout.
func (r *WebEndpointRepository) ListWhere(ctx context.Context, w *filterspec.Where, page pagination.Pagination) (pagination.Result[*webendpoint.Endpoint], error) {
	var empty pagination.Result[*webendpoint.Endpoint]
	if err := checkWebEndpointWhere(w); err != nil {
		return empty, err
	}
	tx, err := r.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return empty, fmt.Errorf("begin endpoint list: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, "SET LOCAL statement_timeout = '"+webEndpointListTimeout+"'"); err != nil {
		return empty, fmt.Errorf("set endpoint list timeout: %w", err)
	}
	var total int64
	if err := tx.QueryRowContext(ctx, "SELECT COUNT(*)"+webEndpointFrom+" WHERE "+w.SQL, w.Args...).Scan(&total); err != nil {
		return empty, fmt.Errorf("count endpoints: %w", err)
	}
	// w.SQL and w.OrderBy come from filterspec.Compile (checked above):
	// registry constants and bound placeholders only.
	q := fmt.Sprintf("SELECT %s%s WHERE %s ORDER BY %s LIMIT %d OFFSET %d", //nolint:gosec // G201: compiled filter
		webEndpointColumns, webEndpointFrom, w.SQL, w.OrderBy, page.Limit(), page.Offset())
	rows, err := tx.QueryContext(ctx, q, w.Args...)
	if err != nil {
		return empty, fmt.Errorf("list endpoints: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := make([]*webendpoint.Endpoint, 0, 100)
	for rows.Next() {
		e, err := scanWebEndpoint(rows)
		if err != nil {
			return empty, fmt.Errorf("scan endpoint: %w", err)
		}
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		return empty, fmt.Errorf("list endpoints: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return empty, fmt.Errorf("commit endpoint list: %w", err)
	}
	return pagination.NewResult(out, total, page), nil
}

// StatsWhere counts the endpoints of a compiled filter by method, kind, auth
// state and state, and those out of scope: the same WHERE as the list.
func (r *WebEndpointRepository) StatsWhere(ctx context.Context, w *filterspec.Where) (*webendpoint.Stats, error) {
	if err := checkWebEndpointWhere(w); err != nil {
		return nil, err
	}
	tx, err := r.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, fmt.Errorf("begin endpoint stats: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, "SET LOCAL statement_timeout = '"+webEndpointStatsTimeout+"'"); err != nil {
		return nil, fmt.Errorf("set endpoint stats timeout: %w", err)
	}
	// w.SQL comes from filterspec.Compile (checked above): registry
	// constants and bound placeholders only.
	q := `SELECT 'method', e.method, count(*)` + webEndpointFrom + ` WHERE ` + w.SQL + ` GROUP BY e.method` + //nolint:gosec // G202: compiled filter
		`
		UNION ALL SELECT 'kind', e.kind, count(*)` + webEndpointFrom + ` WHERE ` + w.SQL + ` GROUP BY e.kind
		UNION ALL SELECT 'auth_state', e.auth_state, count(*)` + webEndpointFrom + ` WHERE ` + w.SQL + ` GROUP BY e.auth_state
		UNION ALL SELECT 'state', e.state, count(*)` + webEndpointFrom + ` WHERE ` + w.SQL + ` GROUP BY e.state
		UNION ALL SELECT 'in_scope', e.in_scope::text, count(*)` + webEndpointFrom + ` WHERE ` + w.SQL + ` GROUP BY e.in_scope`
	rows, err := tx.QueryContext(ctx, q, w.Args...)
	if err != nil {
		return nil, fmt.Errorf("endpoint stats: %w", err)
	}
	defer func() { _ = rows.Close() }()
	st := &webendpoint.Stats{ByMethod: map[string]int64{}, ByKind: map[string]int64{}, ByAuthState: map[string]int64{}, ByState: map[string]int64{}}
	for rows.Next() {
		var dim, key string
		var n int64
		if err := rows.Scan(&dim, &key, &n); err != nil {
			return nil, fmt.Errorf("scan endpoint stats: %w", err)
		}
		switch dim {
		case "method":
			st.ByMethod[key] = n
			st.Total += n
		case "kind":
			st.ByKind[key] = n
		case "auth_state":
			st.ByAuthState[key] = n
		case "state":
			st.ByState[key] = n
		case "in_scope":
			if key == "false" {
				st.ExcludedUntested = n
			}
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("endpoint stats: %w", err)
	}
	return st, tx.Commit()
}

// Get returns one endpoint of the tenant (with a live origin), or
// shared.ErrNotFound.
func (r *WebEndpointRepository) Get(ctx context.Context, tenantID, id shared.ID) (*webendpoint.Endpoint, error) {
	row := r.db.QueryRowContext(ctx, "SELECT "+webEndpointColumns+webEndpointFrom+" WHERE e.tenant_id = $1 AND e.id = $2",
		tenantID.String(), id.String())
	e, err := scanWebEndpoint(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, shared.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get endpoint: %w", err)
	}
	return e, nil
}

// Params returns the parameters of one endpoint of the tenant, by location
// and name.
func (r *WebEndpointRepository) Params(ctx context.Context, tenantID, endpointID shared.ID) ([]webendpoint.Param, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT location, name, COALESCE(type_hint, ''), required, risk_hints,
			COALESCE(sensitive, ''), sources, first_seen_at, last_seen_at
		FROM web_endpoint_params WHERE tenant_id = $1 AND endpoint_id = $2 ORDER BY location, name LIMIT $3`,
		tenantID.String(), endpointID.String(), webendpoint.MaxParamsPerEndpoint)
	if err != nil {
		return nil, fmt.Errorf("list params: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := make([]webendpoint.Param, 0, 16)
	for rows.Next() {
		var p webendpoint.Param
		var risk, src pq.StringArray
		if err := rows.Scan(&p.Location, &p.Name, &p.TypeHint, &p.Required, &risk, &p.Sensitive, &src,
			&p.FirstSeenAt, &p.LastSeenAt); err != nil {
			return nil, fmt.Errorf("scan param: %w", err)
		}
		p.RiskHints, p.Sources = []string(risk), []string(src)
		out = append(out, p)
	}
	return out, rows.Err()
}

// Update sets an endpoint's state and/or labels. Only active and ignored are
// settable (gone is the platform's call).
func (r *WebEndpointRepository) Update(ctx context.Context, tenantID, id shared.ID, u webendpoint.Update) error {
	var state any
	if u.State != nil {
		state = string(*u.State)
	}
	var labels any
	if u.Labels != nil {
		labels = pq.Array(*u.Labels)
	}
	res, err := r.db.ExecContext(ctx, `UPDATE web_endpoints SET
			state = COALESCE($3, state),
			labels = COALESCE($4::text[], labels)
		WHERE tenant_id = $1 AND id = $2`, tenantID.String(), id.String(), state, labels)
	if err != nil {
		return fmt.Errorf("update endpoint: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return shared.ErrNotFound
	}
	return nil
}
