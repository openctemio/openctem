package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/webendpoint"
	"github.com/openctemio/openctem/api/pkg/filterspec"
	"github.com/openctemio/openctem/api/pkg/pagination"
)

// The grouped reads of the web surface (path patterns, origins with their
// coverage gap) and the change feed. Every query takes a WHERE compiled by
// filterspec for the caller: the tenant predicate first, then the caller's
// data scope on the origin asset.

var errUncompiledWebEventFilter = fmt.Errorf("web endpoint event filter was not compiled for a tenant")

func readTx(ctx context.Context, db *DB, timeout string) (*sql.Tx, error) {
	tx, err := db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, fmt.Errorf("begin read: %w", err)
	}
	if _, err := tx.ExecContext(ctx, "SET LOCAL statement_timeout = '"+timeout+"'"); err != nil {
		_ = tx.Rollback()
		return nil, fmt.Errorf("set statement timeout: %w", err)
	}
	return tx, nil
}

// PatternsWhere groups the filtered endpoints by path pattern (the
// host-less template hash), most widespread first.
func (r *WebEndpointRepository) PatternsWhere(ctx context.Context, w *filterspec.Where, page pagination.Pagination) (pagination.Result[*webendpoint.Pattern], error) {
	var empty pagination.Result[*webendpoint.Pattern]
	if err := checkWebEndpointWhere(w); err != nil {
		return empty, err
	}
	tx, err := readTx(ctx, r.db, webEndpointListTimeout)
	if err != nil {
		return empty, err
	}
	defer func() { _ = tx.Rollback() }()
	var total int64
	// w.SQL is a compiled filter (checked above): constants and placeholders.
	if err := tx.QueryRowContext(ctx, "SELECT COUNT(DISTINCT e.path_hash)"+webEndpointFrom+" WHERE "+w.SQL, w.Args...).Scan(&total); err != nil { //nolint:gosec // G202: compiled filter
		return empty, fmt.Errorf("count patterns: %w", err)
	}
	q := fmt.Sprintf( //nolint:gosec // G201: a compiled filter (constants and placeholders)
		`SELECT e.path_hash, min(e.path_template), array_agg(DISTINCT e.method ORDER BY e.method),
			count(*), count(DISTINCT e.origin_asset_id),
			count(*) FILTER (WHERE e.last_status BETWEEN 200 AND 299),
			count(*) FILTER (WHERE e.auth_state = 'none'),
			count(*) FILTER (WHERE NOT e.in_scope),
			COALESCE(max(e.catalog_key), ''), min(e.first_seen_at), max(e.last_seen_at)
		%s WHERE %s GROUP BY e.path_hash
		ORDER BY count(DISTINCT e.origin_asset_id) DESC, count(*) DESC, min(e.path_template) LIMIT %d OFFSET %d`,
		webEndpointFrom, w.SQL, page.Limit(), page.Offset())
	rows, err := tx.QueryContext(ctx, q, w.Args...)
	if err != nil {
		return empty, fmt.Errorf("list patterns: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := make([]*webendpoint.Pattern, 0, 100)
	for rows.Next() {
		p := &webendpoint.Pattern{}
		var methods pq.StringArray
		if err := rows.Scan(&p.PathHash, &p.PathTemplate, &methods, &p.EndpointCount, &p.OriginCount,
			&p.ReachableCount, &p.UnauthCount, &p.ExcludedUntested, &p.CatalogKey, &p.FirstSeenAt, &p.LastSeenAt); err != nil {
			return empty, fmt.Errorf("scan pattern: %w", err)
		}
		p.PathHash, p.Methods = strings.TrimSpace(p.PathHash), []string(methods)
		out = append(out, p)
	}
	if err := rows.Err(); err != nil {
		return empty, fmt.Errorf("list patterns: %w", err)
	}
	return pagination.NewResult(out, total, page), tx.Commit()
}

// OriginsWhere groups the filtered endpoints by origin asset, with the
// coverage gap: endpoints excluded-untested, the sensitive ones among them,
// and sensitive endpoints answering without authentication.
func (r *WebEndpointRepository) OriginsWhere(ctx context.Context, w *filterspec.Where, page pagination.Pagination) (pagination.Result[*webendpoint.Origin], error) {
	var empty pagination.Result[*webendpoint.Origin]
	if err := checkWebEndpointWhere(w); err != nil {
		return empty, err
	}
	tx, err := readTx(ctx, r.db, webEndpointListTimeout)
	if err != nil {
		return empty, err
	}
	defer func() { _ = tx.Rollback() }()
	var total int64
	if err := tx.QueryRowContext(ctx, "SELECT COUNT(DISTINCT e.origin_asset_id)"+webEndpointFrom+" WHERE "+w.SQL, w.Args...).Scan(&total); err != nil { //nolint:gosec // G202: compiled filter
		return empty, fmt.Errorf("count origins: %w", err)
	}
	q := fmt.Sprintf( //nolint:gosec // G201: a compiled filter (constants and placeholders)
		`SELECT e.origin_asset_id, min(a.name), count(*),
			count(*) FILTER (WHERE e.state = 'active'),
			count(*) FILTER (WHERE NOT e.in_scope),
			count(*) FILTER (WHERE NOT e.in_scope AND e.catalog_key IS NOT NULL),
			count(*) FILTER (WHERE e.catalog_key IS NOT NULL AND e.auth_state = 'none' AND e.last_status BETWEEN 200 AND 299),
			count(*) FILTER (WHERE e.first_seen_at > now() - interval '7 days'),
			max(e.last_seen_at)
		%s WHERE %s GROUP BY e.origin_asset_id
		ORDER BY count(*) FILTER (WHERE NOT e.in_scope AND e.catalog_key IS NOT NULL) DESC, count(*) DESC, min(a.name)
		LIMIT %d OFFSET %d`,
		webEndpointFrom, w.SQL, page.Limit(), page.Offset())
	rows, err := tx.QueryContext(ctx, q, w.Args...)
	if err != nil {
		return empty, fmt.Errorf("list origins: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := make([]*webendpoint.Origin, 0, 100)
	for rows.Next() {
		o := &webendpoint.Origin{}
		var id string
		if err := rows.Scan(&id, &o.Origin, &o.EndpointCount, &o.ActiveCount, &o.ExcludedUntested, &o.ExcludedSensitive,
			&o.UnauthSensitive, &o.NewLast7Days, &o.LastSeenAt); err != nil {
			return empty, fmt.Errorf("scan origin: %w", err)
		}
		o.OriginAssetID = shared.MustIDFromString(id)
		out = append(out, o)
	}
	if err := rows.Err(); err != nil {
		return empty, fmt.Errorf("list origins: %w", err)
	}
	return pagination.NewResult(out, total, page), tx.Commit()
}

const webEventFrom = ` FROM web_endpoint_events ev
	JOIN web_endpoints e ON e.id = ev.endpoint_id AND e.tenant_id = ev.tenant_id
	JOIN assets a ON a.id = ev.origin_asset_id AND a.tenant_id = ev.tenant_id AND a.deleted_at IS NULL`

// EventsWhere lists one page of the change feed.
func (r *WebEndpointRepository) EventsWhere(ctx context.Context, w *filterspec.Where, page pagination.Pagination) (pagination.Result[*webendpoint.Event], error) {
	var empty pagination.Result[*webendpoint.Event]
	if w == nil || !strings.HasPrefix(w.SQL, webendpoint.EventFields.TenantSQL+" = $") || w.OrderBy == "" {
		return empty, errUncompiledWebEventFilter
	}
	tx, err := readTx(ctx, r.db, webEndpointListTimeout)
	if err != nil {
		return empty, err
	}
	defer func() { _ = tx.Rollback() }()
	var total int64
	if err := tx.QueryRowContext(ctx, "SELECT COUNT(*)"+webEventFrom+" WHERE "+w.SQL, w.Args...).Scan(&total); err != nil { //nolint:gosec // G202: compiled filter
		return empty, fmt.Errorf("count events: %w", err)
	}
	q := fmt.Sprintf( //nolint:gosec // G201: a compiled filter (constants and placeholders)
		`SELECT ev.id, ev.endpoint_id, ev.origin_asset_id, a.name, e.method, e.path_template,
			COALESCE(e.catalog_key, ''), ev.kind, ev.at, ev.detail
		%s WHERE %s ORDER BY %s LIMIT %d OFFSET %d`,
		webEventFrom, w.SQL, w.OrderBy, page.Limit(), page.Offset())
	rows, err := tx.QueryContext(ctx, q, w.Args...)
	if err != nil {
		return empty, fmt.Errorf("list events: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := make([]*webendpoint.Event, 0, 100)
	for rows.Next() {
		ev := &webendpoint.Event{}
		var id, ep, origin string
		var detail []byte
		if err := rows.Scan(&id, &ep, &origin, &ev.Origin, &ev.Method, &ev.PathTemplate, &ev.CatalogKey, &ev.Kind, &ev.At, &detail); err != nil {
			return empty, fmt.Errorf("scan event: %w", err)
		}
		ev.ID, ev.EndpointID, ev.OriginAssetID = shared.MustIDFromString(id), shared.MustIDFromString(ep), shared.MustIDFromString(origin)
		ev.Detail = map[string]any{}
		_ = json.Unmarshal(detail, &ev.Detail)
		out = append(out, ev)
	}
	if err := rows.Err(); err != nil {
		return empty, fmt.Errorf("list events: %w", err)
	}
	return pagination.NewResult(out, total, page), tx.Commit()
}

// MarkGone marks active endpoints not seen since unseenSince as gone (every
// tenant: a platform job; each row keeps its tenant) and records a gone
// event for each, in batches of limit.
func (r *WebEndpointRepository) MarkGone(ctx context.Context, unseenSince time.Time, limit int) (int64, error) {
	var n int64
	err := r.db.QueryRowContext(ctx, `WITH gone AS (
			UPDATE web_endpoints SET state = 'gone'
			WHERE id IN (SELECT id FROM web_endpoints WHERE state = 'active' AND last_seen_at < $1 ORDER BY last_seen_at LIMIT $2)
			RETURNING id, tenant_id, origin_asset_id
		), ev AS (
			INSERT INTO web_endpoint_events (tenant_id, endpoint_id, origin_asset_id, kind)
			SELECT tenant_id, id, origin_asset_id, 'gone' FROM gone
		)
		SELECT count(*) FROM gone`, unseenSince, limit).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("mark endpoints gone: %w", err)
	}
	return n, nil
}

// PurgeGone deletes endpoints gone since before goneBefore (their params and
// events follow; findings are never touched).
func (r *WebEndpointRepository) PurgeGone(ctx context.Context, goneBefore time.Time, limit int) (int64, error) {
	res, err := r.db.ExecContext(ctx, `DELETE FROM web_endpoints
		WHERE id IN (SELECT id FROM web_endpoints WHERE state = 'gone' AND last_seen_at < $1 ORDER BY last_seen_at LIMIT $2)`,
		goneBefore, limit)
	if err != nil {
		return 0, fmt.Errorf("purge gone endpoints: %w", err)
	}
	n, _ := res.RowsAffected()
	return n, nil
}

// DeleteEventsBefore deletes change feed rows older than before.
func (r *WebEndpointRepository) DeleteEventsBefore(ctx context.Context, before time.Time, limit int) (int64, error) {
	res, err := r.db.ExecContext(ctx, `DELETE FROM web_endpoint_events
		WHERE id IN (SELECT id FROM web_endpoint_events WHERE at < $1 ORDER BY at LIMIT $2)`, before, limit)
	if err != nil {
		return 0, fmt.Errorf("delete old endpoint events: %w", err)
	}
	n, _ := res.RowsAffected()
	return n, nil
}

var (
	_ webendpoint.ViewReader     = (*WebEndpointRepository)(nil)
	_ webendpoint.RetentionStore = (*WebEndpointRepository)(nil)
)

// SelectEndpointURLs returns, per origin asset of the tenant, the URLs of
// its active, in-scope, non-script endpoints first seen (mode "new") or
// first seen or changed (mode "changed") at or after since, newest first,
// at most limit in all. A URL is the origin and the endpoint's example path
// with its masked segments filled by type placeholders, never a recorded
// value (webendpoint.FillTemplate).
func (r *WebEndpointRepository) SelectEndpointURLs(ctx context.Context, tenantID shared.ID, originAssetIDs []shared.ID,
	mode string, since time.Time, limit int,
) (map[shared.ID][]string, error) {
	out := map[shared.ID][]string{}
	if len(originAssetIDs) == 0 || limit <= 0 {
		return out, nil
	}
	ids := make([]string, len(originAssetIDs))
	for i, id := range originAssetIDs {
		ids[i] = id.String()
	}
	changed := mode == "changed"
	rows, err := r.db.QueryContext(ctx, `SELECT e.origin_asset_id, a.name, COALESCE(e.example_path, e.path_template)
		FROM web_endpoints e
		JOIN assets a ON a.id = e.origin_asset_id AND a.tenant_id = e.tenant_id AND a.deleted_at IS NULL
		WHERE e.tenant_id = $1 AND e.origin_asset_id = ANY($2::uuid[]) AND e.state = 'active' AND e.in_scope
			AND e.kind <> 'script'
			AND (e.first_seen_at >= $3 OR ($4 AND e.last_changed_at >= $3))
		ORDER BY e.first_seen_at DESC LIMIT $5`, tenantID.String(), pq.Array(ids), since, changed, limit)
	if err != nil {
		return nil, fmt.Errorf("select endpoints: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var origin, name, path string
		if err := rows.Scan(&origin, &name, &path); err != nil {
			return nil, fmt.Errorf("scan endpoint: %w", err)
		}
		id := shared.MustIDFromString(origin)
		out[id] = append(out[id], strings.TrimRight(name, "/")+webendpoint.FillTemplate(path))
	}
	return out, rows.Err()
}
