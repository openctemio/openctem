package postgres

// Web page monitoring storage (docs/rfcs/RFC-137-web-page-monitoring.md).
// Every statement names the tenant; list reads add the caller's data scope
// on the watch's asset.

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/lib/pq"

	pagemonapp "github.com/openctemio/openctem/api/internal/app/pagemon"
	"github.com/openctemio/openctem/api/pkg/domain/pagemon"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// PageMonitorRepository stores watches, snapshots and changes.
type PageMonitorRepository struct {
	db *DB
}

// NewPageMonitorRepository creates the repository.
func NewPageMonitorRepository(db *DB) *PageMonitorRepository {
	return &PageMonitorRepository{db: db}
}

var _ pagemonapp.Store = (*PageMonitorRepository)(nil)

const watchColumns = `w.id, w.tenant_id, w.asset_id, COALESCE(a.name, ''), w.parent_id, w.url, w.mode, w.source, w.enabled,
	w.cadence_hours, w.ignore_patterns, w.dynamic, w.change_streak, w.state, COALESCE(w.last_error, ''), w.next_due_at,
	w.last_fetched_at, COALESCE(w.last_status, 0), w.last_changed_at, w.created_by, w.created_at, w.updated_at,
	(SELECT count(*) FROM web_changes c WHERE c.tenant_id = w.tenant_id AND c.watch_id = w.id),
	COALESCE((SELECT jsonb_array_length(s.scripts) FROM web_snapshots s WHERE s.tenant_id = w.tenant_id AND s.watch_id = w.id
		ORDER BY s.fetched_at DESC LIMIT 1), 0)`

const watchFrom = ` FROM web_watches w LEFT JOIN assets a ON a.tenant_id = w.tenant_id AND a.id = w.asset_id`

func scanWatch(r rowScanner) (pagemon.Watch, error) {
	var w pagemon.Watch
	var parent, createdBy sql.NullString
	var mode, src, state string
	var patterns pq.StringArray
	err := r.Scan(&w.ID, &w.TenantID, &w.AssetID, &w.AssetName, &parent, &w.URL, &mode, &src, &w.Enabled,
		&w.CadenceHours, &patterns, &w.Dynamic, &w.ChangeStreak, &state, &w.LastError, &w.NextDueAt,
		&w.LastFetchedAt, &w.LastStatus, &w.LastChangedAt, &createdBy, &w.CreatedAt, &w.UpdatedAt,
		&w.Changes, &w.Scripts)
	if err != nil {
		return w, err
	}
	w.Mode, w.Source, w.State = pagemon.Mode(mode), pagemon.Source(src), pagemon.State(state)
	w.IgnorePatterns = []string(patterns)
	if w.IgnorePatterns == nil {
		w.IgnorePatterns = []string{}
	}
	if parent.Valid {
		if id, perr := shared.IDFromString(parent.String); perr == nil {
			w.ParentID = &id
		}
	}
	if createdBy.Valid {
		if id, perr := shared.IDFromString(createdBy.String); perr == nil {
			w.CreatedBy = &id
		}
	}
	return w, nil
}

func (r *PageMonitorRepository) queryWatches(ctx context.Context, q string, args ...any) ([]pagemon.Watch, error) {
	rows, err := r.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("list watches: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := []pagemon.Watch{}
	for rows.Next() {
		w, err := scanWatch(rows)
		if err != nil {
			return nil, fmt.Errorf("scan watch: %w", err)
		}
		out = append(out, w)
	}
	return out, rows.Err()
}

// ListWatches returns the tenant's watches in the scope, pages first.
func (r *PageMonitorRepository) ListWatches(ctx context.Context, tenantID shared.ID, scope *shared.DataScope) ([]pagemon.Watch, error) {
	cond, args := dataScopeCond("w.asset_id", scope, []any{tenantID.String()})
	return r.queryWatches(ctx, `SELECT `+watchColumns+watchFrom+`
		WHERE w.tenant_id = $1 AND `+cond+`
		ORDER BY COALESCE(w.parent_id, w.id), w.parent_id NULLS FIRST, w.url
		LIMIT `+strconv.Itoa(pagemon.MaxWatchesPerTenant+pagemon.MaxDerivedPerPage), args...)
}

// GetWatch returns one watch (shared.ErrNotFound otherwise).
func (r *PageMonitorRepository) GetWatch(ctx context.Context, tenantID, id shared.ID) (*pagemon.Watch, error) {
	w, err := scanWatch(r.db.QueryRowContext(ctx, `SELECT `+watchColumns+watchFrom+` WHERE w.tenant_id = $1 AND w.id = $2`,
		tenantID.String(), id.String()))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, shared.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get watch: %w", err)
	}
	return &w, nil
}

// CountWatches counts the tenant's watches.
func (r *PageMonitorRepository) CountWatches(ctx context.Context, tenantID shared.ID) (int, error) {
	var n int
	err := r.db.QueryRowContext(ctx, `SELECT count(*) FROM web_watches WHERE tenant_id = $1`, tenantID.String()).Scan(&n)
	return n, err
}

func pmNullID(id *shared.ID) any {
	if id == nil {
		return nil
	}
	return id.String()
}

// CreateWatch inserts a watch (shared.ErrConflict when the URL is watched).
func (r *PageMonitorRepository) CreateWatch(ctx context.Context, w *pagemon.Watch) error {
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO web_watches (id, tenant_id, asset_id, parent_id, url, mode, source, enabled, cadence_hours,
			ignore_patterns, state, next_due_at, created_by, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $14)`,
		w.ID.String(), w.TenantID.String(), w.AssetID.String(), pmNullID(w.ParentID), w.URL, string(w.Mode), string(w.Source),
		w.Enabled, w.CadenceHours, pq.StringArray(w.IgnorePatterns), string(w.State), w.NextDueAt, pmNullID(w.CreatedBy), w.CreatedAt)
	if isUniqueViolation(err) {
		return fmt.Errorf("%w: this URL is watched already", shared.ErrConflict)
	}
	if err != nil {
		return fmt.Errorf("create watch: %w", err)
	}
	return nil
}

// UpdateWatch writes a watch's settings and URL.
func (r *PageMonitorRepository) UpdateWatch(ctx context.Context, w *pagemon.Watch) error {
	res, err := r.db.ExecContext(ctx, `
		UPDATE web_watches SET url = $3, mode = $4, enabled = $5, cadence_hours = $6, ignore_patterns = $7,
			dynamic = $8, change_streak = $9, next_due_at = $10, updated_at = $11
		WHERE tenant_id = $1 AND id = $2`,
		w.TenantID.String(), w.ID.String(), w.URL, string(w.Mode), w.Enabled, w.CadenceHours, pq.StringArray(w.IgnorePatterns),
		w.Dynamic, w.ChangeStreak, w.NextDueAt, w.UpdatedAt)
	if isUniqueViolation(err) {
		return fmt.Errorf("%w: this URL is watched already", shared.ErrConflict)
	}
	if err != nil {
		return fmt.Errorf("update watch: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return shared.ErrNotFound
	}
	return nil
}

// DeleteWatch deletes a watch with its derived watches, snapshots and changes.
func (r *PageMonitorRepository) DeleteWatch(ctx context.Context, tenantID, id shared.ID) error {
	res, err := r.db.ExecContext(ctx, `DELETE FROM web_watches WHERE tenant_id = $1 AND id = $2`, tenantID.String(), id.String())
	if err != nil {
		return fmt.Errorf("delete watch: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return shared.ErrNotFound
	}
	return nil
}

// ListChildren returns a page's derived script watches.
func (r *PageMonitorRepository) ListChildren(ctx context.Context, tenantID, parentID shared.ID) ([]pagemon.Watch, error) {
	return r.queryWatches(ctx, `SELECT `+watchColumns+watchFrom+` WHERE w.tenant_id = $1 AND w.parent_id = $2 ORDER BY w.url LIMIT 100`,
		tenantID.String(), parentID.String())
}

// OriginAsset returns the live http_service asset with the stored name.
func (r *PageMonitorRepository) OriginAsset(ctx context.Context, tenantID shared.ID, originName string) (shared.ID, error) {
	var id shared.ID
	err := r.db.QueryRowContext(ctx, `
		SELECT id FROM assets
		WHERE tenant_id = $1 AND asset_type = 'service' AND sub_type = 'http' AND name = $2 AND deleted_at IS NULL
		LIMIT 1`, tenantID.String(), originName).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return shared.ID{}, shared.ErrNotFound
	}
	return id, err
}

// EnabledWatchesByURL returns the tenant's enabled watches of the URLs.
func (r *PageMonitorRepository) EnabledWatchesByURL(ctx context.Context, tenantID shared.ID, urls []string) (map[string]pagemon.Watch, error) {
	ws, err := r.queryWatches(ctx, `SELECT `+watchColumns+watchFrom+` WHERE w.tenant_id = $1 AND w.enabled AND w.url = ANY($2)`,
		tenantID.String(), pq.StringArray(urls))
	if err != nil {
		return nil, err
	}
	out := make(map[string]pagemon.Watch, len(ws))
	for _, w := range ws {
		out[w.URL] = w
	}
	return out, nil
}

// LatestSnapshot returns a watch's newest snapshot, nil when it has none.
func (r *PageMonitorRepository) LatestSnapshot(ctx context.Context, tenantID, watchID shared.ID) (*pagemon.Snapshot, error) {
	var s pagemon.Snapshot
	var ct, fu, bh, tool sql.NullString
	var status sql.NullInt64
	var kind string
	var scripts, urls, text []byte
	err := r.db.QueryRowContext(ctx, `
		SELECT id, fetched_at, status_code, content_type, final_url, size, body_sha256, content_hash, kind, truncated,
			scripts, urls, text_lines, tool
		FROM web_snapshots WHERE tenant_id = $1 AND watch_id = $2 ORDER BY fetched_at DESC, created_at DESC LIMIT 1`,
		tenantID.String(), watchID.String()).Scan(&s.ID, &s.FetchedAt, &status, &ct, &fu, &s.Size, &bh, &s.ContentHash, &kind,
		&s.Truncated, &scripts, &urls, &text, &tool)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("latest snapshot: %w", err)
	}
	s.StatusCode, s.ContentType, s.FinalURL = int(status.Int64), ct.String, fu.String
	s.BodySHA256, s.Kind, s.Tool = strings.TrimSpace(bh.String), pagemon.Kind(kind), tool.String
	s.ContentHash = strings.TrimSpace(s.ContentHash)
	if err := json.Unmarshal(scripts, &s.Scripts); err != nil {
		return nil, fmt.Errorf("snapshot scripts: %w", err)
	}
	if err := json.Unmarshal(urls, &s.URLs); err != nil {
		return nil, fmt.Errorf("snapshot urls: %w", err)
	}
	if err := json.Unmarshal(text, &s.Text); err != nil {
		return nil, fmt.Errorf("snapshot text: %w", err)
	}
	return &s, nil
}

func pmNullStr(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func pmJSON(v any, empty string) ([]byte, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	if string(b) == "null" {
		return []byte(empty), nil
	}
	return b, nil
}

// SaveFetch writes one fetch's outcome in one transaction: the snapshot and
// change when there are, the watch's state and times, and the snapshot
// retention.
func (r *PageMonitorRepository) SaveFetch(ctx context.Context, tenantID shared.ID, o pagemon.FetchOutcome) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	tid, wid := tenantID.String(), o.WatchID.String()
	if o.Failed {
		_, err = tx.ExecContext(ctx, `
			UPDATE web_watches SET state = 'failed', last_error = $3, last_fetched_at = $4, last_status = $5, updated_at = now()
			WHERE tenant_id = $1 AND id = $2`, tid, wid, "the URL answered with status "+strconv.Itoa(o.Status), o.FetchedAt, o.Status)
		if err != nil {
			return fmt.Errorf("save failed fetch: %w", err)
		}
		return tx.Commit()
	}
	if s := o.Snapshot; s != nil {
		scripts, err := pmJSON(s.Scripts, "[]")
		if err != nil {
			return err
		}
		urls, err := pmJSON(s.URLs, "[]")
		if err != nil {
			return err
		}
		text, err := pmJSON(s.Text, "[]")
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO web_snapshots (id, tenant_id, watch_id, fetched_at, status_code, content_type, final_url, size,
				body_sha256, content_hash, kind, truncated, scripts, urls, text_lines, tool)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)`,
			s.ID.String(), tid, wid, s.FetchedAt, s.StatusCode, pmNullStr(s.ContentType), pmNullStr(s.FinalURL), s.Size,
			pmNullStr(s.BodySHA256), s.ContentHash, string(s.Kind), s.Truncated, scripts, urls, text, pmNullStr(s.Tool)); err != nil {
			return fmt.Errorf("insert snapshot: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `
			DELETE FROM web_snapshots WHERE tenant_id = $1 AND watch_id = $2 AND id NOT IN (
				SELECT id FROM web_snapshots WHERE tenant_id = $1 AND watch_id = $2 ORDER BY fetched_at DESC, created_at DESC LIMIT $3)`,
			tid, wid, pagemon.SnapshotsKept); err != nil {
			return fmt.Errorf("prune snapshots: %w", err)
		}
	}
	var changedAt any
	if c := o.Change; c != nil {
		sum, err := json.Marshal(c.Summary)
		if err != nil {
			return err
		}
		diff, err := json.Marshal(o.Diff)
		if err != nil {
			return err
		}
		var to any
		if o.Snapshot != nil {
			to = o.Snapshot.ID.String()
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO web_changes (id, tenant_id, watch_id, asset_id, detected_at, severity, muted, summary, diff, to_snapshot_id)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
			c.ID.String(), tid, wid, c.AssetID.String(), c.DetectedAt, string(c.Severity), c.Muted, sum, diff, to); err != nil {
			return fmt.Errorf("insert change: %w", err)
		}
		changedAt = c.DetectedAt
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE web_watches SET state = 'ok', last_error = NULL, last_fetched_at = $3, last_status = $4,
			change_streak = $5, dynamic = $6, last_changed_at = COALESCE($7, last_changed_at), updated_at = now()
		WHERE tenant_id = $1 AND id = $2`, tid, wid, o.FetchedAt, o.Status, min(o.ChangeStreak, 1000), o.Dynamic, changedAt); err != nil {
		return fmt.Errorf("update watch: %w", err)
	}
	return tx.Commit()
}

// KnownHosts returns which hosts are live domain or subdomain assets of the tenant.
func (r *PageMonitorRepository) KnownHosts(ctx context.Context, tenantID shared.ID, hosts []string) (map[string]bool, error) {
	out := map[string]bool{}
	if len(hosts) == 0 {
		return out, nil
	}
	rows, err := r.db.QueryContext(ctx, `
		SELECT name FROM assets
		WHERE tenant_id = $1 AND asset_type IN ('domain', 'subdomain') AND name = ANY($2) AND deleted_at IS NULL`,
		tenantID.String(), pq.StringArray(hosts))
	if err != nil {
		return nil, fmt.Errorf("known hosts: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			return nil, err
		}
		out[n] = true
	}
	return out, rows.Err()
}

// TenantsWithDueWatches returns the tenants with an enabled watch due by now.
func (r *PageMonitorRepository) TenantsWithDueWatches(ctx context.Context, now time.Time) ([]shared.ID, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT DISTINCT tenant_id FROM web_watches WHERE enabled AND next_due_at <= $1 LIMIT 5000`, now)
	if err != nil {
		return nil, fmt.Errorf("due tenants: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []shared.ID
	for rows.Next() {
		var id shared.ID
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// DueWatches returns the tenant's enabled watches due by now, oldest first.
func (r *PageMonitorRepository) DueWatches(ctx context.Context, tenantID shared.ID, now time.Time, limit int) ([]pagemon.Watch, error) {
	return r.queryWatches(ctx, `SELECT `+watchColumns+watchFrom+`
		WHERE w.tenant_id = $1 AND w.enabled AND w.next_due_at <= $2
		ORDER BY w.next_due_at, w.id LIMIT $3`, tenantID.String(), now, limit)
}

func pmIDs(ids []shared.ID) pq.StringArray {
	out := make(pq.StringArray, 0, len(ids))
	for _, id := range ids {
		out = append(out, id.String())
	}
	return out
}

// MarkDispatched records that the watches were handed to a run; each is due
// again after its cadence.
func (r *PageMonitorRepository) MarkDispatched(ctx context.Context, tenantID shared.ID, ids []shared.ID, runID *shared.ID, now time.Time) error {
	_, err := r.db.ExecContext(ctx, `
		UPDATE web_watches SET last_dispatched_at = $3::timestamptz, last_run_id = $4,
			next_due_at = $3::timestamptz + make_interval(hours => cadence_hours),
			state = CASE WHEN state IN ('blocked', 'waiting') THEN 'pending' ELSE state END,
			last_error = CASE WHEN state IN ('blocked', 'waiting') THEN NULL ELSE last_error END
		WHERE tenant_id = $1 AND id = ANY($2)`, tenantID.String(), pmIDs(ids), now, pmNullID(runID))
	if err != nil {
		return fmt.Errorf("mark dispatched: %w", err)
	}
	return nil
}

// MarkHeld records why watches were not dispatched; they are due again at retryAt.
func (r *PageMonitorRepository) MarkHeld(ctx context.Context, tenantID shared.ID, reasons map[shared.ID]string, state pagemon.State, retryAt time.Time) error {
	if len(reasons) == 0 {
		return nil
	}
	ids := make([]string, 0, len(reasons))
	msgs := make([]string, 0, len(reasons))
	for id, m := range reasons {
		ids = append(ids, id.String())
		if len(m) > 300 {
			m = m[:300]
		}
		msgs = append(msgs, m)
	}
	_, err := r.db.ExecContext(ctx, `
		UPDATE web_watches w SET state = $3, last_error = v.msg, next_due_at = $4, updated_at = now()
		FROM unnest($2::uuid[], $5::text[]) AS v(id, msg)
		WHERE w.tenant_id = $1 AND w.id = v.id`, tenantID.String(), pq.StringArray(ids), string(state), retryAt, pq.StringArray(msgs))
	if err != nil {
		return fmt.Errorf("mark held: %w", err)
	}
	return nil
}

const changeColumns = `c.id, c.watch_id, c.asset_id, w.url, w.parent_id, COALESCE(p.url, ''), c.detected_at, c.severity, c.muted, c.summary`

const changeFrom = ` FROM web_changes c
	JOIN web_watches w ON w.tenant_id = c.tenant_id AND w.id = c.watch_id
	LEFT JOIN web_watches p ON p.tenant_id = w.tenant_id AND p.id = w.parent_id`

func scanChange(r rowScanner, withDiff bool) (pagemon.Change, error) {
	var c pagemon.Change
	var parent sql.NullString
	var sev string
	var sum, diff []byte
	dest := []any{&c.ID, &c.WatchID, &c.AssetID, &c.URL, &parent, &c.ParentURL, &c.DetectedAt, &sev, &c.Muted, &sum}
	if withDiff {
		dest = append(dest, &diff)
	}
	if err := r.Scan(dest...); err != nil {
		return c, err
	}
	c.Severity = pagemon.Severity(sev)
	if parent.Valid {
		if id, err := shared.IDFromString(parent.String); err == nil {
			c.ParentID = &id
		}
	}
	if err := json.Unmarshal(sum, &c.Summary); err != nil {
		return c, err
	}
	if withDiff {
		var d pagemon.Diff
		if err := json.Unmarshal(diff, &d); err != nil {
			return c, err
		}
		c.Diff = &d
	}
	return c, nil
}

// severitiesFrom lists the severities at or above min.
func severitiesFrom(minSev pagemon.Severity) []string {
	all := []pagemon.Severity{pagemon.SeverityInfo, pagemon.SeverityLow, pagemon.SeverityMedium, pagemon.SeverityHigh}
	out := make([]string, 0, len(all))
	for _, s := range all {
		if s.AtLeast(minSev) {
			out = append(out, string(s))
		}
	}
	return out
}

// ListChanges returns the tenant's changes in the scope, newest first, with the total.
func (r *PageMonitorRepository) ListChanges(ctx context.Context, tenantID shared.ID, scope *shared.DataScope, f pagemon.ChangeFilter) ([]pagemon.Change, int, error) {
	args := []any{tenantID.String()}
	where := []string{"c.tenant_id = $1"}
	if f.WatchID != nil {
		args = append(args, f.WatchID.String())
		where = append(where, "(c.watch_id = $"+strconv.Itoa(len(args))+" OR w.parent_id = $"+strconv.Itoa(len(args))+")")
	}
	if f.MinSeverity != "" {
		args = append(args, pq.StringArray(severitiesFrom(f.MinSeverity)))
		where = append(where, "c.severity = ANY($"+strconv.Itoa(len(args))+")")
	}
	if !f.IncludeMute {
		where = append(where, "NOT c.muted")
	}
	if f.Since != nil {
		args = append(args, *f.Since)
		where = append(where, "c.detected_at >= $"+strconv.Itoa(len(args)))
	}
	cond, args := dataScopeCond("c.asset_id", scope, args)
	where = append(where, cond)
	clause := " WHERE " + strings.Join(where, " AND ")
	var total int
	if err := r.db.QueryRowContext(ctx, `SELECT count(*)`+changeFrom+clause, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count changes: %w", err)
	}
	args = append(args, f.Limit, f.Offset)
	rows, err := r.db.QueryContext(ctx, `SELECT `+changeColumns+changeFrom+clause+
		` ORDER BY c.detected_at DESC, c.id LIMIT $`+strconv.Itoa(len(args)-1)+` OFFSET $`+strconv.Itoa(len(args)), args...)
	if err != nil {
		return nil, 0, fmt.Errorf("list changes: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := []pagemon.Change{}
	for rows.Next() {
		c, err := scanChange(rows, false)
		if err != nil {
			return nil, 0, fmt.Errorf("scan change: %w", err)
		}
		out = append(out, c)
	}
	return out, total, rows.Err()
}

// GetChange returns one change with its diff (shared.ErrNotFound outside the tenant or scope).
func (r *PageMonitorRepository) GetChange(ctx context.Context, tenantID shared.ID, scope *shared.DataScope, id shared.ID) (*pagemon.Change, error) {
	cond, args := dataScopeCond("c.asset_id", scope, []any{tenantID.String(), id.String()})
	c, err := scanChange(r.db.QueryRowContext(ctx, `SELECT `+changeColumns+`, c.diff`+changeFrom+
		` WHERE c.tenant_id = $1 AND c.id = $2 AND `+cond, args...), true)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, shared.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get change: %w", err)
	}
	return &c, nil
}

// SuggestionCandidates returns origins in the scope (their root page) and
// their login, admin and script endpoints that no watch covers yet.
func (r *PageMonitorRepository) SuggestionCandidates(ctx context.Context, tenantID shared.ID, scope *shared.DataScope, limit int) ([]pagemonapp.SuggestionCandidate, error) {
	cond, args := dataScopeCond("a.id", scope, []any{tenantID.String()})
	args = append(args, limit)
	lim := "$" + strconv.Itoa(len(args))
	q := `
		WITH origins AS (
			SELECT a.id, a.name FROM assets a
			WHERE a.tenant_id = $1 AND a.asset_type = 'service' AND a.sub_type = 'http' AND a.deleted_at IS NULL AND ` + cond + `
			ORDER BY a.last_seen DESC NULLS LAST LIMIT 200
		), cands AS (
			SELECT o.id, o.name, '/' AS path, 'root' AS kind, '{}'::text[] AS labels, '' AS catalog_key, 0 AS rank FROM origins o
			UNION ALL
			SELECT o.id, o.name, e.path_template, e.kind, e.labels, COALESCE(e.catalog_key, ''),
				CASE WHEN 'auth:login' = ANY(e.labels) THEN 1 WHEN e.catalog_key IS NOT NULL THEN 2 ELSE 3 END
			FROM origins o JOIN web_endpoints e ON e.tenant_id = $1 AND e.origin_asset_id = o.id
			WHERE e.state = 'active' AND e.method = 'GET'
			  AND (e.kind = 'script' OR 'auth:login' = ANY(e.labels) OR e.catalog_key IS NOT NULL)
		)
		SELECT c.id, c.name, c.path, c.kind, c.labels, c.catalog_key FROM cands c
		WHERE NOT EXISTS (SELECT 1 FROM web_watches w WHERE w.tenant_id = $1 AND w.asset_id = c.id
			AND (w.url = rtrim(c.name, '/') || c.path))
		ORDER BY c.rank, c.name, c.path LIMIT ` + lim
	rows, err := r.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("suggestions: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []pagemonapp.SuggestionCandidate
	for rows.Next() {
		var c pagemonapp.SuggestionCandidate
		var labels pq.StringArray
		if err := rows.Scan(&c.AssetID, &c.AssetName, &c.Path, &c.Kind, &labels, &c.CatalogKey); err != nil {
			return nil, err
		}
		c.Labels = labels
		out = append(out, c)
	}
	return out, rows.Err()
}

// DeleteChangesBefore deletes changes older than before (every tenant: retention).
func (r *PageMonitorRepository) DeleteChangesBefore(ctx context.Context, before time.Time) (int64, error) {
	res, err := r.db.ExecContext(ctx, `DELETE FROM web_changes WHERE id IN (SELECT id FROM web_changes WHERE detected_at < $1 LIMIT 5000)`, before)
	if err != nil {
		return 0, fmt.Errorf("delete old changes: %w", err)
	}
	return res.RowsAffected()
}
