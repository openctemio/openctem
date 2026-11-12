package postgres

// Typed attack-surface changes and the weekly digest claim
// (docs/rfcs/RFC-080-attack-surface-changes-and-digest.md). Changes are read
// from the records the platform already keeps; nothing is written twice.

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/pkg/domain/easmchange"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/webendpoint"
)

// EASMChangeRepository reads typed changes and claims weekly digests.
type EASMChangeRepository struct {
	db *DB
}

// NewEASMChangeRepository creates the repository.
func NewEASMChangeRepository(db *DB) *EASMChangeRepository {
	return &EASMChangeRepository{db: db}
}

// easmChangeSkippedExposureTypes are exposure types that are not a change of
// their own: the asset they describe already appears as host_added /
// port_opened (or its removal), or the type announces something going away.
var easmChangeSkippedExposureTypes = []string{
	"port_open", "port_closed", "service_detected", "subdomain_discovered", "subdomain_removed",
	"bucket_private", "repo_private", "api_removed",
}

// webChangeHighKeys and webChangeCriticalKeys are the catalog keys whose
// severity is high or critical, for the web change kinds.
var webChangeHighKeys, webChangeCriticalKeys = webendpoint.KeysBySeverity()

// changeAssetFilter keeps an asset that is part of the external surface (a
// surface type, or anything internet-facing), not deleted, and in the
// attributed inventory (not discovered without a claim, not waiting for
// review, not rejected).
func changeAssetFilter(ctx context.Context, alias string) string {
	return fmt.Sprintf(` AND %[1]s.deleted_at IS NULL AND (%[1]s.asset_type = ANY($4) OR %[1]s.exposure = 'public')`, alias) +
		MetricsInventorySQL(ctx, alias+".id")
}

// changeUnion is the typed change feed: $1 tenant, $2 from, $3 to, $4 the
// surface types, $5 the skipped exposure types. Every branch is
// tenant-scoped on its own table and on the joined asset.
func changeUnion(ctx context.Context) string {
	surface := changeAssetFilter(ctx, "a")
	return `
	SELECT h.id::text AS id, h.changed_at AS at, h.asset_id AS asset_id, a.name AS asset_name, a.asset_type AS asset_type,
	       CASE WHEN h.change_type IN ('appeared', 'recovered') THEN
	                 CASE a.asset_type WHEN 'certificate' THEN 'cert_changed' WHEN 'service' THEN 'port_opened' ELSE 'host_added' END
	            ELSE CASE a.asset_type WHEN 'service' THEN 'port_closed' ELSE 'host_removed' END
	       END AS kind,
	       h.change_type::text AS detail, ''::text AS old_value, ''::text AS new_value,
	       NULL::text[] AS added, NULL::text[] AS removed, ''::text AS severity, NULL::uuid AS exposure_id
	FROM asset_state_history h
	JOIN assets a ON a.id = h.asset_id AND a.tenant_id = h.tenant_id
	WHERE h.tenant_id = $1 AND h.changed_at >= $2 AND h.changed_at < $3
	  AND h.change_type IN ('appeared', 'recovered', 'disappeared')
	  AND NOT (h.change_type = 'disappeared' AND a.asset_type = 'certificate')` + surface + `
	UNION ALL
	SELECT e.id::text, e.at, e.asset_id, a.name, a.asset_type,
	       CASE e.attribute WHEN 'ip_addresses' THEN 'dns_changed' ELSE 'tech_changed' END,
	       e.attribute, e.old_value, e.new_value, e.added, e.removed, '', NULL::uuid
	FROM asset_change_events e
	JOIN assets a ON a.id = e.asset_id AND a.tenant_id = e.tenant_id
	WHERE e.tenant_id = $1 AND e.at >= $2 AND e.at < $3
	  AND e.attribute IN ('ip_addresses', 'technologies')` + surface + `
	UNION ALL
	SELECT e.id::text, e.at, e.asset_id, a.name, a.asset_type, 'port_opened',
	       e.attribute, '', '', e.added, NULL::text[], '', NULL::uuid
	FROM asset_change_events e
	JOIN assets a ON a.id = e.asset_id AND a.tenant_id = e.tenant_id
	WHERE e.tenant_id = $1 AND e.at >= $2 AND e.at < $3
	  AND e.attribute = 'open_ports' AND COALESCE(cardinality(e.added), 0) > 0` + surface + `
	UNION ALL
	SELECT e.id::text, e.at, e.asset_id, a.name, a.asset_type, 'port_closed',
	       e.attribute, '', '', NULL::text[], e.removed, '', NULL::uuid
	FROM asset_change_events e
	JOIN assets a ON a.id = e.asset_id AND a.tenant_id = e.tenant_id
	WHERE e.tenant_id = $1 AND e.at >= $2 AND e.at < $3
	  AND e.attribute = 'open_ports' AND COALESCE(cardinality(e.removed), 0) > 0` + surface + `
	UNION ALL
	SELECT x.id::text, x.first_seen_at, x.asset_id, COALESCE(a.name, ''), COALESCE(a.asset_type, ''),
	       CASE WHEN x.event_type IN ('dangling_cname', 'dangling_ns', 'subdomain_takeover') THEN 'dns_dangling'
	            WHEN x.event_type IN ('certificate_expiring', 'certificate_expired') THEN 'cert_expiring'
	            WHEN x.event_type = 'dns_change' THEN 'dns_changed'
	            ELSE 'exposure_new' END,
	       x.event_type, '', x.title, NULL::text[], NULL::text[], x.severity, x.id
	FROM exposure_events x
	LEFT JOIN assets a ON a.id = x.asset_id AND a.tenant_id = x.tenant_id
	WHERE x.tenant_id = $1 AND x.first_seen_at >= $2 AND x.first_seen_at < $3
	  AND x.state <> 'false_positive' AND NOT (x.event_type = ANY($5))
	  AND (x.asset_id IS NULL OR (a.id IS NOT NULL AND a.deleted_at IS NULL))` + notRejectedFor("x.asset_id") + `
	UNION ALL` + webChangeBranches(ctx)
}

// webChangeBranches reads the web endpoint feed (web_endpoint_events) as
// three kinds. $6 holds the catalog keys of severity high or critical, $7
// the critical ones. Only in-scope, active endpoints count: an endpoint
// under a path exclusion is stored for visibility and never reported as a
// change. The origin asset is joined tenant-scoped and passes the same
// surface filter as every other branch.
func webChangeBranches(ctx context.Context) string {
	surface := changeAssetFilter(ctx, "a")
	const base = `
	FROM web_endpoint_events ev
	JOIN web_endpoints we ON we.tenant_id = ev.tenant_id AND we.id = ev.endpoint_id
	JOIN assets a ON a.id = ev.origin_asset_id AND a.tenant_id = ev.tenant_id
	WHERE ev.tenant_id = $1 AND ev.at >= $2 AND ev.at < $3
	  AND we.in_scope AND we.state = 'active'`
	return `
	SELECT ev.id::text, ev.at, ev.origin_asset_id, a.name, a.asset_type, 'web_sensitive_new',
	       we.method || ' ' || we.path_template, '', we.path_template, NULL::text[], NULL::text[],
	       CASE WHEN we.catalog_key = ANY($7) THEN 'critical' WHEN we.catalog_key = ANY($6) THEN 'high' ELSE 'medium' END,
	       NULL::uuid` + base + `
	  AND ev.kind IN ('appeared', 'returned')
	  AND (we.catalog_key = ANY($6) OR EXISTS (SELECT 1 FROM unnest(we.labels) l WHERE l LIKE 'panel:%'))` + surface + `
	UNION ALL
	SELECT ev.id::text, ev.at, ev.origin_asset_id, a.name, a.asset_type, 'web_auth_lost',
	       we.method || ' ' || we.path_template, ev.detail->>'from', ev.detail->>'to', NULL::text[], NULL::text[],
	       'high', NULL::uuid` + base + `
	  AND ev.kind = 'auth_changed' AND ev.detail->>'to' = 'none' AND ev.detail->>'from' IN ('required', 'redirect_login')
	  AND (we.catalog_key IS NOT NULL OR we.kind IN ('api', 'graphql'))` + surface + `
	UNION ALL
	SELECT ev.id::text, ev.at, ev.origin_asset_id, a.name, a.asset_type, 'web_param_added_sensitive',
	       we.method || ' ' || we.path_template, '', we.path_template, NULL::text[], NULL::text[],
	       CASE WHEN we.catalog_key = ANY($7) THEN 'high' ELSE 'medium' END, NULL::uuid` + base + `
	  AND ev.kind = 'param_added'
	  AND (we.catalog_key = ANY($6) OR EXISTS (SELECT 1 FROM web_endpoint_params p
	         WHERE p.tenant_id = ev.tenant_id AND p.endpoint_id = ev.endpoint_id AND p.sensitive = 'credential'
	           AND p.first_seen_at BETWEEN ev.at - interval '1 second' AND ev.at + interval '1 second'))` + surface
}

// changeCursor is the keyset position of the last row of a page.
type changeCursor struct {
	At   time.Time `json:"a"`
	ID   string    `json:"i"`
	Kind string    `json:"k"`
}

func encodeChangeCursor(c changeCursor) string {
	b, _ := json.Marshal(c)
	return base64.RawURLEncoding.EncodeToString(b)
}

func decodeChangeCursor(s string) (changeCursor, error) {
	var c changeCursor
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil || json.Unmarshal(b, &c) != nil || c.At.IsZero() || c.ID == "" {
		return c, fmt.Errorf("%w: bad cursor", easmchange.ErrInvalidQuery)
	}
	return c, nil
}

func (r *EASMChangeRepository) baseArgs(tenantID shared.ID, q easmchange.Query) []any {
	return []any{tenantID.String(), q.From, q.To, pq.Array(EASMSurfaceTypes), pq.Array(easmChangeSkippedExposureTypes),
		pq.Array(webChangeHighKeys), pq.Array(webChangeCriticalKeys)}
}

// ListChanges returns one page of typed changes in [q.From, q.To), newest
// first, narrowed to the data scope (nil = unrestricted), plus the count of
// every kind in the window.
func (r *EASMChangeRepository) ListChanges(ctx context.Context, tenantID shared.ID, scope *shared.DataScope, q easmchange.Query) (*easmchange.Page, error) {
	counts, total, err := r.CountChanges(ctx, tenantID, scope, q.From, q.To)
	if err != nil {
		return nil, err
	}
	args := r.baseArgs(tenantID, q)
	sc, args := scopeClause("c.asset_id", scope, args)
	where := []string{"TRUE"}
	if len(q.Kinds) > 0 {
		kinds := make([]string, 0, len(q.Kinds))
		for _, k := range q.Kinds {
			kinds = append(kinds, string(k))
		}
		args = append(args, pq.Array(kinds))
		where = append(where, fmt.Sprintf("c.kind = ANY($%d)", len(args)))
	}
	if q.Cursor != "" {
		cur, err := decodeChangeCursor(q.Cursor)
		if err != nil {
			return nil, err
		}
		args = append(args, cur.At, cur.ID, cur.Kind)
		n := len(args)
		where = append(where, fmt.Sprintf("(c.at, c.id, c.kind) < ($%d, $%d, $%d)", n-2, n-1, n))
	}
	args = append(args, q.Limit+1)
	query := `SELECT c.id, c.at, c.asset_id, c.asset_name, c.asset_type, c.kind, c.detail, c.old_value, c.new_value,
	                 c.added, c.removed, c.severity, c.exposure_id
	          FROM (` + changeUnion(ctx) + `) c
	          WHERE ` + strings.Join(where, " AND ") + sc + `
	          ORDER BY c.at DESC, c.id DESC, c.kind DESC
	          LIMIT $` + fmt.Sprint(len(args))
	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("easm changes: %w", err)
	}
	defer rows.Close()
	page := &easmchange.Page{From: q.From, To: q.To, Counts: counts, Total: total, Items: []easmchange.Change{}}
	for rows.Next() {
		var c easmchange.Change
		var assetID, exposureID sql.NullString
		var kind string
		var added, removed pq.StringArray
		if err := rows.Scan(&c.ID, &c.At, &assetID, &c.AssetName, &c.AssetType, &kind, &c.Detail, &c.Old, &c.New,
			&added, &removed, &c.Severity, &exposureID); err != nil {
			return nil, fmt.Errorf("easm changes scan: %w", err)
		}
		c.Kind = easmchange.Kind(kind)
		c.Added, c.Removed = added, removed
		if assetID.Valid {
			c.AssetID = &assetID.String
		}
		if exposureID.Valid {
			c.ExposureID = &exposureID.String
		}
		page.Items = append(page.Items, c)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(page.Items) > q.Limit {
		last := page.Items[q.Limit-1]
		page.Items = page.Items[:q.Limit]
		page.NextCursor = encodeChangeCursor(changeCursor{At: last.At, ID: last.ID, Kind: string(last.Kind)})
	}
	return page, nil
}

// CountChanges counts the typed changes in [from, to) by kind.
func (r *EASMChangeRepository) CountChanges(ctx context.Context, tenantID shared.ID, scope *shared.DataScope, from, to time.Time) (map[easmchange.Kind]int, int, error) {
	args := r.baseArgs(tenantID, easmchange.Query{From: from, To: to})
	sc, args := scopeClause("c.asset_id", scope, args)
	rows, err := r.db.QueryContext(ctx, `SELECT c.kind, count(*) FROM (`+changeUnion(ctx)+`) c WHERE TRUE`+sc+` GROUP BY c.kind`, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("easm change counts: %w", err)
	}
	defer rows.Close()
	counts := map[easmchange.Kind]int{}
	for _, k := range easmchange.AllKinds() {
		counts[k] = 0
	}
	total := 0
	for rows.Next() {
		var k string
		var n int
		if err := rows.Scan(&k, &n); err != nil {
			return nil, 0, err
		}
		counts[easmchange.Kind(k)] = n
		total += n
	}
	return counts, total, rows.Err()
}

// ClaimDigest records the digest of one slot for the tenant. It reports
// false when the slot was already claimed (another replica, or an earlier
// tick), and then nothing must be sent.
func (r *EASMChangeRepository) ClaimDigest(ctx context.Context, tenantID shared.ID, slot, from time.Time, counts map[easmchange.Kind]int, total int) (bool, error) {
	b, err := json.Marshal(counts)
	if err != nil {
		return false, err
	}
	res, err := r.db.ExecContext(ctx, `
		INSERT INTO easm_weekly_digests (tenant_id, slot, window_from, total, counts)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (tenant_id, slot) DO NOTHING`, tenantID.String(), slot, from, total, b)
	if err != nil {
		return false, fmt.Errorf("claim easm digest: %w", err)
	}
	n, err := res.RowsAffected()
	return n == 1, err
}

// ReleaseDigest gives a claimed slot back so the next tick retries it (the
// digest could not be delivered).
func (r *EASMChangeRepository) ReleaseDigest(ctx context.Context, tenantID shared.ID, slot time.Time) error {
	_, err := r.db.ExecContext(ctx, `DELETE FROM easm_weekly_digests WHERE tenant_id = $1 AND slot = $2`, tenantID.String(), slot)
	return err
}

// LastDigestAt returns when the tenant's latest digest was recorded.
func (r *EASMChangeRepository) LastDigestAt(ctx context.Context, tenantID shared.ID) (*time.Time, error) {
	var t sql.NullTime
	if err := r.db.QueryRowContext(ctx, `SELECT max(sent_at) FROM easm_weekly_digests WHERE tenant_id = $1`, tenantID.String()).Scan(&t); err != nil {
		return nil, fmt.Errorf("last easm digest: %w", err)
	}
	return nullTimeValue(t), nil
}
