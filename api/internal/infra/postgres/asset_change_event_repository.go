package postgres

// Asset change timeline (RFC-069 §11,
// docs/architecture/asset-attribute-reconciliation.md). Events are written
// by AssetAttributeSourceRepository.Apply; this file reads them and keeps
// the monthly partitions and retention.

import (
	"context"
	"database/sql"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// AssetChangeEventRepository implements asset.ChangeEventRepository and
// asset.ChangeTimelineMaintainer.
type AssetChangeEventRepository struct {
	db *DB
}

// NewAssetChangeEventRepository creates the repository.
func NewAssetChangeEventRepository(db *DB) *AssetChangeEventRepository {
	return &AssetChangeEventRepository{db: db}
}

var (
	_ asset.ChangeEventRepository    = (*AssetChangeEventRepository)(nil)
	_ asset.ChangeTimelineMaintainer = (*AssetChangeEventRepository)(nil)
)

// ListChanges returns a page of the tenant's timeline, newest first. With
// q.AssetID it is one asset's timeline; without, the organization feed,
// narrowed to q.ScopeUserID's assets when set.
func (r *AssetChangeEventRepository) ListChanges(ctx context.Context, tenantID shared.ID, q asset.ChangeQuery) ([]asset.ChangeEvent, bool, error) {
	limit := q.Limit
	if limit <= 0 || limit > asset.MaxChangePageSize {
		limit = 50
	}
	args := []any{tenantID.String()}
	arg := func(v any) string {
		args = append(args, v)
		return fmt.Sprintf("$%d", len(args))
	}
	where := []string{"e.tenant_id = $1", "a.tenant_id = $1"}
	if q.AssetID != nil {
		where = append(where, "e.asset_id = "+arg(q.AssetID.String()))
	}
	if len(q.Attributes) > 0 {
		where = append(where, "e.attribute = ANY("+arg(pq.Array(q.Attributes))+"::text[])")
	}
	if len(q.SourceKinds) > 0 {
		kinds := make([]string, 0, len(q.SourceKinds))
		for _, k := range q.SourceKinds {
			kinds = append(kinds, string(k))
		}
		where = append(where, "e.source_kind = ANY("+arg(pq.Array(kinds))+"::text[])")
	}
	if q.SourceName != "" {
		where = append(where, "e.source_name = "+arg(q.SourceName))
	}
	if q.Tag != "" {
		where = append(where, arg(q.Tag)+" = ANY(a.tags)")
	}
	if q.ScopeUserID != nil {
		where = append(where, "e.asset_id IN (SELECT asset_id FROM user_accessible_assets WHERE tenant_id = $1 AND user_id = "+
			arg(q.ScopeUserID.String())+")")
	}
	if q.BeforeAt != nil && q.BeforeID != nil {
		where = append(where, "(e.at, e.id) < ("+arg(q.BeforeAt.UTC())+"::timestamptz, "+arg(q.BeforeID.String())+"::uuid)")
	}
	query := `
		SELECT e.id, e.asset_id, e.at, e.attribute, e.old_value, e.new_value, e.added, e.removed,
		       e.source_kind, e.source_name, e.source_run, e.actor_id, e.reason, e.flap_count, e.created_at,
		       a.name, a.asset_type
		  FROM asset_change_events e
		  JOIN assets a ON a.tenant_id = e.tenant_id AND a.id = e.asset_id
		 WHERE ` + strings.Join(where, " AND ") + `
		 ORDER BY e.at DESC, e.id DESC
		 LIMIT ` + arg(limit+1)
	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, false, fmt.Errorf("list asset changes: %w", err)
	}
	defer rows.Close()
	out := make([]asset.ChangeEvent, 0, limit)
	for rows.Next() {
		var (
			id, assetID, kind, reason string
			actor                     sql.NullString
			added, removed            pq.StringArray
			ev                        asset.ChangeEvent
		)
		if err := rows.Scan(&id, &assetID, &ev.At, &ev.Attribute, &ev.Old, &ev.New, &added, &removed,
			&kind, &ev.SourceName, &ev.SourceRun, &actor, &reason, &ev.FlapCount, &ev.CreatedAt,
			&ev.AssetName, &ev.AssetType); err != nil {
			return nil, false, fmt.Errorf("list asset changes: %w", err)
		}
		if ev.ID, err = shared.IDFromString(id); err != nil {
			return nil, false, fmt.Errorf("list asset changes: %w", err)
		}
		if ev.AssetID, err = shared.IDFromString(assetID); err != nil {
			return nil, false, fmt.Errorf("list asset changes: %w", err)
		}
		if actor.Valid {
			if a, perr := shared.IDFromString(actor.String); perr == nil {
				ev.ActorID = &a
			}
		}
		ev.TenantID = tenantID
		ev.SourceKind = asset.SourceKind(kind)
		ev.Reason = asset.ChangeReason(reason)
		ev.Added, ev.Removed = added, removed
		out = append(out, ev)
	}
	if err := rows.Err(); err != nil {
		return nil, false, fmt.Errorf("list asset changes: %w", err)
	}
	more := len(out) > limit
	if more {
		out = out[:limit]
	}
	return out, more, nil
}

// EnsurePartitions creates the monthly partitions from the month of from.
func (r *AssetChangeEventRepository) EnsurePartitions(ctx context.Context, from time.Time, months int) (int, error) {
	var n int
	if err := r.db.QueryRowContext(ctx, `SELECT asset_change_events_ensure_partitions($1::date, $2)`,
		from.UTC().Format("2006-01-02"), months).Scan(&n); err != nil {
		return 0, fmt.Errorf("ensure asset change partitions: %w", err)
	}
	return n, nil
}

// changePartitionName matches the monthly partitions the ensure function
// creates; nothing else is ever dropped.
var changePartitionName = regexp.MustCompile(`^asset_change_events_(\d{4})_(\d{2})$`)

// DropBefore drops the monthly partitions that end at or before cutoff and
// deletes older rows from the default partition. Platform retention across
// every tenant; never driven by a tenant request.
func (r *AssetChangeEventRepository) DropBefore(ctx context.Context, cutoff time.Time) (int, int64, error) {
	drop, err := r.expiredPartitions(ctx, cutoff)
	if err != nil {
		return 0, 0, err
	}
	for _, name := range drop {
		if _, err := r.db.ExecContext(ctx, `DROP TABLE IF EXISTS `+pq.QuoteIdentifier(name)); err != nil {
			return 0, 0, fmt.Errorf("drop asset change partition %s: %w", name, err)
		}
	}
	res, err := r.db.ExecContext(ctx, `DELETE FROM asset_change_events_default WHERE at < $1`, cutoff.UTC())
	if err != nil {
		return len(drop), 0, fmt.Errorf("asset change retention: %w", err)
	}
	n, _ := res.RowsAffected()
	return len(drop), n, nil
}

// expiredPartitions lists the monthly partitions that end at or before cutoff.
func (r *AssetChangeEventRepository) expiredPartitions(ctx context.Context, cutoff time.Time) ([]string, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT c.relname
		  FROM pg_inherits i
		  JOIN pg_class c ON c.oid = i.inhrelid
		 WHERE i.inhparent = 'asset_change_events'::regclass`)
	if err != nil {
		return nil, fmt.Errorf("list asset change partitions: %w", err)
	}
	defer rows.Close()
	var drop []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, fmt.Errorf("list asset change partitions: %w", err)
		}
		m := changePartitionName.FindStringSubmatch(name)
		if m == nil {
			continue
		}
		start, perr := time.Parse("2006-01", m[1]+"-"+m[2])
		if perr != nil {
			continue
		}
		if !start.AddDate(0, 1, 0).After(cutoff) {
			drop = append(drop, name)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list asset change partitions: %w", err)
	}
	return drop, nil
}

// AssetsWithAttributeSources returns up to limit ids of the tenant's assets
// that have a recorded source, after the id after (keyset), for bulk
// re-resolution.
func (r *AssetChangeEventRepository) AssetsWithAttributeSources(ctx context.Context, tenantID shared.ID, after *shared.ID, limit int) ([]shared.ID, error) {
	var cursor any // nil: from the start
	if after != nil {
		cursor = after.String()
	}
	rows, err := r.db.QueryContext(ctx, `
		SELECT DISTINCT asset_id FROM asset_attribute_sources
		 WHERE tenant_id = $1 AND ($2::uuid IS NULL OR asset_id > $2::uuid)
		 ORDER BY asset_id
		 LIMIT $3`, tenantID.String(), cursor, limit)
	if err != nil {
		return nil, fmt.Errorf("assets with attribute sources: %w", err)
	}
	defer rows.Close()
	var out []shared.ID
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			return nil, fmt.Errorf("assets with attribute sources: %w", err)
		}
		id, err := shared.IDFromString(s)
		if err != nil {
			return nil, fmt.Errorf("assets with attribute sources: %w", err)
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// TenantsWithAttributeSources lists the tenants that have a recorded source.
func (r *AssetChangeEventRepository) TenantsWithAttributeSources(ctx context.Context) ([]shared.ID, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT DISTINCT tenant_id FROM asset_attribute_sources`)
	if err != nil {
		return nil, fmt.Errorf("tenants with attribute sources: %w", err)
	}
	defer rows.Close()
	var out []shared.ID
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			return nil, fmt.Errorf("tenants with attribute sources: %w", err)
		}
		id, err := shared.IDFromString(s)
		if err != nil {
			return nil, fmt.Errorf("tenants with attribute sources: %w", err)
		}
		out = append(out, id)
	}
	return out, rows.Err()
}
