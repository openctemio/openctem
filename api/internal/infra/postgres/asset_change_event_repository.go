package postgres

// Asset change timeline (RFC-069 §11,
// docs/architecture/asset-attribute-reconciliation.md). Events are written
// by AssetAttributeSourceRepository.Apply; this file reads them and applies
// retention.

import (
	"context"
	"database/sql"
	"fmt"
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
	var out []asset.ChangeEvent
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

// changeRetentionBatch bounds one retention delete; changeRetentionMaxBatches
// bounds one run (the next run continues).
const (
	changeRetentionBatch      = 5000
	changeRetentionMaxBatches = 100
)

// DeleteBefore deletes events older than cutoff in batches. Platform
// retention across every tenant, never driven by a tenant request; plain DML
// (the server runs no DDL).
func (r *AssetChangeEventRepository) DeleteBefore(ctx context.Context, cutoff time.Time) (int64, error) {
	var total int64
	for i := 0; i < changeRetentionMaxBatches; i++ {
		res, err := r.db.ExecContext(ctx, `
			DELETE FROM asset_change_events
			 WHERE (tenant_id, at, id) IN (
			       SELECT tenant_id, at, id FROM asset_change_events
			        WHERE at < $1
			        LIMIT $2)`, cutoff.UTC(), changeRetentionBatch)
		if err != nil {
			return total, fmt.Errorf("asset change retention: %w", err)
		}
		n, _ := res.RowsAffected()
		total += n
		if n < changeRetentionBatch {
			break
		}
	}
	// Set element records a source removed or stopped reporting before the
	// cutoff go with the events that could mention them.
	for i := 0; i < changeRetentionMaxBatches; i++ {
		res, err := r.db.ExecContext(ctx, `
			DELETE FROM asset_attribute_set_elements
			 WHERE ctid IN (
			       SELECT ctid FROM asset_attribute_set_elements
			        WHERE COALESCE(removed_at, last_seen) < $1
			        LIMIT $2)`, cutoff.UTC(), changeRetentionBatch)
		if err != nil {
			return total, fmt.Errorf("asset set element retention: %w", err)
		}
		n, _ := res.RowsAffected()
		total += n
		if n < changeRetentionBatch {
			break
		}
	}
	return total, nil
}

// AssetsWithAttributeSources returns up to limit ids of the tenant's assets
// that have a recorded source (of a value or a set element), after the id after (keyset), for bulk
// re-resolution.
func (r *AssetChangeEventRepository) AssetsWithAttributeSources(ctx context.Context, tenantID shared.ID, after *shared.ID, limit int) ([]shared.ID, error) {
	var cursor any // nil: from the start
	if after != nil {
		cursor = after.String()
	}
	rows, err := r.db.QueryContext(ctx, `
		SELECT asset_id FROM (
		       SELECT asset_id FROM asset_attribute_sources
		        WHERE tenant_id = $1 AND ($2::uuid IS NULL OR asset_id > $2::uuid)
		       UNION
		       SELECT asset_id FROM asset_attribute_set_elements
		        WHERE tenant_id = $1 AND ($2::uuid IS NULL OR asset_id > $2::uuid)
		       ) s
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
	rows, err := r.db.QueryContext(ctx, `SELECT tenant_id FROM asset_attribute_sources UNION SELECT tenant_id FROM asset_attribute_set_elements`)
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
