package postgres

// Open ports of assets (docs/architecture/asset-ports.md): the
// asset-ports worker drains asset_port_queue and rewrites asset_ports for
// the queued assets and the assets that depend on them. Every statement is
// pinned to one tenant.

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/server/pkg/domain/assetport"
)

// assetPortTimeout bounds one batch statement.
const assetPortTimeout = "30s"

// AssetPortRepository maintains asset_ports.
type AssetPortRepository struct {
	db *DB
}

// NewAssetPortRepository creates the repository.
func NewAssetPortRepository(db *DB) *AssetPortRepository {
	return &AssetPortRepository{db: db}
}

// ProcessQueue claims up to limit queued assets, oldest first, and rewrites
// the rows of them and their dependents in one transaction. SKIP LOCKED lets
// replicas run it side by side; a failure rolls the claim back.
func (r *AssetPortRepository) ProcessQueue(ctx context.Context, limit int) (assetport.QueueResult, error) {
	var res assetport.QueueResult
	if limit <= 0 {
		return res, nil
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return res, fmt.Errorf("begin asset ports batch: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, "SET LOCAL statement_timeout = '"+assetPortTimeout+"'"); err != nil {
		return res, fmt.Errorf("set asset ports timeout: %w", err)
	}
	byTenant, order, err := claimAssetPortQueue(ctx, tx, limit)
	if err != nil {
		return res, err
	}
	for _, ids := range byTenant {
		res.Claimed += len(ids)
	}
	for _, tid := range order {
		n, err := refreshAssetPorts(ctx, tx, tid, byTenant[tid])
		if err != nil {
			return res, err
		}
		res.Refreshed += n
	}
	if err := tx.Commit(); err != nil {
		return res, fmt.Errorf("commit asset ports batch: %w", err)
	}
	return res, nil
}

// claimAssetPortQueue removes up to limit queued assets, oldest first,
// grouped by tenant in claim order.
func claimAssetPortQueue(ctx context.Context, tx *sql.Tx, limit int) (map[string][]string, []string, error) {
	rows, err := tx.QueryContext(ctx, `
		DELETE FROM asset_port_queue q
		USING (SELECT asset_id FROM asset_port_queue ORDER BY enqueued_at LIMIT $1 FOR UPDATE SKIP LOCKED) due
		WHERE q.asset_id = due.asset_id
		RETURNING q.tenant_id::text, q.asset_id::text`, limit)
	if err != nil {
		return nil, nil, fmt.Errorf("claim asset ports queue: %w", err)
	}
	defer func() { _ = rows.Close() }()
	byTenant := map[string][]string{}
	var order []string
	for rows.Next() {
		var tid, aid string
		if err := rows.Scan(&tid, &aid); err != nil {
			return nil, nil, fmt.Errorf("scan asset ports queue: %w", err)
		}
		if _, ok := byTenant[tid]; !ok {
			order = append(order, tid)
		}
		byTenant[tid] = append(byTenant[tid], aid)
	}
	if err := rows.Err(); err != nil {
		return nil, nil, fmt.Errorf("iterate asset ports queue: %w", err)
	}
	return byTenant, order, nil
}

// QueueDepth is the number of queued assets.
func (r *AssetPortRepository) QueueDepth(ctx context.Context) (int64, error) {
	var n int64
	if err := r.db.QueryRowContext(ctx, "SELECT count(*) FROM asset_port_queue").Scan(&n); err != nil {
		return 0, fmt.Errorf("count asset ports queue: %w", err)
	}
	return n, nil
}

// assetPortSubjectsSQL is the assets whose rows a change of the claimed
// assets $2 of tenant $1 touches: the claimed assets, the addresses that
// expose a claimed port, and the names that resolve to any of those.
const assetPortSubjectsSQL = `
	WITH claimed AS (SELECT unnest($2::uuid[]) AS id),
	addr AS (
		SELECT id FROM claimed
		UNION
		SELECT e.source_asset_id FROM asset_relationships e JOIN claimed c ON e.target_asset_id = c.id
		 WHERE e.tenant_id = $1 AND e.relationship_type = 'exposes'
	),
	subj AS (
		SELECT id FROM addr
		UNION
		SELECT r.source_asset_id FROM asset_relationships r JOIN addr a ON r.target_asset_id = a.id
		 WHERE r.tenant_id = $1 AND r.relationship_type = 'resolves_to'
	)
	SELECT s.id::text FROM subj s JOIN assets x ON x.tenant_id = $1 AND x.id = s.id
	ORDER BY s.id`

// assetPortRowsSQL writes the rows of subjects $2 of tenant $1: an
// open_port service answers on its own port, the address that exposes it
// and every name resolving to that address answer on it too. Only live,
// active open ports with a valid port number count.
const assetPortRowsSQL = `
	INSERT INTO asset_ports (tenant_id, asset_id, port_asset_id, port, transport, service)
	SELECT $1, x.asset_id, p.id,
	       (p.properties ->> 'port')::int,
	       CASE WHEN lower(COALESCE(NULLIF(p.properties ->> 'transport', ''), p.properties ->> 'protocol', '')) IN ('tcp', 'udp', 'sctp')
	            THEN lower(COALESCE(NULLIF(p.properties ->> 'transport', ''), p.properties ->> 'protocol')) ELSE '' END,
	       left(lower(COALESCE(NULLIF(p.properties ->> 'service', ''), p.properties ->> 'name', '')), 64)
	FROM (
		SELECT s.id AS asset_id, s.id AS port_id FROM unnest($2::uuid[]) AS s(id)
		UNION
		SELECT e.source_asset_id, e.target_asset_id FROM asset_relationships e
		 WHERE e.tenant_id = $1 AND e.relationship_type = 'exposes' AND e.source_asset_id = ANY($2::uuid[])
		UNION
		SELECT r.source_asset_id, e.target_asset_id FROM asset_relationships r
		  JOIN asset_relationships e ON e.tenant_id = r.tenant_id AND e.source_asset_id = r.target_asset_id
		   AND e.relationship_type = 'exposes'
		 WHERE r.tenant_id = $1 AND r.relationship_type = 'resolves_to' AND r.source_asset_id = ANY($2::uuid[])
	) x
	JOIN assets p ON p.tenant_id = $1 AND p.id = x.port_id AND p.asset_type = 'service' AND p.sub_type = 'open_port'
	     AND p.deleted_at IS NULL AND p.status = 'active'
	JOIN assets o ON o.tenant_id = $1 AND o.id = x.asset_id AND o.deleted_at IS NULL
	WHERE COALESCE(p.properties ->> 'port', '') ~ '^[0-9]{1,5}$' AND (p.properties ->> 'port')::int <= 65535
	ON CONFLICT DO NOTHING`

// refreshAssetPorts rewrites the rows of the claimed assets of one tenant
// and of the assets that depend on them, in chunks of
// assetport.RefreshChunk assets.
func refreshAssetPorts(ctx context.Context, tx *sql.Tx, tenantID string, ids []string) (int, error) {
	subjects, err := assetPortSubjects(ctx, tx, tenantID, ids)
	if err != nil {
		return 0, err
	}
	for start := 0; start < len(subjects); start += assetport.RefreshChunk {
		chunk := subjects[start:min(start+assetport.RefreshChunk, len(subjects))]
		if _, err := tx.ExecContext(ctx, `DELETE FROM asset_ports WHERE tenant_id = $1 AND asset_id = ANY($2::uuid[])`,
			tenantID, pq.Array(chunk)); err != nil {
			return 0, fmt.Errorf("clear asset ports: %w", err)
		}
		if _, err := tx.ExecContext(ctx, assetPortRowsSQL, tenantID, pq.Array(chunk)); err != nil {
			return 0, fmt.Errorf("write asset ports: %w", err)
		}
	}
	return len(subjects), nil
}

// assetPortSubjects lists the assets whose rows a change of ids touches.
func assetPortSubjects(ctx context.Context, tx *sql.Tx, tenantID string, ids []string) ([]string, error) {
	rows, err := tx.QueryContext(ctx, assetPortSubjectsSQL, tenantID, pq.Array(ids))
	if err != nil {
		return nil, fmt.Errorf("asset ports subjects: %w", err)
	}
	defer func() { _ = rows.Close() }()
	subjects := make([]string, 0, len(ids))
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("scan asset ports subject: %w", err)
		}
		subjects = append(subjects, id)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("asset ports subjects: %w", err)
	}
	return subjects, nil
}
