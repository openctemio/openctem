package postgres

// Domain membership of assets (docs/architecture/asset-domain-membership.md):
// drains asset_domain_queue, which triggers fill on every asset and edge
// change, and rewrites asset_domain_memberships for the queued assets and the
// assets that depend on them. The rules live in pkg/domain/assetdomain; this
// file only loads their evidence and stores the keys. Every read is pinned to
// the queued asset's tenant on both sides of an edge.

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/pkg/domain/assetdomain"
	"github.com/openctemio/openctem/api/pkg/domain/edgeaddr"
)

const (
	// assetDomainTimeout bounds one batch.
	assetDomainTimeout = "60s"
	// maxDomainRefresh caps the assets one tenant's batch rewrites, queued
	// ones and dependents together; the rest go back to the queue.
	maxDomainRefresh = 5000
	// maxResolversPerAddress caps the names read for one address (an address
	// that many names resolve to is shared hosting long before the cap).
	maxResolversPerAddress = 1000
)

// assetDomainProps are the property keys assetdomain reads.
var assetDomainProps = pq.StringArray{"hostname", "fqdn", "subject_cn", "sans", "san", "url", "base_url", "host", "dns_name", "endpoint", "cdn", "asn_org"}

// AssetDomainMembershipRepository maintains asset_domain_memberships.
type AssetDomainMembershipRepository struct {
	db         *DB
	classifier *edgeaddr.Classifier
}

// NewAssetDomainMembershipRepository creates the repository with the built-in
// edge address classifier.
func NewAssetDomainMembershipRepository(db *DB) *AssetDomainMembershipRepository {
	return &AssetDomainMembershipRepository{db: db, classifier: edgeaddr.Default()}
}

// ProcessQueue claims up to limit queued assets, oldest first, and rewrites
// the membership of them and their dependents in one transaction. SKIP
// LOCKED lets replicas run it side by side; a failure rolls the claim back.
func (r *AssetDomainMembershipRepository) ProcessQueue(ctx context.Context, limit int) (assetdomain.QueueResult, error) {
	var res assetdomain.QueueResult
	if limit <= 0 {
		return res, nil
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return res, fmt.Errorf("begin asset domain batch: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, "SET LOCAL statement_timeout = '"+assetDomainTimeout+"'"); err != nil {
		return res, fmt.Errorf("set asset domain timeout: %w", err)
	}
	byTenant, order, err := claimDomainQueue(ctx, tx, limit)
	if err != nil {
		return res, err
	}
	for _, ids := range byTenant {
		res.Claimed += len(ids)
	}
	for _, tid := range order {
		n, deferred, err := r.refreshTenant(ctx, tx, tid, byTenant[tid])
		if err != nil {
			return res, err
		}
		res.Refreshed += n
		res.Deferred += deferred
	}
	if err := tx.Commit(); err != nil {
		return res, fmt.Errorf("commit asset domain batch: %w", err)
	}
	return res, nil
}

// claimDomainQueue removes up to limit queued assets, oldest first, grouped
// by tenant in claim order.
func claimDomainQueue(ctx context.Context, tx *sql.Tx, limit int) (map[string][]string, []string, error) {
	rows, err := tx.QueryContext(ctx, `
		DELETE FROM asset_domain_queue q
		USING (SELECT asset_id FROM asset_domain_queue ORDER BY enqueued_at LIMIT $1 FOR UPDATE SKIP LOCKED) due
		WHERE q.asset_id = due.asset_id
		RETURNING q.tenant_id::text, q.asset_id::text`, limit)
	if err != nil {
		return nil, nil, fmt.Errorf("claim asset domain queue: %w", err)
	}
	defer func() { _ = rows.Close() }()
	byTenant := map[string][]string{}
	order := []string{}
	for rows.Next() {
		var tid, aid string
		if err := rows.Scan(&tid, &aid); err != nil {
			return nil, nil, fmt.Errorf("scan asset domain queue: %w", err)
		}
		if _, ok := byTenant[tid]; !ok {
			order = append(order, tid)
		}
		byTenant[tid] = append(byTenant[tid], aid)
	}
	if err := rows.Err(); err != nil {
		return nil, nil, fmt.Errorf("iterate asset domain queue: %w", err)
	}
	return byTenant, order, nil
}

// QueueDepth is the number of queued assets.
func (r *AssetDomainMembershipRepository) QueueDepth(ctx context.Context) (int64, error) {
	var n int64
	if err := r.db.QueryRowContext(ctx, "SELECT count(*) FROM asset_domain_queue").Scan(&n); err != nil {
		return 0, fmt.Errorf("count asset domain queue: %w", err)
	}
	return n, nil
}

// refreshTenant rewrites the membership of ids and their dependents in one
// tenant. It returns the assets rewritten and the dependents queued again
// because the batch was full.
func (r *AssetDomainMembershipRepository) refreshTenant(ctx context.Context, tx *sql.Tx, tenantID string, ids []string) (int, int, error) {
	set, deferred, err := r.withDependents(ctx, tx, tenantID, ids)
	if err != nil {
		return 0, 0, err
	}
	assets, err := loadDomainEvidence(ctx, tx, tenantID, set)
	if err != nil {
		return 0, 0, err
	}
	hostsOf, err := domainHosts(ctx, tx, tenantID, set)
	if err != nil {
		return 0, 0, err
	}
	var hostIDs []string
	for _, hs := range hostsOf {
		for _, h := range hs {
			if _, ok := assets[h]; !ok {
				hostIDs = append(hostIDs, h)
			}
		}
	}
	hosts, err := loadDomainEvidence(ctx, tx, tenantID, hostIDs)
	if err != nil {
		return 0, 0, err
	}
	for id, e := range assets {
		hosts[id] = e
	}
	resolvers, err := domainResolvers(ctx, tx, tenantID, keysOf(hosts))
	if err != nil {
		return 0, 0, err
	}
	assetCol := make([]string, 0, len(set)*2)
	keyCol := make([]string, 0, len(set)*2)
	for _, id := range set {
		e, ok := assets[id]
		if !ok || e.deleted {
			continue
		}
		ev := e.ev
		ev.Resolvers = resolvers[id]
		for _, h := range hostsOf[id] {
			if he, ok := hosts[h]; ok && !he.deleted {
				hev := he.ev
				hev.Resolvers = resolvers[h]
				ev.Hosts = append(ev.Hosts, hev)
			}
		}
		for _, k := range assetdomain.Keys(assetdomain.Names(ev, r.classifier)) {
			assetCol = append(assetCol, id)
			keyCol = append(keyCol, k)
		}
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM asset_domain_memberships WHERE tenant_id = $1 AND asset_id = ANY($2::uuid[])`,
		tenantID, pq.StringArray(set)); err != nil {
		return 0, 0, fmt.Errorf("clear asset domain memberships: %w", err)
	}
	if len(keyCol) > 0 {
		// The join keeps an id that is not the tenant's asset out.
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO asset_domain_memberships (tenant_id, asset_id, key)
			SELECT a.tenant_id, a.id, m.key
			FROM unnest($2::uuid[], $3::text[]) AS m(asset_id, key)
			JOIN assets a ON a.tenant_id = $1 AND a.id = m.asset_id
			ON CONFLICT DO NOTHING`, tenantID, pq.StringArray(assetCol), pq.StringArray(keyCol)); err != nil {
			return 0, 0, fmt.Errorf("write asset domain memberships: %w", err)
		}
	}
	return len(set), deferred, nil
}

// withDependents adds the assets whose membership reads the given ones, two
// edge hops out (a name, the addresses it resolves to, the services on
// them). Above maxDomainRefresh the extra dependents are queued for a later
// batch instead of dropped.
func (r *AssetDomainMembershipRepository) withDependents(ctx context.Context, tx *sql.Tx, tenantID string, ids []string) ([]string, int, error) {
	seen := make(map[string]bool, len(ids))
	set := make([]string, 0, len(ids))
	for _, id := range ids {
		if !seen[id] {
			seen[id] = true
			set = append(set, id)
		}
	}
	var overflow []string
	frontier := set
	for hop := 0; hop < 2 && len(frontier) > 0; hop++ {
		found, err := domainDependents(ctx, tx, tenantID, frontier)
		if err != nil {
			return nil, 0, err
		}
		var next []string
		for _, id := range found {
			if seen[id] {
				continue
			}
			seen[id] = true
			if len(set) >= maxDomainRefresh {
				overflow = append(overflow, id)
				continue
			}
			set = append(set, id)
			next = append(next, id)
		}
		frontier = next
	}
	if len(overflow) > 0 {
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO asset_domain_queue (asset_id, tenant_id)
			SELECT a.id, a.tenant_id FROM assets a WHERE a.tenant_id = $1 AND a.id = ANY($2::uuid[])
			ORDER BY a.id
			ON CONFLICT (asset_id) DO NOTHING`, tenantID, pq.StringArray(overflow)); err != nil {
			return nil, 0, fmt.Errorf("queue asset domain overflow: %w", err)
		}
	}
	return set, len(overflow), nil
}

// domainDependents are the assets one edge out whose membership reads ids:
// the targets of their resolves_to and exposes edges, the sources of
// runs_on edges to them.
func domainDependents(ctx context.Context, tx *sql.Tx, tenantID string, ids []string) ([]string, error) {
	rows, err := tx.QueryContext(ctx, `
		SELECT r.target_asset_id::text FROM asset_relationships r
		WHERE r.tenant_id = $1 AND r.source_asset_id = ANY($2::uuid[]) AND r.relationship_type IN ('resolves_to', 'exposes')
		UNION
		SELECT r.source_asset_id::text FROM asset_relationships r
		WHERE r.tenant_id = $1 AND r.target_asset_id = ANY($2::uuid[]) AND r.relationship_type = 'runs_on'`,
		tenantID, pq.StringArray(ids))
	if err != nil {
		return nil, fmt.Errorf("load asset domain dependents: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("scan asset domain dependent: %w", err)
		}
		out = append(out, id)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate asset domain dependents: %w", err)
	}
	return out, nil
}

type domainAsset struct {
	ev      assetdomain.Evidence
	deleted bool
}

// loadDomainEvidence reads the tenant's assets among ids, with only the
// name-bearing property keys.
func loadDomainEvidence(ctx context.Context, tx *sql.Tx, tenantID string, ids []string) (map[string]domainAsset, error) {
	out := make(map[string]domainAsset, len(ids))
	if len(ids) == 0 {
		return out, nil
	}
	rows, err := tx.QueryContext(ctx, `
		SELECT a.id::text, a.asset_type, a.name, a.deleted_at IS NOT NULL,
			COALESCE((SELECT jsonb_object_agg(k, a.properties -> k) FROM unnest($3::text[]) k WHERE a.properties ? k), '{}'::jsonb)
		FROM assets a WHERE a.tenant_id = $1 AND a.id = ANY($2::uuid[])`,
		tenantID, pq.StringArray(ids), assetDomainProps)
	if err != nil {
		return nil, fmt.Errorf("load asset domain evidence: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var id, typ, name string
		var deleted bool
		var raw []byte
		if err := rows.Scan(&id, &typ, &name, &deleted, &raw); err != nil {
			return nil, fmt.Errorf("scan asset domain evidence: %w", err)
		}
		props := map[string]any{}
		if err := json.Unmarshal(raw, &props); err != nil {
			props = map[string]any{}
		}
		out[id] = domainAsset{ev: assetdomain.Evidence{Type: typ, Name: name, Props: props}, deleted: deleted}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate asset domain evidence: %w", err)
	}
	return out, nil
}

// domainHosts maps each asset to the assets it is exposed by or runs on.
func domainHosts(ctx context.Context, tx *sql.Tx, tenantID string, ids []string) (map[string][]string, error) {
	out := map[string][]string{}
	rows, err := tx.QueryContext(ctx, `
		SELECT r.target_asset_id::text, r.source_asset_id::text FROM asset_relationships r
		WHERE r.tenant_id = $1 AND r.target_asset_id = ANY($2::uuid[]) AND r.relationship_type = 'exposes'
		UNION
		SELECT r.source_asset_id::text, r.target_asset_id::text FROM asset_relationships r
		WHERE r.tenant_id = $1 AND r.source_asset_id = ANY($2::uuid[]) AND r.relationship_type = 'runs_on'`,
		tenantID, pq.StringArray(ids))
	if err != nil {
		return nil, fmt.Errorf("load asset domain hosts: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var a, h string
		if err := rows.Scan(&a, &h); err != nil {
			return nil, fmt.Errorf("scan asset domain host: %w", err)
		}
		out[a] = append(out[a], h)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate asset domain hosts: %w", err)
	}
	return out, nil
}

// domainResolvers maps each asset to the names of the tenant's live assets
// that resolve to it.
func domainResolvers(ctx context.Context, tx *sql.Tx, tenantID string, ids []string) (map[string][]string, error) {
	out := map[string][]string{}
	if len(ids) == 0 {
		return out, nil
	}
	rows, err := tx.QueryContext(ctx, `
		SELECT t, n FROM (
			SELECT r.target_asset_id::text AS t, s.name AS n,
				row_number() OVER (PARTITION BY r.target_asset_id ORDER BY s.name) AS rn
			FROM asset_relationships r
			JOIN assets s ON s.tenant_id = r.tenant_id AND s.id = r.source_asset_id AND s.deleted_at IS NULL
			WHERE r.tenant_id = $1 AND r.target_asset_id = ANY($2::uuid[]) AND r.relationship_type = 'resolves_to'
		) x WHERE rn <= $3`, tenantID, pq.StringArray(ids), maxResolversPerAddress)
	if err != nil {
		return nil, fmt.Errorf("load asset domain resolvers: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var t, n string
		if err := rows.Scan(&t, &n); err != nil {
			return nil, fmt.Errorf("scan asset domain resolver: %w", err)
		}
		out[t] = append(out[t], n)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate asset domain resolvers: %w", err)
	}
	return out, nil
}

func keysOf(m map[string]domainAsset) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
