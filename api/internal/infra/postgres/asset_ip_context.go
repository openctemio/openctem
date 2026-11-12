package postgres

// The IP addresses tab of the asset inventory: the names that resolve to an
// address and its open ports (asset_ports), and the group by network. Every
// statement is pinned to the tenant and to the caller's data scope.

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/assetlist"
	"github.com/openctemio/openctem/api/pkg/filterspec"
)

// IPContexts returns, for the address assets ids of the actor's tenant, the
// names resolving to each (at most asset.IPContextNames, by name) and its
// open ports (at most asset.IPContextPorts, by port), with totals. A name
// or port outside the actor's data scope is neither listed nor counted.
func (r *AssetRepository) IPContexts(ctx context.Context, actor filterspec.Actor, ids []string) (map[string]asset.IPContext, error) {
	out := make(map[string]asset.IPContext, len(ids))
	if len(ids) == 0 {
		return out, nil
	}
	tenant := actor.TenantID().String()
	nameScope, nameArgs := actor.AssetScopeSQL("n.id", 3)
	//nolint:gosec // G202: the scope predicate is constant SQL with numbered placeholders
	rows, err := r.db.QueryContext(ctx, `
		SELECT ip, name, total FROM (
			SELECT r.target_asset_id::text AS ip, n.name,
			       count(*) OVER (PARTITION BY r.target_asset_id) AS total,
			       row_number() OVER (PARTITION BY r.target_asset_id ORDER BY n.name, n.id) AS rn
			FROM asset_relationships r
			JOIN assets n ON n.tenant_id = r.tenant_id AND n.id = r.source_asset_id AND n.deleted_at IS NULL
			WHERE r.tenant_id = $1 AND r.relationship_type = 'resolves_to' AND r.target_asset_id = ANY($2::uuid[])
			  AND `+nameScope+`) x
		WHERE rn <= `+fmt.Sprint(asset.IPContextNames)+` ORDER BY ip, name`,
		append([]any{tenant, pq.Array(ids)}, nameArgs...)...)
	if err != nil {
		return nil, fmt.Errorf("ip names: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var id, name string
		var total int
		if err := rows.Scan(&id, &name, &total); err != nil {
			return nil, fmt.Errorf("scan ip name: %w", err)
		}
		c := out[id]
		c.Names = append(c.Names, name)
		c.NamesTotal = total
		out[id] = c
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("ip names: %w", err)
	}

	portScope, portArgs := actor.AssetScopeSQL("ap.port_asset_id", 3)
	//nolint:gosec // G202: as above
	portQuery := `
		SELECT ip, port, transport, service, total FROM (
			SELECT ap.asset_id::text AS ip, ap.port, ap.transport, ap.service,
			       count(*) OVER (PARTITION BY ap.asset_id) AS total,
			       row_number() OVER (PARTITION BY ap.asset_id ORDER BY ap.port, ap.transport) AS rn
			FROM asset_ports ap
			WHERE ap.tenant_id = $1 AND ap.asset_id = ANY($2::uuid[]) AND ap.port_asset_id <> ap.asset_id
			  AND ` + portScope + `) x
		WHERE rn <= ` + fmt.Sprint(asset.IPContextPorts) + ` ORDER BY ip, port`
	ports, err := r.db.QueryContext(ctx, portQuery, append([]any{tenant, pq.Array(ids)}, portArgs...)...)
	if err != nil {
		return nil, fmt.Errorf("ip ports: %w", err)
	}
	defer func() { _ = ports.Close() }()
	for ports.Next() {
		var id string
		var p asset.IPPort
		var total int
		if err := ports.Scan(&id, &p.Port, &p.Transport, &p.Service, &total); err != nil {
			return nil, fmt.Errorf("scan ip port: %w", err)
		}
		c := out[id]
		c.Ports = append(c.Ports, p)
		c.PortsTotal = total
		out[id] = c
	}
	if err := ports.Err(); err != nil {
		return nil, fmt.Errorf("ip ports: %w", err)
	}
	return out, nil
}

// NetworkCounts groups the address assets a compiled filter matches by
// network (asset_ip_network), most addresses first, at most
// asset.MaxNetworks; capped reports more networks than that.
func (r *AssetRepository) NetworkCounts(ctx context.Context, w *filterspec.Where) ([]asset.NetworkCount, bool, error) {
	if w == nil || !strings.HasPrefix(w.SQL, assetlist.Fields.TenantSQL+" = $") {
		return nil, false, errUncompiledAssetFilter
	}
	tx, err := r.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, false, fmt.Errorf("begin network counts: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, "SET LOCAL statement_timeout = '"+assetListTimeout+"'"); err != nil {
		return nil, false, fmt.Errorf("set network counts timeout: %w", err)
	}
	//nolint:gosec // G202: the WHERE is compiled from registry constants; every value is bound
	q := `SELECT asset_ip_network(a.name)::text AS net, count(*) FROM assets a
		WHERE ` + liveAssetSQL("a") + ` AND ` + w.SQL + ` AND a.asset_type = 'ip_address' AND asset_ip_network(a.name) IS NOT NULL
		GROUP BY 1 ORDER BY 2 DESC, 1 LIMIT ` + fmt.Sprint(asset.MaxNetworks+1)
	rows, err := tx.QueryContext(ctx, q, w.Args...)
	if err != nil {
		return nil, false, assetTimeout(fmt.Errorf("network counts: %w", err))
	}
	defer func() { _ = rows.Close() }()
	out := make([]asset.NetworkCount, 0, 64)
	for rows.Next() {
		var n asset.NetworkCount
		if err := rows.Scan(&n.Network, &n.Count); err != nil {
			return nil, false, fmt.Errorf("scan network count: %w", err)
		}
		out = append(out, n)
	}
	if err := rows.Err(); err != nil {
		return nil, false, assetTimeout(fmt.Errorf("network counts: %w", err))
	}
	capped := len(out) > asset.MaxNetworks
	if capped {
		out = out[:asset.MaxNetworks]
	}
	return out, capped, tx.Commit()
}
