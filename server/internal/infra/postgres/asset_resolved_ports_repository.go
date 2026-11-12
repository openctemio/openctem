package postgres

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// resolvedPortsFrom joins name $2 of tenant $1 to the live open ports of the
// live addresses it resolves to. Every table is bound to the tenant.
const resolvedPortsFrom = `
	FROM asset_relationships rr
	JOIN assets ip ON ip.tenant_id = rr.tenant_id AND ip.id = rr.target_asset_id
		AND ip.asset_type = 'ip_address' AND ip.deleted_at IS NULL
	JOIN asset_relationships rp ON rp.tenant_id = rr.tenant_id AND rp.source_asset_id = ip.id
		AND rp.relationship_type = 'exposes'
	JOIN assets p ON p.tenant_id = rr.tenant_id AND p.id = rp.target_asset_id
		AND p.asset_type = 'service' AND p.sub_type = 'open_port'
		AND p.deleted_at IS NULL AND p.status = 'active'
	WHERE rr.tenant_id = $1 AND rr.source_asset_id = $2 AND rr.relationship_type = 'resolves_to'`

// ResolvedPorts returns the open ports of the addresses asset assetID
// resolves to, by address then port number, at most limit rows. With a
// restricted scope only rows whose address and port are both in it are
// returned; the rest are counted in HiddenCount.
func (r *AssetRelationshipRepository) ResolvedPorts(
	ctx context.Context, tenantID, assetID shared.ID, scope *shared.DataScope, limit int,
) (*asset.ResolvedPorts, error) {
	args := []any{tenantID.String(), assetID.String()}
	visible := sqlTrue
	if scope != nil {
		ipCond, ipArgs := dataScopeCondAt("ip.id", scope, len(args)+1)
		args = append(args, ipArgs...)
		portCond, portArgs := dataScopeCondAt("p.id", scope, len(args)+1)
		args = append(args, portArgs...)
		visible = "(" + ipCond + ") AND (" + portCond + ")"
	}
	out := &asset.ResolvedPorts{Items: []asset.ResolvedPort{}}

	var total int64
	//nolint:gosec // G201: visible is built from fixed SQL and numbered placeholders
	countQuery := fmt.Sprintf(`SELECT COUNT(*), COUNT(*) FILTER (WHERE %s)`+resolvedPortsFrom, visible)
	var shown int64
	if err := r.db.QueryRowContext(ctx, countQuery, args...).Scan(&total, &shown); err != nil {
		return nil, fmt.Errorf("count resolved ports: %w", err)
	}
	out.HiddenCount = total - shown
	if shown == 0 {
		return out, nil
	}
	out.Truncated = shown > int64(limit)

	args = append(args, limit)
	//nolint:gosec // G201: visible is built from fixed SQL and numbered placeholders
	itemsQuery := fmt.Sprintf(`
		SELECT ip.id, ip.name, p.id,
		       CASE WHEN COALESCE(p.properties->>'port', '') ~ '^[0-9]{1,5}$' THEN (p.properties->>'port')::int ELSE 0 END AS port,
		       COALESCE(NULLIF(p.properties->>'transport', ''), p.properties->>'protocol', ''),
		       COALESCE(NULLIF(p.properties->>'service', ''), p.properties->>'name', ''),
		       COALESCE(p.properties->>'product', ''), COALESCE(p.properties->>'version', ''),
		       p.last_seen`+resolvedPortsFrom+` AND %s
		ORDER BY ip.name, port, p.id
		LIMIT $%d`, visible, len(args))
	rows, err := r.db.QueryContext(ctx, itemsQuery, args...)
	if err != nil {
		return nil, fmt.Errorf("list resolved ports: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var (
			it       asset.ResolvedPort
			addrID   string
			portID   string
			lastSeen sql.NullTime
		)
		if err := rows.Scan(&addrID, &it.Address, &portID, &it.Port, &it.Transport, &it.Service,
			&it.Product, &it.Version, &lastSeen); err != nil {
			return nil, fmt.Errorf("scan resolved port: %w", err)
		}
		if it.AddressID, err = shared.IDFromString(addrID); err != nil {
			return nil, fmt.Errorf("resolved port address id: %w", err)
		}
		if it.PortID, err = shared.IDFromString(portID); err != nil {
			return nil, fmt.Errorf("resolved port id: %w", err)
		}
		if lastSeen.Valid {
			t := lastSeen.Time.In(time.UTC)
			it.LastSeen = &t
		}
		out.Items = append(out.Items, it)
	}
	return out, rows.Err()
}
