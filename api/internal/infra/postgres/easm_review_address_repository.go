package postgres

// What explains an address row of the review queue (easm/review_ip.go):
// the names that resolve to it and the network facts we already hold.
// Tenant-scoped; the names are narrowed to the caller's data scope.

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/internal/app/easm"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

var _ easm.ReviewAddressStore = (*AttributionRepository)(nil)

// maxResolvingNames bounds the names read per page of addresses.
const maxResolvingNames = 500

// ResolvedFrom maps each address to the tenant's domain and subdomain names
// with a resolves_to edge to its ip_address asset, only names in the
// caller's data scope (scope nil = unrestricted).
func (r *AttributionRepository) ResolvedFrom(ctx context.Context, tenantID shared.ID, scope *shared.DataScope, addrs []string) (map[string][]string, error) {
	out := map[string][]string{}
	if len(addrs) == 0 {
		return out, nil
	}
	args := []any{tenantID.String(), pq.Array(addrs)}
	sc, args := scopeClause("src.id", scope, args)
	args = append(args, maxResolvingNames)
	rows, err := r.db.QueryContext(ctx, `
		SELECT ip.name, lower(src.name)
		FROM assets ip
		JOIN asset_relationships rel ON rel.tenant_id = ip.tenant_id AND rel.target_asset_id = ip.id
			AND rel.relationship_type = 'resolves_to'
		JOIN assets src ON src.id = rel.source_asset_id AND src.tenant_id = ip.tenant_id AND src.deleted_at IS NULL
			AND src.asset_type IN ('domain', 'subdomain')
		WHERE ip.tenant_id = $1 AND ip.asset_type = 'ip_address' AND ip.deleted_at IS NULL
		  AND ip.name = ANY($2)`+sc+fmt.Sprintf(`
		ORDER BY ip.name, lower(src.name)
		LIMIT $%d`, len(args)), args...)
	if err != nil {
		return nil, fmt.Errorf("list names resolving to review addresses: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var ip, name string
		if err := rows.Scan(&ip, &name); err != nil {
			return nil, err
		}
		out[ip] = append(out[ip], name)
	}
	return out, rows.Err()
}

// AddressProps maps each address to the properties of the tenant's
// ip_address asset of that name.
func (r *AttributionRepository) AddressProps(ctx context.Context, tenantID shared.ID, addrs []string) (map[string]map[string]any, error) {
	out := map[string]map[string]any{}
	if len(addrs) == 0 {
		return out, nil
	}
	rows, err := r.db.QueryContext(ctx, `
		SELECT name, COALESCE(properties, '{}'::jsonb) FROM assets
		WHERE tenant_id = $1 AND asset_type = 'ip_address' AND deleted_at IS NULL AND name = ANY($2)`,
		tenantID.String(), pq.Array(addrs))
	if err != nil {
		return nil, fmt.Errorf("read review address facts: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var (
			name string
			raw  []byte
		)
		if err := rows.Scan(&name, &raw); err != nil {
			return nil, err
		}
		props := map[string]any{}
		_ = json.Unmarshal(raw, &props)
		out[name] = props
	}
	return out, rows.Err()
}

// sensorNames maps sensor ids to the names a tenant may see: its own
// sensors by name, platform sensors as "platform sensor" (their names are
// operator infrastructure), anything else not at all.
func (r *AttributionRepository) sensorNames(ctx context.Context, tenantID shared.ID, ids []string) (map[string]string, error) {
	out := map[string]string{}
	if len(ids) == 0 {
		return out, nil
	}
	rows, err := r.db.QueryContext(ctx, `
		SELECT id::text, CASE WHEN tenant_id = $1 AND NOT is_platform_sensor THEN name ELSE 'platform sensor' END
		FROM sensors
		WHERE id = ANY($2::uuid[]) AND (tenant_id = $1 OR is_platform_sensor)`,
		tenantID.String(), pq.Array(ids))
	if err != nil {
		return nil, fmt.Errorf("read sensor names for review evidence: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var id, name string
		if err := rows.Scan(&id, &name); err != nil {
			return nil, err
		}
		out[id] = name
	}
	return out, rows.Err()
}
