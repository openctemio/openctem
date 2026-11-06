package postgres

// Reads for the attack surface suggestion cards (research/117). Every query
// is tenant-scoped; a non-nil data scope narrows the rows (and the names
// shown with them) to the caller's assets exactly as the asset list does.

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/internal/app/easm"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

var _ easm.SuggestionStore = (*AttributionRepository)(nil)

// AddressesBehindNames lists the tenant's address assets that domain or
// subdomain assets resolve to (resolves_to), in the caller's data scope,
// unless a person decided the address is anything but confirmed (rejected,
// dependency, monitor only, sent back to review). AllNames are every
// resolving name of the tenant (used only to tell shared hosting);
// VisibleNames those in the caller's data scope.
func (r *AttributionRepository) AddressesBehindNames(ctx context.Context, tenantID shared.ID, scope *shared.DataScope, limit int) ([]easm.AddressBehindNames, error) {
	if limit <= 0 {
		return nil, nil
	}
	args := []any{tenantID.String()}
	visible := "TRUE"
	if scope != nil {
		var sargs []any
		visible, sargs = dataScopeCondAt("src.id", scope, len(args)+1)
		args = append(args, sargs...)
	}
	sc, args := scopeClause("ip.id", scope, args)
	args = append(args, limit)
	rows, err := r.db.QueryContext(ctx, `
		SELECT ip.id, ip.name, COALESCE(ip.properties, '{}'::jsonb), ip.first_seen,
		       array_agg(DISTINCT lower(src.name)),
		       COALESCE(array_agg(DISTINCT lower(src.name)) FILTER (WHERE `+visible+`), '{}'),
		       COALESCE(array_agg(DISTINCT src.id::text) FILTER (WHERE `+visible+`), '{}')
		FROM assets ip
		JOIN asset_relationships rel ON rel.tenant_id = ip.tenant_id AND rel.target_asset_id = ip.id
			AND rel.relationship_type = 'resolves_to'
		JOIN assets src ON src.id = rel.source_asset_id AND src.tenant_id = ip.tenant_id AND src.deleted_at IS NULL
			AND src.asset_type IN ('domain', 'subdomain')
		LEFT JOIN asset_attributions aa ON aa.asset_id = ip.id AND aa.tenant_id = ip.tenant_id
		WHERE ip.tenant_id = $1 AND ip.asset_type = 'ip_address' AND ip.deleted_at IS NULL
		  AND (aa.asset_id IS NULL OR aa.state = 'confirmed'
		       OR (aa.state IN ('discovered', 'needs_review', 'candidate') AND aa.decided_at IS NULL))`+sc+fmt.Sprintf(`
		GROUP BY ip.id, ip.name, ip.properties, ip.first_seen
		ORDER BY ip.name
		LIMIT $%d`, len(args)), args...)
	if err != nil {
		return nil, fmt.Errorf("list addresses behind names: %w", err)
	}
	defer rows.Close()
	var out []easm.AddressBehindNames
	nameIDs := map[string][]string{} // address asset id -> its visible names' ids
	for rows.Next() {
		var (
			a   easm.AddressBehindNames
			raw []byte
			ids []string
		)
		if err := rows.Scan(&a.AssetID, &a.Address, &raw, &a.FirstSeen, pq.Array(&a.AllNames), pq.Array(&a.VisibleNames), pq.Array(&ids)); err != nil {
			return nil, err
		}
		a.Props = map[string]any{}
		_ = json.Unmarshal(raw, &a.Props)
		nameIDs[a.AssetID] = ids
		out = append(out, a)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if err := r.fillAddressPorts(ctx, tenantID, out, nameIDs); err != nil {
		return nil, err
	}
	return out, nil
}

// fillAddressPorts sets each row's Ports: the ports asset_services records
// on the address asset or on its visible names, tenant-scoped.
func (r *AttributionRepository) fillAddressPorts(ctx context.Context, tenantID shared.ID, rows []easm.AddressBehindNames, nameIDs map[string][]string) error {
	if len(rows) == 0 {
		return nil
	}
	ids := make([]string, 0, len(rows)*2)
	for _, a := range rows {
		ids = append(ids, a.AssetID)
		ids = append(ids, nameIDs[a.AssetID]...)
	}
	q, err := r.db.QueryContext(ctx, `
		SELECT asset_id::text, array_agg(DISTINCT port)
		FROM asset_services
		WHERE tenant_id = $1 AND asset_id::text = ANY($2)
		GROUP BY asset_id`, tenantID.String(), pq.Array(ids))
	if err != nil {
		return fmt.Errorf("ports behind addresses: %w", err)
	}
	defer q.Close()
	ports := map[string][]int64{}
	for q.Next() {
		var (
			id string
			ps []int64
		)
		if err := q.Scan(&id, pq.Array(&ps)); err != nil {
			return err
		}
		ports[id] = ps
	}
	if err := q.Err(); err != nil {
		return err
	}
	for i := range rows {
		seen := map[int]bool{}
		for _, id := range append([]string{rows[i].AssetID}, nameIDs[rows[i].AssetID]...) {
			for _, p := range ports[id] {
				if p > 0 && p <= 65535 && !seen[int(p)] {
					seen[int(p)] = true
					rows[i].Ports = append(rows[i].Ports, int(p))
				}
			}
		}
		slices.Sort(rows[i].Ports)
	}
	return nil
}

// ConfirmedByPerson lists the tenant's domain, subdomain and address assets
// a person confirmed, in the caller's data scope, most recent decision
// first.
func (r *AttributionRepository) ConfirmedByPerson(ctx context.Context, tenantID shared.ID, scope *shared.DataScope, limit int) ([]easm.SuggestionAsset, error) {
	if limit <= 0 {
		return nil, nil
	}
	args := []any{tenantID.String()}
	sc, args := scopeClause("a.id", scope, args)
	args = append(args, limit)
	rows, err := r.db.QueryContext(ctx, `
		SELECT a.id, a.name, a.asset_type
		FROM asset_attributions aa
		JOIN assets a ON a.id = aa.asset_id AND a.tenant_id = aa.tenant_id AND a.deleted_at IS NULL
		WHERE aa.tenant_id = $1 AND aa.state = 'confirmed' AND aa.decided_at IS NOT NULL
		  AND a.asset_type IN ('domain', 'subdomain', 'ip_address')`+sc+fmt.Sprintf(`
		ORDER BY aa.decided_at DESC, a.id
		LIMIT $%d`, len(args)), args...)
	if err != nil {
		return nil, fmt.Errorf("list confirmed assets: %w", err)
	}
	defer rows.Close()
	var out []easm.SuggestionAsset
	for rows.Next() {
		var (
			a   easm.SuggestionAsset
			typ string
		)
		if err := rows.Scan(&a.AssetID, &a.Name, &typ); err != nil {
			return nil, err
		}
		a.TargetType = easm.SuggestionTargetType(typ)
		out = append(out, a)
	}
	return out, rows.Err()
}

// NamesResolvingTo maps each of the tenant's address assets among
// addressIDs to the lower-cased names of the tenant's live domain and
// subdomain assets that resolve to it (resolves_to). Tenant-scoped on every
// table; ids of another tenant or unknown ids are absent. For the
// shared-hosting guardrail (RFC-054 §16).
func (r *AttributionRepository) NamesResolvingTo(ctx context.Context, tenantID shared.ID, addressIDs []string) (map[string][]string, error) {
	out := map[string][]string{}
	if len(addressIDs) == 0 {
		return out, nil
	}
	rows, err := r.db.QueryContext(ctx, `
		SELECT rel.target_asset_id::text, array_agg(DISTINCT lower(src.name))
		FROM asset_relationships rel
		JOIN assets src ON src.id = rel.source_asset_id AND src.tenant_id = rel.tenant_id AND src.deleted_at IS NULL
			AND src.asset_type IN ('domain', 'subdomain')
		WHERE rel.tenant_id = $1 AND rel.relationship_type = 'resolves_to'
		  AND rel.target_asset_id::text = ANY($2)
		GROUP BY rel.target_asset_id`, tenantID.String(), pq.Array(addressIDs))
	if err != nil {
		return nil, fmt.Errorf("names resolving to addresses: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var (
			id    string
			names []string
		)
		if err := rows.Scan(&id, pq.Array(&names)); err != nil {
			return nil, err
		}
		out[id] = names
	}
	return out, rows.Err()
}

// AddressesOf maps each of the given names (matched case-insensitively) to
// the names of the tenant's live address assets the tenant's live domain or
// subdomain asset of that name resolves to (resolves_to). Tenant-scoped on
// every table; a name with no such asset or relation is absent. For the
// web-port cap of a name's port scan (RFC-054 §16).
func (r *AttributionRepository) AddressesOf(ctx context.Context, tenantID shared.ID, names []string) (map[string][]string, error) {
	out := map[string][]string{}
	if len(names) == 0 {
		return out, nil
	}
	lower := make([]string, 0, len(names))
	for _, n := range names {
		lower = append(lower, strings.ToLower(strings.TrimSpace(n)))
	}
	rows, err := r.db.QueryContext(ctx, `
		SELECT lower(src.name), array_agg(DISTINCT ip.name)
		FROM assets src
		JOIN asset_relationships rel ON rel.tenant_id = src.tenant_id AND rel.source_asset_id = src.id
			AND rel.relationship_type = 'resolves_to'
		JOIN assets ip ON ip.id = rel.target_asset_id AND ip.tenant_id = src.tenant_id AND ip.deleted_at IS NULL
			AND ip.asset_type = 'ip_address'
		WHERE src.tenant_id = $1 AND src.deleted_at IS NULL AND src.asset_type IN ('domain', 'subdomain')
		  AND lower(src.name) = ANY($2)
		GROUP BY lower(src.name)`, tenantID.String(), pq.Array(lower))
	if err != nil {
		return nil, fmt.Errorf("addresses of names: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var (
			name  string
			addrs []string
		)
		if err := rows.Scan(&name, pq.Array(&addrs)); err != nil {
			return nil, err
		}
		out[name] = addrs
	}
	return out, rows.Err()
}

// OpenPortsOfNames maps each of the given names (matched case-insensitively,
// keyed lower-case) to the port numbers of the live open TCP ports of the
// live addresses the tenant's live domain or subdomain asset of that name
// resolves to (name resolves_to address exposes open_port). Tenant-scoped on
// every table; a name with none is absent. For the coverage HTTP probe of a
// name (scan.NamePortReader).
func (r *AttributionRepository) OpenPortsOfNames(ctx context.Context, tenantID shared.ID, names []string) (map[string][]int, error) {
	out := map[string][]int{}
	if len(names) == 0 {
		return out, nil
	}
	lower := make([]string, 0, len(names))
	for _, n := range names {
		lower = append(lower, strings.ToLower(strings.TrimSpace(n)))
	}
	rows, err := r.db.QueryContext(ctx, `
		SELECT lower(src.name), array_agg(DISTINCT (p.properties->>'port')::int)
		FROM assets src
		JOIN asset_relationships rel ON rel.tenant_id = src.tenant_id AND rel.source_asset_id = src.id
			AND rel.relationship_type = 'resolves_to'
		JOIN assets ip ON ip.id = rel.target_asset_id AND ip.tenant_id = src.tenant_id AND ip.deleted_at IS NULL
			AND ip.asset_type = 'ip_address'
		JOIN asset_relationships rp ON rp.tenant_id = src.tenant_id AND rp.source_asset_id = ip.id
			AND rp.relationship_type = 'exposes'
		JOIN assets p ON p.id = rp.target_asset_id AND p.tenant_id = src.tenant_id AND p.deleted_at IS NULL
			AND p.status = 'active' AND p.asset_type = 'service' AND p.sub_type = 'open_port'
		WHERE src.tenant_id = $1 AND src.deleted_at IS NULL AND src.asset_type IN ('domain', 'subdomain')
		  AND lower(src.name) = ANY($2)
		  AND COALESCE(p.properties->>'port', '') ~ '^[0-9]{1,5}$'
		  AND COALESCE(NULLIF(p.properties->>'transport', ''), NULLIF(p.properties->>'protocol', ''), 'tcp') = 'tcp'
		GROUP BY lower(src.name)`, tenantID.String(), pq.Array(lower))
	if err != nil {
		return nil, fmt.Errorf("open ports of names: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var (
			name  string
			ports []int64
		)
		if err := rows.Scan(&name, pq.Array(&ports)); err != nil {
			return nil, err
		}
		for _, p := range ports {
			out[name] = append(out[name], int(p))
		}
	}
	return out, rows.Err()
}
