package postgres

// Reads for the attack surface suggestion cards (research/117). Every query
// is tenant-scoped; a non-nil data scope narrows the rows (and the names
// shown with them) to the caller's assets exactly as the asset list does.

import (
	"context"
	"encoding/json"
	"fmt"
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
		SELECT ip.id, ip.name, COALESCE(ip.properties, '{}'::jsonb),
		       array_agg(DISTINCT lower(src.name)),
		       COALESCE(array_agg(DISTINCT lower(src.name)) FILTER (WHERE `+visible+`), '{}')
		FROM assets ip
		JOIN asset_relationships rel ON rel.tenant_id = ip.tenant_id AND rel.target_asset_id = ip.id
			AND rel.relationship_type = 'resolves_to'
		JOIN assets src ON src.id = rel.source_asset_id AND src.tenant_id = ip.tenant_id AND src.deleted_at IS NULL
			AND src.asset_type IN ('domain', 'subdomain')
		LEFT JOIN asset_attributions aa ON aa.asset_id = ip.id AND aa.tenant_id = ip.tenant_id
		WHERE ip.tenant_id = $1 AND ip.asset_type = 'ip_address' AND ip.deleted_at IS NULL
		  AND (aa.asset_id IS NULL OR aa.state = 'confirmed'
		       OR (aa.state IN ('discovered', 'needs_review', 'candidate') AND aa.decided_at IS NULL))`+sc+fmt.Sprintf(`
		GROUP BY ip.id, ip.name, ip.properties
		ORDER BY ip.name
		LIMIT $%d`, len(args)), args...)
	if err != nil {
		return nil, fmt.Errorf("list addresses behind names: %w", err)
	}
	defer rows.Close()
	var out []easm.AddressBehindNames
	for rows.Next() {
		var (
			a   easm.AddressBehindNames
			raw []byte
		)
		if err := rows.Scan(&a.AssetID, &a.Address, &raw, pq.Array(&a.AllNames), pq.Array(&a.VisibleNames)); err != nil {
			return nil, err
		}
		a.Props = map[string]any{}
		_ = json.Unmarshal(raw, &a.Props)
		out = append(out, a)
	}
	return out, rows.Err()
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
