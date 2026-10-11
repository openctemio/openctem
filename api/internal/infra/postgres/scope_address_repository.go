package postgres

// The addresses the tenant's names resolve to (asset_relationships
// resolves_to edges), for the scope address suggestions (RFC-054 §14.7).
// Tenant-scoped on every table.

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/internal/app/easm"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// ScopeAddressRepository reads resolution edges for scope suggestions.
type ScopeAddressRepository struct{ db *DB }

// NewScopeAddressRepository creates the repository.
func NewScopeAddressRepository(db *DB) *ScopeAddressRepository {
	return &ScopeAddressRepository{db: db}
}

// ResolvedAddresses lists up to limit IP address assets of the tenant that a
// name of the tenant resolves to, each with every name that resolves to it
// (at most 50 per address) and its properties (cdn, asn_org).
func (r *ScopeAddressRepository) ResolvedAddresses(ctx context.Context, tenantID shared.ID, limit int) ([]easm.ResolvedAddress, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT ip.id, ip.name, ip.properties,
		       (array_agg(DISTINCT n.id::text || '|' || lower(n.name)))[1:50]
		FROM asset_relationships rel
		JOIN assets ip ON ip.id = rel.target_asset_id AND ip.tenant_id = rel.tenant_id
		JOIN assets n ON n.id = rel.source_asset_id AND n.tenant_id = rel.tenant_id
		WHERE rel.tenant_id = $1
		  AND rel.relationship_type = 'resolves_to'
		  AND ip.asset_type = 'ip_address' AND ip.deleted_at IS NULL
		  AND n.deleted_at IS NULL
		GROUP BY ip.id, ip.name, ip.properties
		ORDER BY ip.name
		LIMIT $2`, tenantID.String(), limit)
	if err != nil {
		return nil, fmt.Errorf("resolved addresses: %w", err)
	}
	defer rows.Close()
	var out []easm.ResolvedAddress
	for rows.Next() {
		var (
			a     easm.ResolvedAddress
			props []byte
			pairs []string
		)
		if err := rows.Scan(&a.AssetID, &a.Address, &props, pq.Array(&pairs)); err != nil {
			return nil, fmt.Errorf("scan resolved address: %w", err)
		}
		if len(props) > 0 {
			_ = json.Unmarshal(props, &a.Properties)
		}
		for _, p := range pairs {
			id, name, ok := strings.Cut(p, "|")
			if ok {
				a.Names = append(a.Names, easm.ResolvedName{AssetID: id, Name: name})
			}
		}
		out = append(out, a)
	}
	return out, rows.Err()
}
