package postgres

import (
	"context"
	"fmt"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// KnownNamesRepository reads the DNS names an organization already knows, for
// the wordlists generated for its jobs (contentpin). Every query is scoped to
// one tenant.
type KnownNamesRepository struct {
	db *DB
}

// NewKnownNamesRepository creates a KnownNamesRepository.
func NewKnownNamesRepository(db *DB) *KnownNamesRepository { return &KnownNamesRepository{db: db} }

// KnownNames returns up to limit active domain and subdomain names of the
// tenant that are root or end in ".root". Nothing of another tenant is read:
// tenant_id is part of every predicate.
func (r *KnownNamesRepository) KnownNames(ctx context.Context, tenantID shared.ID, root string, limit int) ([]string, error) {
	if tenantID.IsZero() || root == "" || limit <= 0 {
		return nil, nil
	}
	like := "%." + escapeLikePattern(root)
	rows, err := r.db.QueryContext(ctx, `
		SELECT name FROM assets
		WHERE tenant_id = $1 AND deleted_at IS NULL AND status = 'active'
		  AND asset_type IN ('domain', 'subdomain')
		  AND (name = $2 OR name LIKE $3 ESCAPE '\')
		ORDER BY name
		LIMIT $4`, tenantID.String(), root, like, limit)
	if err != nil {
		return nil, fmt.Errorf("known names: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			return nil, fmt.Errorf("known names: %w", err)
		}
		out = append(out, n)
	}
	return out, rows.Err()
}
