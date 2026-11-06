package postgres

import (
	"context"
	"fmt"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// VerifiedDomainNameRepository lists a tenant's verified domain names: the
// proof of control (RFC-054 §8.1). Since seeds folded into scope entries
// (research/53 SC1, SC2) a verified domain never authorizes by itself.
type VerifiedDomainNameRepository struct {
	db *DB
}

// NewVerifiedDomainNameRepository creates the repository.
func NewVerifiedDomainNameRepository(db *DB) *VerifiedDomainNameRepository {
	return &VerifiedDomainNameRepository{db: db}
}

// VerifiedDomainNames returns the tenant's verified domains, any purpose.
func (r *VerifiedDomainNameRepository) VerifiedDomainNames(ctx context.Context, tenantID shared.ID) ([]string, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT domain FROM verified_domains WHERE tenant_id = $1 AND status = 'verified'`, tenantID.String())
	if err != nil {
		return nil, fmt.Errorf("list verified domains: %w", err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var d string
		if err := rows.Scan(&d); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}
