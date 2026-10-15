package postgres

import (
	"context"
	"fmt"
	"strings"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// ListActiveEmailsOnDomain returns the addresses of active accounts on domain
// (and its subdomains when includeSubdomains) that are not members of
// excludeTenant, at most limit. It reads across tenants on purpose: a domain
// claim concerns every account on the domain, and the caller only mails each
// address its own notice (docs/rfcs/RFC-104, existing accounts).
func (r *UserRepository) ListActiveEmailsOnDomain(ctx context.Context, domain string, includeSubdomains bool, excludeTenant shared.ID, limit int) ([]string, error) {
	domain = strings.ToLower(strings.TrimSpace(domain))
	if domain == "" || limit <= 0 {
		return nil, nil
	}
	escaped := strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(domain)
	rows, err := r.db.QueryContext(ctx, `
		SELECT u.email
		  FROM users u
		 WHERE u.status = 'active'
		   AND (lower(u.email) LIKE '%@' || $1 ESCAPE '\'
		        OR ($2 AND lower(u.email) LIKE '%@%.' || $1 ESCAPE '\'))
		   AND NOT EXISTS (SELECT 1 FROM tenant_members m WHERE m.user_id = u.id AND m.tenant_id = $3)
		 ORDER BY u.created_at
		 LIMIT $4`, escaped, includeSubdomains, excludeTenant.String(), limit)
	if err != nil {
		return nil, fmt.Errorf("list accounts on domain: %w", err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var e string
		if err := rows.Scan(&e); err != nil {
			return nil, fmt.Errorf("scan account email: %w", err)
		}
		out = append(out, e)
	}
	return out, rows.Err()
}
