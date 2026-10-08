package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/pkg/domain/admin"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// AdminOrganizationRepository is the platform admin's cross-tenant read model
// over tenants (RFC-022 Phase 2). It is deliberately NOT tenant-scoped: it is
// wired only into /api/v1/admin routes behind AdminAuthMiddleware.
type AdminOrganizationRepository struct {
	db *DB
}

// NewAdminOrganizationRepository creates the repository.
func NewAdminOrganizationRepository(db *DB) *AdminOrganizationRepository {
	return &AdminOrganizationRepository{db: db}
}

var _ admin.OrganizationReader = (*AdminOrganizationRepository)(nil)

// One row per tenant; every aggregate is a correlated subquery on an indexed
// tenant_id, so the page costs a fixed number of index lookups (no N+1).
const adminOrganizationSelect = `
	SELECT t.id, t.name, t.slug, COALESCE(t.description, ''), t.created_at,
	       (SELECT COUNT(*) FROM tenant_members m
	         WHERE m.tenant_id = t.id AND m.status = 'active'),
	       COALESCE((SELECT array_agg(u.email ORDER BY u.email) FROM tenant_members m
	         JOIN users u ON u.id = m.user_id
	         WHERE m.tenant_id = t.id AND m.role = 'owner' AND m.status = 'active'), '{}'),
	       EXISTS (SELECT 1 FROM saml_providers s WHERE s.tenant_id = t.id AND s.enabled),
	       (SELECT COUNT(*) FROM tenant_identity_providers p
	         WHERE p.tenant_id = t.id AND p.is_active),
	       (SELECT COUNT(*) FROM verified_domains d
	         WHERE d.tenant_id = t.id AND d.verified_at IS NOT NULL),
	       COALESCE((t.settings -> 'security' ->> 'sso_enforced')::boolean, FALSE),
	       ` + adminOrganizationPlanExpr + `
	FROM tenants t`

// adminOrganizationPlanExpr is the organization's plan: the stored one, or
// enterprise for an organization created before plans (plan.go).
const adminOrganizationPlanExpr = `COALESCE((SELECT tp.plan FROM tenant_plans tp WHERE tp.tenant_id = t.id), 'enterprise')`

// adminOrganizationActiveOwner holds when the organization has an active owner.
const adminOrganizationActiveOwner = `EXISTS (SELECT 1 FROM tenant_members m
	WHERE m.tenant_id = t.id AND m.role = 'owner' AND m.status = 'active')`

func scanOrganization(sc interface{ Scan(...any) error }) (*admin.Organization, error) {
	var (
		o      admin.Organization
		id     string
		owners pq.StringArray
	)
	if err := sc.Scan(&id, &o.Name, &o.Slug, &o.Description, &o.CreatedAt,
		&o.ActiveMembers, &owners, &o.SAMLEnabled, &o.ActiveIdentityProviders,
		&o.VerifiedDomains, &o.SSOEnforced, &o.Plan); err != nil {
		return nil, err
	}
	parsed, err := shared.IDFromString(id)
	if err != nil {
		return nil, err
	}
	o.ID = parsed
	o.OwnerEmails = []string(owners)
	return &o, nil
}

// ListOrganizations returns one page of organizations, newest first, and the
// total matching the filter.
func (r *AdminOrganizationRepository) ListOrganizations(ctx context.Context, f admin.OrganizationFilter) ([]*admin.Organization, int, error) {
	conds := []string{}
	args := []any{}
	if s := strings.TrimSpace(f.Search); s != "" {
		args = append(args, "%"+escapeLikePattern(s)+"%")
		conds = append(conds, fmt.Sprintf("(t.name ILIKE $%d OR t.slug ILIKE $%d)", len(args), len(args)))
	}
	switch f.Owner {
	case admin.OrganizationOwnerNone:
		conds = append(conds, "NOT "+adminOrganizationActiveOwner)
	case admin.OrganizationOwnerPresent:
		conds = append(conds, adminOrganizationActiveOwner)
	}
	if f.Plan != "" {
		args = append(args, f.Plan)
		conds = append(conds, fmt.Sprintf("%s = $%d", adminOrganizationPlanExpr, len(args)))
	}
	where := ""
	if len(conds) > 0 {
		where = " WHERE " + strings.Join(conds, " AND ")
	}

	var total int
	if err := r.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM tenants t`+where, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count organizations: %w", err)
	}

	limit := f.Limit
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	offset := max(f.Offset, 0)
	q := adminOrganizationSelect + where +
		fmt.Sprintf(" ORDER BY t.created_at DESC, t.id LIMIT $%d OFFSET $%d", len(args)+1, len(args)+2)
	rows, err := r.db.QueryContext(ctx, q, append(args, limit, offset)...)
	if err != nil {
		return nil, 0, fmt.Errorf("list organizations: %w", err)
	}
	defer rows.Close()

	// Fixed capacity: limit is bounded above, but sizing an allocation from a
	// request value is exactly what static analysis (rightly) distrusts.
	out := make([]*admin.Organization, 0, 64)
	for rows.Next() {
		o, err := scanOrganization(rows)
		if err != nil {
			return nil, 0, fmt.Errorf("scan organization: %w", err)
		}
		out = append(out, o)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("list organizations: %w", err)
	}
	return out, total, nil
}

// GetOrganization returns one organization.
func (r *AdminOrganizationRepository) GetOrganization(ctx context.Context, id shared.ID) (*admin.Organization, error) {
	o, err := scanOrganization(r.db.QueryRowContext(ctx, adminOrganizationSelect+` WHERE t.id = $1`, id.String()))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("%w: organization", shared.ErrNotFound)
	}
	if err != nil {
		return nil, fmt.Errorf("get organization: %w", err)
	}
	return o, nil
}
