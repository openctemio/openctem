package postgres

import (
	"context"
	"fmt"
	"time"
)

// The platform admin console's attention queue (Console > Overview).
//
// Deliberately NOT tenant-scoped, like the admin organization read model: it
// is wired only into /api/v1/admin behind the console session. It returns
// counts, plus the id and name of a few organizations that need an owner;
// nothing from inside an organization (no findings, assets or member
// details) leaves this file.

// AdminOverviewOrg names one organization in an attention item.
type AdminOverviewOrg struct {
	ID   string
	Name string
}

// AdminOverviewCounts is one read of the console's attention counts.
type AdminOverviewCounts struct {
	Organizations int64
	// Organizations with no active owner: nobody in them can manage
	// members, SSO or the plan. Sample holds at most adminOverviewSample.
	OrganizationsWithoutOwner       int64
	OrganizationsWithoutOwnerSample []AdminOverviewOrg

	// Emergency-access sign-ins since now - 7 days.
	BreakGlassSignIns7d int64
	// Refused or failed administrator actions since now - 24 hours.
	FailedAdminActions24h int64
}

const adminOverviewSample = 5

// ReadAdminOverview reads the console's attention counts. Every query is an
// aggregate over an indexed column (tenant_members.tenant_id,
// admin_audit_logs.created_at).
func ReadAdminOverview(ctx context.Context, db opsQuerier, now time.Time) (AdminOverviewCounts, error) {
	var c AdminOverviewCounts

	const noOwner = `NOT EXISTS (SELECT 1 FROM tenant_members m
		WHERE m.tenant_id = t.id AND m.role = 'owner' AND m.status = 'active')`

	if err := db.QueryRowContext(ctx, `
		SELECT count(*), count(*) FILTER (WHERE `+noOwner+`)
		FROM tenants t`,
	).Scan(&c.Organizations, &c.OrganizationsWithoutOwner); err != nil {
		return c, fmt.Errorf("organizations: %w", err)
	}

	if c.OrganizationsWithoutOwner > 0 {
		rows, err := db.QueryContext(ctx, `
			SELECT t.id::text, t.name FROM tenants t
			WHERE `+noOwner+`
			ORDER BY t.created_at DESC, t.id
			LIMIT $1`, adminOverviewSample)
		if err != nil {
			return c, fmt.Errorf("organizations without owner: %w", err)
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			var o AdminOverviewOrg
			if err := rows.Scan(&o.ID, &o.Name); err != nil {
				return c, fmt.Errorf("scan organization: %w", err)
			}
			c.OrganizationsWithoutOwnerSample = append(c.OrganizationsWithoutOwnerSample, o)
		}
		if err := rows.Err(); err != nil {
			return c, fmt.Errorf("organizations without owner: %w", err)
		}
	}

	if err := db.QueryRowContext(ctx, `
		SELECT count(*) FILTER (WHERE action = $1 AND created_at >= $2),
		       count(*) FILTER (WHERE NOT success AND created_at >= $3)
		FROM admin_audit_logs
		WHERE created_at >= LEAST($2, $3)`,
		adminOverviewBreakGlassAction, now.Add(-7*24*time.Hour), now.Add(-24*time.Hour),
	).Scan(&c.BreakGlassSignIns7d, &c.FailedAdminActions24h); err != nil {
		return c, fmt.Errorf("admin activity: %w", err)
	}

	return c, nil
}

// adminOverviewBreakGlassAction is adminconsole.ActionBreakGlassSignIn
// (postgres cannot import the app layer; a test pins the two together).
const adminOverviewBreakGlassAction = "console.break_glass_sign_in"
