package postgres

import (
	"context"
	"fmt"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/tenant"
)

// ListInvitationOffersForEmail lists the pending, unexpired invitations
// addressed to email, across organizations: the invitee's own onboarding
// (the caller has proved the address). At most 50.
func (r *TenantRepository) ListInvitationOffersForEmail(ctx context.Context, email string) ([]tenant.InvitationOffer, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT i.id, i.tenant_id, t.name, i.role, COALESCE(u.name, ''), i.expires_at
		  FROM tenant_invitations i
		  JOIN tenants t ON t.id = i.tenant_id
		  LEFT JOIN users u ON u.id = i.invited_by
		 WHERE lower(i.email) = lower($1) AND i.accepted_at IS NULL AND i.revoked_at IS NULL AND i.expires_at > NOW()
		 ORDER BY i.created_at DESC
		 LIMIT 50`, email)
	if err != nil {
		return nil, fmt.Errorf("list invitation offers: %w", err)
	}
	defer rows.Close()
	var out []tenant.InvitationOffer
	for rows.Next() {
		var (
			id, tid   string
			o         tenant.InvitationOffer
			expiresAt time.Time
		)
		if err := rows.Scan(&id, &tid, &o.TenantName, &o.Role, &o.InviterName, &expiresAt); err != nil {
			return nil, fmt.Errorf("scan invitation offer: %w", err)
		}
		o.InvitationID, o.TenantID, o.ExpiresAt = shared.MustIDFromString(id), shared.MustIDFromString(tid), expiresAt
		out = append(out, o)
	}
	return out, rows.Err()
}
