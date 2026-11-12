package postgres

import (
	"context"
	"fmt"
	"time"

	"github.com/openctemio/openctem/api/internal/app/securityoverview"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// SecurityOverviewRepository counts the rows behind the security overview
// (docs/architecture/security-overview.md). Every count carries the tenant.
type SecurityOverviewRepository struct {
	db *DB
}

// NewSecurityOverviewRepository creates the repository.
func NewSecurityOverviewRepository(db *DB) *SecurityOverviewRepository {
	return &SecurityOverviewRepository{db: db}
}

var _ securityoverview.Counter = (*SecurityOverviewRepository)(nil)

// securityOverviewCountsSQL: $1 tenant, $2 now, $3 key expiry window, $4 unused
// window, $5 never-used grace (all intervals in seconds).
const securityOverviewCountsSQL = `
SELECT
	(SELECT count(*) FROM tenant_members m
		JOIN users u ON u.id = m.user_id
		LEFT JOIN v_user_effective_role ver ON ver.user_id = m.user_id AND ver.tenant_id = m.tenant_id
		WHERE m.tenant_id = $1 AND COALESCE(m.status, 'active') = 'active' AND u.kind = 'person'
		  AND COALESCE(ver.role, 'member') IN ('owner', 'admin')
		  AND u.auth_provider = 'local'
		  AND NOT EXISTS (SELECT 1 FROM user_mfa f WHERE f.user_id = m.user_id AND f.enabled)),
	(SELECT count(*) FROM tenant_members m
		JOIN users u ON u.id = m.user_id
		WHERE m.tenant_id = $1 AND COALESCE(m.status, 'active') = 'active' AND u.kind = 'person'
		  AND ((u.last_login_at IS NOT NULL AND u.last_login_at < $2::timestamptz - make_interval(secs => $4))
		    OR (u.last_login_at IS NULL AND m.joined_at < $2::timestamptz - make_interval(secs => $5)))),
	(SELECT count(*) FROM organization_join_requests j
		WHERE j.tenant_id = $1 AND j.status = 'pending' AND j.expires_at > $2),
	(SELECT count(*) FROM api_keys k
		WHERE k.tenant_id = $1 AND k.status = 'active'
		  AND k.expires_at IS NOT NULL AND k.expires_at <= $2::timestamptz + make_interval(secs => $3)),
	(SELECT count(*) FROM api_keys k
		WHERE k.tenant_id = $1 AND k.status = 'active'
		  AND (k.expires_at IS NULL OR k.expires_at > $2)
		  AND ((k.last_used_at IS NULL AND k.created_at < $2::timestamptz - make_interval(secs => $5))
		    OR k.last_used_at < $2::timestamptz - make_interval(secs => $4))),
	(SELECT count(*) FROM scim_tokens t WHERE t.tenant_id = $1 AND t.status = 'active'),
	(SELECT count(*) FROM scim_tokens t
		WHERE t.tenant_id = $1 AND t.status = 'active'
		  AND ((t.last_used_at IS NULL AND t.created_at < $2::timestamptz - make_interval(secs => $5))
		    OR t.last_used_at < $2::timestamptz - make_interval(secs => $4))),
	(SELECT count(*) FROM verified_domains d
		WHERE d.tenant_id = $1 AND d.purpose = 'sso' AND d.status = 'verified'),
	(SELECT count(*) FROM support_grants g
		WHERE g.tenant_id = $1 AND g.revoked_at IS NULL AND g.starts_at <= $2 AND g.expires_at > $2)`

// Counts returns the organization's counts as of now.
func (r *SecurityOverviewRepository) Counts(ctx context.Context, tenantID shared.ID, now time.Time) (securityoverview.Counts, error) {
	var c securityoverview.Counts
	if tenantID.IsZero() {
		return c, fmt.Errorf("%w: tenant required", shared.ErrValidation)
	}
	err := r.db.QueryRowContext(ctx, securityOverviewCountsSQL,
		tenantID.String(), now,
		int64(securityoverview.APIKeyExpiryWindow/time.Second),
		int64(securityoverview.UnusedAfter/time.Second),
		int64(securityoverview.NeverUsedGrace/time.Second),
	).Scan(&c.AdminsWithoutMFA, &c.DormantMembers, &c.PendingJoinRequests,
		&c.APIKeysExpiring, &c.APIKeysUnused, &c.SCIMTokensActive, &c.SCIMTokensUnused,
		&c.VerifiedDomains, &c.ActiveSupportGrants)
	if err != nil {
		return c, fmt.Errorf("security overview counts: %w", err)
	}
	return c, nil
}
