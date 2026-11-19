package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/openctemio/openctem/server/pkg/domain/shared"
	"github.com/openctemio/openctem/server/pkg/domain/tenant"
)

// The personal organization at sign-up (docs/architecture/user-onboarding.md,
// "Personal organization at sign-up"). These methods work on the account's
// own mark and on new rows only: the account id comes from the signed-in
// account, never from a request.

var _ tenant.PersonalOrgRepository = (*TenantRepository)(nil)

// personalOrgLockKey serializes personal organization creation on the
// platform, so the rate bounds count exactly. Each holder is one short
// transaction.
const personalOrgLockKey int64 = 0x7065727367 // "persg"

// ReservePersonalOrganization marks a new account pending; an existing mark
// is kept.
func (r *TenantRepository) ReservePersonalOrganization(ctx context.Context, userID shared.ID, at time.Time) error {
	if _, err := r.db.ExecContext(ctx, `
		INSERT INTO personal_organizations (user_id, status, reserved_at)
		VALUES ($1, 'pending', $2)
		ON CONFLICT (user_id) DO NOTHING`, userID.String(), at); err != nil {
		return fmt.Errorf("reserve personal organization: %w", err)
	}
	return nil
}

// PersonalOrganizationPending reports whether the account is marked and not
// settled.
func (r *TenantRepository) PersonalOrganizationPending(ctx context.Context, userID shared.ID, at time.Time) (bool, error) {
	var ok bool
	if err := r.db.QueryRowContext(ctx, `
		SELECT EXISTS (SELECT 1 FROM personal_organizations WHERE user_id = $1 AND status = 'pending' AND reserved_at > $2)`,
		userID.String(), at.Add(-tenant.PersonalOrgMarkLifetime)).Scan(&ok); err != nil {
		return false, fmt.Errorf("read personal organization mark: %w", err)
	}
	return ok, nil
}

// CreatePersonalOrganization makes the organization and its owner and
// settles the mark, in one transaction holding the mark's row lock.
func (r *TenantRepository) CreatePersonalOrganization(ctx context.Context, c tenant.PersonalOrgCreation) error {
	if c.Tenant == nil || c.Membership == nil || c.Membership.UserID() != c.UserID || c.Membership.TenantID() != c.Tenant.ID() {
		return fmt.Errorf("%w: personal organization owner mismatch", shared.ErrValidation)
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin personal organization: %w", err)
	}
	// Rolled back on every early return; after Commit it is a no-op.
	defer func() { _ = tx.Rollback() }()

	// The mark's row lock: a second sign-in of the same account waits here
	// and then finds the mark settled.
	var status string
	var reservedAt time.Time
	err = tx.QueryRowContext(ctx, `SELECT status, reserved_at FROM personal_organizations WHERE user_id = $1 FOR UPDATE`,
		c.UserID.String()).Scan(&status, &reservedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return tenant.ErrPersonalOrgNotPending
	}
	if err != nil {
		return fmt.Errorf("lock personal organization mark: %w", err)
	}
	if tenant.PersonalOrgStatus(status) != tenant.PersonalOrgPending {
		return tenant.ErrPersonalOrgNotPending
	}
	if !reservedAt.After(c.At.Add(-tenant.PersonalOrgMarkLifetime)) {
		return tenant.ErrPersonalOrgNotPending // too old to be honored
	}

	// Rechecked under the lock: an organization joined or created another
	// way settles the mark; a waiting invitation leaves it pending.
	var member, invited, claimed bool
	if err := tx.QueryRowContext(ctx, `
		SELECT EXISTS (SELECT 1 FROM tenant_members WHERE user_id = $1),
		       EXISTS (SELECT 1 FROM tenant_invitations
		                WHERE lower(email) = lower($2) AND accepted_at IS NULL AND revoked_at IS NULL AND expires_at > $3)
		    OR EXISTS (SELECT 1 FROM organization_owner_invitations
		                WHERE invitee_user_id = $1 AND status = 'pending' AND expires_at > $3)`,
		c.UserID.String(), c.Email, c.At).Scan(&member, &invited); err != nil {
		return fmt.Errorf("check personal organization conditions: %w", err)
	}
	// A domain claim verified after the service read the domain facts: the
	// person joins that organization instead. Slightly wider than the
	// service's own check (any verified SSO claim of the domain or a parent
	// counts, whatever its include_subdomains setting), which only errs
	// towards leaving the mark pending.
	if err := tx.QueryRowContext(ctx, `
		SELECT EXISTS (SELECT 1 FROM verified_domains v
		                WHERE v.purpose = 'sso' AND v.status = 'verified'
		                  AND (lower(substring($1 from '[^@]*$')) = v.domain
		                    OR lower(substring($1 from '[^@]*$')) LIKE '%.' || replace(replace(v.domain, '_', '\_'), '%', '\%'))
		)`, c.Email).Scan(&claimed); err != nil {
		return fmt.Errorf("check personal organization domain claim: %w", err)
	}
	if member {
		if _, err := tx.ExecContext(ctx, `
			UPDATE personal_organizations SET status = 'skipped', settled_at = $2 WHERE user_id = $1`,
			c.UserID.String(), c.At); err != nil {
			return fmt.Errorf("settle personal organization mark: %w", err)
		}
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("commit personal organization mark: %w", err)
		}
		return tenant.ErrPersonalOrgHasMembership
	}
	if invited {
		return tenant.ErrPersonalOrgInvited
	}
	if claimed {
		return tenant.ErrPersonalOrgDomainClaimed
	}

	if err := r.withinPersonalOrgRates(ctx, tx, c); err != nil {
		return err
	}

	if err := r.insertTenantTx(ctx, tx, c.Tenant); err != nil {
		if isUniqueViolation(err) {
			return tenant.ErrPersonalOrgSlugTaken
		}
		return err
	}
	if err := insertOwnerMembershipTx(ctx, tx, c.Membership); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE personal_organizations
		   SET status = 'created', tenant_id = $2, email_domain = NULLIF($3, ''),
		       ip_prefix = NULLIF($4, '')::cidr, settled_at = $5
		 WHERE user_id = $1`,
		c.UserID.String(), c.Tenant.ID().String(), c.EmailDomain, c.IPPrefix, c.At); err != nil {
		return fmt.Errorf("settle personal organization mark: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit personal organization: %w", err)
	}
	return nil
}

// withinPersonalOrgRates takes the platform lock and refuses when the
// prefix or the domain made too many personal organizations in the window.
func (r *TenantRepository) withinPersonalOrgRates(ctx context.Context, tx *sql.Tx, c tenant.PersonalOrgCreation) error {
	rates := c.Rates
	if rates.Window <= 0 || (rates.PerPrefix <= 0 && rates.PerDomain <= 0) {
		return nil
	}
	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock($1)`, personalOrgLockKey); err != nil {
		return fmt.Errorf("lock personal organization rates: %w", err)
	}
	var byPrefix, byDomain int
	if err := tx.QueryRowContext(ctx, `
		SELECT count(*) FILTER (WHERE $2 <> '' AND ip_prefix = NULLIF($2, '')::cidr),
		       count(*) FILTER (WHERE $3 <> '' AND email_domain = $3)
		  FROM personal_organizations
		 WHERE status = 'created' AND settled_at > $1`,
		c.At.Add(-rates.Window), c.IPPrefix, c.EmailDomain).Scan(&byPrefix, &byDomain); err != nil {
		return fmt.Errorf("count personal organizations: %w", err)
	}
	if (rates.PerPrefix > 0 && c.IPPrefix != "" && byPrefix >= rates.PerPrefix) ||
		(rates.PerDomain > 0 && c.EmailDomain != "" && byDomain >= rates.PerDomain) {
		return tenant.ErrPersonalOrgRateLimited
	}
	return nil
}
