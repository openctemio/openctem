package postgres

// Ownership invitations (docs/architecture/organization-ownership-invitations.md).
//
// Every write that can give an organization an owner, or (re)issue an
// invitation, takes the organization's first-owner advisory lock (the same
// lock as CreateFirstOwnerMembership), so an acceptance, a first-owner
// bootstrap and a new invitation for one organization never interleave.
// Invitee-side reads and writes are keyed by the invitee's account id as
// well as the invitation id: another account's invitation is not found.

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/openctemio/openctem/server/pkg/domain/shared"
	"github.com/openctemio/openctem/server/pkg/domain/tenant"
)

var _ tenant.OwnerInvitationRepository = (*TenantRepository)(nil)

const ownerInvitationColumns = `id, tenant_id, invitee_user_id, invitee_email, invited_by, status,
	expires_at, send_count, last_sent_at, responded_at, created_at`

func scanOwnerInvitation(sc interface{ Scan(...any) error }) (*tenant.OwnerInvitation, error) {
	var (
		inv                         tenant.OwnerInvitation
		id, tenantID, invitee       string
		invitedBy                   sql.NullString
		status                      string
		respondedAt                 sql.NullTime
		expiresAt, lastSent, create time.Time
	)
	if err := sc.Scan(&id, &tenantID, &invitee, &inv.InviteeEmail, &invitedBy, &status,
		&expiresAt, &inv.SendCount, &lastSent, &respondedAt, &create); err != nil {
		return nil, err
	}
	var err error
	if inv.ID, err = shared.IDFromString(id); err != nil {
		return nil, err
	}
	if inv.TenantID, err = shared.IDFromString(tenantID); err != nil {
		return nil, err
	}
	if inv.InviteeUserID, err = shared.IDFromString(invitee); err != nil {
		return nil, err
	}
	if invitedBy.Valid {
		inv.InvitedBy, _ = shared.IDFromString(invitedBy.String)
	}
	inv.Status = tenant.OwnerInvitationStatus(status)
	inv.ExpiresAt, inv.LastSentAt, inv.CreatedAt = expiresAt.UTC(), lastSent.UTC(), create.UTC()
	if respondedAt.Valid {
		t := respondedAt.Time.UTC()
		inv.RespondedAt = &t
	}
	return &inv, nil
}

func ownerInviterID(id shared.ID) sql.NullString {
	if id.IsZero() {
		return sql.NullString{}
	}
	return sql.NullString{String: id.String(), Valid: true}
}

// checkOwnerInviteeTx refuses an account that cannot own an organization:
// not active, erased, or a service account (ErrOwnerInviteeNotEligible), or
// a break-glass administrator, which stays console-only
// (ErrBreakGlassMembership).
func checkOwnerInviteeTx(ctx context.Context, tx *sql.Tx, userID shared.ID) error {
	var ok bool
	err := tx.QueryRowContext(ctx, `
		SELECT status = 'active' AND erased_at IS NULL AND kind <> 'service'
		  FROM users WHERE id = $1`, userID.String()).Scan(&ok)
	if errors.Is(err, sql.ErrNoRows) || (err == nil && !ok) {
		return tenant.ErrOwnerInviteeNotEligible
	}
	if err != nil {
		return fmt.Errorf("check invitee: %w", err)
	}
	var breakGlass bool
	if err := tx.QueryRowContext(ctx, `
		SELECT EXISTS (SELECT 1 FROM admin_users WHERE user_id = $1 AND is_break_glass)`,
		userID.String()).Scan(&breakGlass); err != nil {
		return fmt.Errorf("check invitee: %w", err)
	}
	if breakGlass {
		return tenant.ErrBreakGlassMembership
	}
	return nil
}

func insertOwnerInvitationTx(ctx context.Context, tx *sql.Tx, inv *tenant.OwnerInvitation) error {
	if err := checkOwnerInviteeTx(ctx, tx, inv.InviteeUserID); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO organization_owner_invitations
			(id, tenant_id, invitee_user_id, invitee_email, invited_by, status,
			 expires_at, send_count, last_sent_at, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, 'pending', $6, $7, $8, $9, $9)`,
		inv.ID.String(), inv.TenantID.String(), inv.InviteeUserID.String(), inv.InviteeEmail,
		ownerInviterID(inv.InvitedBy), inv.ExpiresAt, inv.SendCount, inv.LastSentAt, inv.CreatedAt,
	); err != nil {
		return fmt.Errorf("store ownership invitation: %w", err)
	}
	return nil
}

func lockFirstOwner(ctx context.Context, tx *sql.Tx, tenantID string) error {
	if _, err := tx.ExecContext(ctx,
		`SELECT pg_advisory_xact_lock(hashtext('tenant_first_owner'), hashtext($1))`, tenantID); err != nil {
		return fmt.Errorf("lock organization: %w", err)
	}
	return nil
}

// withTx runs fn in a transaction, committing when it returns nil.
func (r *TenantRepository) withTx(ctx context.Context, fn func(tx *sql.Tx) error) (err error) {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin tx: %w", err)
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()
	err = fn(tx)
	if err != nil {
		return err
	}
	if err = tx.Commit(); err != nil {
		return fmt.Errorf("commit: %w", err)
	}
	return nil
}

// CreateWithOwnerInvitation creates the organization (no member) and its
// pending invitation in one transaction.
func (r *TenantRepository) CreateWithOwnerInvitation(ctx context.Context, t *tenant.Tenant, inv *tenant.OwnerInvitation) error {
	if inv.TenantID != t.ID() {
		return fmt.Errorf("%w: invitation for another organization", shared.ErrValidation)
	}
	return r.withTx(ctx, func(tx *sql.Tx) error {
		if err := r.insertTenantTx(ctx, tx, t); err != nil {
			return err
		}
		return insertOwnerInvitationTx(ctx, tx, inv)
	})
}

// LatestOwnerInvitation returns the organization's newest invitation.
func (r *TenantRepository) LatestOwnerInvitation(ctx context.Context, tenantID shared.ID) (*tenant.OwnerInvitation, error) {
	inv, err := scanOwnerInvitation(r.db.QueryRowContext(ctx, `SELECT `+ownerInvitationColumns+`
		FROM organization_owner_invitations WHERE tenant_id = $1
		ORDER BY created_at DESC, id DESC LIMIT 1`, tenantID.String()))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, shared.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("read ownership invitation: %w", err)
	}
	return inv, nil
}

// ReplaceOwnerInvitation cancels the pending invitation and stores inv, while
// the organization is still waiting for its first owner: it has an invitation
// history, none was ever accepted, and it has no member at all (any status).
// Those conditions keep the platform administrator from inviting an account
// of its choosing into an organization that holds anyone's data.
func (r *TenantRepository) ReplaceOwnerInvitation(ctx context.Context, inv *tenant.OwnerInvitation) (*tenant.OwnerInvitation, error) {
	var canceled *tenant.OwnerInvitation
	err := r.withTx(ctx, func(tx *sql.Tx) error {
		tid := inv.TenantID.String()
		if err := lockFirstOwner(ctx, tx, tid); err != nil {
			return err
		}
		var waiting bool
		if err := tx.QueryRowContext(ctx, `
			SELECT EXISTS (SELECT 1 FROM organization_owner_invitations WHERE tenant_id = $1)
			   AND NOT EXISTS (SELECT 1 FROM organization_owner_invitations
			                    WHERE tenant_id = $1 AND status = 'accepted')
			   AND NOT EXISTS (SELECT 1 FROM tenant_members WHERE tenant_id = $1)`, tid).Scan(&waiting); err != nil {
			return fmt.Errorf("check organization: %w", err)
		}
		if !waiting {
			return tenant.ErrOwnerInvitationNotAllowed
		}
		old, err := scanOwnerInvitation(tx.QueryRowContext(ctx, `
			UPDATE organization_owner_invitations
			   SET status = 'canceled', responded_at = $2, updated_at = $2
			 WHERE tenant_id = $1 AND status = 'pending'
			RETURNING `+ownerInvitationColumns, tid, inv.CreatedAt))
		switch {
		case err == nil:
			canceled = old
		case errors.Is(err, sql.ErrNoRows):
		default:
			return fmt.Errorf("cancel ownership invitation: %w", err)
		}
		return insertOwnerInvitationTx(ctx, tx, inv)
	})
	if err != nil {
		return nil, err
	}
	return canceled, nil
}

// ResendOwnerInvitation records a new send of the pending invitation and
// renews its expiry, when the resend interval and cap allow it.
func (r *TenantRepository) ResendOwnerInvitation(ctx context.Context, tenantID shared.ID, now time.Time) (*tenant.OwnerInvitation, error) {
	var out *tenant.OwnerInvitation
	err := r.withTx(ctx, func(tx *sql.Tx) error {
		cur, err := scanOwnerInvitation(tx.QueryRowContext(ctx, `SELECT `+ownerInvitationColumns+`
			FROM organization_owner_invitations
			WHERE tenant_id = $1 AND status = 'pending' FOR UPDATE`, tenantID.String()))
		if errors.Is(err, sql.ErrNoRows) {
			return tenant.ErrOwnerInvitationNotFound
		}
		if err != nil {
			return fmt.Errorf("read ownership invitation: %w", err)
		}
		if err := cur.CheckResend(now); err != nil {
			return err
		}
		out, err = scanOwnerInvitation(tx.QueryRowContext(ctx, `
			UPDATE organization_owner_invitations
			   SET send_count = send_count + 1, last_sent_at = $2, expires_at = $3, updated_at = $2
			 WHERE id = $1 AND tenant_id = $4 AND status = 'pending'
			RETURNING `+ownerInvitationColumns,
			cur.ID.String(), now, now.Add(tenant.OwnerInvitationTTL), tenantID.String()))
		if err != nil {
			return fmt.Errorf("record ownership invitation send: %w", err)
		}
		return nil
	})
	return out, err
}

// CancelOwnerInvitation cancels the organization's pending invitation.
func (r *TenantRepository) CancelOwnerInvitation(ctx context.Context, tenantID shared.ID, now time.Time) (*tenant.OwnerInvitation, error) {
	inv, err := scanOwnerInvitation(r.db.QueryRowContext(ctx, `
		UPDATE organization_owner_invitations
		   SET status = 'canceled', responded_at = $2, updated_at = $2
		 WHERE tenant_id = $1 AND status = 'pending'
		RETURNING `+ownerInvitationColumns, tenantID.String(), now))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, tenant.ErrOwnerInvitationNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("cancel ownership invitation: %w", err)
	}
	return inv, nil
}

// ListOpenOwnerInvitations lists the invitations userID can accept at now.
func (r *TenantRepository) ListOpenOwnerInvitations(ctx context.Context, userID shared.ID, now time.Time) ([]tenant.OwnerInvitationOffer, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT i.id, i.tenant_id, t.name, t.slug, i.created_at, i.expires_at
		  FROM organization_owner_invitations i
		  JOIN tenants t ON t.id = i.tenant_id
		 WHERE i.invitee_user_id = $1 AND i.status = 'pending' AND i.expires_at > $2
		 ORDER BY i.created_at DESC
		 LIMIT 50`, userID.String(), now)
	if err != nil {
		return nil, fmt.Errorf("list ownership invitations: %w", err)
	}
	defer rows.Close()
	out := make([]tenant.OwnerInvitationOffer, 0, 4)
	for rows.Next() {
		var o tenant.OwnerInvitationOffer
		var id, tid string
		if err := rows.Scan(&id, &tid, &o.OrganizationName, &o.OrganizationSlug, &o.CreatedAt, &o.ExpiresAt); err != nil {
			return nil, fmt.Errorf("scan ownership invitation: %w", err)
		}
		if o.ID, err = shared.IDFromString(id); err != nil {
			return nil, err
		}
		if o.TenantID, err = shared.IDFromString(tid); err != nil {
			return nil, err
		}
		out = append(out, o)
	}
	return out, rows.Err()
}

// inviteeInvitationTx locks userID's invitation id (not found for anyone
// else's).
func inviteeInvitationTx(ctx context.Context, tx *sql.Tx, id, userID shared.ID) (*tenant.OwnerInvitation, error) {
	inv, err := scanOwnerInvitation(tx.QueryRowContext(ctx, `SELECT `+ownerInvitationColumns+`
		FROM organization_owner_invitations
		WHERE id = $1 AND invitee_user_id = $2 FOR UPDATE`, id.String(), userID.String()))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, tenant.ErrOwnerInvitationNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("read ownership invitation: %w", err)
	}
	return inv, nil
}

// AcceptOwnerInvitation makes userID the owner of the invitation's
// organization: the invitation must be userID's, pending and open, and the
// organization must have no owner (checked under the first-owner lock).
func (r *TenantRepository) AcceptOwnerInvitation(ctx context.Context, id, userID shared.ID,
	newOwner func(tenantID shared.ID) (*tenant.Membership, error), now time.Time,
) (*tenant.OwnerInvitation, *tenant.Membership, error) {
	var (
		inv *tenant.OwnerInvitation
		m   *tenant.Membership
	)
	err := r.withTx(ctx, func(tx *sql.Tx) error {
		var err error
		if inv, err = inviteeInvitationTx(ctx, tx, id, userID); err != nil {
			return err
		}
		if inv.Status != tenant.OwnerInvitationPending {
			return tenant.ErrOwnerInvitationNotFound
		}
		if !inv.IsOpen(now) {
			return tenant.ErrOwnerInvitationExpired
		}
		tid := inv.TenantID.String()
		if err := lockFirstOwner(ctx, tx, tid); err != nil {
			return err
		}
		presence, err := queryOwnerPresence(ctx, tx, tid)
		if err != nil {
			return err
		}
		if presence.Any {
			return tenant.ErrOwnerInvitationNotFound
		}
		if err := checkOwnerInviteeTx(ctx, tx, userID); err != nil {
			return err
		}
		if m, err = newOwner(inv.TenantID); err != nil {
			return err
		}
		if !m.IsOwner() || m.UserID() != userID || m.TenantID() != inv.TenantID {
			return fmt.Errorf("%w: the accepted membership must be the invitee's owner membership", shared.ErrValidation)
		}
		if err := insertOwnerMembershipTx(ctx, tx, m); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `
			UPDATE organization_owner_invitations
			   SET status = 'accepted', responded_at = $2, updated_at = $2
			 WHERE id = $1 AND status = 'pending'`, inv.ID.String(), now); err != nil {
			return fmt.Errorf("mark ownership invitation accepted: %w", err)
		}
		inv.Status = tenant.OwnerInvitationAccepted
		inv.RespondedAt = &now
		return nil
	})
	if err != nil {
		return nil, nil, err
	}
	return inv, m, nil
}

// DeclineOwnerInvitation marks userID's pending invitation declined.
func (r *TenantRepository) DeclineOwnerInvitation(ctx context.Context, id, userID shared.ID, now time.Time) (*tenant.OwnerInvitation, error) {
	inv, err := scanOwnerInvitation(r.db.QueryRowContext(ctx, `
		UPDATE organization_owner_invitations
		   SET status = 'declined', responded_at = $3, updated_at = $3
		 WHERE id = $1 AND invitee_user_id = $2 AND status = 'pending'
		RETURNING `+ownerInvitationColumns, id.String(), userID.String(), now))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, tenant.ErrOwnerInvitationNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("decline ownership invitation: %w", err)
	}
	return inv, nil
}
