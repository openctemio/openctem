package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/openctemio/openctem/api/internal/app/accountdeletion"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// AccountDeletionRepository persists self-service account deletions. Every
// query is keyed by the account (user_id); listing the due ones is the
// platform purge.
type AccountDeletionRepository struct{ db *DB }

// NewAccountDeletionRepository creates the repository.
func NewAccountDeletionRepository(db *DB) *AccountDeletionRepository {
	return &AccountDeletionRepository{db: db}
}

var _ accountdeletion.Repository = (*AccountDeletionRepository)(nil)

// Schedule stores (or replaces) the request.
func (r *AccountDeletionRepository) Schedule(ctx context.Context, userID shared.ID, requestedAt, eraseAfter time.Time) error {
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO account_deletions (user_id, requested_at, erase_after) VALUES ($1, $2, $3)
		ON CONFLICT (user_id) DO UPDATE SET requested_at = EXCLUDED.requested_at, erase_after = EXCLUDED.erase_after`,
		userID.String(), requestedAt, eraseAfter)
	if err != nil {
		return fmt.Errorf("schedule account deletion: %w", err)
	}
	return nil
}

// Get returns when the account will be erased.
func (r *AccountDeletionRepository) Get(ctx context.Context, userID shared.ID) (time.Time, error) {
	var t time.Time
	err := r.db.QueryRowContext(ctx, `SELECT erase_after FROM account_deletions WHERE user_id = $1`, userID.String()).Scan(&t)
	if errors.Is(err, sql.ErrNoRows) {
		return time.Time{}, accountdeletion.ErrNotScheduled
	}
	if err != nil {
		return time.Time{}, fmt.Errorf("get account deletion: %w", err)
	}
	return t, nil
}

// Cancel removes the request.
func (r *AccountDeletionRepository) Cancel(ctx context.Context, userID shared.ID) (bool, error) {
	res, err := r.db.ExecContext(ctx, `DELETE FROM account_deletions WHERE user_id = $1 AND claimed_at IS NULL`, userID.String())
	if err != nil {
		return false, fmt.Errorf("cancel account deletion: %w", err)
	}
	n, err := res.RowsAffected()
	return n > 0, err
}

// Claim marks a due request as being erased.
func (r *AccountDeletionRepository) Claim(ctx context.Context, userID shared.ID, at time.Time) (bool, error) {
	res, err := r.db.ExecContext(ctx, `
		UPDATE account_deletions SET claimed_at = COALESCE(claimed_at, $2)
		 WHERE user_id = $1 AND erase_after < $2`, userID.String(), at)
	if err != nil {
		return false, fmt.Errorf("claim account deletion: %w", err)
	}
	n, err := res.RowsAffected()
	return n > 0, err
}

// Due lists accounts whose grace period ended before t.
func (r *AccountDeletionRepository) Due(ctx context.Context, t time.Time, limit int) ([]shared.ID, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT user_id FROM account_deletions WHERE erase_after < $1 ORDER BY erase_after LIMIT $2`, t, limit)
	if err != nil {
		return nil, fmt.Errorf("list due account deletions: %w", err)
	}
	defer rows.Close()
	var out []shared.ID
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, shared.MustIDFromString(id))
	}
	return out, rows.Err()
}

// SoleOwnerOrganizations names the organizations the account is the only
// active owner of (effective role, as the member lifecycle reads it).
func (r *AccountDeletionRepository) SoleOwnerOrganizations(ctx context.Context, userID shared.ID) ([]string, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT t.name
		  FROM tenant_members m
		  JOIN tenants t ON t.id = m.tenant_id
		  JOIN v_user_effective_role ver ON ver.user_id = m.user_id AND ver.tenant_id = m.tenant_id AND ver.role = 'owner'
		 WHERE m.user_id = $1 AND m.status = 'active'
		   AND NOT EXISTS (
		       SELECT 1
		         FROM tenant_members o
		         JOIN v_user_effective_role ov ON ov.user_id = o.user_id AND ov.tenant_id = o.tenant_id AND ov.role = 'owner'
		         JOIN users ou ON ou.id = o.user_id AND ou.status = 'active'
		        WHERE o.tenant_id = m.tenant_id AND o.user_id <> m.user_id AND o.status = 'active')
		 ORDER BY t.name`, userID.String())
	if err != nil {
		return nil, fmt.Errorf("list sole-owner organizations: %w", err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		out = append(out, name)
	}
	return out, rows.Err()
}

// IsPlatformAdmin reports whether the account is a platform administrator.
func (r *AccountDeletionRepository) IsPlatformAdmin(ctx context.Context, userID shared.ID) (bool, error) {
	var ok bool
	err := r.db.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM admin_users WHERE user_id = $1)`, userID.String()).Scan(&ok)
	if err != nil {
		return false, fmt.Errorf("check platform administrator: %w", err)
	}
	return ok, nil
}

// ActiveMemberships lists the account's memberships that are not offboarded.
func (r *AccountDeletionRepository) ActiveMemberships(ctx context.Context, userID shared.ID) ([]accountdeletion.Membership, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT tenant_id, id FROM tenant_members WHERE user_id = $1 AND status <> 'offboarded'`, userID.String())
	if err != nil {
		return nil, fmt.Errorf("list memberships: %w", err)
	}
	defer rows.Close()
	var out []accountdeletion.Membership
	for rows.Next() {
		var tid, id string
		if err := rows.Scan(&tid, &id); err != nil {
			return nil, err
		}
		out = append(out, accountdeletion.Membership{TenantID: shared.MustIDFromString(tid), MembershipID: id})
	}
	return out, rows.Err()
}

// RevokeAPIKeys revokes the account's API keys in every organization.
func (r *AccountDeletionRepository) RevokeAPIKeys(ctx context.Context, userID shared.ID) (int64, error) {
	res, err := r.db.ExecContext(ctx, `
		UPDATE api_keys SET status = 'revoked', revoked_at = NOW(), revoked_by = $1, updated_at = NOW()
		 WHERE user_id = $1 AND status <> 'revoked'`, userID.String())
	if err != nil {
		return 0, fmt.Errorf("revoke api keys: %w", err)
	}
	return res.RowsAffected()
}

// EraseAccount anonymises the account and deletes the request, in one
// transaction.
func (r *AccountDeletionRepository) EraseAccount(ctx context.Context, userID shared.ID, label string) error {
	return r.db.Transaction(ctx, func(tx *sql.Tx) error {
		// Only a claimed request is carried out.
		res, err := tx.ExecContext(ctx, `DELETE FROM account_deletions WHERE user_id = $1 AND claimed_at IS NOT NULL`, userID.String())
		if err != nil {
			return fmt.Errorf("take account deletion: %w", err)
		}
		if n, rerr := res.RowsAffected(); rerr != nil || n == 0 {
			return accountdeletion.ErrNotScheduled
		}
		if _, err := tx.ExecContext(ctx, `
			UPDATE users
			SET name = $2, email = $3, avatar_url = NULL, phone = NULL, preferences = '{}'::jsonb,
			    password_hash = NULL, keycloak_id = NULL,
			    email_verification_token = NULL, email_verification_expires_at = NULL,
			    password_reset_token = NULL, password_reset_expires_at = NULL,
			    status = 'inactive', erased_at = NOW(), updated_at = NOW()
			WHERE id = $1 AND erased_at IS NULL`,
			userID.String(), label, ErasedEmail(userID)); err != nil {
			return fmt.Errorf("anonymise user: %w", err)
		}
		for _, q := range []string{
			`DELETE FROM user_mfa WHERE user_id = $1`,
			`DELETE FROM user_identities WHERE user_id = $1`,
			`UPDATE sessions SET status = 'revoked', updated_at = NOW() WHERE user_id = $1 AND status = 'active'`,
			`UPDATE refresh_tokens SET revoked_at = NOW() WHERE user_id = $1 AND revoked_at IS NULL`,
			// The person's own API keys stop working in every organization.
			`UPDATE api_keys SET status = 'revoked', revoked_at = NOW(), updated_at = NOW()
			  WHERE user_id = $1 AND status <> 'revoked'`,
			// The console's sign-up feed no longer links to the person.
			`UPDATE signup_events SET user_id = NULL WHERE user_id = $1`,
		} {
			if _, err := tx.ExecContext(ctx, q, userID.String()); err != nil {
				return fmt.Errorf("erase account: %w", err)
			}
		}
		return nil
	})
}
