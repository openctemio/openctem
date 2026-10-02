package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/pkg/domain/admin"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Break-glass and platform-IdP persistence for administrators (RFC-022
// revision 4).

// adminRosterLock serializes changes that could leave the platform without a
// way in (administrator delete / deactivate / demote / unmark break-glass, and
// turning on "require IdP"). Transaction-scoped advisory lock.
const adminRosterLock = `SELECT pg_advisory_xact_lock(hashtext('openctem.admin_users.roster'))`

// localSuperAdminsSQL counts the active, linked super admins who can sign in
// locally: everyone while "require IdP" is not in force, otherwise only
// break-glass administrators.
const localSuperAdminsSQL = `
	SELECT COUNT(*) FROM admin_users
	WHERE is_active AND role = 'super_admin' AND user_id IS NOT NULL
	  AND (is_break_glass OR NOT COALESCE(
	        (SELECT enabled AND require_idp FROM platform_identity_provider WHERE id = 1), FALSE))`

// withRosterGuard runs mutate under the roster lock and refuses with
// admin.ErrLastLocalAdmin when it takes the number of local super admins from
// at least one to zero.
func withRosterGuard(ctx context.Context, db *DB, mutate func(tx *sql.Tx) error) error {
	return db.Transaction(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, adminRosterLock); err != nil {
			return fmt.Errorf("lock admin roster: %w", err)
		}
		var before, after int
		if err := tx.QueryRowContext(ctx, localSuperAdminsSQL).Scan(&before); err != nil {
			return fmt.Errorf("count local super admins: %w", err)
		}
		if err := mutate(tx); err != nil {
			return err
		}
		if err := tx.QueryRowContext(ctx, localSuperAdminsSQL).Scan(&after); err != nil {
			return fmt.Errorf("count local super admins: %w", err)
		}
		if before > 0 && after == 0 {
			return admin.ErrLastLocalAdmin
		}
		return nil
	})
}

// GuardedUpdate saves name, role, is_active and is_break_glass under the
// roster guard.
func (r *AdminRepository) GuardedUpdate(ctx context.Context, a *admin.AdminUser) error {
	return withRosterGuard(ctx, r.db, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `
			UPDATE admin_users
			SET name = $2, role = $3, is_active = $4, is_break_glass = $5, updated_at = NOW()
			WHERE id = $1`,
			a.ID().String(), a.Name(), string(a.Role()), a.IsActive(), a.IsBreakGlass())
		if err != nil {
			if isCheckViolation(err) {
				return admin.ErrBreakGlassBound
			}
			return fmt.Errorf("update admin user: %w", err)
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return admin.ErrAdminNotFound
		}
		return nil
	})
}

// GuardedDelete deletes an administrator under the roster guard.
func (r *AdminRepository) GuardedDelete(ctx context.Context, id shared.ID) error {
	return withRosterGuard(ctx, r.db, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `DELETE FROM admin_users WHERE id = $1`, id.String())
		if err != nil {
			return fmt.Errorf("delete admin user: %w", err)
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return admin.ErrAdminNotFound
		}
		return nil
	})
}

// GetByIdPSubject returns the administrator bound to (issuer, subject).
func (r *AdminRepository) GetByIdPSubject(ctx context.Context, issuer, subject string) (*admin.AdminUser, error) {
	if issuer == "" || subject == "" {
		return nil, admin.ErrAdminNotFound
	}
	row := r.db.QueryRowContext(ctx, r.selectQuery()+" WHERE idp_issuer = $1 AND idp_subject = $2", issuer, subject)
	return r.scanAdmin(row)
}

// BindIdP binds an unbound, non-break-glass administrator in one conditional
// statement; the unique index refuses an identity already bound elsewhere.
func (r *AdminRepository) BindIdP(ctx context.Context, adminID shared.ID, issuer, subject string) error {
	res, err := r.db.ExecContext(ctx, `
		UPDATE admin_users
		SET idp_issuer = $2, idp_subject = $3, idp_bound_at = NOW(), updated_at = NOW()
		WHERE id = $1 AND idp_subject IS NULL AND NOT is_break_glass`,
		adminID.String(), issuer, subject)
	if err != nil {
		if isUniqueViolation(err) || isCheckViolation(err) {
			return admin.ErrIdPBindingConflict
		}
		return fmt.Errorf("bind admin idp identity: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return admin.ErrIdPBindingConflict
	}
	return nil
}

// UnbindIdP removes an administrator's IdP binding.
func (r *AdminRepository) UnbindIdP(ctx context.Context, adminID shared.ID) error {
	res, err := r.db.ExecContext(ctx, `
		UPDATE admin_users
		SET idp_issuer = NULL, idp_subject = NULL, idp_bound_at = NULL, updated_at = NOW()
		WHERE id = $1`, adminID.String())
	if err != nil {
		return fmt.Errorf("unbind admin idp identity: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return admin.ErrAdminNotFound
	}
	return nil
}

// SetPasswordChangeRequired sets or clears the temporary-password marker.
func (r *AdminRepository) SetPasswordChangeRequired(ctx context.Context, adminID shared.ID, required bool) error {
	if _, err := r.db.ExecContext(ctx,
		`UPDATE admin_users SET password_change_required = $2, updated_at = NOW() WHERE id = $1`,
		adminID.String(), required); err != nil {
		return fmt.Errorf("set password change required: %w", err)
	}
	return nil
}

// SetBreakGlassTestedAt records a confirmed break-glass test.
func (r *AdminRepository) SetBreakGlassTestedAt(ctx context.Context, adminID shared.ID, at time.Time) error {
	res, err := r.db.ExecContext(ctx,
		`UPDATE admin_users SET break_glass_tested_at = $2, updated_at = NOW() WHERE id = $1 AND is_break_glass`,
		adminID.String(), at)
	if err != nil {
		return fmt.Errorf("record break-glass test: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return admin.ErrNotBreakGlass
	}
	return nil
}

// ListActive returns every active administrator. The roster is small (a
// handful of operators); the limit is a safety bound.
func (r *AdminRepository) ListActive(ctx context.Context) ([]*admin.AdminUser, error) {
	rows, err := r.db.QueryContext(ctx, r.selectQuery()+" WHERE is_active ORDER BY created_at LIMIT 500")
	if err != nil {
		return nil, fmt.Errorf("list active admins: %w", err)
	}
	defer rows.Close()
	out := make([]*admin.AdminUser, 0, 8)
	for rows.Next() {
		a, err := scanAdminRow(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list active admins: %w", err)
	}
	return out, nil
}

// =============================================================================
// Platform identity provider
// =============================================================================

// PlatformIdPRepository implements admin.PlatformIdPRepository.
type PlatformIdPRepository struct {
	db *DB
}

// NewPlatformIdPRepository creates the repository.
func NewPlatformIdPRepository(db *DB) *PlatformIdPRepository {
	return &PlatformIdPRepository{db: db}
}

var _ admin.PlatformIdPRepository = (*PlatformIdPRepository)(nil)

// Get returns the configuration or admin.ErrPlatformIdPNotConfigured.
func (r *PlatformIdPRepository) Get(ctx context.Context) (*admin.PlatformIdP, error) {
	var (
		p         admin.PlatformIdP
		updatedBy sql.NullString
	)
	err := r.db.QueryRowContext(ctx, `
		SELECT enabled, display_name, issuer, client_id, client_secret_encrypted, redirect_uri,
		       scopes, authorization_endpoint, token_endpoint, jwks_uri, token_endpoint_auth_method,
		       require_idp, trusted_acr_values, trusted_amr_values, created_at, updated_at, updated_by
		FROM platform_identity_provider WHERE id = 1`).Scan(
		&p.Enabled, &p.DisplayName, &p.Issuer, &p.ClientID, &p.ClientSecretEncrypted, &p.RedirectURI,
		pq.Array(&p.Scopes), &p.AuthorizationEndpoint, &p.TokenEndpoint, &p.JWKSURI, &p.TokenEndpointAuthMethod,
		&p.RequireIdP, pq.Array(&p.TrustedACRValues), pq.Array(&p.TrustedAMRValues),
		&p.CreatedAt, &p.UpdatedAt, &updatedBy,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, admin.ErrPlatformIdPNotConfigured
	}
	if err != nil {
		return nil, fmt.Errorf("get platform idp: %w", err)
	}
	if updatedBy.Valid {
		if id, err := shared.IDFromString(updatedBy.String); err == nil {
			p.UpdatedBy = &id
		}
	}
	return &p, nil
}

// Save upserts the configuration under the roster lock (see the interface).
func (r *PlatformIdPRepository) Save(ctx context.Context, p *admin.PlatformIdP, clearBindings bool) error {
	return r.db.Transaction(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, adminRosterLock); err != nil {
			return fmt.Errorf("lock admin roster: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO platform_identity_provider (
				id, enabled, display_name, issuer, client_id, client_secret_encrypted, redirect_uri,
				scopes, authorization_endpoint, token_endpoint, jwks_uri, token_endpoint_auth_method,
				require_idp, trusted_acr_values, trusted_amr_values, updated_by, updated_at
			) VALUES (1, $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, NOW())
			ON CONFLICT (id) DO UPDATE SET
				enabled = EXCLUDED.enabled, display_name = EXCLUDED.display_name,
				issuer = EXCLUDED.issuer, client_id = EXCLUDED.client_id,
				client_secret_encrypted = EXCLUDED.client_secret_encrypted,
				redirect_uri = EXCLUDED.redirect_uri, scopes = EXCLUDED.scopes,
				authorization_endpoint = EXCLUDED.authorization_endpoint,
				token_endpoint = EXCLUDED.token_endpoint, jwks_uri = EXCLUDED.jwks_uri,
				token_endpoint_auth_method = EXCLUDED.token_endpoint_auth_method,
				require_idp = EXCLUDED.require_idp,
				trusted_acr_values = EXCLUDED.trusted_acr_values,
				trusted_amr_values = EXCLUDED.trusted_amr_values,
				updated_by = EXCLUDED.updated_by, updated_at = NOW()`,
			p.Enabled, p.DisplayName, p.Issuer, p.ClientID, p.ClientSecretEncrypted, p.RedirectURI,
			pq.Array(nonNilStrings(p.Scopes)), p.AuthorizationEndpoint, p.TokenEndpoint, p.JWKSURI, p.TokenEndpointAuthMethod,
			p.RequireIdP, pq.Array(nonNilStrings(p.TrustedACRValues)), pq.Array(nonNilStrings(p.TrustedAMRValues)),
			nullIDString(p.UpdatedBy),
		); err != nil {
			return fmt.Errorf("save platform idp: %w", err)
		}
		if clearBindings {
			if _, err := tx.ExecContext(ctx, `
				UPDATE admin_users SET idp_issuer = NULL, idp_subject = NULL, idp_bound_at = NULL, updated_at = NOW()
				WHERE idp_subject IS NOT NULL`); err != nil {
				return fmt.Errorf("clear idp bindings: %w", err)
			}
		}
		if p.Enforced() {
			var n int
			if err := tx.QueryRowContext(ctx, localSuperAdminsSQL).Scan(&n); err != nil {
				return fmt.Errorf("count break-glass super admins: %w", err)
			}
			if n == 0 {
				return admin.ErrLastLocalAdmin
			}
		}
		return nil
	})
}

// Delete removes the configuration.
func (r *PlatformIdPRepository) Delete(ctx context.Context) error {
	res, err := r.db.ExecContext(ctx, `DELETE FROM platform_identity_provider WHERE id = 1`)
	if err != nil {
		return fmt.Errorf("delete platform idp: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return admin.ErrPlatformIdPNotConfigured
	}
	return nil
}

// CreateLoginState stores one in-flight sign-in.
func (r *PlatformIdPRepository) CreateLoginState(ctx context.Context, s *admin.IdPLoginState) error {
	if _, err := r.db.ExecContext(ctx, `
		INSERT INTO admin_idp_login_states (state_hash, nonce, code_verifier_encrypted, created_at, expires_at)
		VALUES ($1, $2, $3, $4, $5)`,
		s.StateHash, s.Nonce, s.CodeVerifierEncrypted, s.CreatedAt, s.ExpiresAt); err != nil {
		return fmt.Errorf("create idp login state: %w", err)
	}
	return nil
}

// ConsumeLoginState deletes and returns an unexpired state (single use).
func (r *PlatformIdPRepository) ConsumeLoginState(ctx context.Context, stateHash string, now time.Time) (*admin.IdPLoginState, error) {
	var s admin.IdPLoginState
	err := r.db.QueryRowContext(ctx, `
		DELETE FROM admin_idp_login_states WHERE state_hash = $1
		RETURNING state_hash, nonce, code_verifier_encrypted, created_at, expires_at`, stateHash).Scan(
		&s.StateHash, &s.Nonce, &s.CodeVerifierEncrypted, &s.CreatedAt, &s.ExpiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, admin.ErrIdPLoginStateNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("consume idp login state: %w", err)
	}
	if !now.Before(s.ExpiresAt) {
		return nil, admin.ErrIdPLoginStateNotFound
	}
	return &s, nil
}

// DeleteExpiredLoginStates removes abandoned sign-ins.
func (r *PlatformIdPRepository) DeleteExpiredLoginStates(ctx context.Context, now time.Time) error {
	if _, err := r.db.ExecContext(ctx, `DELETE FROM admin_idp_login_states WHERE expires_at < $1`, now); err != nil {
		return fmt.Errorf("delete expired idp login states: %w", err)
	}
	return nil
}

// nonNilStrings keeps NOT NULL text[] columns from receiving NULL.
func nonNilStrings(v []string) []string {
	if v == nil {
		return []string{}
	}
	return v
}
