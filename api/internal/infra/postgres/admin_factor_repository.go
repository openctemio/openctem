package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/pkg/domain/admin"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// AdminFactorRepository persists console WebAuthn authenticators, recovery
// codes and ceremony state (RFC-078, console part). Platform-level tables:
// every query is keyed on the administrator, never on a tenant.
type AdminFactorRepository struct {
	db *DB
}

// NewAdminFactorRepository creates the repository.
func NewAdminFactorRepository(db *DB) *AdminFactorRepository {
	return &AdminFactorRepository{db: db}
}

var _ admin.FactorRepository = (*AdminFactorRepository)(nil)

// ListWebAuthnCredentials returns the administrator's authenticators, oldest first.
func (r *AdminFactorRepository) ListWebAuthnCredentials(ctx context.Context, adminID shared.ID) ([]*admin.WebAuthnCredential, error) {
	const q = `
		SELECT id, admin_id, credential_id, public_key, sign_count, aaguid, transports,
		       attachment, attestation_fmt, user_verified, backup_eligible, backup_state,
		       name, created_at, last_used_at
		FROM admin_webauthn_credentials WHERE admin_id = $1
		ORDER BY created_at, id`
	rows, err := r.db.QueryContext(ctx, q, adminID.String())
	if err != nil {
		return nil, fmt.Errorf("list webauthn credentials: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := make([]*admin.WebAuthnCredential, 0, 4)
	for rows.Next() {
		var (
			c          admin.WebAuthnCredential
			id, aid    string
			aaguid     sql.NullString
			signCount  int64
			transports pq.StringArray
			lastUsed   sql.NullTime
		)
		if err := rows.Scan(&id, &aid, &c.CredentialID, &c.PublicKey, &signCount, &aaguid, &transports,
			&c.Attachment, &c.AttestationFmt, &c.UserVerified, &c.BackupEligible, &c.BackupState,
			&c.Name, &c.CreatedAt, &lastUsed); err != nil {
			return nil, fmt.Errorf("scan webauthn credential: %w", err)
		}
		if c.ID, err = shared.IDFromString(id); err != nil {
			return nil, err
		}
		if c.AdminID, err = shared.IDFromString(aid); err != nil {
			return nil, err
		}
		if signCount >= 0 && signCount <= int64(^uint32(0)) {
			c.SignCount = uint32(signCount)
		}
		if aaguid.Valid {
			if u, perr := uuid.Parse(aaguid.String); perr == nil {
				c.AAGUID = u[:]
			}
		}
		c.Transports = []string(transports)
		if lastUsed.Valid {
			t := lastUsed.Time
			c.LastUsedAt = &t
		}
		out = append(out, &c)
	}
	return out, rows.Err()
}

// CreateWebAuthnCredential stores a new authenticator under the per-admin cap.
// The cap is checked in the same statement, so two concurrent registrations
// cannot pass it together for long (the unique credential id stops duplicates).
func (r *AdminFactorRepository) CreateWebAuthnCredential(ctx context.Context, c *admin.WebAuthnCredential) error {
	var aaguid any
	if len(c.AAGUID) == 16 {
		u, err := uuid.FromBytes(c.AAGUID)
		if err == nil {
			aaguid = u.String()
		}
	}
	transports := c.Transports
	if transports == nil {
		transports = []string{}
	}
	const q = `
		INSERT INTO admin_webauthn_credentials
		    (id, admin_id, credential_id, public_key, sign_count, aaguid, transports,
		     attachment, attestation_fmt, user_verified, backup_eligible, backup_state, name, created_at)
		SELECT $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14
		WHERE (SELECT count(*) FROM admin_webauthn_credentials WHERE admin_id = $2) < $15`
	res, err := r.db.ExecContext(ctx, q, c.ID.String(), c.AdminID.String(), c.CredentialID, c.PublicKey,
		int64(c.SignCount), aaguid, pq.StringArray(transports), c.Attachment, c.AttestationFmt,
		c.UserVerified, c.BackupEligible, c.BackupState, c.Name, c.CreatedAt, admin.MaxWebAuthnCredentials)
	if err != nil {
		var pqErr *pq.Error
		if errors.As(err, &pqErr) && pqErr.Code == "23505" {
			return admin.ErrWebAuthnCredentialExists
		}
		return fmt.Errorf("create webauthn credential: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return admin.ErrTooManyWebAuthnCredentials
	}
	return nil
}

// RecordWebAuthnUse stores a verified assertion's counter. A counter that
// does not move forward is refused when either side is non-zero (synced
// passkeys report 0 and are not counter-checked).
func (r *AdminFactorRepository) RecordWebAuthnUse(ctx context.Context, adminID, id shared.ID, signCount uint32, backupState bool, at time.Time) (bool, error) {
	const q = `
		UPDATE admin_webauthn_credentials
		SET sign_count = $3, backup_state = $4, last_used_at = $5
		WHERE admin_id = $1 AND id = $2
		  AND (($3 = 0 AND sign_count = 0) OR $3 > sign_count)`
	res, err := r.db.ExecContext(ctx, q, adminID.String(), id.String(), int64(signCount), backupState, at)
	if err != nil {
		return false, fmt.Errorf("record webauthn use: %w", err)
	}
	n, _ := res.RowsAffected()
	return n == 1, nil
}

// RenameWebAuthnCredential relabels one authenticator of adminID.
func (r *AdminFactorRepository) RenameWebAuthnCredential(ctx context.Context, adminID, id shared.ID, name string) error {
	res, err := r.db.ExecContext(ctx,
		`UPDATE admin_webauthn_credentials SET name = $3 WHERE admin_id = $1 AND id = $2`,
		adminID.String(), id.String(), name)
	if err != nil {
		return fmt.Errorf("rename webauthn credential: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return admin.ErrWebAuthnCredentialNotFound
	}
	return nil
}

// DeleteWebAuthnCredential removes one authenticator of adminID unless fewer
// than keep would remain. The row lock on the administrator serializes two
// concurrent deletes, so they cannot both pass the floor.
func (r *AdminFactorRepository) DeleteWebAuthnCredential(ctx context.Context, adminID, id shared.ID, keep int) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("delete webauthn credential: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `SELECT 1 FROM admin_users WHERE id = $1 FOR UPDATE`, adminID.String()); err != nil {
		return fmt.Errorf("lock administrator: %w", err)
	}
	var exists bool
	if err := tx.QueryRowContext(ctx,
		`SELECT EXISTS (SELECT 1 FROM admin_webauthn_credentials WHERE admin_id = $1 AND id = $2)`,
		adminID.String(), id.String()).Scan(&exists); err != nil {
		return fmt.Errorf("delete webauthn credential: %w", err)
	}
	if !exists {
		return admin.ErrWebAuthnCredentialNotFound
	}
	var count int
	if err := tx.QueryRowContext(ctx,
		`SELECT count(*) FROM admin_webauthn_credentials WHERE admin_id = $1`, adminID.String()).Scan(&count); err != nil {
		return fmt.Errorf("delete webauthn credential: %w", err)
	}
	if count-1 < keep {
		return admin.ErrLastWebAuthnCredential
	}
	if _, err := tx.ExecContext(ctx,
		`DELETE FROM admin_webauthn_credentials WHERE admin_id = $1 AND id = $2`, adminID.String(), id.String()); err != nil {
		return fmt.Errorf("delete webauthn credential: %w", err)
	}
	return tx.Commit()
}

// DeleteFactorsForAdmin removes every authenticator and recovery code of adminID.
func (r *AdminFactorRepository) DeleteFactorsForAdmin(ctx context.Context, adminID shared.ID) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("delete admin factors: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `DELETE FROM admin_webauthn_credentials WHERE admin_id = $1`, adminID.String()); err != nil {
		return fmt.Errorf("delete admin authenticators: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM admin_recovery_codes WHERE admin_id = $1`, adminID.String()); err != nil {
		return fmt.Errorf("delete admin recovery codes: %w", err)
	}
	return tx.Commit()
}

// ReplaceRecoveryCodes drops every code of adminID and stores the new hashes
// in one transaction.
func (r *AdminFactorRepository) ReplaceRecoveryCodes(ctx context.Context, adminID shared.ID, hashes []string, at time.Time) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("replace recovery codes: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `DELETE FROM admin_recovery_codes WHERE admin_id = $1`, adminID.String()); err != nil {
		return fmt.Errorf("replace recovery codes: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO admin_recovery_codes (admin_id, code_hash, created_at)
		SELECT $1, h, $3 FROM unnest($2::text[]) AS h`,
		adminID.String(), pq.StringArray(hashes), at); err != nil {
		return fmt.Errorf("replace recovery codes: %w", err)
	}
	return tx.Commit()
}

// UseRecoveryCode spends one unused code; false when none matches.
func (r *AdminFactorRepository) UseRecoveryCode(ctx context.Context, adminID shared.ID, hash string, at time.Time) (bool, error) {
	res, err := r.db.ExecContext(ctx, `
		UPDATE admin_recovery_codes SET used_at = $3
		WHERE admin_id = $1 AND code_hash = $2 AND used_at IS NULL`,
		adminID.String(), hash, at)
	if err != nil {
		return false, fmt.Errorf("use recovery code: %w", err)
	}
	n, _ := res.RowsAffected()
	return n == 1, nil
}

// CountRecoveryCodes returns the unused codes of adminID.
func (r *AdminFactorRepository) CountRecoveryCodes(ctx context.Context, adminID shared.ID) (int, error) {
	var n int
	if err := r.db.QueryRowContext(ctx,
		`SELECT count(*) FROM admin_recovery_codes WHERE admin_id = $1 AND used_at IS NULL`,
		adminID.String()).Scan(&n); err != nil {
		return 0, fmt.Errorf("count recovery codes: %w", err)
	}
	return n, nil
}

// SaveCeremony stores (replacing) the open ceremony of a console session.
func (r *AdminFactorRepository) SaveCeremony(ctx context.Context, sessionID shared.ID, purpose string, data []byte, expiresAt time.Time) error {
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO admin_webauthn_ceremonies (session_id, purpose, session_data, expires_at)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (session_id, purpose) DO UPDATE
		SET session_data = EXCLUDED.session_data, expires_at = EXCLUDED.expires_at`,
		sessionID.String(), purpose, data, expiresAt)
	if err != nil {
		return fmt.Errorf("save webauthn ceremony: %w", err)
	}
	return nil
}

// TakeCeremony removes the open ceremony and returns it when it has not expired.
func (r *AdminFactorRepository) TakeCeremony(ctx context.Context, sessionID shared.ID, purpose string, now time.Time) ([]byte, error) {
	var (
		data    []byte
		expires time.Time
	)
	err := r.db.QueryRowContext(ctx, `
		DELETE FROM admin_webauthn_ceremonies WHERE session_id = $1 AND purpose = $2
		RETURNING session_data, expires_at`, sessionID.String(), purpose).Scan(&data, &expires)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, admin.ErrCeremonyNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("take webauthn ceremony: %w", err)
	}
	if !now.Before(expires) {
		return nil, admin.ErrCeremonyNotFound
	}
	return data, nil
}
