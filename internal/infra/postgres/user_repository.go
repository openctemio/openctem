package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/domain/user"
)

// userColumns is the list of columns to select for a user.
const userColumns = `id, keycloak_id, email, name, avatar_url, phone, status, preferences, last_login_at, created_at, updated_at,
	auth_provider, password_hash, email_verified, email_verification_token, email_verification_expires_at,
	password_reset_token, password_reset_expires_at, failed_login_attempts, locked_until`

// UserRepository implements user.Repository using PostgreSQL.
type UserRepository struct {
	db *DB
}

// NewUserRepository creates a new UserRepository.
func NewUserRepository(db *DB) *UserRepository {
	return &UserRepository{db: db}
}

// Create persists a new user.
func (r *UserRepository) Create(ctx context.Context, u *user.User) error {
	preferences, err := json.Marshal(u.Preferences())
	if err != nil {
		return fmt.Errorf("failed to marshal preferences: %w", err)
	}

	query := `
		INSERT INTO users (
			id, keycloak_id, email, name, avatar_url, phone, status, preferences, last_login_at, created_at, updated_at,
			auth_provider, password_hash, email_verified, email_verification_token, email_verification_expires_at,
			password_reset_token, password_reset_expires_at, failed_login_attempts, locked_until
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20)
	`

	_, err = r.db.ExecContext(ctx, query,
		u.ID().String(),
		u.KeycloakID(),
		u.Email(),
		u.Name(),
		nullString(u.AvatarURL()),
		nullString(u.Phone()),
		u.Status().String(),
		preferences,
		nullTime(u.LastLoginAt()),
		u.CreatedAt(),
		u.UpdatedAt(),
		u.AuthProvider().String(),
		u.PasswordHash(),
		u.EmailVerified(),
		u.EmailVerificationToken(),
		nullTime(u.EmailVerificationExpiresAt()),
		u.PasswordResetToken(),
		nullTime(u.PasswordResetExpiresAt()),
		u.FailedLoginAttempts(),
		nullTime(u.LockedUntil()),
	)

	if err != nil {
		if isUniqueViolation(err) {
			return user.AlreadyExistsError(u.Email())
		}
		return fmt.Errorf("failed to create user: %w", err)
	}

	return nil
}

// GetByID retrieves a user by ID.
func (r *UserRepository) GetByID(ctx context.Context, id shared.ID) (*user.User, error) {
	query := fmt.Sprintf(`SELECT %s FROM users WHERE id = $1`, userColumns)

	row := r.db.QueryRowContext(ctx, query, id.String())
	u, err := r.scanUser(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, user.NotFoundError(id)
		}
		return nil, err
	}

	return u, nil
}

// GetByKeycloakID retrieves a user by Keycloak ID.
func (r *UserRepository) GetByKeycloakID(ctx context.Context, keycloakID string) (*user.User, error) {
	query := fmt.Sprintf(`SELECT %s FROM users WHERE keycloak_id = $1`, userColumns)

	row := r.db.QueryRowContext(ctx, query, keycloakID)
	u, err := r.scanUser(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, user.NotFoundByKeycloakIDError(keycloakID)
		}
		return nil, err
	}

	return u, nil
}

// GetByEmail retrieves a user by email.
func (r *UserRepository) GetByEmail(ctx context.Context, email string) (*user.User, error) {
	query := fmt.Sprintf(`SELECT %s FROM users WHERE email = $1`, userColumns)

	row := r.db.QueryRowContext(ctx, query, email)
	u, err := r.scanUser(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, user.NotFoundByEmailError(email)
		}
		return nil, err
	}

	return u, nil
}

// GetByEmailForAuth retrieves a local user by email for authentication.
func (r *UserRepository) GetByEmailForAuth(ctx context.Context, email string) (*user.User, error) {
	query := fmt.Sprintf(`SELECT %s FROM users WHERE email = $1 AND auth_provider = 'local'`, userColumns)

	row := r.db.QueryRowContext(ctx, query, email)
	u, err := r.scanUser(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, user.NotFoundByEmailError(email)
		}
		return nil, err
	}

	return u, nil
}

// GetByEmailVerificationToken retrieves a user by email verification token.
func (r *UserRepository) GetByEmailVerificationToken(ctx context.Context, token string) (*user.User, error) {
	query := fmt.Sprintf(`
		SELECT %s FROM users
		WHERE email_verification_token = $1
		  AND email_verification_expires_at > NOW()
	`, userColumns)

	row := r.db.QueryRowContext(ctx, query, token)
	u, err := r.scanUser(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, user.ErrInvalidVerificationToken
		}
		return nil, err
	}

	return u, nil
}

// GetByPasswordResetToken retrieves a user by password reset token.
func (r *UserRepository) GetByPasswordResetToken(ctx context.Context, token string) (*user.User, error) {
	query := fmt.Sprintf(`
		SELECT %s FROM users
		WHERE password_reset_token = $1
		  AND password_reset_expires_at > NOW()
	`, userColumns)

	row := r.db.QueryRowContext(ctx, query, token)
	u, err := r.scanUser(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, user.ErrInvalidPasswordResetToken
		}
		return nil, err
	}

	return u, nil
}

// Update updates an existing user.
func (r *UserRepository) Update(ctx context.Context, u *user.User) error {
	preferences, err := json.Marshal(u.Preferences())
	if err != nil {
		return fmt.Errorf("failed to marshal preferences: %w", err)
	}

	query := `
		UPDATE users
		SET keycloak_id = $2, email = $3, name = $4, avatar_url = $5, phone = $6,
		    status = $7, preferences = $8, last_login_at = $9, updated_at = $10,
		    auth_provider = $11, password_hash = $12, email_verified = $13,
		    email_verification_token = $14, email_verification_expires_at = $15,
		    password_reset_token = $16, password_reset_expires_at = $17,
		    failed_login_attempts = $18, locked_until = $19
		WHERE id = $1
	`

	result, err := r.db.ExecContext(ctx, query,
		u.ID().String(),
		u.KeycloakID(),
		u.Email(),
		u.Name(),
		nullString(u.AvatarURL()),
		nullString(u.Phone()),
		u.Status().String(),
		preferences,
		nullTime(u.LastLoginAt()),
		u.UpdatedAt(),
		u.AuthProvider().String(),
		u.PasswordHash(),
		u.EmailVerified(),
		u.EmailVerificationToken(),
		nullTime(u.EmailVerificationExpiresAt()),
		u.PasswordResetToken(),
		nullTime(u.PasswordResetExpiresAt()),
		u.FailedLoginAttempts(),
		nullTime(u.LockedUntil()),
	)

	if err != nil {
		if isUniqueViolation(err) {
			return user.AlreadyExistsError(u.Email())
		}
		return fmt.Errorf("failed to update user: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return user.NotFoundError(u.ID())
	}

	return nil
}

// Delete removes a user by ID.
func (r *UserRepository) Delete(ctx context.Context, id shared.ID) error {
	query := `DELETE FROM users WHERE id = $1`

	result, err := r.db.ExecContext(ctx, query, id.String())
	if err != nil {
		return fmt.Errorf("failed to delete user: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return user.NotFoundError(id)
	}

	return nil
}

// ExistsByEmail checks if a user with the given email exists.
func (r *UserRepository) ExistsByEmail(ctx context.Context, email string) (bool, error) {
	query := `SELECT EXISTS(SELECT 1 FROM users WHERE email = $1)`

	var exists bool
	err := r.db.QueryRowContext(ctx, query, email).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("failed to check user existence: %w", err)
	}

	return exists, nil
}

// ExistsByKeycloakID checks if a user with the given Keycloak ID exists.
func (r *UserRepository) ExistsByKeycloakID(ctx context.Context, keycloakID string) (bool, error) {
	query := `SELECT EXISTS(SELECT 1 FROM users WHERE keycloak_id = $1)`

	var exists bool
	err := r.db.QueryRowContext(ctx, query, keycloakID).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("failed to check user existence: %w", err)
	}

	return exists, nil
}

// UpsertFromKeycloak creates or updates a user from Keycloak claims.
// This is the primary method used for syncing users on login.
// It handles email conflicts by keeping the existing email if conflict occurs.
func (r *UserRepository) UpsertFromKeycloak(ctx context.Context, keycloakID, email, name string) (*user.User, error) {
	// Use a more robust upsert that handles email conflicts
	query := fmt.Sprintf(`
		INSERT INTO users (id, keycloak_id, email, name, status, preferences, last_login_at, created_at, updated_at,
			auth_provider, email_verified, failed_login_attempts)
		VALUES (gen_random_uuid(), $1, $2, $3, 'active', '{}', NOW(), NOW(), NOW(), 'oidc', true, 0)
		ON CONFLICT (keycloak_id) DO UPDATE SET
			email = CASE
				WHEN NOT EXISTS (SELECT 1 FROM users WHERE email = EXCLUDED.email AND keycloak_id != $1)
				THEN EXCLUDED.email
				ELSE users.email
			END,
			name = CASE WHEN users.name = 'Unknown User' OR users.name = '' THEN EXCLUDED.name ELSE users.name END,
			last_login_at = NOW(),
			updated_at = NOW()
		RETURNING %s
	`, userColumns)

	row := r.db.QueryRowContext(ctx, query, keycloakID, email, name)
	u, err := r.scanUser(row)
	if err != nil {
		// If email conflict on insert, try to find existing user with same keycloak_id
		if isUniqueViolation(err) {
			return r.GetByKeycloakID(ctx, keycloakID)
		}
		return nil, err
	}
	return u, nil
}

// GetByIDs retrieves multiple users by their IDs.
func (r *UserRepository) GetByIDs(ctx context.Context, ids []shared.ID) ([]*user.User, error) {
	if len(ids) == 0 {
		return []*user.User{}, nil
	}

	// Build placeholder string
	placeholders := make([]string, len(ids))
	args := make([]any, len(ids))
	for i, id := range ids {
		placeholders[i] = fmt.Sprintf("$%d", i+1)
		args[i] = id.String()
	}

	query := fmt.Sprintf(`
		SELECT %s
		FROM users
		WHERE id IN (%s)
	`, userColumns, strings.Join(placeholders, ", "))

	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to query users: %w", err)
	}
	defer rows.Close()

	var users []*user.User
	for rows.Next() {
		u, err := r.scanUserFromRows(rows)
		if err != nil {
			return nil, err
		}
		users = append(users, u)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed to iterate users: %w", err)
	}

	return users, nil
}

// Count returns the total number of users matching the filter.
func (r *UserRepository) Count(ctx context.Context, filter user.Filter) (int64, error) {
	query := `SELECT COUNT(*) FROM users`

	whereClause, args := r.buildWhereClause(filter)
	if whereClause != "" {
		query += " WHERE " + whereClause
	}

	var count int64
	err := r.db.QueryRowContext(ctx, query, args...).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("failed to count users: %w", err)
	}

	return count, nil
}

// Helper methods

// userScanFields is a struct to hold all scanned fields
type userScanFields struct {
	idStr                      string
	keycloakID                 sql.NullString
	email                      string
	name                       string
	avatarURL                  sql.NullString
	phone                      sql.NullString
	status                     string
	preferences                []byte
	lastLoginAt                sql.NullTime
	createdAt                  time.Time
	updatedAt                  time.Time
	authProvider               sql.NullString
	passwordHash               sql.NullString
	emailVerified              bool
	emailVerificationToken     sql.NullString
	emailVerificationExpiresAt sql.NullTime
	passwordResetToken         sql.NullString
	passwordResetExpiresAt     sql.NullTime
	failedLoginAttempts        int
	lockedUntil                sql.NullTime
}

func (r *UserRepository) scanUser(row *sql.Row) (*user.User, error) {
	var f userScanFields

	err := row.Scan(
		&f.idStr, &f.keycloakID, &f.email, &f.name, &f.avatarURL, &f.phone,
		&f.status, &f.preferences, &f.lastLoginAt, &f.createdAt, &f.updatedAt,
		&f.authProvider, &f.passwordHash, &f.emailVerified,
		&f.emailVerificationToken, &f.emailVerificationExpiresAt,
		&f.passwordResetToken, &f.passwordResetExpiresAt,
		&f.failedLoginAttempts, &f.lockedUntil,
	)
	if err != nil {
		return nil, err
	}

	return r.reconstructUser(f)
}

func (r *UserRepository) scanUserFromRows(rows *sql.Rows) (*user.User, error) {
	var f userScanFields

	err := rows.Scan(
		&f.idStr, &f.keycloakID, &f.email, &f.name, &f.avatarURL, &f.phone,
		&f.status, &f.preferences, &f.lastLoginAt, &f.createdAt, &f.updatedAt,
		&f.authProvider, &f.passwordHash, &f.emailVerified,
		&f.emailVerificationToken, &f.emailVerificationExpiresAt,
		&f.passwordResetToken, &f.passwordResetExpiresAt,
		&f.failedLoginAttempts, &f.lockedUntil,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to scan user: %w", err)
	}

	return r.reconstructUser(f)
}

func (r *UserRepository) reconstructUser(f userScanFields) (*user.User, error) {
	parsedID, err := shared.IDFromString(f.idStr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse id: %w", err)
	}

	var kcID *string
	if f.keycloakID.Valid {
		kcID = &f.keycloakID.String
	}

	var prefs user.Preferences
	if len(f.preferences) > 0 {
		if err := json.Unmarshal(f.preferences, &prefs); err != nil {
			prefs = user.Preferences{}
		}
	}

	var lastLogin *time.Time
	if f.lastLoginAt.Valid {
		lastLogin = &f.lastLoginAt.Time
	}

	status := user.Status(f.status)
	if !status.IsValid() {
		status = user.StatusActive
	}

	// Parse auth provider with default
	authProvider := user.AuthProviderOIDC
	if f.authProvider.Valid && f.authProvider.String != "" {
		authProvider = user.AuthProvider(f.authProvider.String)
	}

	var passwordHash *string
	if f.passwordHash.Valid {
		passwordHash = &f.passwordHash.String
	}

	var emailVerificationToken *string
	if f.emailVerificationToken.Valid {
		emailVerificationToken = &f.emailVerificationToken.String
	}

	var emailVerificationExpiresAt *time.Time
	if f.emailVerificationExpiresAt.Valid {
		emailVerificationExpiresAt = &f.emailVerificationExpiresAt.Time
	}

	var passwordResetToken *string
	if f.passwordResetToken.Valid {
		passwordResetToken = &f.passwordResetToken.String
	}

	var passwordResetExpiresAt *time.Time
	if f.passwordResetExpiresAt.Valid {
		passwordResetExpiresAt = &f.passwordResetExpiresAt.Time
	}

	var lockedUntil *time.Time
	if f.lockedUntil.Valid {
		lockedUntil = &f.lockedUntil.Time
	}

	return user.Reconstitute(
		parsedID,
		kcID,
		f.email,
		f.name,
		nullStringValue(f.avatarURL),
		nullStringValue(f.phone),
		status,
		prefs,
		lastLogin,
		f.createdAt,
		f.updatedAt,
		authProvider,
		passwordHash,
		f.emailVerified,
		emailVerificationToken,
		emailVerificationExpiresAt,
		passwordResetToken,
		passwordResetExpiresAt,
		f.failedLoginAttempts,
		lockedUntil,
	), nil
}

func (r *UserRepository) buildWhereClause(filter user.Filter) (string, []any) {
	var conditions []string
	var args []any
	argIndex := 1

	if filter.Email != nil && *filter.Email != "" {
		conditions = append(conditions, fmt.Sprintf("email ILIKE $%d", argIndex))
		args = append(args, wrapLikePattern(*filter.Email))
		argIndex++
	}

	if filter.Status != nil {
		conditions = append(conditions, fmt.Sprintf("status = $%d", argIndex))
		args = append(args, filter.Status.String())
		argIndex++
	}

	if len(filter.Statuses) > 0 {
		placeholders := make([]string, len(filter.Statuses))
		for i, s := range filter.Statuses {
			placeholders[i] = fmt.Sprintf("$%d", argIndex)
			args = append(args, s.String())
			argIndex++
		}
		conditions = append(conditions, fmt.Sprintf("status IN (%s)", strings.Join(placeholders, ", ")))
	}

	return strings.Join(conditions, " AND "), args
}

// Ensure UserRepository implements user.Repository
var _ user.Repository = (*UserRepository)(nil)
