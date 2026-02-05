package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/openctemio/api/pkg/domain/secretstore"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/pagination"
)

// SecretStoreRepository implements secretstore.Repository using PostgreSQL.
type SecretStoreRepository struct {
	db *DB
}

// NewSecretStoreRepository creates a new SecretStoreRepository.
func NewSecretStoreRepository(db *DB) *SecretStoreRepository {
	return &SecretStoreRepository{db: db}
}

// Create persists a new secretstore.
func (r *SecretStoreRepository) Create(ctx context.Context, c *secretstore.Credential) error {
	query := `
		INSERT INTO credentials (
			id, tenant_id, name, credential_type, description,
			encrypted_data, key_version, encryption_algorithm,
			last_used_at, last_rotated_at, expires_at,
			created_by, created_at, updated_at
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
	`

	var createdBy sql.NullString
	var lastUsedAt, lastRotatedAt, expiresAt sql.NullTime

	if c.CreatedBy != nil {
		createdBy = sql.NullString{String: c.CreatedBy.String(), Valid: true}
	}
	if c.LastUsedAt != nil {
		lastUsedAt = sql.NullTime{Time: *c.LastUsedAt, Valid: true}
	}
	if c.LastRotatedAt != nil {
		lastRotatedAt = sql.NullTime{Time: *c.LastRotatedAt, Valid: true}
	}
	if c.ExpiresAt != nil {
		expiresAt = sql.NullTime{Time: *c.ExpiresAt, Valid: true}
	}

	_, err := r.db.ExecContext(ctx, query,
		c.ID.String(),
		c.TenantID.String(),
		c.Name,
		string(c.CredentialType),
		c.Description,
		c.EncryptedData,
		c.KeyVersion,
		c.EncryptionAlgorithm,
		lastUsedAt,
		lastRotatedAt,
		expiresAt,
		createdBy,
		c.CreatedAt,
		c.UpdatedAt,
	)

	if err != nil {
		if isUniqueViolation(err) {
			return shared.NewDomainError("ALREADY_EXISTS", "credential with this name already exists", shared.ErrAlreadyExists)
		}
		return fmt.Errorf("failed to create credential: %w", err)
	}

	return nil
}

// GetByTenantAndID retrieves a credential by tenant and ID.
func (r *SecretStoreRepository) GetByTenantAndID(ctx context.Context, tenantID, id shared.ID) (*secretstore.Credential, error) {
	query := `
		SELECT id, tenant_id, name, credential_type, description,
			encrypted_data, key_version, encryption_algorithm,
			last_used_at, last_rotated_at, expires_at,
			created_by, created_at, updated_at
		FROM credentials
		WHERE tenant_id = $1 AND id = $2
	`

	cred, err := r.scanCredential(r.db.QueryRowContext(ctx, query, tenantID.String(), id.String()))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, shared.NewDomainError("NOT_FOUND", "credential not found", shared.ErrNotFound)
		}
		return nil, fmt.Errorf("failed to get credential: %w", err)
	}

	return cred, nil
}

// GetByTenantAndName retrieves a credential by tenant and name.
func (r *SecretStoreRepository) GetByTenantAndName(ctx context.Context, tenantID shared.ID, name string) (*secretstore.Credential, error) {
	query := `
		SELECT id, tenant_id, name, credential_type, description,
			encrypted_data, key_version, encryption_algorithm,
			last_used_at, last_rotated_at, expires_at,
			created_by, created_at, updated_at
		FROM credentials
		WHERE tenant_id = $1 AND name = $2
	`

	cred, err := r.scanCredential(r.db.QueryRowContext(ctx, query, tenantID.String(), name))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, shared.NewDomainError("NOT_FOUND", "credential not found", shared.ErrNotFound)
		}
		return nil, fmt.Errorf("failed to get credential: %w", err)
	}

	return cred, nil
}

// List lists credentials with pagination and filtering.
func (r *SecretStoreRepository) List(ctx context.Context, input secretstore.ListInput) (*secretstore.ListOutput, error) {
	baseQuery := `
		SELECT id, tenant_id, name, credential_type, description,
			encrypted_data, key_version, encryption_algorithm,
			last_used_at, last_rotated_at, expires_at,
			created_by, created_at, updated_at
		FROM credentials
	`
	countQuery := `SELECT COUNT(*) FROM credentials`

	var conditions []string
	var args []any
	argIdx := 1

	// Tenant filter (required)
	conditions = append(conditions, fmt.Sprintf("tenant_id = $%d", argIdx))
	args = append(args, input.TenantID.String())
	argIdx++

	// Credential type filter
	if input.CredentialType != nil {
		conditions = append(conditions, fmt.Sprintf("credential_type = $%d", argIdx))
		args = append(args, string(*input.CredentialType))
		argIdx++
	}

	whereClause := " WHERE " + strings.Join(conditions, " AND ")
	baseQuery += whereClause
	countQuery += whereClause

	// Get total count
	var totalCount int
	if err := r.db.QueryRowContext(ctx, countQuery, args...).Scan(&totalCount); err != nil {
		return nil, fmt.Errorf("failed to count credentials: %w", err)
	}

	// Sorting
	sortBy := sortFieldCreatedAt
	if input.SortBy != "" {
		switch input.SortBy {
		case "name", "credential_type", sortFieldCreatedAt, sortFieldUpdatedAt, "last_used_at":
			sortBy = input.SortBy
		}
	}
	sortOrder := sortOrderDESC
	if input.SortOrder == sortOrderAscLower {
		sortOrder = sortOrderASC
	}
	baseQuery += fmt.Sprintf(" ORDER BY %s %s", sortBy, sortOrder)

	// Pagination
	p := pagination.New(input.Page, input.PageSize)
	baseQuery += fmt.Sprintf(" LIMIT %d OFFSET %d", p.Limit(), p.Offset())

	// Execute query
	rows, err := r.db.QueryContext(ctx, baseQuery, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to list credentials: %w", err)
	}
	defer rows.Close()

	var creds []*secretstore.Credential
	for rows.Next() {
		cred, err := r.scanCredentialRow(rows)
		if err != nil {
			return nil, fmt.Errorf("failed to scan credential: %w", err)
		}
		creds = append(creds, cred)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed to iterate credentials: %w", err)
	}

	return &secretstore.ListOutput{
		Items:      creds,
		TotalCount: totalCount,
	}, nil
}

// Update updates a secretstore.
func (r *SecretStoreRepository) Update(ctx context.Context, c *secretstore.Credential) error {
	query := `
		UPDATE credentials SET
			name = $1,
			description = $2,
			encrypted_data = $3,
			key_version = $4,
			last_used_at = $5,
			last_rotated_at = $6,
			expires_at = $7,
			updated_at = $8
		WHERE id = $9
	`

	var lastUsedAt, lastRotatedAt, expiresAt sql.NullTime

	if c.LastUsedAt != nil {
		lastUsedAt = sql.NullTime{Time: *c.LastUsedAt, Valid: true}
	}
	if c.LastRotatedAt != nil {
		lastRotatedAt = sql.NullTime{Time: *c.LastRotatedAt, Valid: true}
	}
	if c.ExpiresAt != nil {
		expiresAt = sql.NullTime{Time: *c.ExpiresAt, Valid: true}
	}

	result, err := r.db.ExecContext(ctx, query,
		c.Name,
		c.Description,
		c.EncryptedData,
		c.KeyVersion,
		lastUsedAt,
		lastRotatedAt,
		expiresAt,
		c.UpdatedAt,
		c.ID.String(),
	)

	if err != nil {
		if isUniqueViolation(err) {
			return shared.NewDomainError("ALREADY_EXISTS", "credential with this name already exists", shared.ErrAlreadyExists)
		}
		return fmt.Errorf("failed to update credential: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return shared.NewDomainError("NOT_FOUND", "credential not found", shared.ErrNotFound)
	}

	return nil
}

// DeleteByTenantAndID deletes a credential with tenant validation.
func (r *SecretStoreRepository) DeleteByTenantAndID(ctx context.Context, tenantID, id shared.ID) error {
	query := `DELETE FROM credentials WHERE tenant_id = $1 AND id = $2`

	result, err := r.db.ExecContext(ctx, query, tenantID.String(), id.String())
	if err != nil {
		return fmt.Errorf("failed to delete credential: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return shared.NewDomainError("NOT_FOUND", "credential not found", shared.ErrNotFound)
	}

	return nil
}

// UpdateLastUsedByTenantAndID updates only the last_used_at field with tenant validation.
func (r *SecretStoreRepository) UpdateLastUsedByTenantAndID(ctx context.Context, tenantID, id shared.ID) error {
	query := `UPDATE credentials SET last_used_at = NOW() WHERE tenant_id = $1 AND id = $2`

	result, err := r.db.ExecContext(ctx, query, tenantID.String(), id.String())
	if err != nil {
		return fmt.Errorf("failed to update last used: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return shared.NewDomainError("NOT_FOUND", "credential not found", shared.ErrNotFound)
	}

	return nil
}

// CountByTenant counts credentials for a tenant.
func (r *SecretStoreRepository) CountByTenant(ctx context.Context, tenantID shared.ID) (int, error) {
	query := `SELECT COUNT(*) FROM credentials WHERE tenant_id = $1`

	var count int
	if err := r.db.QueryRowContext(ctx, query, tenantID.String()).Scan(&count); err != nil {
		return 0, fmt.Errorf("failed to count credentials: %w", err)
	}

	return count, nil
}

// scanCredential scans a single row into a Credential.
func (r *SecretStoreRepository) scanCredential(row *sql.Row) (*secretstore.Credential, error) {
	var c secretstore.Credential
	var id, tenantID string
	var createdBy sql.NullString
	var lastUsedAt, lastRotatedAt, expiresAt sql.NullTime

	err := row.Scan(
		&id,
		&tenantID,
		&c.Name,
		&c.CredentialType,
		&c.Description,
		&c.EncryptedData,
		&c.KeyVersion,
		&c.EncryptionAlgorithm,
		&lastUsedAt,
		&lastRotatedAt,
		&expiresAt,
		&createdBy,
		&c.CreatedAt,
		&c.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}

	c.ID, _ = shared.IDFromString(id)
	c.TenantID, _ = shared.IDFromString(tenantID)

	if createdBy.Valid {
		cbID, _ := shared.IDFromString(createdBy.String)
		c.CreatedBy = &cbID
	}
	if lastUsedAt.Valid {
		c.LastUsedAt = &lastUsedAt.Time
	}
	if lastRotatedAt.Valid {
		c.LastRotatedAt = &lastRotatedAt.Time
	}
	if expiresAt.Valid {
		c.ExpiresAt = &expiresAt.Time
	}

	return &c, nil
}

// scanCredentialRow scans a rows.Next() row into a Credential.
func (r *SecretStoreRepository) scanCredentialRow(rows *sql.Rows) (*secretstore.Credential, error) {
	var c secretstore.Credential
	var id, tenantID string
	var createdBy sql.NullString
	var lastUsedAt, lastRotatedAt, expiresAt sql.NullTime

	err := rows.Scan(
		&id,
		&tenantID,
		&c.Name,
		&c.CredentialType,
		&c.Description,
		&c.EncryptedData,
		&c.KeyVersion,
		&c.EncryptionAlgorithm,
		&lastUsedAt,
		&lastRotatedAt,
		&expiresAt,
		&createdBy,
		&c.CreatedAt,
		&c.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}

	c.ID, _ = shared.IDFromString(id)
	c.TenantID, _ = shared.IDFromString(tenantID)

	if createdBy.Valid {
		cbID, _ := shared.IDFromString(createdBy.String)
		c.CreatedBy = &cbID
	}
	if lastUsedAt.Valid {
		c.LastUsedAt = &lastUsedAt.Time
	}
	if lastRotatedAt.Valid {
		c.LastRotatedAt = &lastRotatedAt.Time
	}
	if expiresAt.Valid {
		c.ExpiresAt = &expiresAt.Time
	}

	return &c, nil
}
