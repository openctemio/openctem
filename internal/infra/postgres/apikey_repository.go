package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/lib/pq"

	"github.com/openctemio/api/pkg/domain/apikey"
	"github.com/openctemio/api/pkg/domain/shared"
)

// APIKeyRepository is the PostgreSQL implementation of apikey.Repository.
type APIKeyRepository struct {
	db *DB
}

// NewAPIKeyRepository creates a new APIKeyRepository.
func NewAPIKeyRepository(db *DB) *APIKeyRepository {
	return &APIKeyRepository{db: db}
}

var _ apikey.Repository = (*APIKeyRepository)(nil)

// Create inserts a new API key.
func (r *APIKeyRepository) Create(ctx context.Context, key *apikey.APIKey) error {
	query := `
		INSERT INTO api_keys (
			id, tenant_id, user_id, name, description,
			key_hash, key_prefix, scopes, rate_limit,
			status, expires_at, created_by, created_at, updated_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14
		)
	`

	var userID, createdBy *string
	if key.UserID() != nil {
		s := key.UserID().String()
		userID = &s
	}
	if key.CreatedBy() != nil {
		s := key.CreatedBy().String()
		createdBy = &s
	}

	_, err := r.db.ExecContext(ctx, query,
		key.ID().String(),
		key.TenantID().String(),
		userID,
		key.Name(),
		key.Description(),
		key.KeyHash(),
		key.KeyPrefix(),
		pq.Array(key.Scopes()),
		key.RateLimit(),
		string(key.Status()),
		key.ExpiresAt(),
		createdBy,
		key.CreatedAt(),
		key.UpdatedAt(),
	)
	if err != nil {
		if isUniqueViolation(err) {
			return apikey.ErrAPIKeyNameExists
		}
		return fmt.Errorf("create api key: %w", err)
	}
	return nil
}

// GetByID retrieves an API key by ID and tenant.
func (r *APIKeyRepository) GetByID(ctx context.Context, id, tenantID apikey.ID) (*apikey.APIKey, error) {
	query := `
		SELECT id, tenant_id, user_id, name, description,
			key_hash, key_prefix, scopes, rate_limit,
			status, expires_at, last_used_at, last_used_ip, use_count,
			created_by, created_at, updated_at, revoked_at, revoked_by
		FROM api_keys WHERE id = $1 AND tenant_id = $2
	`
	row := r.db.QueryRowContext(ctx, query, id.String(), tenantID.String())
	return r.scanAPIKey(row)
}

// GetByHash retrieves an API key by its hash.
func (r *APIKeyRepository) GetByHash(ctx context.Context, hash string) (*apikey.APIKey, error) {
	query := `
		SELECT id, tenant_id, user_id, name, description,
			key_hash, key_prefix, scopes, rate_limit,
			status, expires_at, last_used_at, last_used_ip, use_count,
			created_by, created_at, updated_at, revoked_at, revoked_by
		FROM api_keys WHERE key_hash = $1
	`
	row := r.db.QueryRowContext(ctx, query, hash)
	return r.scanAPIKey(row)
}

// List retrieves a paginated list of API keys.
func (r *APIKeyRepository) List(ctx context.Context, filter apikey.Filter) (apikey.ListResult, error) {
	result := apikey.ListResult{
		Data:    make([]*apikey.APIKey, 0),
		Page:    filter.Page,
		PerPage: filter.PerPage,
	}

	if filter.Page < 1 {
		filter.Page = 1
	}
	if filter.PerPage < 1 {
		filter.PerPage = 20
	}

	conditions := make([]string, 0)
	args := make([]any, 0)
	argIdx := 1

	if filter.TenantID != nil {
		conditions = append(conditions, fmt.Sprintf("tenant_id = $%d", argIdx))
		args = append(args, filter.TenantID.String())
		argIdx++
	}

	if filter.UserID != nil {
		conditions = append(conditions, fmt.Sprintf("user_id = $%d", argIdx))
		args = append(args, filter.UserID.String())
		argIdx++
	}

	if filter.Status != nil {
		conditions = append(conditions, fmt.Sprintf("status = $%d", argIdx))
		args = append(args, string(*filter.Status))
		argIdx++
	}

	if filter.Search != "" {
		conditions = append(conditions, fmt.Sprintf("(name ILIKE $%d OR description ILIKE $%d)", argIdx, argIdx))
		args = append(args, wrapLikePattern(filter.Search))
		argIdx++
	}

	whereClause := ""
	if len(conditions) > 0 {
		whereClause = "WHERE " + strings.Join(conditions, " AND ")
	}

	// Count
	countQuery := "SELECT COUNT(*) FROM api_keys " + whereClause
	if err := r.db.QueryRowContext(ctx, countQuery, args...).Scan(&result.Total); err != nil {
		return result, fmt.Errorf("count api keys: %w", err)
	}

	result.TotalPages = int((result.Total + int64(filter.PerPage) - 1) / int64(filter.PerPage))
	result.Page = filter.Page

	// Sort
	orderBy := "created_at DESC"
	if filter.SortBy != "" {
		validFields := map[string]bool{"name": true, "status": true, "created_at": true, "last_used_at": true, "expires_at": true}
		if validFields[filter.SortBy] {
			order := "ASC"
			if strings.EqualFold(filter.SortOrder, "desc") {
				order = "DESC"
			}
			orderBy = filter.SortBy + " " + order
		}
	}

	offset := (filter.Page - 1) * filter.PerPage
	args = append(args, filter.PerPage, offset)

	query := fmt.Sprintf(`
		SELECT id, tenant_id, user_id, name, description,
			key_hash, key_prefix, scopes, rate_limit,
			status, expires_at, last_used_at, last_used_ip, use_count,
			created_by, created_at, updated_at, revoked_at, revoked_by
		FROM api_keys
		%s
		ORDER BY %s
		LIMIT $%d OFFSET $%d
	`, whereClause, orderBy, argIdx, argIdx+1)

	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return result, fmt.Errorf("list api keys: %w", err)
	}
	defer func() { _ = rows.Close() }()

	for rows.Next() {
		key, err := r.scanAPIKeyRow(rows)
		if err != nil {
			return result, err
		}
		result.Data = append(result.Data, key)
	}

	if err := rows.Err(); err != nil {
		return result, fmt.Errorf("iterate api key rows: %w", err)
	}

	return result, nil
}

// Update updates an API key.
func (r *APIKeyRepository) Update(ctx context.Context, key *apikey.APIKey) error {
	query := `
		UPDATE api_keys SET
			name = $2, description = $3, scopes = $4, rate_limit = $5,
			status = $6, expires_at = $7, last_used_at = $8, last_used_ip = $9,
			use_count = $10, revoked_at = $11, revoked_by = $12, updated_at = $13
		WHERE id = $1
	`

	var revokedBy *string
	if key.RevokedBy() != nil {
		s := key.RevokedBy().String()
		revokedBy = &s
	}

	result, err := r.db.ExecContext(ctx, query,
		key.ID().String(),
		key.Name(),
		key.Description(),
		pq.Array(key.Scopes()),
		key.RateLimit(),
		string(key.Status()),
		key.ExpiresAt(),
		key.LastUsedAt(),
		key.LastUsedIP(),
		key.UseCount(),
		key.RevokedAt(),
		revokedBy,
		key.UpdatedAt(),
	)
	if err != nil {
		if isUniqueViolation(err) {
			return apikey.ErrAPIKeyNameExists
		}
		return fmt.Errorf("update api key: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("rows affected: %w", err)
	}
	if rowsAffected == 0 {
		return apikey.ErrAPIKeyNotFound
	}
	return nil
}

// Delete deletes an API key by ID and tenant.
func (r *APIKeyRepository) Delete(ctx context.Context, id, tenantID apikey.ID) error {
	query := `DELETE FROM api_keys WHERE id = $1 AND tenant_id = $2`
	result, err := r.db.ExecContext(ctx, query, id.String(), tenantID.String())
	if err != nil {
		return fmt.Errorf("delete api key: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("rows affected: %w", err)
	}
	if rowsAffected == 0 {
		return apikey.ErrAPIKeyNotFound
	}
	return nil
}

// --- Scan Helpers ---

func (r *APIKeyRepository) scanAPIKey(row *sql.Row) (*apikey.APIKey, error) {
	var (
		id, tenantID          string
		userID, createdBy     sql.NullString
		name                  string
		description           sql.NullString
		keyHash, keyPrefix    string
		scopes                pq.StringArray
		rateLimit             int
		status                string
		expiresAt, lastUsedAt sql.NullTime
		lastUsedIP            sql.NullString
		useCount              int64
		createdAt, updatedAt  time.Time
		revokedAt             sql.NullTime
		revokedBy             sql.NullString
	)

	err := row.Scan(
		&id, &tenantID, &userID, &name, &description,
		&keyHash, &keyPrefix, &scopes, &rateLimit,
		&status, &expiresAt, &lastUsedAt, &lastUsedIP, &useCount,
		&createdBy, &createdAt, &updatedAt, &revokedAt, &revokedBy,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, apikey.ErrAPIKeyNotFound
		}
		return nil, fmt.Errorf("scan api key: %w", err)
	}

	return r.reconstruct(id, tenantID, userID, name, description.String,
		keyHash, keyPrefix, []string(scopes), rateLimit, status,
		expiresAt, lastUsedAt, lastUsedIP, useCount,
		createdBy, createdAt, updatedAt, revokedAt, revokedBy)
}

func (r *APIKeyRepository) scanAPIKeyRow(rows *sql.Rows) (*apikey.APIKey, error) {
	var (
		id, tenantID          string
		userID, createdBy     sql.NullString
		name                  string
		description           sql.NullString
		keyHash, keyPrefix    string
		scopes                pq.StringArray
		rateLimit             int
		status                string
		expiresAt, lastUsedAt sql.NullTime
		lastUsedIP            sql.NullString
		useCount              int64
		createdAt, updatedAt  time.Time
		revokedAt             sql.NullTime
		revokedBy             sql.NullString
	)

	err := rows.Scan(
		&id, &tenantID, &userID, &name, &description,
		&keyHash, &keyPrefix, &scopes, &rateLimit,
		&status, &expiresAt, &lastUsedAt, &lastUsedIP, &useCount,
		&createdBy, &createdAt, &updatedAt, &revokedAt, &revokedBy,
	)
	if err != nil {
		return nil, fmt.Errorf("scan api key row: %w", err)
	}

	return r.reconstruct(id, tenantID, userID, name, description.String,
		keyHash, keyPrefix, []string(scopes), rateLimit, status,
		expiresAt, lastUsedAt, lastUsedIP, useCount,
		createdBy, createdAt, updatedAt, revokedAt, revokedBy)
}

func (r *APIKeyRepository) reconstruct(
	id, tenantID string,
	userID sql.NullString,
	name, description, keyHash, keyPrefix string,
	scopes []string, rateLimit int, status string,
	expiresAt, lastUsedAt sql.NullTime,
	lastUsedIP sql.NullString,
	useCount int64,
	createdBy sql.NullString,
	createdAt, updatedAt time.Time,
	revokedAt sql.NullTime,
	revokedBy sql.NullString,
) (*apikey.APIKey, error) {
	keyID, _ := shared.IDFromString(id)
	keyTenantID, _ := shared.IDFromString(tenantID)

	var uid *shared.ID
	if userID.Valid {
		u, _ := shared.IDFromString(userID.String)
		uid = &u
	}

	var expAt *time.Time
	if expiresAt.Valid {
		expAt = &expiresAt.Time
	}

	var luAt *time.Time
	if lastUsedAt.Valid {
		luAt = &lastUsedAt.Time
	}

	var cbID *shared.ID
	if createdBy.Valid {
		c, _ := shared.IDFromString(createdBy.String)
		cbID = &c
	}

	var revAt *time.Time
	if revokedAt.Valid {
		revAt = &revokedAt.Time
	}

	var revBy *shared.ID
	if revokedBy.Valid {
		rb, _ := shared.IDFromString(revokedBy.String)
		revBy = &rb
	}

	luIP := ""
	if lastUsedIP.Valid {
		luIP = lastUsedIP.String
	}

	return apikey.Reconstruct(
		keyID, keyTenantID, uid,
		name, description, keyHash, keyPrefix,
		scopes, rateLimit, apikey.Status(status),
		expAt, luAt, luIP, useCount,
		cbID, createdAt, updatedAt, revAt, revBy,
	), nil
}
