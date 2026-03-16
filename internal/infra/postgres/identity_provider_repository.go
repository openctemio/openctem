package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/lib/pq"

	"github.com/openctemio/api/pkg/domain/identityprovider"
)

// IdentityProviderRepository implements identityprovider.Repository.
type IdentityProviderRepository struct {
	db *DB
}

// NewIdentityProviderRepository creates a new repository.
func NewIdentityProviderRepository(db *DB) *IdentityProviderRepository {
	return &IdentityProviderRepository{db: db}
}

var _ identityprovider.Repository = (*IdentityProviderRepository)(nil)

const ipSelectFields = `
	id, tenant_id, provider, display_name, client_id, client_secret_encrypted,
	issuer_url, tenant_identifier, scopes, allowed_domains,
	auto_provision, default_role, is_active, metadata,
	created_at, updated_at, created_by
`

func (r *IdentityProviderRepository) Create(ctx context.Context, ip *identityprovider.IdentityProvider) error {
	metadataJSON, err := json.Marshal(ip.Metadata())
	if err != nil {
		return fmt.Errorf("marshal metadata: %w", err)
	}

	query := `
		INSERT INTO tenant_identity_providers (
			id, tenant_id, provider, display_name, client_id, client_secret_encrypted,
			issuer_url, tenant_identifier, scopes, allowed_domains,
			auto_provision, default_role, is_active, metadata, created_by
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
	`

	_, err = r.db.ExecContext(ctx, query,
		ip.ID(), ip.TenantID(), string(ip.Provider()), ip.DisplayName(),
		ip.ClientID(), ip.ClientSecretEncrypted(),
		nullString(ip.IssuerURL()), nullString(ip.TenantIdentifier()),
		pq.Array(ip.Scopes()), pq.Array(ip.AllowedDomains()),
		ip.AutoProvision(), ip.DefaultRole(), ip.IsActive(),
		metadataJSON, nullString(ip.CreatedBy()),
	)
	if err != nil {
		if isUniqueViolation(err) {
			return identityprovider.ErrAlreadyExists
		}
		return fmt.Errorf("create identity provider: %w", err)
	}
	return nil
}

func (r *IdentityProviderRepository) GetByID(ctx context.Context, tenantID, id string) (*identityprovider.IdentityProvider, error) {
	query := fmt.Sprintf("SELECT %s FROM tenant_identity_providers WHERE id = $1 AND tenant_id = $2", ipSelectFields)
	row := r.db.QueryRowContext(ctx, query, id, tenantID)
	return r.scanIP(row)
}

func (r *IdentityProviderRepository) GetByTenantAndProvider(ctx context.Context, tenantID string, provider identityprovider.Provider) (*identityprovider.IdentityProvider, error) {
	query := fmt.Sprintf("SELECT %s FROM tenant_identity_providers WHERE tenant_id = $1 AND provider = $2", ipSelectFields)
	row := r.db.QueryRowContext(ctx, query, tenantID, string(provider))
	return r.scanIP(row)
}

func (r *IdentityProviderRepository) Update(ctx context.Context, ip *identityprovider.IdentityProvider) error {
	metadataJSON, err := json.Marshal(ip.Metadata())
	if err != nil {
		return fmt.Errorf("marshal metadata: %w", err)
	}

	query := `
		UPDATE tenant_identity_providers SET
			display_name = $2, client_id = $3, client_secret_encrypted = $4,
			issuer_url = $5, tenant_identifier = $6, scopes = $7, allowed_domains = $8,
			auto_provision = $9, default_role = $10, is_active = $11, metadata = $12
		WHERE id = $1 AND tenant_id = $13
	`

	result, err := r.db.ExecContext(ctx, query,
		ip.ID(), ip.DisplayName(), ip.ClientID(), ip.ClientSecretEncrypted(),
		nullString(ip.IssuerURL()), nullString(ip.TenantIdentifier()),
		pq.Array(ip.Scopes()), pq.Array(ip.AllowedDomains()),
		ip.AutoProvision(), ip.DefaultRole(), ip.IsActive(),
		metadataJSON, ip.TenantID(),
	)
	if err != nil {
		return fmt.Errorf("update identity provider: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("get rows affected: %w", err)
	}
	if rows == 0 {
		return identityprovider.ErrNotFound
	}
	return nil
}

func (r *IdentityProviderRepository) Delete(ctx context.Context, tenantID, id string) error {
	result, err := r.db.ExecContext(ctx, "DELETE FROM tenant_identity_providers WHERE id = $1 AND tenant_id = $2", id, tenantID)
	if err != nil {
		return fmt.Errorf("delete identity provider: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("get rows affected: %w", err)
	}
	if rows == 0 {
		return identityprovider.ErrNotFound
	}
	return nil
}

func (r *IdentityProviderRepository) ListByTenant(ctx context.Context, tenantID string) ([]*identityprovider.IdentityProvider, error) {
	query := fmt.Sprintf("SELECT %s FROM tenant_identity_providers WHERE tenant_id = $1 ORDER BY created_at ASC", ipSelectFields)
	return r.queryIPs(ctx, query, tenantID)
}

func (r *IdentityProviderRepository) ListActiveByTenant(ctx context.Context, tenantID string) ([]*identityprovider.IdentityProvider, error) {
	query := fmt.Sprintf("SELECT %s FROM tenant_identity_providers WHERE tenant_id = $1 AND is_active = true ORDER BY created_at ASC", ipSelectFields)
	return r.queryIPs(ctx, query, tenantID)
}

func (r *IdentityProviderRepository) queryIPs(ctx context.Context, query string, args ...any) ([]*identityprovider.IdentityProvider, error) {
	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("query identity providers: %w", err)
	}
	defer rows.Close()

	var result []*identityprovider.IdentityProvider
	for rows.Next() {
		ip, err := r.scanIPRow(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, ip)
	}
	return result, rows.Err()
}

func (r *IdentityProviderRepository) scanIP(row *sql.Row) (*identityprovider.IdentityProvider, error) {
	var (
		id, tenantID, provider, displayName, clientID, clientSecretEnc string
		issuerURL, tenantIdentifier, createdBy                        sql.NullString
		scopes, allowedDomains                                        pq.StringArray
		autoProvision, isActive                                       bool
		defaultRole                                                   string
		metadataJSON                                                  []byte
		createdAt, updatedAt                                          sql.NullTime
	)

	err := row.Scan(
		&id, &tenantID, &provider, &displayName, &clientID, &clientSecretEnc,
		&issuerURL, &tenantIdentifier, &scopes, &allowedDomains,
		&autoProvision, &defaultRole, &isActive, &metadataJSON,
		&createdAt, &updatedAt, &createdBy,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, identityprovider.ErrNotFound
		}
		return nil, fmt.Errorf("scan identity provider: %w", err)
	}

	return r.reconstruct(
		id, tenantID, provider, displayName, clientID, clientSecretEnc,
		issuerURL.String, tenantIdentifier.String,
		[]string(scopes), []string(allowedDomains),
		autoProvision, defaultRole, isActive, metadataJSON,
		createdAt.Time, updatedAt.Time, createdBy.String,
	), nil
}

func (r *IdentityProviderRepository) scanIPRow(rows *sql.Rows) (*identityprovider.IdentityProvider, error) {
	var (
		id, tenantID, provider, displayName, clientID, clientSecretEnc string
		issuerURL, tenantIdentifier, createdBy                        sql.NullString
		scopes, allowedDomains                                        pq.StringArray
		autoProvision, isActive                                       bool
		defaultRole                                                   string
		metadataJSON                                                  []byte
		createdAt, updatedAt                                          sql.NullTime
	)

	err := rows.Scan(
		&id, &tenantID, &provider, &displayName, &clientID, &clientSecretEnc,
		&issuerURL, &tenantIdentifier, &scopes, &allowedDomains,
		&autoProvision, &defaultRole, &isActive, &metadataJSON,
		&createdAt, &updatedAt, &createdBy,
	)
	if err != nil {
		return nil, fmt.Errorf("scan identity provider row: %w", err)
	}

	return r.reconstruct(
		id, tenantID, provider, displayName, clientID, clientSecretEnc,
		issuerURL.String, tenantIdentifier.String,
		[]string(scopes), []string(allowedDomains),
		autoProvision, defaultRole, isActive, metadataJSON,
		createdAt.Time, updatedAt.Time, createdBy.String,
	), nil
}

func (r *IdentityProviderRepository) reconstruct(
	id, tenantID, provider, displayName, clientID, clientSecretEnc string,
	issuerURL, tenantIdentifier string,
	scopes, allowedDomains []string,
	autoProvision bool, defaultRole string, isActive bool,
	metadataJSON []byte,
	createdAt, updatedAt time.Time,
	createdBy string,
) *identityprovider.IdentityProvider {
	var metadata map[string]any
	if len(metadataJSON) > 0 {
		_ = json.Unmarshal(metadataJSON, &metadata)
	}

	return identityprovider.Reconstruct(
		id, tenantID,
		identityprovider.Provider(provider),
		displayName, clientID, clientSecretEnc,
		issuerURL, tenantIdentifier,
		scopes, allowedDomains,
		autoProvision, defaultRole, isActive,
		metadata, createdAt, updatedAt, createdBy,
	)
}
