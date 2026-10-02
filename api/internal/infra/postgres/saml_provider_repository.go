package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/lib/pq"

	"github.com/openctemio/api/pkg/domain/samlprovider"
	"github.com/openctemio/api/pkg/domain/shared"
)

// SAMLProviderRepository persists per-tenant SAML SP config.
type SAMLProviderRepository struct {
	db *DB
}

// NewSAMLProviderRepository creates the repository.
func NewSAMLProviderRepository(db *DB) *SAMLProviderRepository {
	return &SAMLProviderRepository{db: db}
}

func (r *SAMLProviderRepository) GetByTenant(ctx context.Context, tenantID shared.ID) (*samlprovider.SAMLProvider, error) {
	const q = `
		SELECT id, idp_entity_id, idp_sso_url, idp_certificate, allowed_domains,
		       default_role, auto_provision, enabled, created_at, updated_at
		  FROM saml_providers WHERE tenant_id = $1
	`
	var (
		idStr, entityID, ssoURL, cert, defaultRole string
		domains                                    pq.StringArray
		autoProvision, enabled                     bool
		createdAt, updatedAt                       sql.NullTime
	)
	err := r.db.QueryRowContext(ctx, q, tenantID.String()).Scan(
		&idStr, &entityID, &ssoURL, &cert, &domains, &defaultRole, &autoProvision, &enabled, &createdAt, &updatedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, samlprovider.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get saml provider: %w", err)
	}
	id, err := shared.IDFromString(idStr)
	if err != nil {
		return nil, fmt.Errorf("parse saml provider id: %w", err)
	}
	return samlprovider.Reconstruct(id, tenantID, entityID, ssoURL, cert, []string(domains), defaultRole, autoProvision, enabled, createdAt.Time, updatedAt.Time), nil
}

// Upsert inserts or replaces the tenant's SAML config (one per tenant).
func (r *SAMLProviderRepository) Upsert(ctx context.Context, p *samlprovider.SAMLProvider) error {
	const q = `
		INSERT INTO saml_providers
		    (id, tenant_id, idp_entity_id, idp_sso_url, idp_certificate, allowed_domains, default_role, auto_provision, enabled, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, NOW(), NOW())
		ON CONFLICT (tenant_id) DO UPDATE SET
		    idp_entity_id   = EXCLUDED.idp_entity_id,
		    idp_sso_url     = EXCLUDED.idp_sso_url,
		    idp_certificate = EXCLUDED.idp_certificate,
		    allowed_domains = EXCLUDED.allowed_domains,
		    default_role    = EXCLUDED.default_role,
		    auto_provision  = EXCLUDED.auto_provision,
		    enabled         = EXCLUDED.enabled,
		    updated_at      = NOW()
	`
	// allowed_domains is NOT NULL DEFAULT '{}'; coerce a nil slice to an empty
	// array so a config with no domain restriction saves cleanly.
	domains := p.AllowedDomains()
	if domains == nil {
		domains = []string{}
	}
	_, err := r.db.ExecContext(ctx, q,
		p.ID().String(), p.TenantID().String(), p.IDPEntityID(), p.IDPSSOURL(), p.IDPCertificate(),
		pq.Array(domains), p.DefaultRole(), p.AutoProvision(), p.Enabled(),
	)
	if err != nil {
		return fmt.Errorf("upsert saml provider: %w", err)
	}
	return nil
}

func (r *SAMLProviderRepository) Delete(ctx context.Context, tenantID shared.ID) error {
	_, err := r.db.ExecContext(ctx, `DELETE FROM saml_providers WHERE tenant_id = $1`, tenantID.String())
	if err != nil {
		return fmt.Errorf("delete saml provider: %w", err)
	}
	return nil
}
