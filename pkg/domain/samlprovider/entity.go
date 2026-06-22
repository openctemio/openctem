// Package samlprovider is the domain model for per-tenant SAML 2.0 Service
// Provider configuration (RFC-009 Phase 9d/9e).
package samlprovider

import (
	"context"
	"errors"
	"time"

	"github.com/openctemio/api/pkg/domain/shared"
)

// ErrNotFound is returned when a tenant has no SAML config.
var ErrNotFound = errors.New("saml provider not configured")

// SAMLProvider is a tenant's SAML SP configuration (IdP side + policy).
type SAMLProvider struct {
	id             shared.ID
	tenantID       shared.ID
	idpEntityID    string
	idpSSOURL      string
	idpCertificate string // PEM
	allowedDomains []string
	defaultRole    string
	autoProvision  bool
	enabled        bool
	createdAt      time.Time
	updatedAt      time.Time
}

// New creates a SAML provider config (disabled-state controlled by Enabled).
func New(id, tenantID shared.ID, idpEntityID, idpSSOURL, idpCert string) *SAMLProvider {
	now := time.Now().UTC()
	return &SAMLProvider{
		id:             id,
		tenantID:       tenantID,
		idpEntityID:    idpEntityID,
		idpSSOURL:      idpSSOURL,
		idpCertificate: idpCert,
		defaultRole:    "member",
		autoProvision:  true,
		enabled:        false,
		createdAt:      now,
		updatedAt:      now,
	}
}

// Reconstruct rebuilds from persistence.
func Reconstruct(id, tenantID shared.ID, idpEntityID, idpSSOURL, idpCert string, allowedDomains []string, defaultRole string, autoProvision, enabled bool, createdAt, updatedAt time.Time) *SAMLProvider {
	return &SAMLProvider{
		id:             id,
		tenantID:       tenantID,
		idpEntityID:    idpEntityID,
		idpSSOURL:      idpSSOURL,
		idpCertificate: idpCert,
		allowedDomains: allowedDomains,
		defaultRole:    defaultRole,
		autoProvision:  autoProvision,
		enabled:        enabled,
		createdAt:      createdAt,
		updatedAt:      updatedAt,
	}
}

func (p *SAMLProvider) ID() shared.ID            { return p.id }
func (p *SAMLProvider) TenantID() shared.ID      { return p.tenantID }
func (p *SAMLProvider) IDPEntityID() string      { return p.idpEntityID }
func (p *SAMLProvider) IDPSSOURL() string        { return p.idpSSOURL }
func (p *SAMLProvider) IDPCertificate() string   { return p.idpCertificate }
func (p *SAMLProvider) AllowedDomains() []string { return p.allowedDomains }
func (p *SAMLProvider) DefaultRole() string      { return p.defaultRole }
func (p *SAMLProvider) AutoProvision() bool      { return p.autoProvision }
func (p *SAMLProvider) Enabled() bool            { return p.enabled }
func (p *SAMLProvider) CreatedAt() time.Time     { return p.createdAt }
func (p *SAMLProvider) UpdatedAt() time.Time     { return p.updatedAt }

func (p *SAMLProvider) SetAllowedDomains(d []string) { p.allowedDomains = d }
func (p *SAMLProvider) SetDefaultRole(r string)      { p.defaultRole = r }
func (p *SAMLProvider) SetAutoProvision(b bool)      { p.autoProvision = b }
func (p *SAMLProvider) SetEnabled(b bool)            { p.enabled = b }

// IsDomainAllowed mirrors the SSO allow-list: empty list = any domain.
func (p *SAMLProvider) IsDomainAllowed(emailDomain string) bool {
	if len(p.allowedDomains) == 0 {
		return true
	}
	for _, d := range p.allowedDomains {
		if d == emailDomain {
			return true
		}
	}
	return false
}

// Repository persists per-tenant SAML config.
type Repository interface {
	GetByTenant(ctx context.Context, tenantID shared.ID) (*SAMLProvider, error)
	Upsert(ctx context.Context, p *SAMLProvider) error
	Delete(ctx context.Context, tenantID shared.ID) error
}
