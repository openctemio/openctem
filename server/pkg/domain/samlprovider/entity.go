// Package samlprovider is the domain model for per-tenant SAML 2.0 Service
// Provider configuration (RFC-009 Phase 9d/9e).
package samlprovider

import (
	"context"
	"errors"
	"time"

	"github.com/openctemio/openctem/server/pkg/domain/shared"
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
	// legacyPathKey is the frozen address key of a configuration that existed
	// before addresses were keyed by connection id (the organization's slug
	// at that time). Empty for every newer configuration.
	legacyPathKey string
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
		defaultRole:    "viewer", // least privilege for SSO just-in-time members
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

func (p *SAMLProvider) ID() shared.ID { return p.id }

// LegacyPathKey is the frozen pre-connection-id address key ("" for a
// configuration created since).
func (p *SAMLProvider) LegacyPathKey() string { return p.legacyPathKey }

// WithLegacyPathKey sets the frozen address key read from persistence.
func (p *SAMLProvider) WithLegacyPathKey(k string) *SAMLProvider { p.legacyPathKey = k; return p }

// PathKey is the key in this connection's public addresses
// (/api/v1/auth/saml/<key>/{metadata,login,acs}) and in its SP entity ID:
// the connection id, or the frozen legacy key of an older configuration
// whose identity provider still holds that address.
func (p *SAMLProvider) PathKey() string {
	if p.legacyPathKey != "" {
		return p.legacyPathKey
	}
	return p.id.String()
}
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
	// GetByID finds a configuration by its connection id (any tenant: the
	// public sign-in addresses carry no tenant).
	GetByID(ctx context.Context, id shared.ID) (*SAMLProvider, error)
	// GetByLegacyPathKey finds the configuration that holds this frozen
	// legacy address key. It never reads tenants.slug.
	GetByLegacyPathKey(ctx context.Context, key string) (*SAMLProvider, error)
	// ReserveConnectionID returns the connection id the tenant's next SAML
	// configuration takes, creating it on first use, so its addresses can be
	// given to the identity provider before the configuration exists.
	ReserveConnectionID(ctx context.Context, tenantID shared.ID) (shared.ID, error)
	Upsert(ctx context.Context, p *SAMLProvider) error
	// Delete removes the configuration and its reserved id: the address is
	// retired, and a new configuration gets a new one.
	Delete(ctx context.Context, tenantID shared.ID) error
}

// CertificateRecord is an enabled SAML config's IdP certificate with the
// tightest expiry notice already sent for it (nil: none yet). The notice state
// resets whenever the certificate changes.
type CertificateRecord struct {
	TenantID    shared.ID
	Certificate string // PEM
	NoticeDays  *int
}

// CertificateExpiryStore is the certificate-expiry sweep's view of the store.
// It reads across organizations (a system job); every write names its tenant.
// ListEnabledCertificates pages by tenant id: it returns up to limit records
// whose tenant id sorts after afterTenantID (the zero ID starts at the first).
type CertificateExpiryStore interface {
	ListEnabledCertificates(ctx context.Context, afterTenantID shared.ID, limit int) ([]CertificateRecord, error)
	SetCertificateNotice(ctx context.Context, tenantID shared.ID, days int) error
}
