package auth

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"encoding/xml"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/crewjam/saml"

	samldom "github.com/openctemio/api/pkg/domain/samlprovider"
	"github.com/openctemio/api/pkg/domain/shared"
	tenantdom "github.com/openctemio/api/pkg/domain/tenant"
	"github.com/openctemio/api/pkg/logger"
)

// SAML errors.
var (
	ErrSAMLTenantNotFound = ErrSSOTenantNotFound
	ErrSAMLNotConfigured  = samldom.ErrNotFound
	ErrSAMLInvalidCert    = fmt.Errorf("%w: invalid IdP certificate (expected a PEM-encoded X.509 certificate)", shared.ErrValidation)
)

func samlValidationErr(msg string) error { return fmt.Errorf("%w: %s", shared.ErrValidation, msg) }

// SAMLService implements the SAML 2.0 Service Provider flow (RFC-009 9d/9e).
// Phase 9d (this iteration): per-tenant config + SP metadata + the
// federated-login seam (via SSOService.CompleteFederatedLogin). The login/ACS
// flow (9e) builds on buildServiceProvider + the stored IdP certificate.
//
// The SP URLs (entity id / ACS / metadata) are derived from the request host so
// they always match the deployment.
type SAMLService struct {
	repo       samldom.Repository
	tenantRepo tenantdom.Repository
	sso        *SSOService
	logger     *logger.Logger
}

// NewSAMLService wires the service. sso supplies the shared session/provisioning
// tail (CompleteFederatedLogin).
func NewSAMLService(repo samldom.Repository, tenantRepo tenantdom.Repository, sso *SSOService, log *logger.Logger) *SAMLService {
	return &SAMLService{repo: repo, tenantRepo: tenantRepo, sso: sso, logger: log.With("service", "saml")}
}

// SAMLConfigInput is an admin create/update of a tenant's SAML config.
type SAMLConfigInput struct {
	IDPEntityID    string
	IDPSSOURL      string
	IDPCertificate string // PEM
	AllowedDomains []string
	DefaultRole    string
	AutoProvision  bool
	Enabled        bool
}

// GetConfig returns the tenant's SAML config (samldom.ErrNotFound when absent).
func (s *SAMLService) GetConfig(ctx context.Context, tenantID shared.ID) (*samldom.SAMLProvider, error) {
	return s.repo.GetByTenant(ctx, tenantID)
}

// UpsertConfig validates and stores the tenant's SAML config.
func (s *SAMLService) UpsertConfig(ctx context.Context, tenantID shared.ID, in SAMLConfigInput) (*samldom.SAMLProvider, error) {
	if strings.TrimSpace(in.IDPEntityID) == "" || strings.TrimSpace(in.IDPSSOURL) == "" {
		return nil, samlValidationErr("idp_entity_id and idp_sso_url are required")
	}
	if _, err := url.Parse(in.IDPSSOURL); err != nil {
		return nil, samlValidationErr("idp_sso_url must be a valid URL")
	}
	if err := validateCertificatePEM(in.IDPCertificate); err != nil {
		return nil, err
	}
	role := strings.ToLower(strings.TrimSpace(in.DefaultRole))
	switch role {
	case string(tenantdom.RoleAdmin), string(tenantdom.RoleMember), string(tenantdom.RoleViewer):
	case "":
		role = string(tenantdom.RoleMember)
	default:
		return nil, samlValidationErr("default_role must be admin, member, or viewer")
	}

	// Preserve the existing id when updating so it's a true upsert.
	id := shared.NewID()
	if existing, err := s.repo.GetByTenant(ctx, tenantID); err == nil && existing != nil {
		id = existing.ID()
	}
	p := samldom.Reconstruct(id, tenantID, in.IDPEntityID, in.IDPSSOURL, in.IDPCertificate,
		in.AllowedDomains, role, in.AutoProvision, in.Enabled, time.Now().UTC(), time.Now().UTC())
	if err := s.repo.Upsert(ctx, p); err != nil {
		return nil, err
	}
	return p, nil
}

// DeleteConfig removes the tenant's SAML config.
func (s *SAMLService) DeleteConfig(ctx context.Context, tenantID shared.ID) error {
	return s.repo.Delete(ctx, tenantID)
}

// Metadata returns the SP metadata XML for a tenant (org slug), which the admin
// registers with their IdP. baseURL is the deployment origin (scheme://host).
func (s *SAMLService) Metadata(ctx context.Context, orgSlug, baseURL string) (string, error) {
	t, err := s.tenantRepo.GetBySlug(ctx, orgSlug)
	if err != nil {
		return "", ErrSAMLTenantNotFound
	}
	sp := s.baseServiceProvider(orgSlug, baseURL)
	_ = t
	md := sp.Metadata()
	out, err := xml.MarshalIndent(md, "", "  ")
	if err != nil {
		return "", fmt.Errorf("marshal sp metadata: %w", err)
	}
	return xml.Header + string(out), nil
}

// baseServiceProvider builds the SP with the deployment-derived URLs. The IdP
// metadata (certificate, SSO endpoint) is layered on for the login/ACS flow (9e).
func (s *SAMLService) baseServiceProvider(orgSlug, baseURL string) *saml.ServiceProvider {
	base := strings.TrimSuffix(baseURL, "/")
	acs, _ := url.Parse(base + "/api/v1/auth/saml/" + orgSlug + "/acs")
	meta, _ := url.Parse(base + "/api/v1/auth/saml/" + orgSlug + "/metadata")
	return &saml.ServiceProvider{
		EntityID:          base + "/api/v1/auth/saml/" + orgSlug + "/metadata",
		AcsURL:            *acs,
		MetadataURL:       *meta,
		AuthnNameIDFormat: saml.EmailAddressNameIDFormat,
	}
}

// validateCertificatePEM ensures the supplied IdP certificate is a parseable
// PEM X.509 certificate (the trust anchor for assertion-signature validation).
func validateCertificatePEM(certPEM string) error {
	if strings.TrimSpace(certPEM) == "" {
		return ErrSAMLInvalidCert
	}
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return ErrSAMLInvalidCert
	}
	if _, err := x509.ParseCertificate(block.Bytes); err != nil {
		return ErrSAMLInvalidCert
	}
	return nil
}
