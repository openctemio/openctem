package auth

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"encoding/xml"
	"fmt"
	"net/http"
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
	ErrSAMLDisabled       = fmt.Errorf("%w: SAML login is not enabled for this organization", shared.ErrValidation)
	// ErrSAMLResponseInvalid is a generic error for any assertion-validation
	// failure (signature, conditions, audience, InResponseTo). The specific
	// reason is logged server-side, never returned to the caller.
	ErrSAMLResponseInvalid = fmt.Errorf("%w: SAML response could not be validated", shared.ErrValidation)
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

// Login starts an SP-initiated SAML login (RFC-009 9e). It returns the IdP
// redirect URL (carrying the deflate+base64 AuthnRequest) and the request ID,
// which the caller stores in a short-lived cookie so the ACS can bind the
// response's InResponseTo (replay/CSRF protection).
func (s *SAMLService) Login(ctx context.Context, orgSlug, baseURL string) (redirectURL, requestID string, err error) {
	sp, _, err := s.resolveServiceProvider(ctx, orgSlug, baseURL)
	if err != nil {
		return "", "", err
	}
	authnReq, err := sp.MakeAuthenticationRequest(sp.IDPMetadata.IDPSSODescriptors[0].SingleSignOnServices[0].Location, saml.HTTPRedirectBinding, saml.HTTPPostBinding)
	if err != nil {
		return "", "", fmt.Errorf("build authn request: %w", err)
	}
	u, err := authnReq.Redirect(orgSlug, sp)
	if err != nil {
		return "", "", fmt.Errorf("build redirect: %w", err)
	}
	return u.String(), authnReq.ID, nil
}

// ACS validates an IdP SAML response and completes the federated login. The
// caller supplies possibleRequestIDs (from the request-tracking cookie) so the
// assertion's InResponseTo is bound to a request this SP actually initiated.
func (s *SAMLService) ACS(ctx context.Context, orgSlug, baseURL string, r *http.Request, possibleRequestIDs []string) (*SSOCallbackResult, error) {
	sp, tenantAndCfg, err := s.resolveServiceProvider(ctx, orgSlug, baseURL)
	if err != nil {
		return nil, err
	}
	assertion, perr := sp.ParseResponse(r, possibleRequestIDs)
	if perr != nil {
		// Never leak the specific crypto/condition failure to the caller.
		s.logger.Warn("saml assertion validation failed", "org", orgSlug, "error", perr)
		return nil, ErrSAMLResponseInvalid
	}

	email, name := extractEmailName(assertion)
	if email == "" {
		return nil, samlValidationErr("assertion has no email address (NameID or email attribute)")
	}

	cfg := tenantAndCfg.cfg
	if at := strings.LastIndex(email, "@"); at >= 0 && !cfg.IsDomainAllowed(email[at+1:]) {
		return nil, ErrSSODomainNotAllowed
	}

	return s.sso.CompleteFederatedLogin(ctx, tenantAndCfg.tenant, email, name, cfg.DefaultRole(), cfg.AutoProvision())
}

// resolvedSAML bundles the tenant + its enabled SAML config.
type resolvedSAML struct {
	tenant *tenantdom.Tenant
	cfg    *samldom.SAMLProvider
}

// resolveServiceProvider loads the tenant + enabled SAML config and builds a
// crewjam ServiceProvider with the IdP metadata (cert + SSO endpoint) attached.
func (s *SAMLService) resolveServiceProvider(ctx context.Context, orgSlug, baseURL string) (*saml.ServiceProvider, resolvedSAML, error) {
	t, err := s.tenantRepo.GetBySlug(ctx, orgSlug)
	if err != nil {
		return nil, resolvedSAML{}, ErrSAMLTenantNotFound
	}
	p, err := s.repo.GetByTenant(ctx, t.ID())
	if err != nil {
		return nil, resolvedSAML{}, ErrSAMLNotConfigured
	}
	if !p.Enabled() {
		return nil, resolvedSAML{}, ErrSAMLDisabled
	}
	md, err := buildIDPMetadata(p)
	if err != nil {
		return nil, resolvedSAML{}, err
	}
	sp := s.baseServiceProvider(orgSlug, baseURL)
	sp.IDPMetadata = md
	return sp, resolvedSAML{tenant: t, cfg: p}, nil
}

// buildIDPMetadata assembles the crewjam EntityDescriptor from the stored IdP
// entity id, SSO URL and signing certificate — the trust anchor ParseResponse
// uses to verify the assertion signature.
func buildIDPMetadata(p *samldom.SAMLProvider) (*saml.EntityDescriptor, error) {
	block, _ := pem.Decode([]byte(p.IDPCertificate()))
	if block == nil {
		return nil, ErrSAMLInvalidCert
	}
	certB64 := base64.StdEncoding.EncodeToString(block.Bytes)

	return &saml.EntityDescriptor{
		EntityID: p.IDPEntityID(),
		IDPSSODescriptors: []saml.IDPSSODescriptor{{
			SSODescriptor: saml.SSODescriptor{
				RoleDescriptor: saml.RoleDescriptor{
					KeyDescriptors: []saml.KeyDescriptor{{
						Use: "signing",
						KeyInfo: saml.KeyInfo{
							X509Data: saml.X509Data{
								X509Certificates: []saml.X509Certificate{{Data: certB64}},
							},
						},
					}},
				},
			},
			SingleSignOnServices: []saml.Endpoint{{
				Binding:  saml.HTTPRedirectBinding,
				Location: p.IDPSSOURL(),
			}},
		}},
	}, nil
}

// samlEmailAttrKeys / samlNameAttrKeys are lowercase substrings matched against
// an attribute's Name/FriendlyName to locate the email and display name.
var samlEmailAttrKeys = []string{"emailaddress", "email", "mail", "urn:oid:0.9.2342.19200300.100.1.3"}
var samlNameAttrKeys = []string{"displayname", "name", "cn", "urn:oid:2.16.840.1.113730.3.1.241"}

// extractEmailName pulls the user's email and display name from the assertion —
// the NameID (when it is an email) plus common attribute names across IdPs.
func extractEmailName(a *saml.Assertion) (email, name string) {
	if a.Subject != nil && a.Subject.NameID != nil {
		if v := strings.TrimSpace(a.Subject.NameID.Value); strings.Contains(v, "@") {
			email = v
		}
	}
	for _, st := range a.AttributeStatements {
		for _, attr := range st.Attributes {
			if len(attr.Values) == 0 {
				continue
			}
			val := strings.TrimSpace(attr.Values[0].Value)
			if val == "" {
				continue
			}
			key := strings.ToLower(attr.Name + " " + attr.FriendlyName)
			if email == "" && matchesAny(key, samlEmailAttrKeys) && strings.Contains(val, "@") {
				email = val
			}
			if name == "" && matchesAny(key, samlNameAttrKeys) {
				name = val
			}
		}
	}
	return strings.ToLower(strings.TrimSpace(email)), strings.TrimSpace(name)
}

func matchesAny(s string, subs []string) bool {
	for _, sub := range subs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}
