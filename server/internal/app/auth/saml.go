package auth

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"encoding/xml"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/openctemio/saml"

	samldom "github.com/openctemio/openctem/server/pkg/domain/samlprovider"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
	tenantdom "github.com/openctemio/openctem/server/pkg/domain/tenant"
	"github.com/openctemio/openctem/server/pkg/domain/useridentity"
	"github.com/openctemio/openctem/server/pkg/logger"
)

// SAML errors.
var (
	ErrSAMLTenantNotFound = ErrSSOTenantNotFound
	ErrSAMLNotConfigured  = samldom.ErrNotFound
	ErrSAMLInvalidCert    = fmt.Errorf("%w: invalid IdP certificate (expected a PEM-encoded X.509 certificate)", shared.ErrValidation)
	ErrSAMLCertExpired    = fmt.Errorf("%w: the IdP certificate has expired; upload the IdP's current signing certificate", shared.ErrValidation)
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
	// replay records each accepted assertion ID once (Redis in production).
	replay SAMLReplayStore
	// expiry alerts owners before the IdP certificate expires.
	expiry samlCertExpiryNotifier
	// metadataFetcher reads IdP metadata URLs (nil: the SSRF-guarded default).
	metadataFetcher *idpMetadataFetcher
}

// NewSAMLService wires the service. sso supplies the shared session/provisioning
// tail (CompleteFederatedLogin).
func NewSAMLService(repo samldom.Repository, tenantRepo tenantdom.Repository, sso *SSOService, log *logger.Logger) *SAMLService {
	return &SAMLService{repo: repo, tenantRepo: tenantRepo, sso: sso, logger: log.With("service", "saml"),
		replay: newMemorySAMLReplayStore()}
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
	p, err := s.BuildConfig(ctx, tenantID, in)
	if err != nil {
		return nil, err
	}
	if err := s.repo.Upsert(ctx, p); err != nil {
		return nil, err
	}
	return p, nil
}

// BuildConfig validates in and returns the SAML config it describes, keeping
// the id of the tenant's existing config, without storing it. An SSO change
// that waits for an owner's approval is validated with it when submitted and
// rebuilt with it when approved.
func (s *SAMLService) BuildConfig(ctx context.Context, tenantID shared.ID, in SAMLConfigInput) (*samldom.SAMLProvider, error) {
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
	case string(tenantdom.RoleMember), string(tenantdom.RoleViewer):
	case "":
		// Least privilege for just-in-time members; the platform administrator
		// raises it per organization when wanted.
		role = string(tenantdom.RoleViewer)
	default:
		// Never admin: an IdP misconfiguration (or a hostile IdP) must not mint
		// administrators by just-in-time provisioning (owner decision B18).
		return nil, samlValidationErr("default_role must be member or viewer")
	}

	// Preserve the existing id when updating so it's a true upsert.
	id := shared.NewID()
	if existing, err := s.repo.GetByTenant(ctx, tenantID); err == nil && existing != nil {
		id = existing.ID()
	} else if err := s.sso.requireRoomForConnection(ctx, tenantID); err != nil {
		// Only the first SAML configuration adds a connection.
		return nil, err
	}
	return samldom.Reconstruct(id, tenantID, in.IDPEntityID, in.IDPSSOURL, in.IDPCertificate,
		in.AllowedDomains, role, in.AutoProvision, in.Enabled, time.Now().UTC(), time.Now().UTC()), nil
}

// DeleteConfig removes the tenant's SAML config.
func (s *SAMLService) DeleteConfig(ctx context.Context, tenantID shared.ID) error {
	return s.repo.Delete(ctx, tenantID)
}

// Metadata returns the SP metadata XML for a tenant (org slug), which the admin
// registers with their IdP. baseURL is the deployment origin (scheme://host).
//
// The metadata is built from the slug and the deployment URL only, so it is
// served for any well-formed slug, known or not: answering 404 for an unknown
// organization would tell an unauthenticated caller which organizations exist.
func (s *SAMLService) Metadata(_ context.Context, orgSlug, baseURL string) (string, error) {
	if !tenantdom.IsValidSlug(orgSlug) {
		return "", ErrSAMLTenantNotFound
	}
	sp := s.baseServiceProvider(orgSlug, baseURL)
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

// validateCertificatePEM ensures the supplied IdP certificate field holds one
// or more parseable PEM X.509 certificates (the trust anchors for
// assertion-signature validation) and that at least one has not expired:
// every signature check fails against an expired certificate, so saving only
// expired ones would just break sign-in. Several certificates are the IdP's
// signing-key rollover (current and next); any of them verifies.
func validateCertificatePEM(certPEM string) error {
	cert, err := parseCertificatePEM(certPEM)
	if err != nil {
		return err
	}
	if time.Now().After(cert.NotAfter) {
		return ErrSAMLCertExpired
	}
	return nil
}

// maxSAMLSigningCertificates bounds the certificates one SAML configuration
// trusts: the IdP's current and next signing keys, with room to spare.
const maxSAMLSigningCertificates = 5

// parseCertificatesPEM parses every PEM block of the stored IdP certificate
// field. Each block must be a CERTIFICATE that parses as X.509; at least one
// is required and at most maxSAMLSigningCertificates are accepted.
func parseCertificatesPEM(certPEM string) ([]*x509.Certificate, error) {
	rest := []byte(strings.TrimSpace(certPEM))
	var certs []*x509.Certificate
	for len(rest) > 0 {
		block, r := pem.Decode(rest)
		if block == nil {
			break
		}
		rest = r
		if block.Type != "CERTIFICATE" {
			return nil, ErrSAMLInvalidCert
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, ErrSAMLInvalidCert
		}
		certs = append(certs, cert)
		if len(certs) > maxSAMLSigningCertificates {
			return nil, ErrSAMLInvalidCert
		}
	}
	if len(certs) == 0 {
		return nil, ErrSAMLInvalidCert
	}
	return certs, nil
}

// parseCertificatePEM returns the certificate whose expiry matters for the
// stored IdP certificate field: the one that expires first among those still
// valid (sign-in breaks when the IdP still signs with it), or, when all have
// expired, the one that expired last.
func parseCertificatePEM(certPEM string) (*x509.Certificate, error) {
	certs, err := parseCertificatesPEM(certPEM)
	if err != nil {
		return nil, err
	}
	return expiryCertificate(certs, time.Now()), nil
}

func expiryCertificate(certs []*x509.Certificate, now time.Time) *x509.Certificate {
	var soonestValid, latest *x509.Certificate
	for _, c := range certs {
		if latest == nil || c.NotAfter.After(latest.NotAfter) {
			latest = c
		}
		if c.NotAfter.After(now) && (soonestValid == nil || c.NotAfter.Before(soonestValid.NotAfter)) {
			soonestValid = c
		}
	}
	if soonestValid != nil {
		return soonestValid
	}
	return latest
}

// Login starts an SP-initiated SAML login (RFC-009 9e). It returns the IdP
// redirect URL (carrying the deflate+base64 AuthnRequest) and the request ID,
// which the caller stores in a short-lived cookie so the ACS can bind the
// response's InResponseTo (replay/CSRF protection).
//
// forceAuthn asks the IdP to authenticate the user again (step-up
// re-authentication); the ACS then refuses an assertion whose AuthnInstant
// is not fresh.
func (s *SAMLService) Login(ctx context.Context, orgSlug, baseURL string, forceAuthn bool) (redirectURL, requestID string, err error) {
	sp, _, err := s.resolveServiceProvider(ctx, orgSlug, baseURL)
	if err != nil {
		return "", "", err
	}
	authnReq, err := sp.MakeAuthenticationRequest(sp.IDPMetadata.IDPSSODescriptors[0].SingleSignOnServices[0].Location, saml.HTTPRedirectBinding, saml.HTTPPostBinding)
	if err != nil {
		return "", "", fmt.Errorf("build authn request: %w", err)
	}
	if forceAuthn {
		force := true
		authnReq.ForceAuthn = &force
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
//
// forcedAuthn says the request asked for ForceAuthn: an assertion whose
// AuthnInstant is older than a few minutes is then refused.
func (s *SAMLService) ACS(ctx context.Context, orgSlug, baseURL string, r *http.Request, possibleRequestIDs []string,
	forcedAuthn bool) (*SSOCallbackResult, error) {
	sp, tenantAndCfg, err := s.resolveServiceProvider(ctx, orgSlug, baseURL)
	if err != nil {
		return nil, err
	}
	// crewjam reads the SAMLResponse from r.PostForm, which is only populated
	// by ParseForm. Without this every IdP POST looked empty ("invalid xml: no
	// root") and SAML sign-in could never succeed.
	if r.PostForm == nil {
		if ferr := r.ParseForm(); ferr != nil {
			return nil, ErrSAMLResponseInvalid
		}
	}
	assertion, perr := s.parseStrictResponse(ctx, sp, tenantAndCfg, r, possibleRequestIDs)
	if perr != nil {
		// Never leak the specific crypto/condition failure to the caller.
		s.logger.Warn("saml assertion validation failed", "org", logger.SanitizeValue(orgSlug), "error", perr)
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

	authAt := assertionAuthnInstant(assertion)
	if forcedAuthn {
		if age := time.Since(authAt); authAt.IsZero() || age > freshAuthMaxAge || age < -time.Minute {
			s.logger.Warn("saml login refused: the IdP did not authenticate the user again", "org", logger.SanitizeValue(orgSlug))
			return nil, ErrSAMLResponseInvalid
		}
	}
	if samlEntraClaimsMismatch(assertion) {
		s.logger.Warn("saml login refused: Entra issuer and tenantid claim disagree", "org", logger.SanitizeValue(orgSlug))
		return nil, ErrSAMLResponseInvalid
	}
	key, legacySubject := samlIdentity(assertion, tenantAndCfg.tenant.ID())
	return s.sso.completeFederatedLogin(ctx, tenantAndCfg.tenant, email, name, cfg.DefaultRole(), cfg.AutoProvision(),
		federatedBinding{authTime: authAt, mfa: samlMFAEvidence(assertion)},
		key, legacySubject)
}

// parseStrictResponse validates the posted response: the hardening checks
// (one signed assertion, no SHA-1), then the library's signature, condition,
// audience, destination and InResponseTo checks, then the replay cache. Only
// the HTTP-POST binding is accepted: an artifact would make the server call
// out to resolve it, and no artifact endpoint is ever advertised.
func (s *SAMLService) parseStrictResponse(ctx context.Context, sp *saml.ServiceProvider, rc resolvedSAML, r *http.Request,
	possibleRequestIDs []string) (*saml.Assertion, error) {
	if r.PostForm.Get("SAMLart") != "" || r.Form.Get("SAMLart") != "" {
		return nil, samlStrictErr("artifact binding is not accepted")
	}
	raw, err := base64.StdEncoding.DecodeString(r.PostForm.Get("SAMLResponse"))
	if err != nil || len(raw) == 0 {
		return nil, samlStrictErr("SAMLResponse is not base64")
	}
	certs, err := parseCertificatesPEM(rc.cfg.IDPCertificate())
	if err != nil {
		return nil, err
	}
	strict, err := checkSAMLResponseStrict(raw, certs, saml.Clock, sp.EntityID)
	if err != nil {
		return nil, err
	}
	sp.SignatureVerifier = samlNoWeakAlgorithmsVerifier{}
	assertion, err := parseSAMLWithoutPanic(func() (*saml.Assertion, error) {
		return sp.ParseXMLResponse(raw, possibleRequestIDs, *r.URL)
	})
	if err != nil {
		var ire *saml.InvalidResponseError
		if errors.As(err, &ire) && ire.PrivateErr != nil {
			return nil, ire.PrivateErr
		}
		return nil, err
	}
	if assertion.ID != strict.assertionID {
		return nil, samlStrictErr("validated assertion is not the signed one")
	}
	if err := s.consumeAssertion(ctx, rc.tenant.ID(), assertion, time.Now()); err != nil {
		return nil, err
	}
	return assertion, nil
}

// parseSAMLWithoutPanic runs the library's parse and turns a panic inside it
// into a refusal. The library dereferences optional elements of a signed
// assertion without nil checks; the shape checks refuse those first, and this
// keeps any other such path a failed sign-in instead of a server error.
func parseSAMLWithoutPanic(parse func() (*saml.Assertion, error)) (a *saml.Assertion, err error) {
	defer func() {
		if rec := recover(); rec != nil {
			a, err = nil, samlStrictErr("saml library panicked: %v", rec)
		}
	}()
	return parse()
}

// Entra ID's immutable user id and directory id, sent by default in every
// SAML assertion of an Entra enterprise application.
const (
	samlEntraObjectIDAttr = "http://schemas.microsoft.com/identity/claims/objectidentifier"
	samlEntraTenantIDAttr = "http://schemas.microsoft.com/identity/claims/tenantid"
	samlEntraIssuerPrefix = "https://sts.windows.net/"
)

// samlEntraClaimsMismatch reports an assertion issued by the Entra STS whose
// tenantid claim does not name the directory in its Issuer (or has none): a
// forged or confused assertion, refused rather than keyed on the NameID.
func samlEntraClaimsMismatch(a *saml.Assertion) bool {
	if a == nil || !strings.HasPrefix(a.Issuer.Value, samlEntraIssuerPrefix) {
		return false
	}
	tid := samlSingleAttribute(a, samlEntraTenantIDAttr)
	return tid == "" || a.Issuer.Value != samlEntraIssuerPrefix+tid+"/"
}

// samlIdentity is the assertion's identity, scoped to the organization whose
// IdP certificate signed the assertion (another organization can configure
// the same entity id, so the pair means nothing outside it). The subject is
// immutable, never the email:
//   - Entra ID's object id (objectidentifier claim, with tenantid), which
//     Entra sends by default, whatever NameID the application is set to;
//   - otherwise a persistent NameID.
//
// Other NameID formats are not stable (transient changes every login;
// emailAddress is the mutable email itself, and a renamed or reused address
// would inherit the old account), so they key nothing and the email finds
// the account as before. legacySubject is a persistent NameID an Entra
// identity may have been bound under before it was keyed on the object id;
// the binding is re-keyed on the next login.
func samlIdentity(a *saml.Assertion, tenantID shared.ID) (key useridentity.Key, legacySubject string) {
	if a == nil || a.Issuer.Value == "" {
		return useridentity.Key{}, ""
	}
	scope := tenantID
	persistent := ""
	if a.Subject != nil && a.Subject.NameID != nil && a.Subject.NameID.Format == string(saml.PersistentNameIDFormat) {
		persistent = strings.TrimSpace(a.Subject.NameID.Value)
	}
	oid, tid := samlSingleAttribute(a, samlEntraObjectIDAttr), samlSingleAttribute(a, samlEntraTenantIDAttr)
	// The claims are attributes any IdP can pass through (a user-editable
	// attribute on another IdP could name someone else's object id), so they
	// count only when the assertion's own Issuer is the Entra STS of that
	// tenant id.
	if oid != "" && tid != "" && a.Issuer.Value == samlEntraIssuerPrefix+tid+"/" {
		subject := tid + "/" + oid
		if persistent == subject {
			persistent = ""
		}
		return useridentity.Key{Issuer: a.Issuer.Value, Subject: subject, ScopeTenantID: &scope}, persistent
	}
	if persistent == "" {
		return useridentity.Key{}, ""
	}
	return useridentity.Key{Issuer: a.Issuer.Value, Subject: persistent, ScopeTenantID: &scope}, ""
}

// samlIdentityKey is samlIdentity without the legacy subject.
func samlIdentityKey(a *saml.Assertion, tenantID shared.ID) useridentity.Key {
	k, _ := samlIdentity(a, tenantID)
	return k
}

// samlSingleAttribute returns the value of the attribute named name when the
// assertion carries it exactly once with exactly one non-empty value of at
// most 128 characters; otherwise "" (an ambiguous identity keys nothing).
func samlSingleAttribute(a *saml.Assertion, name string) string {
	found := ""
	n := 0
	for _, st := range a.AttributeStatements {
		for _, attr := range st.Attributes {
			if attr.Name != name {
				continue
			}
			n++
			if len(attr.Values) != 1 {
				return ""
			}
			found = strings.TrimSpace(attr.Values[0].Value)
		}
	}
	if n != 1 || found == "" || len(found) > 128 || strings.ContainsAny(found, "/ \t\r\n") {
		return ""
	}
	return found
}

// assertionAuthnInstant is the latest AuthnInstant of the (signature- and
// condition-checked) assertion's authentication statements.
func assertionAuthnInstant(a *saml.Assertion) time.Time {
	var at time.Time
	for _, st := range a.AuthnStatements {
		if st.AuthnInstant.After(at) {
			at = st.AuthnInstant
		}
	}
	return at
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
// entity id, SSO URL and signing certificates — the trust anchors
// ParseResponse uses to verify the assertion signature (any one of them).
func buildIDPMetadata(p *samldom.SAMLProvider) (*saml.EntityDescriptor, error) {
	certs, err := parseCertificatesPEM(p.IDPCertificate())
	if err != nil {
		return nil, err
	}
	keys := make([]saml.KeyDescriptor, 0, len(certs))
	for _, c := range certs {
		keys = append(keys, saml.KeyDescriptor{
			Use: "signing",
			KeyInfo: saml.KeyInfo{
				X509Data: saml.X509Data{
					X509Certificates: []saml.X509Certificate{{Data: base64.StdEncoding.EncodeToString(c.Raw)}},
				},
			},
		})
	}

	return &saml.EntityDescriptor{
		EntityID: p.IDPEntityID(),
		IDPSSODescriptors: []saml.IDPSSODescriptor{{
			SSODescriptor: saml.SSODescriptor{
				RoleDescriptor: saml.RoleDescriptor{KeyDescriptors: keys},
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

// SPMetadataForTenant returns the SP metadata XML of an organization (by id)
// and its slug, built on the configured public origin. It is the platform
// admin console's download of the file to upload in the IdP's SAML
// application; the public metadata URL serves the same document.
func (s *SAMLService) SPMetadataForTenant(ctx context.Context, tenantID shared.ID, baseURL string) (xmlDoc, slug string, err error) {
	t, err := s.tenantRepo.GetByID(ctx, tenantID)
	if err != nil {
		return "", "", ErrSAMLTenantNotFound
	}
	doc, err := s.Metadata(ctx, t.Slug(), baseURL)
	if err != nil {
		return "", "", err
	}
	return doc, t.Slug(), nil
}
