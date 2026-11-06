package auth

// Import of an identity provider's SAML 2.0 federation metadata (an uploaded
// file or the IdP's metadata URL) into the SAML configuration form of the
// platform admin console. Design: docs/architecture/sso-authentication.md,
// section "SAML: importing the IdP's federation metadata".
//
// The import only READS and returns the IdP side (entity id, sign-in URL,
// signing certificates); it stores nothing. The administrator saves the
// result through the SAML configuration write, which waits for an owner of
// the organization like any other SSO change, so this adds no write path.
//
// Threat model: the metadata is untrusted input (any URL a platform
// administrator types, or a file). Defenses:
//   - SSRF: https only, no userinfo, the URL and every redirect hop checked by
//     httpsec.ValidateURL, fetched through httpsec.SafeHTTPClient (resolve
//     once, dial the vetted address), 10 s timeout, 1 MiB cap.
//   - XML: any DOCTYPE or other directive is refused before decoding, so no
//     entity (external or recursive) is ever defined; the nesting depth is
//     bounded; only an EntityDescriptor root (or an EntitiesDescriptor with
//     exactly one) is accepted.
//   - Trust: certificates come only from IDPSSODescriptor KeyDescriptors whose
//     use is "signing" or unset (never encryption keys, never other role
//     descriptors), each must parse as X.509, and expired ones are dropped.
//     A signature on the metadata is not required: the administrator chose
//     the source, and an owner approves the resulting configuration.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"encoding/xml"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/openctemio/openctem/server/pkg/domain/shared"
	"github.com/openctemio/openctem/server/pkg/httpsec"
)

const (
	// MaxIdPMetadataBytes caps an IdP metadata document, fetched or uploaded.
	MaxIdPMetadataBytes = 1 << 20
	idpMetadataTimeout  = 10 * time.Second
	maxIdPMetadataURL   = 2048
	maxIdPMetadataDepth = 32
	maxIdPEntityIDLen   = 1024
	// idpCertNotBeforeSkew tolerates an IdP clock slightly ahead of ours for
	// a certificate that has only just become valid.
	idpCertNotBeforeSkew = 5 * time.Minute

	samlMetadataNS  = "urn:oasis:names:tc:SAML:2.0:metadata"
	schemeHTTPS     = "https"
	bindingRedirect = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
	bindingPOST     = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
)

// Reasons an IdP metadata import is refused (SAMLMetadataError.Reason). They
// are stable codes the console translates.
const (
	SAMLMetadataReasonEmpty         = "empty"
	SAMLMetadataReasonTooLarge      = "too_large"
	SAMLMetadataReasonDoctype       = "doctype"
	SAMLMetadataReasonMalformed     = "malformed"
	SAMLMetadataReasonNotMetadata   = "not_metadata"
	SAMLMetadataReasonNoIdP         = "no_idp"
	SAMLMetadataReasonNoEntityID    = "no_entity_id"
	SAMLMetadataReasonNoSSOURL      = "no_sso_url"
	SAMLMetadataReasonNoSigningCert = "no_signing_certificate"
	SAMLMetadataReasonInvalidCert   = "invalid_certificate"
	SAMLMetadataReasonCertExpired   = "certificate_expired"
	SAMLMetadataReasonTooManyCerts  = "too_many_certificates"
	SAMLMetadataReasonBadURL        = "invalid_url"
	SAMLMetadataReasonURLBlocked    = "url_blocked"
	SAMLMetadataReasonUnreachable   = "unreachable"
	SAMLMetadataReasonOneSource     = "one_source"
)

// SAMLMetadataError refuses an IdP metadata import. Reason is one of the
// SAMLMetadataReason codes; the error never carries the document or the URL.
type SAMLMetadataError struct{ Reason string }

func (e *SAMLMetadataError) Error() string { return "saml idp metadata refused: " + e.Reason }

// Unwrap makes every refusal a validation error, except an unreachable URL.
func (e *SAMLMetadataError) Unwrap() error {
	if e.Reason == SAMLMetadataReasonUnreachable {
		return nil
	}
	return shared.ErrValidation
}

func metadataErr(reason string) error { return &SAMLMetadataError{Reason: reason} }

// IdPMetadata is the IdP side of a SAML configuration read from metadata.
type IdPMetadata struct {
	EntityID     string
	SSOURL       string
	SSOBinding   string
	Certificates []IdPMetadataCertificate
}

// IdPMetadataCertificate is one unexpired signing certificate of the IdP.
type IdPMetadataCertificate struct {
	PEM      string
	Subject  string
	NotAfter time.Time
	SHA256   string
}

// CertificatesPEM joins the certificates as the SAML configuration stores
// them (concatenated PEM blocks).
func (m *IdPMetadata) CertificatesPEM() string {
	var b strings.Builder
	for _, c := range m.Certificates {
		b.WriteString(c.PEM)
	}
	return b.String()
}

type mdEndpoint struct {
	Binding  string `xml:"Binding,attr"`
	Location string `xml:"Location,attr"`
}

type mdX509Data struct {
	Certificates []string `xml:"http://www.w3.org/2000/09/xmldsig# X509Certificate"`
}

type mdKeyInfo struct {
	X509Data []mdX509Data `xml:"http://www.w3.org/2000/09/xmldsig# X509Data"`
}

type mdKeyDescriptor struct {
	Use     string    `xml:"use,attr"`
	KeyInfo mdKeyInfo `xml:"http://www.w3.org/2000/09/xmldsig# KeyInfo"`
}

type mdIDPSSODescriptor struct {
	Protocols string            `xml:"protocolSupportEnumeration,attr"`
	Keys      []mdKeyDescriptor `xml:"urn:oasis:names:tc:SAML:2.0:metadata KeyDescriptor"`
	SSO       []mdEndpoint      `xml:"urn:oasis:names:tc:SAML:2.0:metadata SingleSignOnService"`
}

type mdEntityDescriptor struct {
	EntityID string               `xml:"entityID,attr"`
	IDPSSO   []mdIDPSSODescriptor `xml:"urn:oasis:names:tc:SAML:2.0:metadata IDPSSODescriptor"`
}

type mdEntitiesDescriptor struct {
	Entities []mdEntityDescriptor `xml:"urn:oasis:names:tc:SAML:2.0:metadata EntityDescriptor"`
}

// ParseIdPMetadata reads the IdP side of SAML 2.0 metadata. now decides which
// certificates have expired. Every refusal is a *SAMLMetadataError.
func ParseIdPMetadata(raw []byte, now time.Time) (*IdPMetadata, error) {
	if len(bytes.TrimSpace(raw)) == 0 {
		return nil, metadataErr(SAMLMetadataReasonEmpty)
	}
	if len(raw) > MaxIdPMetadataBytes {
		return nil, metadataErr(SAMLMetadataReasonTooLarge)
	}
	root, err := scanMetadataXML(raw)
	if err != nil {
		return nil, err
	}

	var entity mdEntityDescriptor
	switch root {
	case xml.Name{Space: samlMetadataNS, Local: "EntityDescriptor"}:
		if err := xml.Unmarshal(raw, &entity); err != nil {
			return nil, metadataErr(SAMLMetadataReasonMalformed)
		}
	case xml.Name{Space: samlMetadataNS, Local: "EntitiesDescriptor"}:
		var all mdEntitiesDescriptor
		if err := xml.Unmarshal(raw, &all); err != nil {
			return nil, metadataErr(SAMLMetadataReasonMalformed)
		}
		if len(all.Entities) != 1 {
			return nil, metadataErr(SAMLMetadataReasonNotMetadata)
		}
		entity = all.Entities[0]
	default:
		return nil, metadataErr(SAMLMetadataReasonNotMetadata)
	}
	return idpFromEntity(entity, now)
}

// scanMetadataXML walks every token before anything is decoded: a DOCTYPE
// (or any other directive) is refused, so no entity can be declared, and the
// depth is bounded. It returns the root element's name.
func scanMetadataXML(raw []byte) (xml.Name, error) {
	dec := xml.NewDecoder(bytes.NewReader(raw))
	dec.Strict = true
	var root xml.Name
	depth := 0
	for {
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return xml.Name{}, metadataErr(SAMLMetadataReasonMalformed)
		}
		switch t := tok.(type) {
		case xml.Directive:
			return xml.Name{}, metadataErr(SAMLMetadataReasonDoctype)
		case xml.StartElement:
			if depth == 0 {
				if root.Local != "" {
					return xml.Name{}, metadataErr(SAMLMetadataReasonMalformed)
				}
				root = t.Name
			}
			depth++
			if depth > maxIdPMetadataDepth {
				return xml.Name{}, metadataErr(SAMLMetadataReasonMalformed)
			}
		case xml.EndElement:
			depth--
		}
	}
	if root.Local == "" {
		return xml.Name{}, metadataErr(SAMLMetadataReasonMalformed)
	}
	return root, nil
}

func idpFromEntity(e mdEntityDescriptor, now time.Time) (*IdPMetadata, error) {
	var idp *mdIDPSSODescriptor
	for i := range e.IDPSSO {
		if strings.Contains(e.IDPSSO[i].Protocols, samlProtocolNS) {
			idp = &e.IDPSSO[i]
			break
		}
	}
	if idp == nil {
		return nil, metadataErr(SAMLMetadataReasonNoIdP)
	}
	entityID := strings.TrimSpace(e.EntityID)
	if entityID == "" || len(entityID) > maxIdPEntityIDLen {
		return nil, metadataErr(SAMLMetadataReasonNoEntityID)
	}
	ssoURL, binding, err := pickSSOEndpoint(idp.SSO)
	if err != nil {
		return nil, err
	}
	certs, err := signingCertificates(idp.Keys, now)
	if err != nil {
		return nil, err
	}
	return &IdPMetadata{EntityID: entityID, SSOURL: ssoURL, SSOBinding: binding, Certificates: certs}, nil
}

// pickSSOEndpoint prefers the HTTP-Redirect binding (the one sign-in sends)
// and falls back to HTTP-POST. The location must be an https URL.
func pickSSOEndpoint(eps []mdEndpoint) (location, binding string, err error) {
	for _, want := range []string{bindingRedirect, bindingPOST} {
		for _, ep := range eps {
			if ep.Binding != want {
				continue
			}
			loc := strings.TrimSpace(ep.Location)
			u, perr := url.Parse(loc)
			if perr != nil || u.Scheme != schemeHTTPS || u.Host == "" || u.User != nil || len(loc) > maxIdPMetadataURL {
				continue
			}
			return loc, want, nil
		}
	}
	return "", "", metadataErr(SAMLMetadataReasonNoSSOURL)
}

// signingCertificates returns the unexpired certificates of the signing (or
// unspecified-use) KeyDescriptors, deduplicated, at most
// maxSAMLSigningCertificates. Encryption keys are ignored.
func signingCertificates(keys []mdKeyDescriptor, now time.Time) ([]IdPMetadataCertificate, error) {
	var out []IdPMetadataCertificate
	seen := map[string]bool{}
	for _, k := range keys {
		if use := strings.TrimSpace(k.Use); use != "" && use != "signing" {
			continue
		}
		for _, xd := range k.KeyInfo.X509Data {
			for _, data := range xd.Certificates {
				der, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(data), ""))
				if err != nil || len(der) == 0 {
					return nil, metadataErr(SAMLMetadataReasonInvalidCert)
				}
				cert, err := x509.ParseCertificate(der)
				if err != nil {
					return nil, metadataErr(SAMLMetadataReasonInvalidCert)
				}
				sum := sha256.Sum256(der)
				fp := hex.EncodeToString(sum[:])
				if seen[fp] {
					continue
				}
				seen[fp] = true
				if !now.Before(cert.NotAfter) || now.Add(idpCertNotBeforeSkew).Before(cert.NotBefore) {
					continue // expired, or not valid yet
				}
				out = append(out, IdPMetadataCertificate{
					PEM:      string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
					Subject:  cert.Subject.String(),
					NotAfter: cert.NotAfter.UTC(),
					SHA256:   fp,
				})
			}
		}
	}
	switch {
	case len(seen) == 0:
		return nil, metadataErr(SAMLMetadataReasonNoSigningCert)
	case len(out) == 0:
		return nil, metadataErr(SAMLMetadataReasonCertExpired)
	case len(out) > maxSAMLSigningCertificates:
		return nil, metadataErr(SAMLMetadataReasonTooManyCerts)
	}
	return out, nil
}

// idpMetadataFetcher fetches IdP metadata from a URL under the SSRF guard.
type idpMetadataFetcher struct {
	client   *http.Client
	validate func(string) error
}

func newIdPMetadataFetcher() *idpMetadataFetcher {
	return &idpMetadataFetcher{
		client: httpsec.SafeHTTPClient(idpMetadataTimeout),
		validate: func(raw string) error {
			_, err := httpsec.ValidateURL(raw)
			return err
		},
	}
}

func checkMetadataURL(raw string) error {
	if raw == "" || len(raw) > maxIdPMetadataURL {
		return metadataErr(SAMLMetadataReasonBadURL)
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != schemeHTTPS || u.Hostname() == "" || u.User != nil {
		return metadataErr(SAMLMetadataReasonBadURL)
	}
	return nil
}

// fetch GETs the metadata document: https only, every hop validated, bounded
// in time and size.
func (f *idpMetadataFetcher) fetch(ctx context.Context, rawURL string) ([]byte, error) {
	rawURL = strings.TrimSpace(rawURL)
	if err := checkMetadataURL(rawURL); err != nil {
		return nil, err
	}
	if err := f.validate(rawURL); err != nil {
		return nil, metadataErr(SAMLMetadataReasonURLBlocked)
	}
	client := *f.client
	client.Timeout = idpMetadataTimeout
	blocked := false
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if err := httpsec.CheckRedirect(req, via); err != nil {
			blocked = true // https to http, or too many hops
			return err
		}
		next := req.URL.String()
		if checkMetadataURL(next) != nil || f.validate(next) != nil {
			blocked = true
			return errors.New("redirect target refused")
		}
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, idpMetadataTimeout)
	defer cancel()
	// The URL was parsed and validated above (https, no userinfo, public host
	// after DNS resolution, every redirect hop re-checked); the request carries
	// the parsed value, and the client's dialer re-checks the resolved address.
	target, perr := url.Parse(rawURL)
	if perr != nil {
		return nil, metadataErr(SAMLMetadataReasonBadURL)
	}
	req := (&http.Request{Method: http.MethodGet, URL: target, Host: target.Host, Header: make(http.Header)}).WithContext(ctx)
	req.Header.Set("Accept", "application/samlmetadata+xml, application/xml, text/xml")
	resp, err := client.Do(req)
	if err != nil {
		if blocked {
			return nil, metadataErr(SAMLMetadataReasonURLBlocked)
		}
		return nil, metadataErr(SAMLMetadataReasonUnreachable)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, metadataErr(SAMLMetadataReasonUnreachable)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, MaxIdPMetadataBytes+1))
	if err != nil {
		return nil, metadataErr(SAMLMetadataReasonUnreachable)
	}
	if len(body) > MaxIdPMetadataBytes {
		return nil, metadataErr(SAMLMetadataReasonTooLarge)
	}
	return body, nil
}

// IdPMetadataImportInput names the metadata source: exactly one of URL and XML.
type IdPMetadataImportInput struct {
	URL string
	XML string
}

// ImportIdPMetadata reads the IdP side of a SAML configuration from the IdP's
// metadata URL or an uploaded metadata document. It stores nothing.
func (s *SAMLService) ImportIdPMetadata(ctx context.Context, in IdPMetadataImportInput) (*IdPMetadata, error) {
	hasURL, hasXML := strings.TrimSpace(in.URL) != "", strings.TrimSpace(in.XML) != ""
	if hasURL == hasXML {
		return nil, metadataErr(SAMLMetadataReasonOneSource)
	}
	raw := []byte(in.XML)
	source := "file"
	if hasURL {
		source = "url"
		f := s.metadataFetcher
		if f == nil {
			f = newIdPMetadataFetcher()
		}
		body, err := f.fetch(ctx, in.URL)
		if err != nil {
			return nil, err
		}
		raw = body
	}
	md, err := ParseIdPMetadata(raw, time.Now())
	if err != nil {
		return nil, err
	}
	s.logger.Info("saml idp metadata read", "source", source, "certificates", len(md.Certificates))
	return md, nil
}
