package auth

import (
	"context"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/openctem/server/pkg/domain/shared"
	"github.com/openctemio/openctem/server/pkg/logger"
)

// certB64 is the base64 DER of a PEM certificate, as metadata carries it.
func certB64(t *testing.T, certPEM string) string {
	t.Helper()
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		t.Fatal("bad test PEM")
	}
	return base64.StdEncoding.EncodeToString(block.Bytes)
}

func keyDescriptor(use, b64 string) string {
	attr := ""
	if use != "" {
		attr = ` use="` + use + `"`
	}
	return `<KeyDescriptor` + attr + `><KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#"><X509Data><X509Certificate>` +
		b64 + `</X509Certificate></X509Data></KeyInfo></KeyDescriptor>`
}

// entraLikeMetadata is shaped like a federation metadata document: a
// WS-Federation role descriptor with its own key (ignored) and the SAML IdP
// descriptor.
func entraLikeMetadata(keys ...string) string {
	return `<?xml version="1.0" encoding="utf-8"?>
<EntityDescriptor ID="_x" entityID="https://sts.windows.net/00000000-0000-0000-0000-000000000001/" xmlns="urn:oasis:names:tc:SAML:2.0:metadata">
  <RoleDescriptor xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="fed:SecurityTokenServiceType" protocolSupportEnumeration="http://docs.oasis-open.org/wsfed/federation/200706">
    <KeyDescriptor use="signing"><KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#"><X509Data><X509Certificate>bm90LWEtY2VydA==</X509Certificate></X509Data></KeyInfo></KeyDescriptor>
  </RoleDescriptor>
  <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    ` + strings.Join(keys, "\n    ") + `
    <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://login.microsoftonline.com/t/saml2/post"/>
    <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://login.microsoftonline.com/t/saml2"/>
  </IDPSSODescriptor>
</EntityDescriptor>`
}

func wantMetadataReason(t *testing.T, err error, reason string) {
	t.Helper()
	var me *SAMLMetadataError
	if !errors.As(err, &me) {
		t.Fatalf("want SAMLMetadataError(%s), got %v", reason, err)
	}
	if me.Reason != reason {
		t.Fatalf("reason = %q, want %q", me.Reason, reason)
	}
}

func TestParseIdPMetadata_EntraShape(t *testing.T) {
	cur := genTestCertPEM(t)
	next := genTestCertPEM(t)
	enc := genTestCertPEM(t)
	doc := entraLikeMetadata(keyDescriptor("signing", certB64(t, cur)), keyDescriptor("", certB64(t, next)),
		keyDescriptor("encryption", certB64(t, enc)), keyDescriptor("signing", certB64(t, cur)))
	md, err := ParseIdPMetadata([]byte(doc), time.Now())
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if md.EntityID != "https://sts.windows.net/00000000-0000-0000-0000-000000000001/" {
		t.Errorf("entity id = %q", md.EntityID)
	}
	if md.SSOURL != "https://login.microsoftonline.com/t/saml2" || md.SSOBinding != bindingRedirect {
		t.Errorf("sso = %q (%s), want the HTTP-Redirect endpoint", md.SSOURL, md.SSOBinding)
	}
	// The duplicate is dropped, the encryption key and the WS-Fed key ignored.
	if len(md.Certificates) != 2 {
		t.Fatalf("certificates = %d, want 2 (current + next signing)", len(md.Certificates))
	}
	if md.Certificates[0].PEM != cur || md.Certificates[1].PEM != next {
		t.Error("certificates are not the signing ones in document order")
	}
	// The joined form is what the SAML configuration stores, and it validates.
	if err := validateCertificatePEM(md.CertificatesPEM()); err != nil {
		t.Fatalf("joined certificates do not validate: %v", err)
	}
}

func TestParseIdPMetadata_EntitiesDescriptorWithOneEntity(t *testing.T) {
	inner := entraLikeMetadata(keyDescriptor("signing", certB64(t, genTestCertPEM(t))))
	inner = strings.TrimPrefix(inner, `<?xml version="1.0" encoding="utf-8"?>`)
	doc := `<EntitiesDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata">` + inner + `</EntitiesDescriptor>`
	if _, err := ParseIdPMetadata([]byte(doc), time.Now()); err != nil {
		t.Fatalf("one entity in an EntitiesDescriptor must parse: %v", err)
	}
	two := `<EntitiesDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata">` + inner + inner + `</EntitiesDescriptor>`
	_, err := ParseIdPMetadata([]byte(two), time.Now())
	wantMetadataReason(t, err, SAMLMetadataReasonNotMetadata)
}

func TestParseIdPMetadata_HostileAndInvalid(t *testing.T) {
	good := keyDescriptor("signing", certB64(t, genTestCertPEM(t)))
	expired := keyDescriptor("signing", certB64(t, certPEMValidUntil(t, time.Now().Add(-time.Hour))))
	cases := []struct {
		name   string
		doc    string
		reason string
	}{
		{"empty", "  ", SAMLMetadataReasonEmpty},
		{"oversized", "<x>" + strings.Repeat("a", MaxIdPMetadataBytes) + "</x>", SAMLMetadataReasonTooLarge},
		{"xxe external entity", `<?xml version="1.0"?><!DOCTYPE md [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>` +
			`<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="&xxe;"/>`, SAMLMetadataReasonDoctype},
		{"billion laughs", `<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;&lol;&lol;">` +
			`<!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;">]><EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="&lol3;"/>`,
			SAMLMetadataReasonDoctype},
		{"bare doctype", `<!DOCTYPE EntityDescriptor><EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata"/>`, SAMLMetadataReasonDoctype},
		{"undeclared entity", `<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="&x;"/>`, SAMLMetadataReasonMalformed},
		{"not xml", "hello", SAMLMetadataReasonMalformed},
		{"deep nesting", strings.Repeat("<a>", 100) + strings.Repeat("</a>", 100), SAMLMetadataReasonMalformed},
		{"wrong root", `<AuthnRequest xmlns="urn:oasis:names:tc:SAML:2.0:protocol"/>`, SAMLMetadataReasonNotMetadata},
		{"wrong namespace", `<EntityDescriptor entityID="x"/>`, SAMLMetadataReasonNotMetadata},
		{"sp metadata only", `<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="x">` +
			`<SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"/></EntityDescriptor>`, SAMLMetadataReasonNoIdP},
		{"no entity id", strings.Replace(entraLikeMetadata(good), `entityID="https://sts.windows.net/00000000-0000-0000-0000-000000000001/"`, "", 1), SAMLMetadataReasonNoEntityID},
		{"no https sso url", strings.ReplaceAll(entraLikeMetadata(good), `Location="https://`, `Location="http://`), SAMLMetadataReasonNoSSOURL},
		{"encryption key only", entraLikeMetadata(keyDescriptor("encryption", certB64(t, genTestCertPEM(t)))), SAMLMetadataReasonNoSigningCert},
		{"no key at all", entraLikeMetadata(), SAMLMetadataReasonNoSigningCert},
		{"garbage certificate", entraLikeMetadata(keyDescriptor("signing", "bm90LWEtY2VydA==")), SAMLMetadataReasonInvalidCert},
		{"expired only", entraLikeMetadata(expired), SAMLMetadataReasonCertExpired},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseIdPMetadata([]byte(tc.doc), time.Now())
			wantMetadataReason(t, err, tc.reason)
			if !errors.Is(err, shared.ErrValidation) {
				t.Errorf("a refused document must be a validation error, got %v", err)
			}
		})
	}
}

func TestParseIdPMetadata_ExpiredDroppedNextKept(t *testing.T) {
	expired := certPEMValidUntil(t, time.Now().Add(-time.Hour))
	cur := genTestCertPEM(t)
	md, err := ParseIdPMetadata([]byte(entraLikeMetadata(keyDescriptor("signing", certB64(t, expired)),
		keyDescriptor("signing", certB64(t, cur)))), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if len(md.Certificates) != 1 || md.Certificates[0].PEM != cur {
		t.Fatalf("want only the unexpired certificate, got %d", len(md.Certificates))
	}
}

func TestParseIdPMetadata_TooManyCertificates(t *testing.T) {
	keys := make([]string, 0, maxSAMLSigningCertificates+1)
	for i := 0; i <= maxSAMLSigningCertificates; i++ {
		keys = append(keys, keyDescriptor("signing", certB64(t, genTestCertPEM(t))))
	}
	_, err := ParseIdPMetadata([]byte(entraLikeMetadata(keys...)), time.Now())
	wantMetadataReason(t, err, SAMLMetadataReasonTooManyCerts)
}

// --- fetch: the SSRF guard ---

func TestIdPMetadataFetch_RefusesUnsafeURLs(t *testing.T) {
	f := newIdPMetadataFetcher() // the real guard
	ctx := context.Background()
	for _, tc := range []struct{ url, reason string }{
		{"http://login.microsoftonline.com/x/federationmetadata.xml", SAMLMetadataReasonBadURL},
		{"file:///etc/passwd", SAMLMetadataReasonBadURL},
		{"https://user:pw@example.com/md.xml", SAMLMetadataReasonBadURL},
		{"https://127.0.0.1/md.xml", SAMLMetadataReasonURLBlocked},
		{"https://169.254.169.254/latest/meta-data", SAMLMetadataReasonURLBlocked},
		{"https://10.0.0.5/md.xml", SAMLMetadataReasonURLBlocked},
		{"https://localhost/md.xml", SAMLMetadataReasonURLBlocked},
		{"https://example.com/" + strings.Repeat("a", maxIdPMetadataURL), SAMLMetadataReasonBadURL},
	} {
		_, err := f.fetch(ctx, tc.url)
		wantMetadataReason(t, err, tc.reason)
	}
}

// A test fetcher whose guard admits only the test server's origin, so the
// fetch logic (status, size cap, redirects) runs against httptest.
func testFetcher(srv *httptest.Server, allowed string) *idpMetadataFetcher {
	return &idpMetadataFetcher{
		client: srv.Client(),
		validate: func(raw string) error {
			if strings.HasPrefix(raw, allowed) {
				return nil
			}
			return errors.New("blocked")
		},
	}
}

func TestIdPMetadataFetch_ServerBehaviour(t *testing.T) {
	doc := entraLikeMetadata(keyDescriptor("signing", certB64(t, genTestCertPEM(t))))
	mux := http.NewServeMux()
	mux.HandleFunc("/ok", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(doc)) })
	mux.HandleFunc("/big", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(strings.Repeat("a", MaxIdPMetadataBytes+10)))
	})
	mux.HandleFunc("/missing", http.NotFound)
	mux.HandleFunc("/to-internal", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://169.254.169.254/latest/meta-data", http.StatusFound)
	})
	mux.HandleFunc("/to-http", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://example.com/md.xml", http.StatusFound)
	})
	srv := httptest.NewTLSServer(mux)
	defer srv.Close()
	f := testFetcher(srv, srv.URL)
	ctx := context.Background()

	body, err := f.fetch(ctx, srv.URL+"/ok")
	if err != nil || string(body) != doc {
		t.Fatalf("fetch ok: %v", err)
	}
	_, err = f.fetch(ctx, srv.URL+"/big")
	wantMetadataReason(t, err, SAMLMetadataReasonTooLarge)
	_, err = f.fetch(ctx, srv.URL+"/missing")
	wantMetadataReason(t, err, SAMLMetadataReasonUnreachable)
	_, err = f.fetch(ctx, srv.URL+"/to-internal")
	wantMetadataReason(t, err, SAMLMetadataReasonURLBlocked)
	_, err = f.fetch(ctx, srv.URL+"/to-http")
	wantMetadataReason(t, err, SAMLMetadataReasonURLBlocked)
}

func TestImportIdPMetadata_Sources(t *testing.T) {
	svc := &SAMLService{logger: logger.NewNop()}
	ctx := context.Background()
	_, err := svc.ImportIdPMetadata(ctx, IdPMetadataImportInput{})
	wantMetadataReason(t, err, SAMLMetadataReasonOneSource)
	_, err = svc.ImportIdPMetadata(ctx, IdPMetadataImportInput{URL: "https://a.example", XML: "<x/>"})
	wantMetadataReason(t, err, SAMLMetadataReasonOneSource)

	doc := entraLikeMetadata(keyDescriptor("signing", certB64(t, genTestCertPEM(t))))
	md, err := svc.ImportIdPMetadata(ctx, IdPMetadataImportInput{XML: doc})
	if err != nil || md.SSOURL == "" {
		t.Fatalf("file import: %v", err)
	}

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/xml")
		_, _ = fmt.Fprint(w, doc)
	}))
	defer srv.Close()
	svc.metadataFetcher = testFetcher(srv, srv.URL)
	md, err = svc.ImportIdPMetadata(ctx, IdPMetadataImportInput{URL: srv.URL + "/federationmetadata.xml"})
	if err != nil || len(md.Certificates) != 1 {
		t.Fatalf("url import: %v", err)
	}
}

// --- stored certificate field with several certificates ---

func TestParseCertificatesPEM_Multiple(t *testing.T) {
	a, b := genTestCertPEM(t), genTestCertPEM(t)
	certs, err := parseCertificatesPEM(a + "\n" + b)
	if err != nil || len(certs) != 2 {
		t.Fatalf("two blocks: %d, %v", len(certs), err)
	}
	if _, err := parseCertificatesPEM(a + "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n"); !errors.Is(err, ErrSAMLInvalidCert) {
		t.Fatalf("a non-certificate block must be refused, got %v", err)
	}
	many := strings.Repeat(a, maxSAMLSigningCertificates+1)
	if _, err := parseCertificatesPEM(many); !errors.Is(err, ErrSAMLInvalidCert) {
		t.Fatalf("too many certificates must be refused, got %v", err)
	}
}

func TestValidateCertificatePEM_RolloverSet(t *testing.T) {
	expired := certPEMValidUntil(t, time.Now().Add(-time.Hour))
	soon := certPEMValidUntil(t, time.Now().Add(48*time.Hour))
	later := certPEMValidUntil(t, time.Now().Add(400*24*time.Hour))
	if err := validateCertificatePEM(expired + later); err != nil {
		t.Fatalf("a set with an unexpired certificate is valid: %v", err)
	}
	if err := validateCertificatePEM(expired + expired); !errors.Is(err, ErrSAMLCertExpired) {
		t.Fatalf("only expired: want ErrSAMLCertExpired, got %v", err)
	}
	// The expiry shown and alerted on is the first valid one to expire.
	na := CertificateNotAfter(later + soon + expired)
	if d := time.Until(na); d > 49*time.Hour || d < 47*time.Hour {
		t.Fatalf("CertificateNotAfter = %v, want the soonest unexpired (48h)", na)
	}
}
