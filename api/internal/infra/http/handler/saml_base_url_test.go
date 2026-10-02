package handler

import (
	"net/http/httptest"
	"testing"

	"github.com/openctemio/openctem/api/pkg/httpsec"
)

// The SP entity ID / ACS URL were built from X-Forwarded-Host and
// X-Forwarded-Proto taken from ANY client. A request to the ACS carrying
// X-Forwarded-Host: evil.example made the SP expect an assertion whose
// audience/destination is evil.example — so an assertion the IdP issued to
// another service provider could be replayed here — and the metadata and
// AuthnRequest advertised attacker-chosen URLs.
func TestSAMLBaseURL_IgnoresForwardedHeadersFromUntrustedClients(t *testing.T) {
	r := httptest.NewRequest("POST", "http://api.openctem.example/api/v1/auth/saml/acme/acs", nil)
	r.RemoteAddr = "203.0.113.7:51000" // an Internet client, not a proxy
	r.Header.Set("X-Forwarded-Host", "evil.example")
	r.Header.Set("X-Forwarded-Proto", "https")

	got := samlBaseURL(r, "", httpsec.NewTrustedProxySet(nil))
	if got != "http://api.openctem.example" {
		t.Fatalf("base URL %q: forwarded headers from an untrusted client must be ignored", got)
	}
}

func TestSAMLBaseURL_ConfiguredPublicURLWins(t *testing.T) {
	r := httptest.NewRequest("POST", "http://10.0.0.8:8080/api/v1/auth/saml/acme/acs", nil)
	r.RemoteAddr = "10.0.0.2:4000"
	r.Header.Set("X-Forwarded-Host", "evil.example")

	trusted := httpsec.NewTrustedProxySet([]string{"10.0.0.0/8"})
	if got := samlBaseURL(r, "https://ctem.example.com/", trusted); got != "https://ctem.example.com" {
		t.Fatalf("base URL %q, want the configured APP_URL origin", got)
	}
	r.Host = "evil.example"
	if got := samlBaseURL(r, "https://ctem.example.com", trusted); got != "https://ctem.example.com" {
		t.Fatalf("base URL %q, a spoofed Host must not override APP_URL", got)
	}
}

func TestSAMLBaseURL_TrustedProxyForwardingHonored(t *testing.T) {
	r := httptest.NewRequest("GET", "http://api:8080/api/v1/auth/saml/acme/metadata", nil)
	r.RemoteAddr = "10.0.0.2:4000"
	r.Header.Set("X-Forwarded-Host", "ctem.example.com")
	r.Header.Set("X-Forwarded-Proto", "https")

	trusted := httpsec.NewTrustedProxySet([]string{"10.0.0.0/8"})
	if got := samlBaseURL(r, "", trusted); got != "https://ctem.example.com" {
		t.Fatalf("base URL %q, want the proxy-forwarded origin", got)
	}

	// Even from a trusted proxy, junk is not echoed into SP URLs.
	r.Header.Set("X-Forwarded-Proto", "javascript")
	r.Header.Set("X-Forwarded-Host", "a.example/evil?x=")
	if got := samlBaseURL(r, "", trusted); got != "http://api:8080" {
		t.Fatalf("base URL %q, malformed forwarded values must be ignored", got)
	}
}
