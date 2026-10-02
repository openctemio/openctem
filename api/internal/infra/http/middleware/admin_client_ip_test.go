package middleware

import (
	"net/http/httptest"
	"testing"

	"github.com/openctemio/openctem/api/pkg/httpsec"
)

// The admin console records the client IP on sessions and in the admin audit
// log. Forwarding headers count only from a trusted proxy (S-4); without one
// the TCP peer is the client, and behind one the forwarded client is.
func TestExtractIP_TrustedProxyRule(t *testing.T) {
	t.Cleanup(func() { SetTrustedProxies(nil) })

	req := httptest.NewRequest("POST", "/api/v1/admin/auth/session", nil)
	req.RemoteAddr = "203.0.113.9:4444"
	req.Header.Set("X-Forwarded-For", "1.2.3.4")

	SetTrustedProxies(nil)
	if ip := ClientIP(req); ip != "203.0.113.9" {
		t.Errorf("untrusted peer: ClientIP = %q, want the TCP peer", ip)
	}

	SetTrustedProxies(httpsec.NewTrustedProxySet([]string{"203.0.113.0/24"}))
	if ip := ClientIP(req); ip != "1.2.3.4" {
		t.Errorf("trusted proxy: ClientIP = %q, want the forwarded client", ip)
	}
}
