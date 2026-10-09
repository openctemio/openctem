package automation

import (
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/pkg/logger"
)

// TestHTTPRequestHandler_ValidateURL_BlocksNeverRoutable is a regression test
// for SEC-WF14: the handler's own blockedCIDRs list missed several
// never-routable ranges, so http://0.0.0.0:<port>/ and http://[::]:<port>/
// bypassed the SSRF guard and reached loopback-bound services on the API host.
// The guard now defers to the canonical httpsec blocklist.
func TestHTTPRequestHandler_ValidateURL_BlocksNeverRoutable(t *testing.T) {
	h := NewHTTPRequestHandler(logger.NewNop())

	blocked := []string{
		"http://0.0.0.0:19999/",           // "this" network -> loopback on Linux
		"http://0.0.0.0/latest/meta-data", // same, no explicit port
		"http://[::]:8080/",               // IPv6 unspecified -> loopback
		"http://127.0.0.1/",               // loopback (already blocked, keep covered)
		"http://169.254.169.254/",         // cloud IMDS
		"http://[::1]/",                   // IPv6 loopback
	}
	for _, u := range blocked {
		if err := h.validateURL(u); err == nil {
			t.Errorf("expected %q to be blocked by SSRF guard, but it passed", u)
		}
	}
}

// TestHTTPRequestHandler_ValidateURL_RejectsNonHTTPScheme guards the scheme
// allowlist (defense in depth against file://, gopher://, etc.).
func TestHTTPRequestHandler_ValidateURL_RejectsNonHTTPScheme(t *testing.T) {
	h := NewHTTPRequestHandler(logger.NewNop())
	for _, u := range []string{"file:///etc/passwd", "gopher://0.0.0.0:11211/", "ftp://example.com/"} {
		if err := h.validateURL(u); err == nil {
			t.Errorf("expected non-http scheme %q to be rejected", u)
		} else if !strings.Contains(err.Error(), "scheme") {
			t.Errorf("expected scheme error for %q, got %v", u, err)
		}
	}
}
