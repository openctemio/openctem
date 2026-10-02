package handler

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/pkg/httpsec"
)

// Pagination links took X-Forwarded-Host / X-Forwarded-Proto from any client,
// so a request carrying "X-Forwarded-Host: evil.com" got links pointing at
// evil.com (test_e2e_edge_cases G2). Forwarded headers may only come from a
// configured trusted proxy — the rule samlBaseURL and client-IP attribution
// already follow.
func TestPaginationLinksIgnoreForwardedHeadersFromUntrustedPeers(t *testing.T) {
	prev := trustedProxiesForAuth
	t.Cleanup(func() { trustedProxiesForAuth = prev })

	req := httptest.NewRequest("GET", "http://api.example.com/api/v1/assets?page=1&per_page=1", nil)
	req.RemoteAddr = "203.0.113.9:4444"
	req.Header.Set("X-Forwarded-Host", "evil.com")
	req.Header.Set("X-Forwarded-Proto", "https")

	trustedProxiesForAuth = nil
	links := NewPaginationLinks(req, 1, 1, 3)
	if strings.Contains(links.Self, "evil.com") || !strings.HasPrefix(links.Self, "http://api.example.com/") {
		t.Fatalf("untrusted peer steered the link: %s", links.Self)
	}

	trustedProxiesForAuth = httpsec.NewTrustedProxySet([]string{"203.0.113.9/32"})
	links = NewPaginationLinks(req, 1, 1, 3)
	if !strings.HasPrefix(links.Self, "https://evil.com/") {
		t.Fatalf("a trusted proxy's forwarded host/proto should be used, got %s", links.Self)
	}
}
