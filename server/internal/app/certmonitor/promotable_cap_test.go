package certmonitor

import (
	"fmt"
	"testing"
	"time"
)

// The per-domain subdomain cap bounds the exposure list only: every exact
// CT name stays promotable, so a large domain's alphabetical tail reaches
// inventory over later runs instead of never.
func TestCollectDiscoveries_PromotableNotCutBySubdomainCap(t *testing.T) {
	now := time.Date(2026, 8, 18, 0, 0, 0, 0, time.UTC)
	var entries []crtEntry
	for i := range 600 {
		n := fmt.Sprintf("h%03d.example.com", i)
		entries = append(entries, crtEntry{CommonName: n, NameValue: n, NotAfter: "2027-01-01T00:00:00"})
	}
	d := collectDiscoveries("example.com", entries, now, defaultExpiryWindow, defaultExpiredLookback, 500)
	if len(d.subdomains) != 500 || d.subdomainsCut != 100 {
		t.Fatalf("subdomains %d cut %d, want 500 listed and 100 cut", len(d.subdomains), d.subdomainsCut)
	}
	if len(d.promotable) != 600 {
		t.Fatalf("promotable %d, want all 600", len(d.promotable))
	}
	if last := d.promotable[len(d.promotable)-1].Name; last != "h599.example.com" {
		t.Fatalf("last promotable %q, want h599.example.com", last)
	}
}
