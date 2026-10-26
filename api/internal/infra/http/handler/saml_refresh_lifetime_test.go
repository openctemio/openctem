package handler

import (
	"testing"
	"time"
)

// The SAML refresh cookie follows AUTH_REFRESH_TOKEN_DURATION like every other
// sign-in path, instead of a fixed 30 days.
func TestSAMLHandler_RefreshLifetimeFollowsConfig(t *testing.T) {
	h := &SAMLHandler{}
	if got := h.refreshLifetime(); got != 7*24*time.Hour {
		t.Fatalf("unwired: got %v, want the 7 day default", got)
	}
	h.SetRefreshDuration(36 * time.Hour)
	if got := h.refreshLifetime(); got != 36*time.Hour {
		t.Fatalf("got %v, want the configured 36h", got)
	}
}
