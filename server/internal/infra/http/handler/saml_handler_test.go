package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSAMLRequestCookieCarriesForceAuthn(t *testing.T) {
	for _, forced := range []bool{true, false} {
		id, got := parseSAMLRequestCookie(samlRequestCookieValue("id-123", forced))
		if id != "id-123" || got != forced {
			t.Fatalf("forced=%v: round trip gave %q %v", forced, id, got)
		}
	}
	for v, want := range map[string]bool{"true": true, "1": true, "": false, "yes": false, "false": false} {
		if isTrueParam(v) != want {
			t.Fatalf("isTrueParam(%q) != %v", v, want)
		}
	}
}

// Only a real AuthnRequest ID binds the response: a missing cookie, an empty
// one, or one holding only the ForceAuthn marker yields no ID, so a response
// that answers no request is refused.
func TestSAMLRequestIDsFromCookie(t *testing.T) {
	req := func(value string, set bool) *http.Request {
		r := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api/v1/auth/saml/acme/acs", nil)
		if set {
			r.AddCookie(&http.Cookie{Name: samlRequestCookieName("acme"), Value: value})
		}
		return r
	}
	for name, r := range map[string]*http.Request{
		"no cookie":   req("", false),
		"marker only": req(samlForcedSuffix, true),
		"other org cookie": func() *http.Request {
			r := req("", false)
			r.AddCookie(&http.Cookie{Name: samlRequestCookieName("other"), Value: "id-1"})
			return r
		}(),
	} {
		if ids, forced := samlRequestIDsFromCookie(r, "acme"); ids != nil || forced {
			t.Fatalf("%s: got %v %v, want no request ID", name, ids, forced)
		}
	}
	ids, forced := samlRequestIDsFromCookie(req(samlRequestCookieValue("id-1", true), true), "acme")
	if len(ids) != 1 || ids[0] != "id-1" || !forced {
		t.Fatalf("got %v %v", ids, forced)
	}
}
