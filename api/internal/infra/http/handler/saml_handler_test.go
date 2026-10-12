package handler

import "testing"

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
