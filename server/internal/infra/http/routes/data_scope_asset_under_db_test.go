package routes

import (
	"net/http"
	"strings"
	"testing"
)

// GET /assets?under=… is the scan wizard's coverage expansion in one request
// (research/81): the names equal to or below each typed domain. The caller's
// data scope applies, the match stops at a label boundary, and a pattern is
// refused rather than matched.
func TestDataScope_AssetUnderDomains(t *testing.T) {
	h := newDSHarness(t)

	// Both seeded names are below example.com; memberA sees only A1.
	code, body := h.do(h.memberA, false, http.MethodGet, "/api/v1/assets?under=example.com&per_page=100", nil)
	if code != http.StatusOK || !strings.Contains(body, dsMarkerAssetA) || strings.Contains(body, dsMarkerAssetB) {
		t.Fatalf("member, under=example.com: status %d: %s", code, body)
	}
	code, body = h.do(h.owner, true, http.MethodGet, "/api/v1/assets?under=example.com&per_page=100", nil)
	if code != http.StatusOK || !strings.Contains(body, dsMarkerAssetA) || !strings.Contains(body, dsMarkerAssetB) {
		t.Fatalf("owner, under=example.com: status %d: %s", code, body)
	}

	// "dsa-a1.example.com" is not below "a1.example.com": only whole labels.
	code, body = h.do(h.owner, true, http.MethodGet, "/api/v1/assets?under=a1.example.com&per_page=100", nil)
	if code != http.StatusOK || strings.Contains(body, dsMarkerAssetA) {
		t.Fatalf("label boundary: status %d: %s", code, body)
	}

	// The exact name matches too.
	code, body = h.do(h.owner, true, http.MethodGet, "/api/v1/assets?under="+dsMarkerAssetA+"&per_page=100", nil)
	if code != http.StatusOK || !strings.Contains(body, dsMarkerAssetA) || strings.Contains(body, dsMarkerAssetB) {
		t.Fatalf("exact name: status %d: %s", code, body)
	}

	// A wildcard is not a domain name: refused, never a match-all.
	code, _ = h.do(h.owner, true, http.MethodGet, "/api/v1/assets?under=%25&per_page=100", nil)
	if code != http.StatusUnprocessableEntity && code != http.StatusBadRequest {
		t.Fatalf("under=%%: status %d, want a validation error", code)
	}
}
