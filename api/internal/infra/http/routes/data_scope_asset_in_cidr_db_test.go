package routes

import (
	"net/http"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// GET /assets?in_cidr=… is the scan wizard's preview of an inventory-mode
// CIDR target (RFC-068): the address assets inside the range. The caller's
// data scope applies, an address outside the range or a name that is not an
// address never matches, and a value that is not a range is refused.
func TestDataScope_AssetInCIDR(t *testing.T) {
	h := newDSHarness(t)
	tn := h.tenant.String()
	inA, inB, out := shared.NewID(), shared.NewID(), shared.NewID()
	h.exec(`INSERT INTO assets (id, tenant_id, name, asset_type, exposure, criticality) VALUES
		($1, $4, '203.0.113.7', 'ip_address', 'public', 'high'),
		($2, $4, '203.0.113.200', 'ip_address', 'public', 'high'),
		($3, $4, '198.51.100.1', 'ip_address', 'public', 'high')`,
		inA.String(), inB.String(), out.String(), tn)
	h.exec(`INSERT INTO user_accessible_assets (user_id, tenant_id, asset_id, ownership_type) VALUES ($1, $2, $3, 'secondary')`,
		h.memberA.String(), tn, inA.String())

	code, body := h.do(h.owner, true, http.MethodGet, "/api/v1/assets?in_cidr=203.0.113.0/24&per_page=100", nil)
	if code != http.StatusOK || !strings.Contains(body, "203.0.113.7") || !strings.Contains(body, "203.0.113.200") ||
		strings.Contains(body, "198.51.100.1") || strings.Contains(body, dsMarkerAssetA) {
		t.Fatalf("owner, in_cidr: status %d: %s", code, body)
	}
	// memberA sees only the address in its data scope.
	code, body = h.do(h.memberA, false, http.MethodGet, "/api/v1/assets?in_cidr=203.0.113.0/24&per_page=100", nil)
	if code != http.StatusOK || !strings.Contains(body, "203.0.113.7") || strings.Contains(body, "203.0.113.200") {
		t.Fatalf("member, in_cidr: status %d: %s", code, body)
	}
	// Two ranges are alternatives.
	code, body = h.do(h.owner, true, http.MethodGet, "/api/v1/assets?in_cidr=203.0.113.7/32,198.51.100.0/24&per_page=100", nil)
	if code != http.StatusOK || !strings.Contains(body, "203.0.113.7") || !strings.Contains(body, "198.51.100.1") ||
		strings.Contains(body, "203.0.113.200") {
		t.Fatalf("two ranges: status %d: %s", code, body)
	}
	for _, bad := range []string{"%25", "example.com", "203.0.113.0/99"} {
		code, _ = h.do(h.owner, true, http.MethodGet, "/api/v1/assets?in_cidr="+bad+"&per_page=100", nil)
		if code != http.StatusUnprocessableEntity && code != http.StatusBadRequest {
			t.Errorf("in_cidr=%s: status %d, want a validation error", bad, code)
		}
	}
}
