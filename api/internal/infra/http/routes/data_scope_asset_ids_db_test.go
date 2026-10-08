package routes

import (
	"net/http"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// GET /assets?ids=… is the batch read that replaces one GET /assets/{id} per
// row (research/81: the threat-model page resolved each asset name with its
// own request). It must answer exactly what those by-id reads answer: the
// caller's data scope and tenant apply, and an id outside them is left out,
// never returned.
func TestDataScope_AssetIDsBatch_OnlyWhatTheCallerMaySee(t *testing.T) {
	h := newDSHarness(t)
	a, b := h.assetA.String(), h.assetB.String()
	path := "/api/v1/assets?ids=" + a + "," + b + "&per_page=100"

	// memberA sees A1 only: B1 is out of scope and is left out.
	code, body := h.do(h.memberA, false, http.MethodGet, path, nil)
	if code != http.StatusOK {
		t.Fatalf("member: status %d: %s", code, body)
	}
	if !strings.Contains(body, dsMarkerAssetA) || strings.Contains(body, dsMarkerAssetB) {
		t.Fatalf("member batch read must hold A1 and not B1: %s", body)
	}

	// A member with no scope row sees nothing, ids or not.
	code, body = h.do(h.memberStrict, false, http.MethodGet, path, nil)
	if code != http.StatusOK || strings.Contains(body, dsMarkerAssetA) || strings.Contains(body, dsMarkerAssetB) {
		t.Fatalf("scopeless member: status %d, leaked: %s", code, body)
	}

	// The owner sees both, and only the ids asked for.
	code, body = h.do(h.owner, true, http.MethodGet, "/api/v1/assets?ids="+a+"&per_page=100", nil)
	if code != http.StatusOK || !strings.Contains(body, dsMarkerAssetA) || strings.Contains(body, dsMarkerAssetB) {
		t.Fatalf("owner, ids=A1: status %d: %s", code, body)
	}

	// Another tenant's asset id is never returned, even to an owner.
	other, otherTenant := shared.NewID(), shared.NewID()
	h.exec(`INSERT INTO tenants (id, name, slug) VALUES ($1, $2, $2)`, otherTenant.String(), "ds-other-"+otherTenant.String())
	t.Cleanup(func() { h.exec(`DELETE FROM tenants WHERE id = $1`, otherTenant.String()) })
	h.exec(`INSERT INTO assets (id, tenant_id, name, asset_type, exposure, criticality) VALUES ($1, $2, $3, 'domain', 'public', 'high')`,
		other.String(), otherTenant.String(), "ds-other-tenant.example.com")
	code, body = h.do(h.owner, true, http.MethodGet, "/api/v1/assets?ids="+other.String()+"&per_page=100", nil)
	if code != http.StatusOK || strings.Contains(body, "ds-other-tenant.example.com") {
		t.Fatalf("cross-tenant id: status %d, leaked: %s", code, body)
	}

	// Not ids: rejected, not ignored (an ignored filter would list everything).
	code, _ = h.do(h.owner, true, http.MethodGet, "/api/v1/assets?ids=not-a-uuid", nil)
	if code != http.StatusUnprocessableEntity && code != http.StatusBadRequest {
		t.Fatalf("malformed ids: status %d, want a validation error", code)
	}
}
