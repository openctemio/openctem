package routes

import (
	"net/http"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// A role with has_full_data_access is the Layer 2 bypass (owner decision D3,
// research doc 15 L-11): a "Global Reader" custom role sees every asset and
// finding by id and in the lists, even with group rows of its own and in a
// fail-closed tenant. Before, the flag was stored and shown but nothing read
// it, so such a user saw only their groups (or nothing).
func TestDataScope_FullDataRole_IsTheBypass(t *testing.T) {
	h := newDSHarness(t)
	role := shared.NewID()
	h.exec(`INSERT INTO roles (id, tenant_id, slug, name, hierarchy_level, has_full_data_access) VALUES ($1, $2, $3, 'Global Reader', 30, $4)`,
		role, h.tenant, "global-reader-"+role.String()[:8], false)

	byID := []string{
		"/api/v1/assets/" + h.assetB.String(),
		"/api/v1/findings/" + h.findingB.String(),
		"/api/v1/exposures/" + h.exposureB.String(),
	}
	lists := []struct{ path, marker string }{
		{"/api/v1/assets?per_page=100", dsMarkerAssetB},
		{"/api/v1/findings?per_page=100", dsMarkerFindingB},
		{"/api/v1/exposures", dsMarkerExpB},
	}
	check := func(wantSee bool) {
		t.Helper()
		for _, p := range byID {
			status, _ := h.do(h.memberA, false, http.MethodGet, p, nil)
			if (status == http.StatusOK) != wantSee {
				t.Errorf("memberA GET %s = %d, want visible=%v", p, status, wantSee)
			}
		}
		for _, l := range lists {
			status, body := h.do(h.memberA, false, http.MethodGet, l.path, nil)
			if status != http.StatusOK {
				t.Errorf("memberA GET %s = %d (%.200s)", l.path, status, body)
				continue
			}
			if strings.Contains(body, l.marker) != wantSee {
				t.Errorf("memberA GET %s: out-of-scope row visible=%v, want %v", l.path, !wantSee, wantSee)
			}
		}
	}

	// A role without the flag changes nothing.
	h.exec(`INSERT INTO user_roles (user_id, tenant_id, role_id) VALUES ($1, $2, $3)`, h.memberA, h.tenant, role)
	check(false)
	// With the flag, memberA sees the whole tenant.
	h.exec(`UPDATE roles SET has_full_data_access = TRUE WHERE id = $1`, role)
	check(true)
	// Taking the flag away restricts again on the next request.
	h.exec(`UPDATE roles SET has_full_data_access = FALSE WHERE id = $1`, role)
	check(false)
}
