package routes

// /assets/stats and /assets/facets apply the same Layer-2 data scope as the
// asset list (RFC-042 F10). Before, both counted every asset of the tenant,
// so a member restricted to some assets could read counts and property
// values of assets they cannot list.

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

const dsMarkerRegistrarB = "dsB-SECRET-registrar"

type dsStats struct {
	Total          int                       `json:"total"`
	ByType         map[string]int            `json:"by_type"`
	MetadataCounts map[string]map[string]int `json:"metadata_counts"`
}

type dsFacet struct {
	Key    string   `json:"key"`
	Values []string `json:"values"`
	Count  int      `json:"count"`
}

// seedFacetAssets gives A1 and B1 properties and adds a second in-scope
// asset A2, so memberA's scope holds two assets and the tenant three.
func (h *dsHarness) seedFacetAssets() {
	h.t.Helper()
	h.exec(`UPDATE assets SET properties = '{"registrar":"reg-a","cdn":"cf"}' WHERE id = $1`, h.assetA.String())
	h.exec(`UPDATE assets SET properties = jsonb_build_object('registrar', $2::text, 'cdn', 'cf') WHERE id = $1`,
		h.assetB.String(), dsMarkerRegistrarB)
	a2 := shared.NewID()
	h.exec(`INSERT INTO assets (id, tenant_id, name, asset_type, exposure, criticality, properties)
		VALUES ($1, $2, 'dsa-a2.example.com', 'domain', 'public', 'high', '{"registrar":"reg-a","cdn":"cf"}')`,
		a2.String(), h.tenant.String())
	h.exec(`INSERT INTO user_accessible_assets (user_id, tenant_id, asset_id, ownership_type) VALUES ($1, $2, $3, 'secondary')`,
		h.memberA.String(), h.tenant.String(), a2.String())
}

func (h *dsHarness) stats(user shared.ID, admin bool) dsStats {
	h.t.Helper()
	status, body := h.do(user, admin, http.MethodGet, "/api/v1/assets/stats?count_by=registrar", nil)
	if status != http.StatusOK {
		h.t.Fatalf("GET /assets/stats = %d (body %.300s)", status, body)
	}
	var s dsStats
	if err := json.Unmarshal([]byte(body), &s); err != nil {
		h.t.Fatalf("decode stats: %v (%.300s)", err, body)
	}
	return s
}

func (h *dsHarness) facets(user shared.ID, admin bool) (map[string]dsFacet, string) {
	h.t.Helper()
	status, body := h.do(user, admin, http.MethodGet, "/api/v1/assets/facets", nil)
	if status != http.StatusOK {
		h.t.Fatalf("GET /assets/facets = %d (body %.300s)", status, body)
	}
	var list []dsFacet
	if err := json.Unmarshal([]byte(body), &list); err != nil {
		h.t.Fatalf("decode facets: %v (%.300s)", err, body)
	}
	out := make(map[string]dsFacet, len(list))
	for _, f := range list {
		out[f.Key] = f
	}
	return out, body
}

func TestDataScope_AssetStatsAndFacets_CountOnlyInScope(t *testing.T) {
	h := newDSHarness(t)
	h.seedFacetAssets()

	// The scoped member sees exactly the two assets the list shows them.
	st := h.stats(h.memberA, false)
	if st.Total != 2 || st.ByType["domain"] != 2 {
		t.Errorf("memberA stats total=%d by_type.domain=%d, want 2 and 2 (in-scope only)", st.Total, st.ByType["domain"])
	}
	if n, ok := st.MetadataCounts["registrar"][dsMarkerRegistrarB]; ok {
		t.Errorf("memberA stats leaked out-of-scope registrar %q (count %d)", dsMarkerRegistrarB, n)
	}
	if st.MetadataCounts["registrar"]["reg-a"] != 2 {
		t.Errorf("memberA stats registrar[reg-a] = %d, want 2", st.MetadataCounts["registrar"]["reg-a"])
	}

	f, body := h.facets(h.memberA, false)
	if strings.Contains(body, dsMarkerRegistrarB) {
		t.Errorf("memberA facets leaked out-of-scope value %q: %.300s", dsMarkerRegistrarB, body)
	}
	if f["registrar"].Count != 2 || f["cdn"].Count != 2 {
		t.Errorf("memberA facet counts registrar=%d cdn=%d, want 2 and 2 (in-scope only)", f["registrar"].Count, f["cdn"].Count)
	}

	// The list agrees: the facet totals equal what the member can list.
	if status, body := h.do(h.memberA, false, http.MethodGet, "/api/v1/assets", nil); status != http.StatusOK || !strings.Contains(body, `"total":2`) {
		t.Errorf("memberA list = %d, want total 2 (body %.300s)", status, body)
	}

	// Admins and unrestricted members keep the tenant-wide numbers.
	for _, who := range []struct {
		name  string
		user  shared.ID
		admin bool
	}{{"owner", h.owner, true}, {"full-data role", h.memberFull, false}} {
		st := h.stats(who.user, who.admin)
		if st.Total != 3 || st.MetadataCounts["registrar"][dsMarkerRegistrarB] != 1 {
			t.Errorf("%s stats total=%d registrar[B]=%d, want 3 and 1", who.name, st.Total, st.MetadataCounts["registrar"][dsMarkerRegistrarB])
		}
		f, body := h.facets(who.user, who.admin)
		if f["registrar"].Count != 3 || !strings.Contains(body, dsMarkerRegistrarB) {
			t.Errorf("%s facets registrar count=%d, want 3 including %q (body %.300s)", who.name, f["registrar"].Count, dsMarkerRegistrarB, body)
		}
	}
}

func TestDataScope_AssetStatsAndFacets_StrictTenantMemberWithoutGroupSeesNothing(t *testing.T) {
	h := newDSHarness(t)
	h.seedFacetAssets()

	if st := h.stats(h.memberStrict, false); st.Total != 0 || len(st.ByType) != 0 {
		t.Errorf("strict tenant, member without group: stats total=%d by_type=%v, want nothing", st.Total, st.ByType)
	}
	if f, body := h.facets(h.memberStrict, false); len(f) != 0 {
		t.Errorf("strict tenant, member without group: facets = %.300s, want none", body)
	}
	if st := h.stats(h.owner, true); st.Total != 3 {
		t.Errorf("strict tenant: owner stats total = %d, want 3", st.Total)
	}
}
