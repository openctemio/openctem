package routes

// Owning an asset grants view of it (docs/architecture/asset-ownership.md,
// "Ownership and data scope"), end to end over the real routes: a primary
// owner set by a person sees the asset and its findings on every scoped read,
// never another asset, and loses them as soon as the ownership goes. A member
// who creates an asset sees it (creator grant). Requires DATABASE_URL.

import (
	"net/http"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func TestOwnerScope_PrimaryOwnerSeesOwnAssetAndFindings(t *testing.T) {
	h := newDSHarness(t)
	casey := h.memberStrict // a member with no group and no grant
	a, b := h.assetA.String(), h.assetB.String()
	fa, fb := h.findingA.String(), h.findingB.String()

	get := func(user shared.ID, path string) (int, string) {
		t.Helper()
		return h.do(user, false, http.MethodGet, path, nil)
	}
	wantStatus := func(user shared.ID, path string, want int) {
		t.Helper()
		if status, body := get(user, path); status != want {
			t.Errorf("GET %s = %d, want %d (%.200s)", path, status, want, body)
		}
	}

	// Before: nothing.
	wantStatus(casey, "/api/v1/assets/"+a, http.StatusNotFound)
	wantStatus(casey, "/api/v1/findings/"+fa, http.StatusNotFound)

	// An owner matched from owner_ref (data from a source) and a stakeholder
	// grant nothing.
	h.exec(`INSERT INTO asset_owners (asset_id, user_id, ownership_type, assignment_source) VALUES ($1, $2, 'stakeholder', 'manual')`, a, casey.String())
	wantStatus(casey, "/api/v1/assets/"+a, http.StatusNotFound)
	h.exec(`DELETE FROM asset_owners WHERE asset_id = $1 AND user_id = $2`, a, casey.String())
	h.exec(`INSERT INTO asset_owners (asset_id, user_id, ownership_type, assignment_source) VALUES ($1, $2, 'primary', 'owner_ref')`, a, casey.String())
	wantStatus(casey, "/api/v1/assets/"+a, http.StatusNotFound)
	h.exec(`DELETE FROM asset_owners WHERE asset_id = $1 AND user_id = $2`, a, casey.String())

	// Primary owner set by a person: the asset and its findings, nothing else.
	h.exec(`INSERT INTO asset_owners (asset_id, user_id, ownership_type, assignment_source) VALUES ($1, $2, 'primary', 'manual')`, a, casey.String())
	wantStatus(casey, "/api/v1/assets/"+a, http.StatusOK)
	wantStatus(casey, "/api/v1/findings/"+fa, http.StatusOK)
	wantStatus(casey, "/api/v1/assets/"+b, http.StatusNotFound)
	wantStatus(casey, "/api/v1/findings/"+fb, http.StatusNotFound)
	status, body := get(casey, "/api/v1/assets/")
	if status != http.StatusOK || !strings.Contains(body, a) || strings.Contains(body, b) || strings.Contains(body, dsMarkerAssetB) {
		t.Errorf("owner's asset list = %d, want asset A only (%.300s)", status, body)
	}

	// An organization API key (no user) still reads nothing scoped.
	wantStatus(shared.ID{}, "/api/v1/assets/"+a, http.StatusNotFound)

	// Ownership adds no permission: a viewer-like caller without
	// assets:write cannot change the owned asset.
	req := map[string]any{"description": "changed by owner"}
	if status, body := h.doWithPerms(casey, []string{"assets:read", "findings:read"}, http.MethodPut, "/api/v1/assets/"+a, req); status != http.StatusForbidden {
		t.Errorf("owner without assets:write updating the asset = %d, want 403 (%.200s)", status, body)
	}

	// Ownership removed: access goes at once.
	h.exec(`DELETE FROM asset_owners WHERE asset_id = $1 AND user_id = $2`, a, casey.String())
	wantStatus(casey, "/api/v1/assets/"+a, http.StatusNotFound)
	wantStatus(casey, "/api/v1/findings/"+fa, http.StatusNotFound)
}

// A member without full data access who creates an asset sees it (201 then
// 200, not 404), through an audited creator grant. Callers who see everything
// get no grant.
func TestAssetCreate_MemberSeesWhatTheyCreated(t *testing.T) {
	h := newDSHarness(t)
	status, body := h.do(h.memberStrict, false, http.MethodPost, "/api/v1/assets/", map[string]any{
		"name": "creator-" + h.tenant.String()[:8] + ".example.com", "type": "domain", "criticality": "low",
	})
	if status != http.StatusCreated {
		t.Fatalf("create = %d %.300s", status, body)
	}
	id := jsonField(body, "id")
	if status, body := h.do(h.memberStrict, false, http.MethodGet, "/api/v1/assets/"+id, nil); status != http.StatusOK {
		t.Fatalf("creator GET own asset = %d, want 200 (%.200s)", status, body)
	}
	var source string
	if err := h.db.QueryRow(`SELECT source FROM asset_access_grants WHERE tenant_id = $1 AND asset_id = $2 AND user_id = $3`,
		h.tenant.String(), id, h.memberStrict.String()).Scan(&source); err != nil || source != "creator" {
		t.Fatalf("creator grant = %q (%v), want source creator", source, err)
	}
	if n := h.auditCount("asset.access_granted", id); n != 1 {
		t.Errorf("creator grant audit rows = %d, want 1", n)
	}
	// Another scoped member does not see it.
	if status, _ := h.do(h.memberFree, false, http.MethodGet, "/api/v1/assets/"+id, nil); status != http.StatusNotFound {
		t.Errorf("another member GET = %d, want 404", status)
	}

	// The owner and a full-data role need no grant.
	for _, who := range []struct {
		user  shared.ID
		admin bool
	}{{h.owner, true}, {h.memberFull, false}} {
		status, body := h.do(who.user, who.admin, http.MethodPost, "/api/v1/assets/", map[string]any{
			"name": "nogrant-" + who.user.String()[24:] + ".example.com", "type": "domain", "criticality": "low",
		})
		if status != http.StatusCreated {
			t.Fatalf("create = %d %.300s", status, body)
		}
		var n int
		if err := h.db.QueryRow(`SELECT COUNT(*) FROM asset_access_grants WHERE asset_id = $1`, jsonField(body, "id")).Scan(&n); err != nil || n != 0 {
			t.Errorf("unrestricted creator got %d grants (%v), want 0", n, err)
		}
	}
}
