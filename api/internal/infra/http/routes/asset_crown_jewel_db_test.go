package routes

// The crown-jewel flag is the assets.is_crown_jewel column, set only through
// PATCH /api/v1/assets/{id}/crown-jewel. Only a caller with assets:write and
// the asset in their data scope may set it; another tenant's asset is not
// found; free-form properties cannot set it; every change is audited.

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/permission"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func (h *dsHarness) crownJewel(id string) bool {
	h.t.Helper()
	var v bool
	if err := h.db.QueryRow(`SELECT is_crown_jewel FROM assets WHERE id = $1`, id).Scan(&v); err != nil {
		h.t.Fatal(err)
	}
	return v
}

// doWithPerms is do with an explicit permission set for a non-admin caller.
func (h *dsHarness) doWithPerms(user shared.ID, perms []string, method, path string, body any) (int, string) {
	h.t.Helper()
	b, _ := json.Marshal(body)
	req, err := http.NewRequestWithContext(context.Background(), method, h.srv.URL+path, bytes.NewReader(b))
	if err != nil {
		h.t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Test-User", user.String())
	req.Header.Set("X-Test-Perms", strings.Join(perms, ","))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	defer resp.Body.Close()
	var out bytes.Buffer
	_, _ = out.ReadFrom(resp.Body)
	return resp.StatusCode, out.String()
}

func TestCrownJewel_InScopeWriterSetsColumnAndIsAudited(t *testing.T) {
	h := newDSHarness(t)
	a := h.assetA.String()

	status, body := h.do(h.memberA, false, http.MethodPatch, "/api/v1/assets/"+a+"/crown-jewel", map[string]any{
		"is_crown_jewel": true, "business_impact_score": 80, "business_impact_notes": "payments",
	})
	if status != http.StatusOK {
		t.Fatalf("in-scope crown-jewel = %d (body %.300s)", status, body)
	}
	var resp struct {
		IsCrownJewel bool           `json:"is_crown_jewel"`
		Properties   map[string]any `json:"properties"`
	}
	_ = json.Unmarshal([]byte(body), &resp)
	if !resp.IsCrownJewel || !h.crownJewel(a) {
		t.Errorf("flag not set: response %v column %v", resp.IsCrownJewel, h.crownJewel(a))
	}
	if _, ok := resp.Properties["is_crown_jewel"]; ok {
		t.Errorf("flag written into properties: %v", resp.Properties)
	}
	if resp.Properties["business_impact_score"] != float64(80) {
		t.Errorf("business impact not stored: %v", resp.Properties)
	}

	var actor, meta string
	if err := h.db.QueryRow(`SELECT COALESCE(actor_id::text, ''), COALESCE(metadata::text, '') FROM audit_logs
		WHERE tenant_id = $1 AND action = 'asset.crown_jewel_changed' AND resource_id = $2`, h.tenant.String(), a).
		Scan(&actor, &meta); err != nil {
		t.Fatalf("no crown-jewel audit entry: %v", err)
	}
	if actor != h.memberA.String() || !strings.Contains(meta, `"is_crown_jewel"`) || strings.Contains(meta, "payments") {
		t.Errorf("audit entry actor %s metadata %s: want memberA, the changed field names and no values", actor, meta)
	}

	// The list filter reads the column.
	status, body = h.do(h.memberA, false, http.MethodGet, "/api/v1/assets/?is_crown_jewel=true", nil)
	if status != http.StatusOK || !strings.Contains(body, a) {
		t.Errorf("crown-jewel filter = %d, does not list the flagged asset (body %.300s)", status, body)
	}

	// A generic update leaves the flag alone.
	status, body = h.do(h.memberA, false, http.MethodPut, "/api/v1/assets/"+a, map[string]any{"description": "edited"})
	if status != http.StatusOK || !h.crownJewel(a) {
		t.Errorf("update = %d cleared the flag=%v (body %.300s)", status, !h.crownJewel(a), body)
	}
}

func TestCrownJewel_OutOfScopeIsNotFoundAndUnchanged(t *testing.T) {
	h := newDSHarness(t)
	b := h.assetB.String()

	status, body := h.do(h.memberA, false, http.MethodPatch, "/api/v1/assets/"+b+"/crown-jewel", map[string]any{"is_crown_jewel": true})
	if status != http.StatusNotFound {
		t.Errorf("out-of-scope crown-jewel = %d, want 404 (body %.300s)", status, body)
	}
	if strings.Contains(body, dsMarkerAssetB) {
		t.Errorf("404 revealed the asset: %.300s", body)
	}
	if h.crownJewel(b) {
		t.Error("out-of-scope asset was flagged")
	}
	if n := h.auditCount("asset.crown_jewel_changed", b); n != 0 {
		t.Errorf("refused change audited %d times as a success", n)
	}
}

func TestCrownJewel_ReadOnlyCallerIsForbidden(t *testing.T) {
	h := newDSHarness(t)
	a := h.assetA.String()
	status, body := h.doWithPerms(h.memberA, []string{permission.AssetsRead.String()},
		http.MethodPatch, "/api/v1/assets/"+a+"/crown-jewel", map[string]any{"is_crown_jewel": true})
	if status != http.StatusForbidden {
		t.Errorf("assets:read-only crown-jewel = %d, want 403 (body %.300s)", status, body)
	}
	if h.crownJewel(a) {
		t.Error("read-only caller flagged the asset")
	}
}

func TestCrownJewel_OtherTenantAssetIsNotFound(t *testing.T) {
	h := newDSHarness(t)
	other, foreign := shared.NewID().String(), shared.NewID().String()
	h.exec(`INSERT INTO tenants (id, name, slug) VALUES ($1, $2, $2)`, other, "cj-other-"+other)
	t.Cleanup(func() { _, _ = h.db.Exec(`DELETE FROM tenants WHERE id = $1`, other) })
	h.exec(`INSERT INTO assets (id, tenant_id, name, asset_type, criticality) VALUES ($1, $2, 'cj-foreign.example.com', 'domain', 'high')`,
		foreign, other)

	status, body := h.do(h.owner, true, http.MethodPatch, "/api/v1/assets/"+foreign+"/crown-jewel", map[string]any{"is_crown_jewel": true})
	if status != http.StatusNotFound || strings.Contains(body, "cj-foreign") {
		t.Errorf("cross-tenant crown-jewel = %d, want a bare 404 (body %.300s)", status, body)
	}
	if h.crownJewel(foreign) {
		t.Error("another tenant's asset was flagged")
	}
}

func TestCrownJewel_PropertiesCannotSetIt(t *testing.T) {
	h := newDSHarness(t)
	a := h.assetA.String()
	for _, key := range []string{"is_crown_jewel", "isCrownJewel"} {
		status, body := h.do(h.owner, true, http.MethodPut, "/api/v1/assets/"+a, map[string]any{
			"properties": map[string]any{key: true},
		})
		if status != http.StatusBadRequest {
			t.Errorf("PUT properties.%s = %d, want 400 (body %.300s)", key, status, body)
		}
		status, body = h.do(h.owner, true, http.MethodPost, "/api/v1/assets/", map[string]any{
			"name": "cj-new-" + key + ".example.com", "type": "domain", "criticality": "low", "properties": map[string]any{key: true},
		})
		if status != http.StatusBadRequest {
			t.Errorf("POST properties.%s = %d, want 400 (body %.300s)", key, status, body)
		}
	}
	if h.crownJewel(a) {
		t.Error("properties set the crown-jewel flag")
	}
}
