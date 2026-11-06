package routes

// Asset attribute sources (RFC-069) over HTTP: a caller sees and locks the
// attributes of assets in their data scope only (another asset is 404), a
// read-only caller cannot lock, another tenant's asset is not found, and
// every lock and release is audited.

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/permission"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func (h *dsHarness) criticality(id string) string {
	h.t.Helper()
	var v string
	if err := h.db.QueryRow(`SELECT criticality FROM assets WHERE id = $1`, id).Scan(&v); err != nil {
		h.t.Fatal(err)
	}
	return v
}

func TestAttributeSources_InScopeLockReadRelease(t *testing.T) {
	h := newDSHarness(t)
	a := h.assetA.String()
	base := "/api/v1/assets/" + a + "/attribute-sources"

	status, body := h.do(h.memberA, false, http.MethodPut, base+"/criticality/lock", map[string]any{"value": "critical"})
	if status != http.StatusOK {
		t.Fatalf("lock = %d (body %.300s)", status, body)
	}
	if got := h.criticality(a); got != "critical" {
		t.Fatalf("criticality = %s, want critical", got)
	}

	status, body = h.do(h.memberA, false, http.MethodGet, base, nil)
	if status != http.StatusOK {
		t.Fatalf("get = %d (body %.300s)", status, body)
	}
	var list struct {
		Attributes []struct {
			Attribute string `json:"attribute"`
			Value     string `json:"value"`
			Locked    bool   `json:"locked"`
			DecidedBy *struct {
				Kind string `json:"kind"`
				Name string `json:"name"`
			} `json:"decided_by"`
		} `json:"attributes"`
	}
	if err := json.Unmarshal([]byte(body), &list); err != nil {
		t.Fatal(err)
	}
	if len(list.Attributes) != 4 {
		t.Fatalf("attributes = %d, want 4", len(list.Attributes))
	}
	for _, at := range list.Attributes {
		if at.Attribute != "criticality" {
			continue
		}
		if !at.Locked || at.Value != "critical" || at.DecidedBy == nil || at.DecidedBy.Kind != "manual" ||
			at.DecidedBy.Name != h.memberA.String() {
			t.Fatalf("criticality view = %+v", at)
		}
	}

	status, body = h.do(h.memberA, false, http.MethodDelete, base+"/criticality/lock", nil)
	if status != http.StatusOK || !strings.Contains(body, `"locked":false`) {
		t.Fatalf("release = %d (body %.300s)", status, body)
	}
	// No source decides it now: the asset keeps its value.
	if got := h.criticality(a); got != "critical" {
		t.Fatalf("release changed the value without a source: %s", got)
	}
	if n := h.auditCount("asset.updated", a); n != 2 {
		t.Errorf("lock + release audit entries = %d, want 2", n)
	}
}

func TestAttributeSources_RefusesBadInput(t *testing.T) {
	h := newDSHarness(t)
	base := "/api/v1/assets/" + h.assetA.String() + "/attribute-sources"
	for _, c := range []struct {
		path string
		body any
	}{
		{base + "/criticality/lock", map[string]any{"value": "urgent"}},
		{base + "/name/lock", map[string]any{"value": "x"}},
		{base + "/criticality/lock", map[string]any{"value": "high", "kind": "integration"}},
	} {
		if status, body := h.do(h.memberA, false, http.MethodPut, c.path, c.body); status != http.StatusBadRequest {
			t.Errorf("%s %v = %d, want 400 (body %.200s)", c.path, c.body, status, body)
		}
	}
}

func TestAttributeSources_OutOfScopeIsNotFound(t *testing.T) {
	h := newDSHarness(t)
	b := h.assetB.String()
	before := h.criticality(b)
	for _, m := range []string{http.MethodGet, http.MethodPut, http.MethodDelete} {
		path := "/api/v1/assets/" + b + "/attribute-sources"
		var body any
		if m != http.MethodGet {
			path += "/criticality/lock"
			body = map[string]any{"value": "low"}
		}
		status, resp := h.do(h.memberA, false, m, path, body)
		if status != http.StatusNotFound {
			t.Errorf("%s out-of-scope = %d, want 404 (body %.200s)", m, status, resp)
		}
		if strings.Contains(resp, dsMarkerAssetB) {
			t.Errorf("%s 404 revealed the asset: %.200s", m, resp)
		}
	}
	if got := h.criticality(b); got != before {
		t.Errorf("out-of-scope asset changed: %s -> %s", before, got)
	}
}

func TestAttributeSources_ReadOnlyCannotLock(t *testing.T) {
	h := newDSHarness(t)
	a := h.assetA.String()
	before := h.criticality(a)
	path := "/api/v1/assets/" + a + "/attribute-sources/criticality/lock"
	ro := []string{permission.AssetsRead.String()}
	if status, body := h.doWithPerms(h.memberA, ro, http.MethodPut, path, map[string]any{"value": "low"}); status != http.StatusForbidden {
		t.Errorf("read-only lock = %d, want 403 (body %.200s)", status, body)
	}
	if status, body := h.doWithPerms(h.memberA, ro, http.MethodDelete, path, nil); status != http.StatusForbidden {
		t.Errorf("read-only release = %d, want 403 (body %.200s)", status, body)
	}
	if status, body := h.doWithPerms(h.memberA, ro, http.MethodGet, "/api/v1/assets/"+a+"/attribute-sources", nil); status != http.StatusOK {
		t.Errorf("read-only get = %d, want 200 (body %.200s)", status, body)
	}
	if got := h.criticality(a); got != before {
		t.Errorf("read-only caller changed the asset: %s -> %s", before, got)
	}
}

func TestAttributeSources_OtherTenantAssetIsNotFound(t *testing.T) {
	h := newDSHarness(t)
	other, foreign := shared.NewID().String(), shared.NewID().String()
	h.exec(`INSERT INTO tenants (id, name, slug) VALUES ($1, $2, $2)`, other, "as-other-"+other)
	t.Cleanup(func() { _, _ = h.db.Exec(`DELETE FROM tenants WHERE id = $1`, other) })
	h.exec(`INSERT INTO assets (id, tenant_id, name, asset_type, criticality) VALUES ($1, $2, 'as-foreign.example.com', 'domain', 'high')`,
		foreign, other)

	status, body := h.do(h.owner, true, http.MethodPut, "/api/v1/assets/"+foreign+"/attribute-sources/criticality/lock",
		map[string]any{"value": "low"})
	if status != http.StatusNotFound || strings.Contains(body, "as-foreign") {
		t.Errorf("cross-tenant lock = %d, want a bare 404 (body %.300s)", status, body)
	}
	if got := h.criticality(foreign); got != "high" {
		t.Errorf("another tenant's asset changed: %s", got)
	}
	var rows int
	_ = h.db.QueryRow(`SELECT count(*) FROM asset_attribute_sources WHERE asset_id = $1`, foreign).Scan(&rows)
	if rows != 0 {
		t.Errorf("source rows on another tenant's asset: %d", rows)
	}
}
