package routes

// GET /assets and POST /assets/search on the list query contract, over the
// real routes: old params still work and say they are deprecated, unknown
// params are refused without echoing them back as data, and a document
// with an OR across fields never reaches outside the caller's data scope.

import (
	"context"
	"net/http"
	"strings"
	"testing"
)

func TestAssetsList_LegacyParamsDeprecated(t *testing.T) {
	h := newDSHarness(t)
	path := "/api/v1/assets?types=" + "host,domain,subdomain,ip_address,service,application" + "&per_page=100"
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, h.srv.URL+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Test-User", h.memberA.String())
	req.Header.Set("Authorization", "Test "+h.memberA.String())
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d", resp.StatusCode)
	}
	if resp.Header.Get("Deprecation") == "" || resp.Header.Get("Sunset") == "" ||
		!strings.Contains(strings.Join(resp.Header.Values("Warning"), " "), "use type") {
		t.Fatalf("old param without deprecation headers: %v", resp.Header)
	}
}

func TestAssetsList_UnknownParamRefusedWithoutEcho(t *testing.T) {
	h := newDSHarness(t)
	const secret = "zz-secret-value-zz"
	for _, path := range []string{
		"/api/v1/assets?nonsense=" + secret,
		"/api/v1/assets?name_contains=a&" + secret + "=1",
	} {
		code, body := h.do(h.owner, true, http.MethodGet, path, nil)
		if code != http.StatusBadRequest {
			t.Fatalf("%s: status %d: %s", path, code, body)
		}
		if strings.Contains(body, secret) {
			t.Fatalf("%s: the error echoes the value: %s", path, body)
		}
	}
}

func TestAssetsSearch_DocumentStaysInScope(t *testing.T) {
	h := newDSHarness(t)
	doc := map[string]any{"v": 1, "filter": map[string]any{"any": []any{
		map[string]any{"field": "id", "op": "in", "value": []any{h.assetA.String(), h.assetB.String()}},
		map[string]any{"field": "risk_score", "op": "gte", "value": 0},
	}}, "page": map[string]any{"page": 1, "per_page": 100}}

	code, body := h.do(h.memberA, false, http.MethodPost, "/api/v1/assets/search", doc)
	if code != http.StatusOK {
		t.Fatalf("member: status %d: %s", code, body)
	}
	if !strings.Contains(body, dsMarkerAssetA) || strings.Contains(body, dsMarkerAssetB) {
		t.Fatalf("member must see A1 only: %s", body)
	}
	code, body = h.do(h.memberStrict, false, http.MethodPost, "/api/v1/assets/search", doc)
	if code != http.StatusOK || strings.Contains(body, dsMarkerAssetA) || strings.Contains(body, dsMarkerAssetB) {
		t.Fatalf("scopeless member: status %d, leaked: %s", code, body)
	}
	code, body = h.do(h.owner, true, http.MethodPost, "/api/v1/assets/search", doc)
	if code != http.StatusOK || !strings.Contains(body, dsMarkerAssetA) || !strings.Contains(body, dsMarkerAssetB) {
		t.Fatalf("owner: status %d: %s", code, body)
	}
	// A forbidden shape is a 400 with a path, not a full-text search.
	bad := map[string]any{"filter": map[string]any{"field": "tenant_id", "op": "in", "value": []any{"x"}}}
	if code, body = h.do(h.owner, true, http.MethodPost, "/api/v1/assets/search", bad); code != http.StatusBadRequest {
		t.Fatalf("unknown field: status %d: %s", code, body)
	}
}

func TestAssetsList_CursorPagesAndRefusesSort(t *testing.T) {
	h := newDSHarness(t)
	code, body := h.do(h.owner, true, http.MethodGet, "/api/v1/assets?cursor=&per_page=1", nil)
	if code != http.StatusOK || !strings.Contains(body, `"next_cursor"`) {
		t.Fatalf("first keyset page: status %d: %s", code, body)
	}
	if code, body = h.do(h.owner, true, http.MethodGet, "/api/v1/assets?cursor=&sort=name", nil); code != http.StatusBadRequest {
		t.Fatalf("cursor with sort: status %d: %s", code, body)
	}
	if code, body = h.do(h.owner, true, http.MethodGet, "/api/v1/assets?cursor=not-a-cursor", nil); code != http.StatusBadRequest {
		t.Fatalf("bad cursor: status %d: %s", code, body)
	}
}
