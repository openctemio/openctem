package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/openctemio/openctem/api/pkg/brand"
)

func brandReq(kind string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, brand.AssetPath+kind, nil)
	rc := chi.NewRouteContext()
	rc.URLParams.Add("kind", kind)
	return r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rc))
}

func TestBrandHandler(t *testing.T) {
	b := brand.Default()
	b.Name = "Acme Exposure"
	a, err := brand.NewAsset([]byte(`<svg xmlns="http://www.w3.org/2000/svg"><rect/></svg>`))
	if err != nil {
		t.Fatal(err)
	}
	b.Assets = map[brand.AssetKind]brand.Asset{brand.AssetLogoLight: a}
	h := NewBrandHandler(b)

	rec := httptest.NewRecorder()
	h.Get(rec, httptest.NewRequest(http.MethodGet, "/api/v1/brand", nil))
	var got brand.Public
	if err := json.NewDecoder(rec.Body).Decode(&got); err != nil || got.Name != "Acme Exposure" {
		t.Fatalf("brand = %+v, %v", got, err)
	}

	rec = httptest.NewRecorder()
	h.Asset(rec, brandReq("logo-dark")) // falls back to the light logo
	if rec.Code != http.StatusOK || rec.Header().Get("Content-Type") != brand.TypeSVG {
		t.Fatalf("asset = %d %q", rec.Code, rec.Header().Get("Content-Type"))
	}
	if rec.Header().Get("X-Content-Type-Options") != "nosniff" || rec.Header().Get("Content-Security-Policy") == "" {
		t.Error("asset served without nosniff or sandbox policy")
	}

	req := brandReq("logo-light")
	req.Header.Set("If-None-Match", `"`+a.ETag+`"`)
	rec = httptest.NewRecorder()
	h.Asset(rec, req)
	if rec.Code != http.StatusNotModified {
		t.Errorf("conditional GET = %d", rec.Code)
	}

	for _, k := range []string{"favicon", "../etc/passwd", "secret"} {
		rec = httptest.NewRecorder()
		h.Asset(rec, brandReq(k))
		if rec.Code != http.StatusNotFound {
			t.Errorf("%s = %d, want 404", k, rec.Code)
		}
	}
}
