package handler

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/openctemio/openctem/api/pkg/brand"
)

// BrandHandler serves the instance brand (docs/architecture/brand.md):
// public on purpose, because the sign-in page and emails show it before
// anyone signs in. It carries no secret and no tenant data.
type BrandHandler struct {
	brand  brand.Brand
	public brand.Public
}

// NewBrandHandler returns a handler for the configured brand.
func NewBrandHandler(b brand.Brand) *BrandHandler {
	return &BrandHandler{brand: b, public: b.Public()}
}

// Get returns the brand.
// @Summary      Product brand
// @Description  The product name, color, links and image URLs of this installation. Public: the sign-in page shows them.
// @Tags         System
// @Produce      json
// @Success      200  {object}  brand.Public
// @Router       /brand [get]
func (h *BrandHandler) Get(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=60")
	_ = json.NewEncoder(w).Encode(h.public)
}

// Asset serves one brand image (logo-light, logo-dark or favicon). The
// image was validated at startup; it is served with its sniffed type,
// nosniff, and a sandboxing policy so an SVG opened on its own cannot run
// script even if one were present.
// @Summary      Product brand image
// @Tags         System
// @Produce      image/png
// @Produce      image/svg+xml
// @Param        kind  path  string  true  "logo-light, logo-dark or favicon"
// @Success      200
// @Failure      404
// @Router       /brand/assets/{kind} [get]
func (h *BrandHandler) Asset(w http.ResponseWriter, r *http.Request) {
	kind := brand.AssetKind(chi.URLParam(r, "kind"))
	a, ok := h.brand.Assets[kind]
	if !ok && kind == brand.AssetLogoDark {
		a, ok = h.brand.Assets[brand.AssetLogoLight]
	}
	if !ok {
		http.NotFound(w, r)
		return
	}
	etag := `"` + a.ETag + `"`
	w.Header().Set("Content-Type", a.ContentType)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; sandbox")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	w.Header().Set("ETag", etag)
	if r.Header.Get("If-None-Match") == etag {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	_, _ = w.Write(a.Data)
}
