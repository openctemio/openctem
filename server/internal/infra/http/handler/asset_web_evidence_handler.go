package handler

// Web evidence of an asset (docs/rfcs/RFC-081-web-evidence-screenshots.md).

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/apierror"
	assetdom "github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/webevidence"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// WebEvidenceAssetScope returns an asset only when it is in the caller's data
// scope (shared.ErrNotFound otherwise).
type WebEvidenceAssetScope interface {
	GetAssetInCallerScope(ctx context.Context, tenantID, assetID string) (*assetdom.Asset, error)
}

// WebEvidenceReader serves stored captures.
type WebEvidenceReader interface {
	List(ctx context.Context, tenantID, assetID shared.ID) ([]webevidence.Record, error)
	Screenshot(ctx context.Context, tenantID, assetID shared.ID, id string) (io.ReadCloser, *webevidence.Record, error)
}

// AssetWebEvidenceHandler serves /api/v1/assets/{id}/web-evidence.
type AssetWebEvidenceHandler struct {
	assets WebEvidenceAssetScope
	svc    WebEvidenceReader
	logger *logger.Logger
}

// NewAssetWebEvidenceHandler creates the handler.
func NewAssetWebEvidenceHandler(assets WebEvidenceAssetScope, svc WebEvidenceReader, log *logger.Logger) *AssetWebEvidenceHandler {
	return &AssetWebEvidenceHandler{assets: assets, svc: svc, logger: log.With("handler", "asset-web-evidence")}
}

// WebEvidenceResponse is one capture of a web asset.
type WebEvidenceResponse struct {
	ID               string     `json:"id"`
	URL              string     `json:"url"`
	FinalURL         string     `json:"final_url,omitempty"`
	StatusCode       int        `json:"status_code,omitempty"`
	Title            string     `json:"title,omitempty"`
	Server           string     `json:"server,omitempty"`
	ContentType      string     `json:"content_type,omitempty"`
	Snippet          string     `json:"snippet,omitempty"`
	SnippetTruncated bool       `json:"snippet_truncated"`
	Tool             string     `json:"tool,omitempty"`
	CapturedAt       time.Time  `json:"captured_at"`
	HasScreenshot    bool       `json:"has_screenshot"`
	ScreenshotWidth  int        `json:"screenshot_width,omitempty"`
	ScreenshotHeight int        `json:"screenshot_height,omitempty"`
	ScreenshotSHA256 string     `json:"screenshot_sha256,omitempty"`
	ScreenshotExpiry *time.Time `json:"screenshot_expires_at,omitempty"`
}

// WebEvidenceListResponse lists an asset's captures, newest first.
type WebEvidenceListResponse struct {
	Items []WebEvidenceResponse `json:"items"`
}

// asset resolves the path's asset in the caller's scope; it writes the 404
// itself (out of scope answers like a missing asset).
func (h *AssetWebEvidenceHandler) asset(w http.ResponseWriter, r *http.Request) (shared.ID, shared.ID, bool) {
	tenantID, err := shared.IDFromString(middleware.MustGetTenantID(r.Context()))
	if err != nil {
		apierror.Unauthorized("Invalid tenant ID").WriteJSON(w)
		return shared.ID{}, shared.ID{}, false
	}
	a, err := h.assets.GetAssetInCallerScope(r.Context(), tenantID.String(), r.PathValue("id"))
	if err != nil {
		if errors.Is(err, shared.ErrNotFound) || errors.Is(err, shared.ErrValidation) || errors.Is(err, shared.ErrForbidden) {
			apierror.NotFound("Asset").WriteJSON(w)
			return shared.ID{}, shared.ID{}, false
		}
		h.logger.Error("web evidence: asset lookup", "error", logger.SanitizeError(err))
		apierror.InternalServerError("failed to read the asset").WriteJSON(w)
		return shared.ID{}, shared.ID{}, false
	}
	return tenantID, a.ID(), true
}

// List handles GET /api/v1/assets/{id}/web-evidence
// @Summary      Web evidence of an asset
// @Description  What sensors saw when they fetched the asset: final URL, status, title, server, a short masked response snippet, and whether a screenshot is kept (screenshots are kept 30 days, only when the organization turned them on). Newest first, at most 5. 404 for an asset outside the caller's data scope.
// @Tags         Assets
// @Produce      json
// @Security     BearerAuth
// @Param        id   path  string  true  "Asset ID"
// @Success      200  {object}  WebEvidenceListResponse
// @Failure      404  {object}  apierror.Error
// @Router       /assets/{id}/web-evidence [get]
func (h *AssetWebEvidenceHandler) List(w http.ResponseWriter, r *http.Request) {
	tenantID, assetID, ok := h.asset(w, r)
	if !ok {
		return
	}
	recs, err := h.svc.List(r.Context(), tenantID, assetID)
	if err != nil {
		h.logger.Error("web evidence: list", "error", logger.SanitizeError(err))
		apierror.InternalServerError("failed to list web evidence").WriteJSON(w)
		return
	}
	out := WebEvidenceListResponse{Items: make([]WebEvidenceResponse, 0, len(recs))}
	for _, rec := range recs {
		out.Items = append(out.Items, WebEvidenceResponse{
			ID: rec.ID, URL: rec.URL, FinalURL: rec.FinalURL, StatusCode: rec.StatusCode, Title: rec.Title,
			Server: rec.Server, ContentType: rec.ContentType, Snippet: rec.Snippet, SnippetTruncated: rec.SnippetTruncated,
			Tool: rec.Tool, CapturedAt: rec.CapturedAt, HasScreenshot: rec.HasScreenshot(),
			ScreenshotWidth: rec.ScreenshotWidth, ScreenshotHeight: rec.ScreenshotHeight,
			ScreenshotSHA256: rec.ScreenshotSHA256, ScreenshotExpiry: rec.ScreenshotExpiresAt,
		})
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(out)
}

// Screenshot handles GET /api/v1/assets/{id}/web-evidence/{evidence_id}/screenshot
// @Summary      Screenshot of a web asset
// @Description  The PNG screenshot of one capture (re-encoded by the platform; served with a sandboxing content security policy). 404 when the asset is outside the caller's data scope, the capture has no screenshot or it expired.
// @Tags         Assets
// @Produce      png
// @Security     BearerAuth
// @Param        id          path  string  true  "Asset ID"
// @Param        evidence_id path  string  true  "Capture ID"
// @Success      200
// @Failure      404  {object}  apierror.Error
// @Router       /assets/{id}/web-evidence/{evidence_id}/screenshot [get]
func (h *AssetWebEvidenceHandler) Screenshot(w http.ResponseWriter, r *http.Request) {
	tenantID, assetID, ok := h.asset(w, r)
	if !ok {
		return
	}
	rc, rec, err := h.svc.Screenshot(r.Context(), tenantID, assetID, r.PathValue("evidence_id"))
	if err != nil {
		if errors.Is(err, shared.ErrNotFound) {
			apierror.NotFound("Screenshot").WriteJSON(w)
			return
		}
		h.logger.Error("web evidence: screenshot", "error", logger.SanitizeError(err))
		apierror.InternalServerError("failed to read the screenshot").WriteJSON(w)
		return
	}
	defer func() { _ = rc.Close() }()
	hd := w.Header()
	hd.Set("Content-Type", webevidence.ScreenshotMediaType)
	hd.Set("Content-Length", strconv.Itoa(rec.ScreenshotSize))
	hd.Set("Content-Disposition", `inline; filename="screenshot.png"`)
	hd.Set("Content-Security-Policy", "default-src 'none'; sandbox")
	hd.Set("X-Content-Type-Options", "nosniff")
	hd.Set("Cache-Control", "private, no-store")
	hd.Set("Cross-Origin-Resource-Policy", "same-origin")
	_, _ = io.Copy(w, rc)
}
