package handler

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	toolsourceapp "github.com/openctemio/openctem/api/internal/app/toolsource"
	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// ToolSourceHandler serves the organization's keys of third-party tool
// sources (docs/architecture/tool-source-keys.md). A key is write-only: no
// response ever carries it, only its last four characters.
type ToolSourceHandler struct {
	service *toolsourceapp.Service
	logger  *logger.Logger
}

// NewToolSourceHandler creates the handler.
func NewToolSourceHandler(svc *toolsourceapp.Service, log *logger.Logger) *ToolSourceHandler {
	return &ToolSourceHandler{service: svc, logger: log.With("handler", "tool_source")}
}

// Service is the tool source key service (the sensor route uses it too).
func (h *ToolSourceHandler) Service() *toolsourceapp.Service { return h.service }

// ToolSourceKeyResponse is what is shown of a stored key.
type ToolSourceKeyResponse struct {
	Set           bool       `json:"set"`
	Last4         string     `json:"last4"`
	Enabled       bool       `json:"enabled"`
	UpdatedAt     time.Time  `json:"updated_at"`
	UpdatedByName string     `json:"updated_by_name"`
	LastUsedAt    *time.Time `json:"last_used_at"`
}

// ToolSourceResponse is one source with the organization's key facts.
type ToolSourceResponse struct {
	ID         string                 `json:"id"`
	Name       string                 `json:"name"`
	Tools      []string               `json:"tools"`
	Format     string                 `json:"format" enums:"key,pair"`
	FormatHint string                 `json:"format_hint"`
	Key        *ToolSourceKeyResponse `json:"key"`
}

// ToolSourceListResponse is every source.
type ToolSourceListResponse struct {
	Sources []ToolSourceResponse `json:"sources"`
}

// SetToolSourceKeyRequest sets or replaces a key.
type SetToolSourceKeyRequest struct {
	Value string `json:"value"`
}

// UpdateToolSourceRequest switches a stored key on or off.
type UpdateToolSourceRequest struct {
	Enabled *bool `json:"enabled"`
}

func toToolSourceResponse(v toolsourceapp.SourceView) ToolSourceResponse {
	out := ToolSourceResponse{ID: v.Source.ID, Name: v.Source.Name, Tools: v.Source.Tools, Format: string(v.Source.Format),
		FormatHint: v.Source.PairHint}
	if out.Tools == nil {
		out.Tools = []string{}
	}
	if k := v.Key; k != nil {
		out.Key = &ToolSourceKeyResponse{Set: true, Last4: k.Last4, Enabled: k.Enabled, UpdatedAt: k.UpdatedAt,
			UpdatedByName: k.UpdatedByName, LastUsedAt: k.LastUsedAt}
	}
	return out
}

// List handles GET /api/v1/tool-sources
// @Summary      List tool sources and the organization's keys
// @Description  Every third-party source a scan tool queries with a key, and whether the organization stored one (last four characters only).
// @Tags         Tool Sources
// @Produce      json
// @Success      200  {object}  ToolSourceListResponse
// @Failure      401  {object}  apierror.Error
// @Failure      403  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /tool-sources [get]
func (h *ToolSourceHandler) List(w http.ResponseWriter, r *http.Request) {
	actx := buildScanZoneAuditContext(r)
	views, err := h.service.List(r.Context(), actx.TenantID)
	if err != nil {
		h.handleError(w, err)
		return
	}
	out := ToolSourceListResponse{Sources: make([]ToolSourceResponse, 0, len(views))}
	for _, v := range views {
		out.Sources = append(out.Sources, toToolSourceResponse(v))
	}
	writeScanZoneJSON(w, http.StatusOK, out)
}

// SetKey handles PUT /api/v1/tool-sources/{source}/key
// @Summary      Set or replace a tool source key
// @Tags         Tool Sources
// @Accept       json
// @Produce      json
// @Param        source  path      string                   true  "Source id"
// @Param        body    body      SetToolSourceKeyRequest  true  "Key"
// @Success      200     {object}  ToolSourceResponse
// @Failure      400     {object}  apierror.Error
// @Failure      401     {object}  apierror.Error
// @Failure      403     {object}  apierror.Error
// @Failure      404     {object}  apierror.Error
// @Security     BearerAuth
// @Router       /tool-sources/{source}/key [put]
func (h *ToolSourceHandler) SetKey(w http.ResponseWriter, r *http.Request) {
	var req SetToolSourceKeyRequest
	if !decodeToolSourceBody(w, r, &req) {
		return
	}
	actx := buildScanZoneAuditContext(r)
	v, err := h.service.StoreKey(r.Context(), actx.TenantID, chi.URLParam(r, "source"), req.Value, actx)
	if err != nil {
		h.handleError(w, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeScanZoneJSON(w, http.StatusOK, toToolSourceResponse(v))
}

// Update handles PATCH /api/v1/tool-sources/{source}
// @Summary      Enable or disable a tool source key
// @Tags         Tool Sources
// @Accept       json
// @Produce      json
// @Param        source  path      string                   true  "Source id"
// @Param        body    body      UpdateToolSourceRequest  true  "Switch"
// @Success      200     {object}  ToolSourceResponse
// @Failure      400     {object}  apierror.Error
// @Failure      401     {object}  apierror.Error
// @Failure      403     {object}  apierror.Error
// @Failure      404     {object}  apierror.Error
// @Security     BearerAuth
// @Router       /tool-sources/{source} [patch]
func (h *ToolSourceHandler) Update(w http.ResponseWriter, r *http.Request) {
	var req UpdateToolSourceRequest
	if !decodeToolSourceBody(w, r, &req) {
		return
	}
	if req.Enabled == nil {
		apierror.BadRequest("enabled is required").WriteJSON(w)
		return
	}
	actx := buildScanZoneAuditContext(r)
	v, err := h.service.SwitchKey(r.Context(), actx.TenantID, chi.URLParam(r, "source"), *req.Enabled, actx)
	if err != nil {
		h.handleError(w, err)
		return
	}
	writeScanZoneJSON(w, http.StatusOK, toToolSourceResponse(v))
}

// DeleteKey handles DELETE /api/v1/tool-sources/{source}/key
// @Summary      Remove a tool source key
// @Tags         Tool Sources
// @Param        source  path  string  true  "Source id"
// @Success      204
// @Failure      401  {object}  apierror.Error
// @Failure      403  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /tool-sources/{source}/key [delete]
func (h *ToolSourceHandler) DeleteKey(w http.ResponseWriter, r *http.Request) {
	actx := buildScanZoneAuditContext(r)
	if err := h.service.DeleteKey(r.Context(), actx.TenantID, chi.URLParam(r, "source"), actx); err != nil {
		h.handleError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// maxToolSourceBody bounds a request body (a key is at most 1 KiB).
const maxToolSourceBody = 8 << 10

func decodeToolSourceBody(w http.ResponseWriter, r *http.Request, v any) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxToolSourceBody))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return false
	}
	return true
}

func (h *ToolSourceHandler) handleError(w http.ResponseWriter, err error) {
	var de *shared.DomainError
	switch {
	case errors.Is(err, shared.ErrNotFound):
		apierror.NotFound("Tool source key").WriteJSON(w)
	case errors.As(err, &de) && errors.Is(err, shared.ErrValidation):
		apierror.New(http.StatusBadRequest, apierror.Code(de.Code), de.Message).WriteJSON(w)
	case errors.Is(err, shared.ErrValidation):
		apierror.BadRequest("Invalid request").WriteJSON(w)
	default:
		h.logger.Error("tool source key service error", "error", sanitizeLogField(err.Error()))
		apierror.InternalError(err).WriteJSON(w)
	}
}
