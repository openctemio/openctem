package handler

// GET and PUT /api/v1/me/pins: the caller's sidebar pins in the current
// organization (research/236 C4). Self-scoped: the tenant and the user come
// from the authenticated context, never from the request.

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"

	navpinapp "github.com/openctemio/openctem/api/internal/app/navpin"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/domain/navpin"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// InformationalChoice says whether a member's work views show
// informational findings.
type InformationalChoice interface {
	IncludeInformational(ctx context.Context, tenantID string, memberChoice *bool) bool
}

// NavPinHandler serves the caller's sidebar pins.
type NavPinHandler struct {
	service *navpinapp.Service
	info    InformationalChoice
	logger  *logger.Logger
}

// NewNavPinHandler creates a NavPinHandler.
func NewNavPinHandler(svc *navpinapp.Service, info InformationalChoice, log *logger.Logger) *NavPinHandler {
	return &NavPinHandler{service: svc, info: info, logger: log}
}

// NavPinRequest is one pin to store.
type NavPinRequest struct {
	Kind string `json:"kind" enums:"page,quick_view,saved_view"`
	Ref  string `json:"ref"`
}

// NavPinsRequest replaces the caller's pins, in order.
type NavPinsRequest struct {
	Pins []NavPinRequest `json:"pins"`
}

// NavPinResponse is a pin as the sidebar shows it.
type NavPinResponse struct {
	Kind   string `json:"kind" enums:"page,quick_view,saved_view"`
	Ref    string `json:"ref"`
	Name   string `json:"name,omitempty"`   // saved view name
	Params string `json:"params,omitempty"` // quick view list query
	Count  *int64 `json:"count,omitempty"`  // quick or saved view count, in the caller's scope
}

// NavPinsResponse is the caller's pins.
type NavPinsResponse struct {
	Data []NavPinResponse `json:"data"`
	Max  int              `json:"max"`
	// IncludeInformational: whether the caller's work views show
	// informational findings (how a quick view's link is built).
	IncludeInformational bool `json:"include_informational"`
}

func (h *NavPinHandler) caller(r *http.Request) (navpinapp.Caller, bool) {
	ctx := r.Context()
	tid, err1 := shared.IDFromString(middleware.GetTenantID(ctx))
	uid, err2 := shared.IDFromString(middleware.GetUserID(ctx))
	if err1 != nil || err2 != nil {
		return navpinapp.Caller{}, false
	}
	var memberChoice *bool
	if u := middleware.GetLocalUser(ctx); u != nil {
		memberChoice = u.Preferences().FindingsIncludeInformational
	}
	include := false
	if h.info != nil {
		include = h.info.IncludeInformational(ctx, tid.String(), memberChoice)
	}
	has := func(p string) bool { return middleware.HasPermission(ctx, p) }
	return navpinapp.Caller{
		TenantID: tid, UserID: uid, Has: has,
		Filter:               filterCaller(r),
		View:                 savedViewCaller(r),
		IncludeInformational: include,
	}, true
}

func (h *NavPinHandler) write(w http.ResponseWriter, c navpinapp.Caller, pins []navpinapp.PinView) {
	resp := NavPinsResponse{Data: make([]NavPinResponse, len(pins)), Max: navpin.MaxPins, IncludeInformational: c.IncludeInformational}
	for i, p := range pins {
		resp.Data[i] = NavPinResponse{Kind: string(p.Kind), Ref: p.Ref, Name: p.Name, Params: p.Params, Count: p.Count}
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "private, no-store")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)
}

func (h *NavPinHandler) writeErr(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, shared.ErrValidation):
		apierror.BadRequest(err.Error()).WriteJSON(w)
	case errors.Is(err, shared.ErrForbidden):
		apierror.Forbidden("Pinning a findings view needs findings:read").WriteJSON(w)
	case errors.Is(err, shared.ErrNotFound):
		apierror.NotFound("Saved view").WriteJSON(w)
	default:
		h.logger.Error("nav pins failed", "error", logger.SanitizeError(err))
		apierror.InternalError(err).WriteJSON(w)
	}
}

// List handles GET /api/v1/me/pins
// @Summary      My sidebar pins
// @Description  The caller's pins in the current organization, in order: pages, findings quick views and saved
// @Description  views. A saved view the caller can no longer see is left out. Counts are computed as the caller.
// @Tags         Navigation
// @Produce      json
// @Security     BearerAuth
// @Success      200  {object}  NavPinsResponse
// @Router       /me/pins [get]
func (h *NavPinHandler) List(w http.ResponseWriter, r *http.Request) {
	c, ok := h.caller(r)
	if !ok {
		apierror.Unauthorized("No user").WriteJSON(w)
		return
	}
	pins, err := h.service.List(r.Context(), c)
	if err != nil {
		h.writeErr(w, err)
		return
	}
	h.write(w, c, pins)
}

// Replace handles PUT /api/v1/me/pins
// @Summary      Set my sidebar pins
// @Description  Replaces the caller's pins in the current organization with this ordered list (at most 12). A page
// @Description  pin is an in-app path; a quick view pin names a built-in findings view; a saved view pin must be a
// @Description  view the caller can see. View pins need findings:read.
// @Tags         Navigation
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        request  body      NavPinsRequest  true  "Pins in order"
// @Success      200  {object}  NavPinsResponse
// @Failure      400  {object}  map[string]string
// @Failure      403  {object}  map[string]string
// @Failure      404  {object}  map[string]string
// @Router       /me/pins [put]
func (h *NavPinHandler) Replace(w http.ResponseWriter, r *http.Request) {
	c, ok := h.caller(r)
	if !ok {
		apierror.Unauthorized("No user").WriteJSON(w)
		return
	}
	var req NavPinsRequest
	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}
	if len(req.Pins) > navpin.MaxPins {
		apierror.BadRequest("At most 12 pins").WriteJSON(w)
		return
	}
	pins := make([]navpin.Pin, len(req.Pins))
	for i, p := range req.Pins {
		pins[i] = navpin.Pin{Kind: navpin.Kind(p.Kind), Ref: p.Ref}
	}
	out, err := h.service.Replace(r.Context(), c, pins)
	if err != nil {
		h.writeErr(w, err)
		return
	}
	h.write(w, c, out)
}
