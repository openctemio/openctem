package handler

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	dashboardapp "github.com/openctemio/openctem/api/internal/app/dashboard"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/apierror"
	dashboard "github.com/openctemio/openctem/api/pkg/domain/dashboard"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// UserDashboardHandler serves the per-user dashboards API (RFC-021), mounted
// under /api/v1/me/dashboards. Tenant and user are read from the authenticated
// context — never from the request body.
type UserDashboardHandler struct {
	service *dashboardapp.Service
	logger  *logger.Logger
}

// NewUserDashboardHandler creates a new UserDashboardHandler.
func NewUserDashboardHandler(svc *dashboardapp.Service, log *logger.Logger) *UserDashboardHandler {
	return &UserDashboardHandler{service: svc, logger: log}
}

type userDashboardResponse struct {
	ID          string             `json:"id"`
	Name        string             `json:"name"`
	Description string             `json:"description"`
	Columns     int                `json:"columns"`
	IsDefault   bool               `json:"is_default"`
	Layout      []dashboard.Widget `json:"layout"`
	CreatedAt   time.Time          `json:"created_at"`
	UpdatedAt   time.Time          `json:"updated_at"`
}

type userDashboardRequest struct {
	Name        string             `json:"name"`
	Description string             `json:"description"`
	Columns     int                `json:"columns"`
	Layout      []dashboard.Widget `json:"layout"`
}

func toUserDashboardResponse(d *dashboard.Dashboard) userDashboardResponse {
	layout := d.Widgets()
	if layout == nil {
		layout = make([]dashboard.Widget, 0)
	}
	return userDashboardResponse{
		ID:          d.ID().String(),
		Name:        d.Name(),
		Description: d.Description(),
		Columns:     d.Columns(),
		IsDefault:   d.IsDefault(),
		Layout:      layout,
		CreatedAt:   d.CreatedAt(),
		UpdatedAt:   d.UpdatedAt(),
	}
}

// List handles GET /api/v1/me/dashboards
func (h *UserDashboardHandler) List(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())
	userID := middleware.GetUserID(r.Context())
	if userID == "" {
		apierror.Unauthorized("user context required").WriteJSON(w)
		return
	}

	items, err := h.service.List(r.Context(), tenantID, userID)
	if err != nil {
		h.handleError(w, err)
		return
	}

	data := make([]userDashboardResponse, 0, len(items))
	for _, d := range items {
		data = append(data, toUserDashboardResponse(d))
	}

	writeJSON(w, http.StatusOK, map[string]any{"data": data})
}

// Create handles POST /api/v1/me/dashboards
func (h *UserDashboardHandler) Create(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())
	userID := middleware.GetUserID(r.Context())
	if userID == "" {
		apierror.Unauthorized("user context required").WriteJSON(w)
		return
	}

	var req userDashboardRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("invalid request body").WriteJSON(w)
		return
	}

	d, err := h.service.Create(r.Context(), tenantID, userID, dashboardapp.CreateInput{
		Name:        req.Name,
		Description: req.Description,
		Columns:     req.Columns,
		Widgets:     req.Layout,
	})
	if err != nil {
		h.handleError(w, err)
		return
	}

	writeJSON(w, http.StatusCreated, toUserDashboardResponse(d))
}

// Get handles GET /api/v1/me/dashboards/{id}
func (h *UserDashboardHandler) Get(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())
	userID := middleware.GetUserID(r.Context())
	if userID == "" {
		apierror.Unauthorized("user context required").WriteJSON(w)
		return
	}

	d, err := h.service.Get(r.Context(), tenantID, userID, r.PathValue("id"))
	if err != nil {
		h.handleError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, toUserDashboardResponse(d))
}

// Update handles PUT /api/v1/me/dashboards/{id}
func (h *UserDashboardHandler) Update(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())
	userID := middleware.GetUserID(r.Context())
	if userID == "" {
		apierror.Unauthorized("user context required").WriteJSON(w)
		return
	}

	var req userDashboardRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("invalid request body").WriteJSON(w)
		return
	}

	d, err := h.service.Update(r.Context(), tenantID, userID, r.PathValue("id"), dashboardapp.CreateInput{
		Name:        req.Name,
		Description: req.Description,
		Columns:     req.Columns,
		Widgets:     req.Layout,
	})
	if err != nil {
		h.handleError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, toUserDashboardResponse(d))
}

// Delete handles DELETE /api/v1/me/dashboards/{id}
func (h *UserDashboardHandler) Delete(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())
	userID := middleware.GetUserID(r.Context())
	if userID == "" {
		apierror.Unauthorized("user context required").WriteJSON(w)
		return
	}

	if err := h.service.Delete(r.Context(), tenantID, userID, r.PathValue("id")); err != nil {
		h.handleError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// SetDefault handles POST /api/v1/me/dashboards/{id}/default
func (h *UserDashboardHandler) SetDefault(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())
	userID := middleware.GetUserID(r.Context())
	if userID == "" {
		apierror.Unauthorized("user context required").WriteJSON(w)
		return
	}

	if err := h.service.SetDefault(r.Context(), tenantID, userID, r.PathValue("id")); err != nil {
		h.handleError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "updated"})
}

func (h *UserDashboardHandler) handleError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, shared.ErrNotFound):
		apierror.NotFound("Dashboard").WriteJSON(w)
	case errors.Is(err, shared.ErrValidation):
		apierror.BadRequest(err.Error()).WriteJSON(w)
	case errors.Is(err, shared.ErrConflict):
		apierror.Conflict(strings.TrimPrefix(err.Error(), shared.ErrConflict.Error()+": ")).WriteJSON(w)
	default:
		h.logger.Error("user dashboard error", "error", err)
		apierror.InternalServerError("internal error").WriteJSON(w)
	}
}
