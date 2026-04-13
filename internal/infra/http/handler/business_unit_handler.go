package handler

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/openctemio/api/internal/app"
	"github.com/openctemio/api/internal/infra/http/middleware"
	"github.com/openctemio/api/pkg/apierror"
	"github.com/openctemio/api/pkg/domain/businessunit"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/logger"
	"github.com/openctemio/api/pkg/pagination"
)

// BusinessUnitHandler handles business unit endpoints.
type BusinessUnitHandler struct {
	service *app.BusinessUnitService
	logger  *logger.Logger
}

// NewBusinessUnitHandler creates a new handler.
func NewBusinessUnitHandler(svc *app.BusinessUnitService, log *logger.Logger) *BusinessUnitHandler {
	return &BusinessUnitHandler{service: svc, logger: log}
}

// List lists business units.
func (h *BusinessUnitHandler) List(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())
	perPage := parseQueryInt(r.URL.Query().Get("per_page"), 20)
	if perPage < 1 { perPage = 20 } else if perPage > 100 { perPage = 100 }
	page := pagination.New(max(parseQueryInt(r.URL.Query().Get("page"), 1), 1), perPage)

	filter := businessunit.Filter{}
	if q := r.URL.Query().Get("search"); q != "" { filter.Search = &q }

	result, err := h.service.List(r.Context(), tenantID, filter, page)
	if err != nil { h.handleError(w, err); return }

	resp := make([]BUResponse, 0, len(result.Data))
	for _, bu := range result.Data { resp = append(resp, toBUResp(bu)) }
	writeJSON(w, http.StatusOK, pagination.NewResult(resp, result.Total, page))
}

// Create creates a business unit.
func (h *BusinessUnitHandler) Create(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())
	var req CreateBURequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("invalid request body").WriteJSON(w); return
	}
	bu, err := h.service.Create(r.Context(), app.CreateBusinessUnitInput{
		TenantID: tenantID, Name: req.Name, Description: req.Description,
		OwnerName: req.OwnerName, OwnerEmail: req.OwnerEmail, Tags: req.Tags,
	})
	if err != nil { h.handleError(w, err); return }
	writeJSON(w, http.StatusCreated, toBUResp(bu))
}

// Get retrieves a business unit.
func (h *BusinessUnitHandler) Get(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())
	bu, err := h.service.Get(r.Context(), tenantID, chi.URLParam(r, "id"))
	if err != nil { h.handleError(w, err); return }
	writeJSON(w, http.StatusOK, toBUResp(bu))
}

// Delete deletes a business unit.
func (h *BusinessUnitHandler) Delete(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())
	if err := h.service.Delete(r.Context(), tenantID, chi.URLParam(r, "id")); err != nil {
		h.handleError(w, err); return
	}
	w.WriteHeader(http.StatusNoContent)
}

// AddAsset links an asset to a business unit.
func (h *BusinessUnitHandler) AddAsset(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())
	buID := chi.URLParam(r, "id")
	var req struct { AssetID string `json:"asset_id"` }
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("invalid request body").WriteJSON(w); return
	}
	if err := h.service.AddAsset(r.Context(), tenantID, buID, req.AssetID); err != nil {
		h.handleError(w, err); return
	}
	w.WriteHeader(http.StatusNoContent)
}

// RemoveAsset unlinks an asset from a business unit.
func (h *BusinessUnitHandler) RemoveAsset(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())
	buID := chi.URLParam(r, "id")
	assetID := chi.URLParam(r, "assetId")
	if err := h.service.RemoveAsset(r.Context(), tenantID, buID, assetID); err != nil {
		h.handleError(w, err); return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *BusinessUnitHandler) handleError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, shared.ErrNotFound):
		apierror.NotFound("business unit not found").WriteJSON(w)
	case errors.Is(err, shared.ErrValidation):
		apierror.BadRequest(err.Error()).WriteJSON(w)
	default:
		h.logger.Error("business unit error", "error", err)
		apierror.InternalServerError("internal error").WriteJSON(w)
	}
}

type CreateBURequest struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	OwnerName   string   `json:"owner_name"`
	OwnerEmail  string   `json:"owner_email"`
	Tags        []string `json:"tags"`
}

type BUResponse struct {
	ID                   string    `json:"id"`
	Name                 string    `json:"name"`
	Description          string    `json:"description"`
	OwnerName            string    `json:"owner_name,omitempty"`
	OwnerEmail           string    `json:"owner_email,omitempty"`
	AssetCount           int       `json:"asset_count"`
	FindingCount         int       `json:"finding_count"`
	AvgRiskScore         float64   `json:"avg_risk_score"`
	CriticalFindingCount int       `json:"critical_finding_count"`
	Tags                 []string  `json:"tags"`
	CreatedAt            time.Time `json:"created_at"`
	UpdatedAt            time.Time `json:"updated_at"`
}

func toBUResp(bu *businessunit.BusinessUnit) BUResponse {
	return BUResponse{
		ID: bu.ID().String(), Name: bu.Name(), Description: bu.Description(),
		OwnerName: bu.OwnerName(), OwnerEmail: bu.OwnerEmail(),
		AssetCount: bu.AssetCount(), FindingCount: bu.FindingCount(),
		AvgRiskScore: bu.AvgRiskScore(), CriticalFindingCount: bu.CriticalFindingCount(),
		Tags: bu.Tags(), CreatedAt: bu.CreatedAt(), UpdatedAt: bu.UpdatedAt(),
	}
}
