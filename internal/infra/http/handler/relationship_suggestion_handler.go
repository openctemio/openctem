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
	"github.com/openctemio/api/pkg/domain/relationship"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/logger"
	"github.com/openctemio/api/pkg/pagination"
)

// RelationshipSuggestionHandler handles relationship suggestion HTTP requests.
type RelationshipSuggestionHandler struct {
	service *app.RelationshipSuggestionService
	logger  *logger.Logger
}

// NewRelationshipSuggestionHandler creates a new RelationshipSuggestionHandler.
func NewRelationshipSuggestionHandler(svc *app.RelationshipSuggestionService, log *logger.Logger) *RelationshipSuggestionHandler {
	return &RelationshipSuggestionHandler{
		service: svc,
		logger:  log,
	}
}

// =============================================================================
// Response types
// =============================================================================

// SuggestionResponse represents a suggestion in API responses.
type SuggestionResponse struct {
	ID               string     `json:"id"`
	SourceAssetID    string     `json:"source_asset_id"`
	SourceAssetName  string     `json:"source_asset_name"`
	SourceAssetType  string     `json:"source_asset_type"`
	TargetAssetID    string     `json:"target_asset_id"`
	TargetAssetName  string     `json:"target_asset_name"`
	TargetAssetType  string     `json:"target_asset_type"`
	RelationshipType string     `json:"relationship_type"`
	Reason           string     `json:"reason"`
	Confidence       float64    `json:"confidence"`
	Status           string     `json:"status"`
	ReviewedBy       *string    `json:"reviewed_by,omitempty"`
	ReviewedAt       *time.Time `json:"reviewed_at,omitempty"`
	CreatedAt        time.Time  `json:"created_at"`
}

// =============================================================================
// Handlers
// =============================================================================

// List handles GET /api/v1/relationships/suggestions
func (h *RelationshipSuggestionHandler) List(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())

	query := r.URL.Query()
	page := pagination.New(
		parseQueryInt(query.Get("page"), 1),
		parseQueryInt(query.Get("per_page"), 20),
	)

	search := query.Get("search")
	result, err := h.service.ListPending(r.Context(), tenantID, search, page)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	data := make([]SuggestionResponse, 0, len(result.Data))
	for _, s := range result.Data {
		data = append(data, toSuggestionResponse(s))
	}

	response := ListResponse[SuggestionResponse]{
		Data:       data,
		Total:      result.Total,
		Page:       result.Page,
		PerPage:    result.PerPage,
		TotalPages: result.TotalPages,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(response)
}

// Approve handles POST /api/v1/relationships/suggestions/{id}/approve
func (h *RelationshipSuggestionHandler) Approve(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())
	suggestionID := chi.URLParam(r, "id")
	reviewerID := middleware.GetUserID(r.Context())

	if reviewerID == "" {
		apierror.Unauthorized("user ID required").WriteJSON(w)
		return
	}

	if err := h.service.Approve(r.Context(), tenantID, suggestionID, reviewerID); err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "approved"})
}

// Dismiss handles POST /api/v1/relationships/suggestions/{id}/dismiss
func (h *RelationshipSuggestionHandler) Dismiss(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())
	suggestionID := chi.URLParam(r, "id")
	reviewerID := middleware.GetUserID(r.Context())

	if reviewerID == "" {
		apierror.Unauthorized("user ID required").WriteJSON(w)
		return
	}

	if err := h.service.Dismiss(r.Context(), tenantID, suggestionID, reviewerID); err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "dismissed"})
}

// ApproveAll handles POST /api/v1/relationships/suggestions/approve-all
func (h *RelationshipSuggestionHandler) ApproveAll(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())
	reviewerID := middleware.GetUserID(r.Context())

	if reviewerID == "" {
		apierror.Unauthorized("user ID required").WriteJSON(w)
		return
	}

	count, err := h.service.ApproveAll(r.Context(), tenantID, reviewerID)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]any{"status": "approved", "count": count})
}

// ApproveBatch handles POST /api/v1/relationships/suggestions/approve-batch
func (h *RelationshipSuggestionHandler) ApproveBatch(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())
	reviewerID := middleware.GetUserID(r.Context())

	if reviewerID == "" {
		apierror.Unauthorized("user ID required").WriteJSON(w)
		return
	}

	var req struct {
		IDs []string `json:"ids"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("invalid request body").WriteJSON(w)
		return
	}
	if len(req.IDs) == 0 {
		apierror.BadRequest("ids array is required").WriteJSON(w)
		return
	}

	count, err := h.service.ApproveBatch(r.Context(), tenantID, req.IDs, reviewerID)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]any{"status": "approved", "count": count})
}

// Generate handles POST /api/v1/relationships/suggestions/generate
func (h *RelationshipSuggestionHandler) Generate(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())

	count, err := h.service.GenerateSuggestions(r.Context(), tenantID)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]any{"status": "generated", "count": count})
}

// CountPending handles GET /api/v1/relationships/suggestions/count
func (h *RelationshipSuggestionHandler) CountPending(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())

	count, err := h.service.CountPending(r.Context(), tenantID)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]any{"count": count})
}

// =============================================================================
// Helpers
// =============================================================================

func toSuggestionResponse(s *relationship.Suggestion) SuggestionResponse {
	resp := SuggestionResponse{
		ID:               s.ID().String(),
		SourceAssetID:    s.SourceAssetID().String(),
		SourceAssetName:  s.SourceAssetName(),
		SourceAssetType:  s.SourceAssetType(),
		TargetAssetID:    s.TargetAssetID().String(),
		TargetAssetName:  s.TargetAssetName(),
		TargetAssetType:  s.TargetAssetType(),
		RelationshipType: s.RelationshipType(),
		Reason:           s.Reason(),
		Confidence:       s.Confidence(),
		Status:           s.Status(),
		ReviewedAt:       s.ReviewedAt(),
		CreatedAt:        s.CreatedAt(),
	}
	if s.ReviewedBy() != nil {
		reviewedByStr := s.ReviewedBy().String()
		resp.ReviewedBy = &reviewedByStr
	}
	return resp
}

func (h *RelationshipSuggestionHandler) handleServiceError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, shared.ErrNotFound):
		apierror.NotFound("Suggestion").WriteJSON(w)
	case errors.Is(err, shared.ErrAlreadyExists):
		apierror.Conflict("Suggestion already exists").WriteJSON(w)
	case errors.Is(err, shared.ErrValidation):
		apierror.BadRequest(err.Error()).WriteJSON(w)
	default:
		h.logger.Error("service error", "error", err)
		apierror.InternalError(err).WriteJSON(w)
	}
}
