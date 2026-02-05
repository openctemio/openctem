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
	"github.com/openctemio/api/pkg/domain/asset"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/logger"
	"github.com/openctemio/api/pkg/validator"
)

// AssetRelationshipHandler handles asset relationship HTTP requests.
type AssetRelationshipHandler struct {
	service   *app.AssetRelationshipService
	validator *validator.Validator
	logger    *logger.Logger
}

// NewAssetRelationshipHandler creates a new AssetRelationshipHandler.
func NewAssetRelationshipHandler(svc *app.AssetRelationshipService, v *validator.Validator, log *logger.Logger) *AssetRelationshipHandler {
	return &AssetRelationshipHandler{
		service:   svc,
		validator: v,
		logger:    log,
	}
}

// =============================================================================
// Request / Response types
// =============================================================================

// RelationshipResponse represents a relationship in API responses.
type RelationshipResponse struct {
	ID              string     `json:"id"`
	Type            string     `json:"type"`
	SourceAssetID   string     `json:"source_asset_id"`
	SourceAssetName string     `json:"source_asset_name"`
	SourceAssetType string     `json:"source_asset_type"`
	TargetAssetID   string     `json:"target_asset_id"`
	TargetAssetName string     `json:"target_asset_name"`
	TargetAssetType string     `json:"target_asset_type"`
	Description     string     `json:"description,omitempty"`
	Confidence      string     `json:"confidence"`
	DiscoveryMethod string     `json:"discovery_method"`
	ImpactWeight    int        `json:"impact_weight"`
	Tags            []string   `json:"tags,omitempty"`
	CreatedAt       time.Time  `json:"created_at"`
	UpdatedAt       time.Time  `json:"updated_at"`
	LastVerified    *time.Time `json:"last_verified,omitempty"`
}

// CreateRelationshipRequest represents the request to create a relationship.
type CreateRelationshipRequest struct {
	Type            string   `json:"type" validate:"required"`
	SourceAssetID   string   `json:"source_asset_id" validate:"required,uuid"`
	TargetAssetID   string   `json:"target_asset_id" validate:"required,uuid"`
	Description     string   `json:"description" validate:"max=1000"`
	Confidence      string   `json:"confidence" validate:"omitempty"`
	DiscoveryMethod string   `json:"discovery_method" validate:"omitempty"`
	ImpactWeight    *int     `json:"impact_weight" validate:"omitempty,min=1,max=10"`
	Tags            []string `json:"tags" validate:"omitempty,max=20,dive,max=50"`
}

// UpdateRelationshipRequest represents the request to update a relationship.
type UpdateRelationshipRequest struct {
	Description  *string  `json:"description" validate:"omitempty,max=1000"`
	Confidence   *string  `json:"confidence" validate:"omitempty"`
	ImpactWeight *int     `json:"impact_weight" validate:"omitempty,min=1,max=10"`
	Tags         []string `json:"tags" validate:"omitempty,max=20,dive,max=50"`
	MarkVerified bool     `json:"mark_verified"`
}

// =============================================================================
// Handlers
// =============================================================================

// ListByAsset handles GET /api/v1/assets/{id}/relationships
func (h *AssetRelationshipHandler) ListByAsset(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())
	assetID := chi.URLParam(r, "id")

	query := r.URL.Query()

	// Parse filter
	filter := asset.RelationshipFilter{
		Direction: query.Get("direction"),
		Page:      parseQueryInt(query.Get("page"), 1),
		PerPage:   parseQueryInt(query.Get("per_page"), 50),
	}

	if types := query.Get("types"); types != "" {
		for _, t := range parseQueryArray(types) {
			parsed, err := asset.ParseRelationshipType(t)
			if err != nil {
				apierror.BadRequest(err.Error()).WriteJSON(w)
				return
			}
			filter.Types = append(filter.Types, parsed)
		}
	}

	if confidences := query.Get("confidences"); confidences != "" {
		for _, c := range parseQueryArray(confidences) {
			parsed, err := asset.ParseRelationshipConfidence(c)
			if err != nil {
				apierror.BadRequest(err.Error()).WriteJSON(w)
				return
			}
			filter.Confidences = append(filter.Confidences, parsed)
		}
	}

	filter.MinImpactWeight = parseQueryIntPtr(query.Get("min_impact"))
	filter.MaxImpactWeight = parseQueryIntPtr(query.Get("max_impact"))

	// Call service
	results, total, err := h.service.ListAssetRelationships(r.Context(), tenantID, assetID, filter)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	// Build response
	data := make([]RelationshipResponse, len(results))
	for i, rel := range results {
		data[i] = toRelationshipResponse(rel)
	}

	totalPages := 0
	if filter.PerPage > 0 {
		totalPages = (int(total) + filter.PerPage - 1) / filter.PerPage
	}

	response := ListResponse[RelationshipResponse]{
		Data:       data,
		Total:      total,
		Page:       filter.Page,
		PerPage:    filter.PerPage,
		TotalPages: totalPages,
		Links:      NewPaginationLinks(r, filter.Page, filter.PerPage, totalPages),
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(response)
}

// Create handles POST /api/v1/assets/{id}/relationships
func (h *AssetRelationshipHandler) Create(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())

	var req CreateRelationshipRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}

	if err := h.validator.Validate(req); err != nil {
		apierror.BadRequest(err.Error()).WriteJSON(w)
		return
	}

	input := app.CreateRelationshipInput{
		TenantID:        tenantID,
		SourceAssetID:   req.SourceAssetID,
		TargetAssetID:   req.TargetAssetID,
		Type:            req.Type,
		Description:     req.Description,
		Confidence:      req.Confidence,
		DiscoveryMethod: req.DiscoveryMethod,
		ImpactWeight:    req.ImpactWeight,
		Tags:            req.Tags,
	}

	result, err := h.service.CreateRelationship(r.Context(), input)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(toRelationshipResponse(result))
}

// Get handles GET /api/v1/relationships/{relationshipId}
func (h *AssetRelationshipHandler) Get(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())
	relationshipID := chi.URLParam(r, "relationshipId")

	result, err := h.service.GetRelationship(r.Context(), tenantID, relationshipID)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(toRelationshipResponse(result))
}

// Update handles PUT /api/v1/relationships/{relationshipId}
func (h *AssetRelationshipHandler) Update(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())
	relationshipID := chi.URLParam(r, "relationshipId")

	var req UpdateRelationshipRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}

	if err := h.validator.Validate(req); err != nil {
		apierror.BadRequest(err.Error()).WriteJSON(w)
		return
	}

	input := app.UpdateRelationshipInput{
		Description:  req.Description,
		Confidence:   req.Confidence,
		ImpactWeight: req.ImpactWeight,
		Tags:         req.Tags,
		MarkVerified: req.MarkVerified,
	}

	result, err := h.service.UpdateRelationship(r.Context(), tenantID, relationshipID, input)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(toRelationshipResponse(result))
}

// Delete handles DELETE /api/v1/relationships/{relationshipId}
func (h *AssetRelationshipHandler) Delete(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())
	relationshipID := chi.URLParam(r, "relationshipId")

	if err := h.service.DeleteRelationship(r.Context(), tenantID, relationshipID); err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// =============================================================================
// Helpers
// =============================================================================

func toRelationshipResponse(rwa *asset.RelationshipWithAssets) RelationshipResponse {
	rel := rwa.Relationship
	resp := RelationshipResponse{
		ID:              rel.ID().String(),
		Type:            rel.Type().String(),
		SourceAssetID:   rel.SourceAssetID().String(),
		SourceAssetName: rwa.SourceAssetName,
		SourceAssetType: rwa.SourceAssetType.String(),
		TargetAssetID:   rel.TargetAssetID().String(),
		TargetAssetName: rwa.TargetAssetName,
		TargetAssetType: rwa.TargetAssetType.String(),
		Description:     rel.Description(),
		Confidence:      rel.Confidence().String(),
		DiscoveryMethod: rel.DiscoveryMethod().String(),
		ImpactWeight:    rel.ImpactWeight(),
		Tags:            rel.Tags(),
		CreatedAt:       rel.CreatedAt(),
		UpdatedAt:       rel.UpdatedAt(),
		LastVerified:    rel.LastVerified(),
	}
	return resp
}

func (h *AssetRelationshipHandler) handleServiceError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, shared.ErrNotFound):
		apierror.NotFound("Relationship").WriteJSON(w)
	case errors.Is(err, shared.ErrAlreadyExists):
		apierror.Conflict("Relationship already exists between these assets with this type").WriteJSON(w)
	case errors.Is(err, shared.ErrValidation):
		apierror.BadRequest(err.Error()).WriteJSON(w)
	default:
		h.logger.Error("service error", "error", err)
		apierror.InternalError(err).WriteJSON(w)
	}
}
