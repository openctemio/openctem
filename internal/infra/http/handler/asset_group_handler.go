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
	"github.com/openctemio/api/pkg/domain/assetgroup"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/logger"
	"github.com/openctemio/api/pkg/validator"
)

// AssetGroupHandler handles asset group HTTP requests.
type AssetGroupHandler struct {
	service   *app.AssetGroupService
	validator *validator.Validator
	logger    *logger.Logger
}

// NewAssetGroupHandler creates a new asset group handler.
func NewAssetGroupHandler(svc *app.AssetGroupService, v *validator.Validator, log *logger.Logger) *AssetGroupHandler {
	return &AssetGroupHandler{
		service:   svc,
		validator: v,
		logger:    log,
	}
}

// AssetGroupResponse represents an asset group in API responses.
type AssetGroupResponse struct {
	ID              string    `json:"id"`
	Name            string    `json:"name"`
	Description     string    `json:"description,omitempty"`
	Environment     string    `json:"environment"`
	Criticality     string    `json:"criticality"`
	BusinessUnit    string    `json:"business_unit,omitempty"`
	Owner           string    `json:"owner,omitempty"`
	OwnerEmail      string    `json:"owner_email,omitempty"`
	Tags            []string  `json:"tags,omitempty"`
	AssetCount      int       `json:"asset_count"`
	DomainCount     int       `json:"domain_count"`
	WebsiteCount    int       `json:"website_count"`
	ServiceCount    int       `json:"service_count"`
	RepositoryCount int       `json:"repository_count"`
	CloudCount      int       `json:"cloud_count"`
	CredentialCount int       `json:"credential_count"`
	RiskScore       int       `json:"risk_score"`
	FindingCount    int       `json:"finding_count"`
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at"`
}

// CreateAssetGroupRequest represents the request to create an asset group.
type CreateAssetGroupRequest struct {
	Name         string   `json:"name" validate:"required,min=1,max=255"`
	Description  string   `json:"description" validate:"max=1000"`
	Environment  string   `json:"environment" validate:"required,asset_group_environment"`
	Criticality  string   `json:"criticality" validate:"required,asset_group_criticality"`
	BusinessUnit string   `json:"business_unit" validate:"max=255"`
	Owner        string   `json:"owner" validate:"max=255"`
	OwnerEmail   string   `json:"owner_email" validate:"omitempty,email,max=255"`
	Tags         []string `json:"tags" validate:"max=20,dive,max=50"`
	AssetIDs     []string `json:"existing_asset_ids" validate:"dive,uuid"`
}

// UpdateAssetGroupRequest represents the request to update an asset group.
type UpdateAssetGroupRequest struct {
	Name         *string  `json:"name" validate:"omitempty,min=1,max=255"`
	Description  *string  `json:"description" validate:"omitempty,max=1000"`
	Environment  *string  `json:"environment" validate:"omitempty,asset_group_environment"`
	Criticality  *string  `json:"criticality" validate:"omitempty,asset_group_criticality"`
	BusinessUnit *string  `json:"business_unit" validate:"omitempty,max=255"`
	Owner        *string  `json:"owner" validate:"omitempty,max=255"`
	OwnerEmail   *string  `json:"owner_email" validate:"omitempty,email,max=255"`
	Tags         []string `json:"tags" validate:"omitempty,max=20,dive,max=50"`
}

// AddAssetsRequest represents the request to add assets to a group.
type AddAssetsRequest struct {
	AssetIDs []string `json:"asset_ids" validate:"required,min=1,dive,uuid"`
}

// RemoveAssetsRequest represents the request to remove assets from a group.
type RemoveAssetsRequest struct {
	AssetIDs []string `json:"asset_ids" validate:"required,min=1,dive,uuid"`
}

// BulkUpdateRequest represents bulk update request.
type BulkUpdateRequest struct {
	GroupIDs []string `json:"group_ids" validate:"required,min=1,dive,uuid"`
	Update   struct {
		Environment *string `json:"environment" validate:"omitempty,asset_group_environment"`
		Criticality *string `json:"criticality" validate:"omitempty,asset_group_criticality"`
	} `json:"update"`
}

// BulkDeleteRequest represents bulk delete request.
type BulkDeleteRequest struct {
	GroupIDs []string `json:"group_ids" validate:"required,min=1,dive,uuid"`
}

// AssetGroupStatsResponse represents stats response.
type AssetGroupStatsResponse struct {
	Total            int64            `json:"total"`
	ByEnvironment    map[string]int64 `json:"by_environment"`
	ByCriticality    map[string]int64 `json:"by_criticality"`
	TotalAssets      int64            `json:"total_assets"`
	TotalFindings    int64            `json:"total_findings"`
	AverageRiskScore float64          `json:"average_risk_score"`
}

// GroupAssetResponse represents an asset in group context.
type GroupAssetResponse struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	Type         string `json:"type"`
	Status       string `json:"status"`
	RiskScore    int    `json:"risk_score"`
	FindingCount int    `json:"finding_count"`
	LastSeen     string `json:"last_seen"`
}

func toAssetGroupResponse(g *assetgroup.AssetGroup) AssetGroupResponse {
	return AssetGroupResponse{
		ID:              g.ID().String(),
		Name:            g.Name(),
		Description:     g.Description(),
		Environment:     g.Environment().String(),
		Criticality:     g.Criticality().String(),
		BusinessUnit:    g.BusinessUnit(),
		Owner:           g.Owner(),
		OwnerEmail:      g.OwnerEmail(),
		Tags:            g.Tags(),
		AssetCount:      g.AssetCount(),
		DomainCount:     g.DomainCount(),
		WebsiteCount:    g.WebsiteCount(),
		ServiceCount:    g.ServiceCount(),
		RepositoryCount: g.RepositoryCount(),
		CloudCount:      g.CloudCount(),
		CredentialCount: g.CredentialCount(),
		RiskScore:       g.RiskScore(),
		FindingCount:    g.FindingCount(),
		CreatedAt:       g.CreatedAt(),
		UpdatedAt:       g.UpdatedAt(),
	}
}

func toGroupAssetResponse(a *assetgroup.GroupAsset) GroupAssetResponse {
	return GroupAssetResponse{
		ID:           a.ID.String(),
		Name:         a.Name,
		Type:         a.Type,
		Status:       a.Status,
		RiskScore:    a.RiskScore,
		FindingCount: a.FindingCount,
		LastSeen:     a.LastSeen,
	}
}

func (h *AssetGroupHandler) handleValidationError(w http.ResponseWriter, err error) {
	var validationErrors validator.ValidationErrors
	if errors.As(err, &validationErrors) {
		apiErrors := make([]apierror.ValidationError, len(validationErrors))
		for i, ve := range validationErrors {
			apiErrors[i] = apierror.ValidationError{
				Field:   ve.Field,
				Message: ve.Message,
			}
		}
		apierror.ValidationFailed("Validation failed", apiErrors).WriteJSON(w)
		return
	}
	apierror.BadRequest("Validation error").WriteJSON(w)
}

func (h *AssetGroupHandler) handleServiceError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, shared.ErrNotFound):
		apierror.NotFound("Asset group").WriteJSON(w)
	case errors.Is(err, shared.ErrAlreadyExists):
		apierror.Conflict("Asset group already exists").WriteJSON(w)
	case errors.Is(err, shared.ErrValidation):
		apierror.BadRequest(err.Error()).WriteJSON(w)
	default:
		h.logger.Error("service error", "error", err)
		apierror.InternalError(err).WriteJSON(w)
	}
}

// List handles GET /api/v1/asset-groups
// @Summary      List asset groups
// @Description  Get a paginated list of asset groups for the current tenant
// @Tags         Asset Groups
// @Accept       json
// @Produce      json
// @Param        search         query     string  false  "Search by name"
// @Param        environments   query     string  false  "Filter by environments (comma-separated)"
// @Param        criticalities  query     string  false  "Filter by criticalities (comma-separated)"
// @Param        business_unit  query     string  false  "Filter by business unit"
// @Param        owner          query     string  false  "Filter by owner"
// @Param        tags           query     string  false  "Filter by tags (comma-separated)"
// @Param        has_findings   query     bool    false  "Filter groups with findings"
// @Param        min_risk_score query     int     false  "Minimum risk score"
// @Param        max_risk_score query     int     false  "Maximum risk score"
// @Param        sort           query     string  false  "Sort field (name, created_at, risk_score)"
// @Param        page           query     int     false  "Page number" default(1)
// @Param        per_page       query     int     false  "Items per page" default(20)
// @Success      200  {object}  ListResponse[AssetGroupResponse]
// @Failure      400  {object}  apierror.Error
// @Failure      401  {object}  apierror.Error
// @Failure      500  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /asset-groups [get]
func (h *AssetGroupHandler) List(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())
	query := r.URL.Query()

	input := app.ListAssetGroupsInput{
		TenantID:      tenantID,
		Search:        query.Get("search"),
		Environments:  parseQueryArray(query.Get("environments")),
		Criticalities: parseQueryArray(query.Get("criticalities")),
		BusinessUnit:  query.Get("business_unit"),
		Owner:         query.Get("owner"),
		Tags:          parseQueryArray(query.Get("tags")),
		HasFindings:   parseQueryBoolPtr(query.Get("has_findings")),
		MinRiskScore:  parseQueryIntPtr(query.Get("min_risk_score")),
		MaxRiskScore:  parseQueryIntPtr(query.Get("max_risk_score")),
		Sort:          query.Get("sort"),
		Page:          parseQueryInt(query.Get("page"), 1),
		PerPage:       parseQueryInt(query.Get("per_page"), 20),
	}

	if err := h.validator.Validate(input); err != nil {
		h.handleValidationError(w, err)
		return
	}

	result, err := h.service.ListAssetGroups(r.Context(), input)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	groups := make([]AssetGroupResponse, len(result.Groups))
	for i, g := range result.Groups {
		groups[i] = toAssetGroupResponse(g)
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(ListResponse[AssetGroupResponse]{
		Data:       groups,
		Total:      result.Total,
		Page:       result.Page,
		PerPage:    input.PerPage,
		TotalPages: result.Pages,
	})
}

// Get handles GET /api/v1/asset-groups/{id}
// @Summary      Get asset group
// @Description  Get a single asset group by ID
// @Tags         Asset Groups
// @Accept       json
// @Produce      json
// @Param        id   path      string  true  "Asset Group ID"
// @Success      200  {object}  AssetGroupResponse
// @Failure      400  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Failure      500  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /asset-groups/{id} [get]
func (h *AssetGroupHandler) Get(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, err := shared.IDFromString(idStr)
	if err != nil {
		apierror.BadRequest("Invalid group ID").WriteJSON(w)
		return
	}

	group, err := h.service.GetAssetGroup(r.Context(), id)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(toAssetGroupResponse(group))
}

// Create handles POST /api/v1/asset-groups
// @Summary      Create asset group
// @Description  Create a new asset group
// @Tags         Asset Groups
// @Accept       json
// @Produce      json
// @Param        body  body      CreateAssetGroupRequest  true  "Asset group data"
// @Success      201   {object}  AssetGroupResponse
// @Failure      400   {object}  apierror.Error
// @Failure      409   {object}  apierror.Error
// @Failure      500   {object}  apierror.Error
// @Security     BearerAuth
// @Router       /asset-groups [post]
func (h *AssetGroupHandler) Create(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())

	var req CreateAssetGroupRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}

	if err := h.validator.Validate(req); err != nil {
		h.handleValidationError(w, err)
		return
	}

	input := app.CreateAssetGroupInput{
		TenantID:     tenantID,
		Name:         req.Name,
		Description:  req.Description,
		Environment:  req.Environment,
		Criticality:  req.Criticality,
		BusinessUnit: req.BusinessUnit,
		Owner:        req.Owner,
		OwnerEmail:   req.OwnerEmail,
		Tags:         req.Tags,
		AssetIDs:     req.AssetIDs,
	}

	group, err := h.service.CreateAssetGroup(r.Context(), input)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(toAssetGroupResponse(group))
}

// Update handles PATCH /api/v1/asset-groups/{id}
// @Summary      Update asset group
// @Description  Update an existing asset group
// @Tags         Asset Groups
// @Accept       json
// @Produce      json
// @Param        id    path      string                   true  "Asset Group ID"
// @Param        body  body      UpdateAssetGroupRequest  true  "Update data"
// @Success      200   {object}  AssetGroupResponse
// @Failure      400   {object}  apierror.Error
// @Failure      404   {object}  apierror.Error
// @Failure      500   {object}  apierror.Error
// @Security     BearerAuth
// @Router       /asset-groups/{id} [patch]
func (h *AssetGroupHandler) Update(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, err := shared.IDFromString(idStr)
	if err != nil {
		apierror.BadRequest("Invalid group ID").WriteJSON(w)
		return
	}

	var req UpdateAssetGroupRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}

	if err := h.validator.Validate(req); err != nil {
		h.handleValidationError(w, err)
		return
	}

	input := app.UpdateAssetGroupInput{
		Name:         req.Name,
		Description:  req.Description,
		Environment:  req.Environment,
		Criticality:  req.Criticality,
		BusinessUnit: req.BusinessUnit,
		Owner:        req.Owner,
		OwnerEmail:   req.OwnerEmail,
		Tags:         req.Tags,
	}

	group, err := h.service.UpdateAssetGroup(r.Context(), id, input)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(toAssetGroupResponse(group))
}

// Delete handles DELETE /api/v1/asset-groups/{id}
// @Summary      Delete asset group
// @Description  Delete an asset group
// @Tags         Asset Groups
// @Accept       json
// @Produce      json
// @Param        id   path      string  true  "Asset Group ID"
// @Success      204  "No Content"
// @Failure      400  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Failure      500  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /asset-groups/{id} [delete]
func (h *AssetGroupHandler) Delete(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, err := shared.IDFromString(idStr)
	if err != nil {
		apierror.BadRequest("Invalid group ID").WriteJSON(w)
		return
	}

	if err := h.service.DeleteAssetGroup(r.Context(), id); err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// GetStats handles GET /api/v1/asset-groups/stats
// @Summary      Get asset group statistics
// @Description  Get aggregated statistics for asset groups
// @Tags         Asset Groups
// @Accept       json
// @Produce      json
// @Success      200  {object}  AssetGroupStatsResponse
// @Failure      401  {object}  apierror.Error
// @Failure      500  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /asset-groups/stats [get]
func (h *AssetGroupHandler) GetStats(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())

	stats, err := h.service.GetAssetGroupStats(r.Context(), tenantID)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	byEnv := make(map[string]int64)
	for env, count := range stats.ByEnvironment {
		byEnv[env.String()] = count
	}

	byCrit := make(map[string]int64)
	for crit, count := range stats.ByCriticality {
		byCrit[crit.String()] = count
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(AssetGroupStatsResponse{
		Total:            stats.Total,
		ByEnvironment:    byEnv,
		ByCriticality:    byCrit,
		TotalAssets:      stats.TotalAssets,
		TotalFindings:    stats.TotalFindings,
		AverageRiskScore: stats.AverageRiskScore,
	})
}

// GetAssets handles GET /api/v1/asset-groups/{id}/assets
// @Summary      Get assets in group
// @Description  Get a paginated list of assets belonging to the group
// @Tags         Asset Groups
// @Accept       json
// @Produce      json
// @Param        id        path      string  true   "Asset Group ID"
// @Param        page      query     int     false  "Page number" default(1)
// @Param        per_page  query     int     false  "Items per page" default(20)
// @Success      200  {object}  ListResponse[GroupAssetResponse]
// @Failure      400  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Failure      500  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /asset-groups/{id}/assets [get]
func (h *AssetGroupHandler) GetAssets(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, err := shared.IDFromString(idStr)
	if err != nil {
		apierror.BadRequest("Invalid group ID").WriteJSON(w)
		return
	}

	query := r.URL.Query()
	page := parseQueryInt(query.Get("page"), 1)
	perPage := parseQueryInt(query.Get("per_page"), 20)

	result, err := h.service.GetGroupAssets(r.Context(), id, page, perPage)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	assets := make([]GroupAssetResponse, len(result.Data))
	for i, a := range result.Data {
		assets[i] = toGroupAssetResponse(a)
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(ListResponse[GroupAssetResponse]{
		Data:       assets,
		Total:      result.Total,
		Page:       result.Page,
		PerPage:    perPage,
		TotalPages: result.TotalPages,
	})
}

// GroupFindingResponse represents a finding in group context.
type GroupFindingResponse struct {
	ID           string `json:"id"`
	Title        string `json:"title"`
	Severity     string `json:"severity"`
	Status       string `json:"status"`
	AssetID      string `json:"asset_id"`
	AssetName    string `json:"asset_name"`
	AssetType    string `json:"asset_type"`
	DiscoveredAt string `json:"discovered_at"`
}

// GetFindings handles GET /api/v1/asset-groups/{id}/findings
// @Summary      Get findings in group
// @Description  Get a paginated list of findings from assets in the group
// @Tags         Asset Groups
// @Accept       json
// @Produce      json
// @Param        id        path      string  true   "Asset Group ID"
// @Param        page      query     int     false  "Page number" default(1)
// @Param        per_page  query     int     false  "Items per page" default(20)
// @Success      200  {object}  ListResponse[GroupFindingResponse]
// @Failure      400  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Failure      500  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /asset-groups/{id}/findings [get]
func (h *AssetGroupHandler) GetFindings(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, err := shared.IDFromString(idStr)
	if err != nil {
		apierror.BadRequest("Invalid group ID").WriteJSON(w)
		return
	}

	query := r.URL.Query()
	page := parseQueryInt(query.Get("page"), 1)
	perPage := parseQueryInt(query.Get("per_page"), 20)

	result, err := h.service.GetGroupFindings(r.Context(), id, page, perPage)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	findings := make([]GroupFindingResponse, len(result.Data))
	for i, f := range result.Data {
		findings[i] = GroupFindingResponse{
			ID:           f.ID.String(),
			Title:        f.Title,
			Severity:     f.Severity,
			Status:       f.Status,
			AssetID:      f.AssetID.String(),
			AssetName:    f.AssetName,
			AssetType:    f.AssetType,
			DiscoveredAt: f.DiscoveredAt,
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(ListResponse[GroupFindingResponse]{
		Data:       findings,
		Total:      result.Total,
		Page:       result.Page,
		PerPage:    perPage,
		TotalPages: result.TotalPages,
	})
}

// AddAssets handles POST /api/v1/asset-groups/{id}/assets
// @Summary      Add assets to group
// @Description  Add one or more assets to an asset group
// @Tags         Asset Groups
// @Accept       json
// @Produce      json
// @Param        id    path      string            true  "Asset Group ID"
// @Param        body  body      AddAssetsRequest  true  "Asset IDs to add"
// @Success      200   {object}  AssetGroupResponse
// @Failure      400   {object}  apierror.Error
// @Failure      404   {object}  apierror.Error
// @Failure      500   {object}  apierror.Error
// @Security     BearerAuth
// @Router       /asset-groups/{id}/assets [post]
func (h *AssetGroupHandler) AddAssets(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, err := shared.IDFromString(idStr)
	if err != nil {
		apierror.BadRequest("Invalid group ID").WriteJSON(w)
		return
	}

	var req AddAssetsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}

	if err := h.validator.Validate(req); err != nil {
		h.handleValidationError(w, err)
		return
	}

	if err := h.service.AddAssetsToGroup(r.Context(), id, req.AssetIDs); err != nil {
		h.handleServiceError(w, err)
		return
	}

	// Return updated group
	group, err := h.service.GetAssetGroup(r.Context(), id)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(toAssetGroupResponse(group))
}

// RemoveAssets handles POST /api/v1/asset-groups/{id}/assets/remove
// @Summary      Remove assets from group
// @Description  Remove one or more assets from an asset group
// @Tags         Asset Groups
// @Accept       json
// @Produce      json
// @Param        id    path      string               true  "Asset Group ID"
// @Param        body  body      RemoveAssetsRequest  true  "Asset IDs to remove"
// @Success      200   {object}  AssetGroupResponse
// @Failure      400   {object}  apierror.Error
// @Failure      404   {object}  apierror.Error
// @Failure      500   {object}  apierror.Error
// @Security     BearerAuth
// @Router       /asset-groups/{id}/assets/remove [post]
func (h *AssetGroupHandler) RemoveAssets(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, err := shared.IDFromString(idStr)
	if err != nil {
		apierror.BadRequest("Invalid group ID").WriteJSON(w)
		return
	}

	var req RemoveAssetsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}

	if err := h.validator.Validate(req); err != nil {
		h.handleValidationError(w, err)
		return
	}

	if err := h.service.RemoveAssetsFromGroup(r.Context(), id, req.AssetIDs); err != nil {
		h.handleServiceError(w, err)
		return
	}

	// Return updated group
	group, err := h.service.GetAssetGroup(r.Context(), id)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(toAssetGroupResponse(group))
}

// BulkUpdate handles PATCH /api/v1/asset-groups/bulk
// @Summary      Bulk update asset groups
// @Description  Update multiple asset groups at once
// @Tags         Asset Groups
// @Accept       json
// @Produce      json
// @Param        body  body      BulkUpdateRequest  true  "Bulk update data"
// @Success      200   {object}  map[string]interface{}
// @Failure      400   {object}  apierror.Error
// @Failure      500   {object}  apierror.Error
// @Security     BearerAuth
// @Router       /asset-groups/bulk [patch]
func (h *AssetGroupHandler) BulkUpdate(w http.ResponseWriter, r *http.Request) {
	var req BulkUpdateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}

	if err := h.validator.Validate(req); err != nil {
		h.handleValidationError(w, err)
		return
	}

	input := app.BulkUpdateInput{
		GroupIDs:    req.GroupIDs,
		Environment: req.Update.Environment,
		Criticality: req.Update.Criticality,
	}

	updated, err := h.service.BulkUpdateAssetGroups(r.Context(), input)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"updated": updated,
		"total":   len(req.GroupIDs),
	})
}

// BulkDelete handles POST /api/v1/asset-groups/bulk/delete
// @Summary      Bulk delete asset groups
// @Description  Delete multiple asset groups at once
// @Tags         Asset Groups
// @Accept       json
// @Produce      json
// @Param        body  body      BulkDeleteRequest  true  "Bulk delete data"
// @Success      200   {object}  map[string]interface{}
// @Failure      400   {object}  apierror.Error
// @Failure      500   {object}  apierror.Error
// @Security     BearerAuth
// @Router       /asset-groups/bulk/delete [post]
func (h *AssetGroupHandler) BulkDelete(w http.ResponseWriter, r *http.Request) {
	var req BulkDeleteRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}

	if err := h.validator.Validate(req); err != nil {
		h.handleValidationError(w, err)
		return
	}

	deleted, err := h.service.BulkDeleteAssetGroups(r.Context(), req.GroupIDs)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"deleted": deleted,
		"total":   len(req.GroupIDs),
	})
}
