package handler

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"time"

	assetsvc "github.com/openctemio/openctem/api/internal/app/asset"
	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/assettype"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/pagination"
	"github.com/openctemio/openctem/api/pkg/validator"
)

// AssetTypeHandler handles asset type-related HTTP requests.
// Asset types are read-only system configuration.
type AssetTypeHandler struct {
	service   *assetsvc.AssetTypeService
	validator *validator.Validator
	logger    *logger.Logger
}

// NewAssetTypeHandler creates a new asset type handler.
func NewAssetTypeHandler(svc *assetsvc.AssetTypeService, v *validator.Validator, log *logger.Logger) *AssetTypeHandler {
	return &AssetTypeHandler{
		service:   svc,
		validator: v,
		logger:    log,
	}
}

// CategoryResponse represents a category in API responses.
type CategoryResponse struct {
	ID           string    `json:"id"`
	Code         string    `json:"code"`
	Name         string    `json:"name"`
	Description  string    `json:"description,omitempty"`
	Icon         string    `json:"icon,omitempty"`
	DisplayOrder int       `json:"display_order"`
	IsActive     bool      `json:"is_active"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

// AssetTypeResponse represents an asset type in API responses.
type AssetTypeResponse struct {
	ID                 string            `json:"id"`
	CategoryID         string            `json:"category_id,omitempty"`
	Category           *CategoryResponse `json:"category,omitempty"`
	Code               string            `json:"code"`
	Name               string            `json:"name"`
	Description        string            `json:"description,omitempty"`
	Icon               string            `json:"icon,omitempty"`
	Color              string            `json:"color,omitempty"`
	DisplayOrder       int               `json:"display_order"`
	PatternRegex       string            `json:"pattern_regex,omitempty"`
	PatternPlaceholder string            `json:"pattern_placeholder,omitempty"`
	PatternExample     string            `json:"pattern_example,omitempty"`
	SupportsWildcard   bool              `json:"supports_wildcard"`
	SupportsCIDR       bool              `json:"supports_cidr"`
	IsDiscoverable     bool              `json:"is_discoverable"`
	IsScannable        bool              `json:"is_scannable"`
	IsSystem           bool              `json:"is_system"`
	IsActive           bool              `json:"is_active"`
	CreatedAt          time.Time         `json:"created_at"`
	UpdatedAt          time.Time         `json:"updated_at"`
}

// toCategoryResponse converts a domain category to API response.
func toCategoryResponse(c *assettype.Category) CategoryResponse {
	return CategoryResponse{
		ID:           c.ID().String(),
		Code:         c.Code(),
		Name:         c.Name(),
		Description:  c.Description(),
		Icon:         c.Icon(),
		DisplayOrder: c.DisplayOrder(),
		IsActive:     c.IsActive(),
		CreatedAt:    c.CreatedAt(),
		UpdatedAt:    c.UpdatedAt(),
	}
}

// toAssetTypeResponse converts a domain asset type to API response.
func toAssetTypeResponse(at *assettype.AssetType) AssetTypeResponse {
	resp := AssetTypeResponse{
		ID:                 at.ID().String(),
		Code:               at.Code(),
		Name:               at.Name(),
		Description:        at.Description(),
		Icon:               at.Icon(),
		Color:              at.Color(),
		DisplayOrder:       at.DisplayOrder(),
		PatternRegex:       at.PatternRegex(),
		PatternPlaceholder: at.PatternPlaceholder(),
		PatternExample:     at.PatternExample(),
		SupportsWildcard:   at.SupportsWildcard(),
		SupportsCIDR:       at.SupportsCIDR(),
		IsDiscoverable:     at.IsDiscoverable(),
		IsScannable:        at.IsScannable(),
		IsSystem:           at.IsSystem(),
		IsActive:           at.IsActive(),
		CreatedAt:          at.CreatedAt(),
		UpdatedAt:          at.UpdatedAt(),
	}

	if at.CategoryID() != nil {
		resp.CategoryID = at.CategoryID().String()
	}

	return resp
}

// toAssetTypeWithCategoryResponse converts a domain asset type with category to API response.
func toAssetTypeWithCategoryResponse(atc *assettype.AssetTypeWithCategory) AssetTypeResponse {
	resp := toAssetTypeResponse(atc.AssetType)
	if atc.Category != nil {
		cat := toCategoryResponse(atc.Category)
		resp.Category = &cat
	}
	return resp
}

// handleServiceError converts service errors to API errors.
func (h *AssetTypeHandler) handleServiceError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, assettype.ErrAssetTypeNotFound):
		apierror.NotFound("Asset Type").WriteJSON(w)
	case errors.Is(err, assettype.ErrCategoryNotFound):
		apierror.NotFound("Category").WriteJSON(w)
	case errors.Is(err, shared.ErrNotFound):
		apierror.NotFound("Resource").WriteJSON(w)
	case errors.Is(err, shared.ErrValidation):
		apierror.BadRequest(err.Error()).WriteJSON(w)
	default:
		h.logger.Error("service error", "error", err)
		apierror.InternalError(err).WriteJSON(w)
	}
}

// ===== Category Handlers =====

// ListCategories handles GET /api/v1/asset-types/categories
// @Summary      List asset type categories
// @Description  Retrieves a paginated list of asset type categories. Use active_only=true to get all active categories without pagination.
// @Tags         Asset Types
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        active_only query bool false "Return only active categories (bypasses pagination)"
// @Param        search query string false "Search by name or code"
// @Param        page query int false "Page number" default(1)
// @Param        per_page query int false "Items per page" default(20)
// @Success      200  {object}  object{data=[]CategoryResponse,total=int,page=int,per_page=int,total_pages=int}
// @Failure      400  {object}  apierror.Error
// @Failure      401  {object}  apierror.Error
// @Failure      500  {object}  apierror.Error
// @Deprecated
// @Router       /asset-types/categories [get]
func (h *AssetTypeHandler) ListCategories(w http.ResponseWriter, r *http.Request) { //nolint:dupl // Similar to FindingSourceHandler.ListCategories but different types
	query := r.URL.Query()
	activeOnly := query.Get("active_only") == queryParamTrue

	if activeOnly {
		categories, err := h.service.ListActiveCategories(r.Context())
		if err != nil {
			h.handleServiceError(w, err)
			return
		}

		data := make([]CategoryResponse, len(categories))
		for i, c := range categories {
			data[i] = toCategoryResponse(c)
		}

		response := struct {
			Data  []CategoryResponse `json:"data"`
			Total int                `json:"total"`
		}{
			Data:  data,
			Total: len(data),
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(response)
		return
	}

	// Parse pagination
	pageNum := 1
	perPage := 20
	if p := query.Get("page"); p != "" {
		if parsed, err := strconv.Atoi(p); err == nil && parsed > 0 {
			pageNum = parsed
		}
	}
	if pp := query.Get("per_page"); pp != "" {
		if parsed, err := strconv.Atoi(pp); err == nil && parsed > 0 {
			perPage = parsed
		}
	}
	page := pagination.New(pageNum, perPage)

	// Build filter
	filter := assettype.NewCategoryFilter()
	if search := query.Get("search"); search != "" {
		filter = filter.WithSearch(search)
	}

	categories, err := h.service.ListCategories(r.Context(), filter, page)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	data := make([]CategoryResponse, len(categories.Data))
	for i, c := range categories.Data {
		data[i] = toCategoryResponse(c)
	}

	response := struct {
		Data       []CategoryResponse `json:"data"`
		Total      int64              `json:"total"`
		Page       int                `json:"page"`
		PerPage    int                `json:"per_page"`
		TotalPages int                `json:"total_pages"`
	}{
		Data:       data,
		Total:      categories.Total,
		Page:       categories.Page,
		PerPage:    categories.PerPage,
		TotalPages: categories.TotalPages,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(response)
}

// GetCategory handles GET /api/v1/asset-types/categories/{categoryId}
// @Summary      Get a category by ID
// @Description  Retrieves a single asset type category by its unique identifier
// @Tags         Asset Types
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        categoryId path string true "Category ID (UUID)"
// @Success      200  {object}  CategoryResponse
// @Failure      400  {object}  apierror.Error
// @Failure      401  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Failure      500  {object}  apierror.Error
// @Deprecated
// @Router       /asset-types/categories/{categoryId} [get]
func (h *AssetTypeHandler) GetCategory(w http.ResponseWriter, r *http.Request) {
	categoryID := r.PathValue("categoryId")
	if categoryID == "" {
		apierror.BadRequest("Category ID is required").WriteJSON(w)
		return
	}

	c, err := h.service.GetCategory(r.Context(), categoryID)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(toCategoryResponse(c))
}

// ===== Asset Type Handlers =====

// AssetTypeRegistryResponse is the body of GET /api/v1/asset-types: the
// RFC-042 asset type registry (version, lenses, classes, types, sections,
// cards, core_fields), generated from api/configs/asset-types.yaml.
//
// data, total, page, per_page and total_pages are the legacy asset_types
// rows that this route returned before the registry. They are kept,
// unchanged, for one release (RFC-041 §7: changes within v1 are additive)
// and are deprecated: read types instead.
type AssetTypeRegistryResponse struct {
	Version    string                    `json:"version"`
	Lenses     []asset.LensDefinition    `json:"lenses"`
	Classes    []asset.ClassDefinition   `json:"classes"`
	Types      []asset.TypeDefinition    `json:"types"`
	Sections   []asset.SectionDefinition `json:"sections"`
	Cards      []string                  `json:"cards"`
	CoreFields []string                  `json:"core_fields"`

	// Deprecated: the legacy asset_types rows; use Types.
	Data       []AssetTypeResponse `json:"data"`
	Total      int64               `json:"total"`
	Page       int                 `json:"page,omitempty"`
	PerPage    int                 `json:"per_page,omitempty"`
	TotalPages int                 `json:"total_pages,omitempty"`
}

// ListAssetTypes handles GET /api/v1/asset-types
// @Summary      Asset type registry
// @Description  Returns the asset type registry (RFC-042): every asset type with its class, lens, attribute schema, facets, group-by fields, row columns, card renderer, detail sections, allowed relationships and identity keys, plus the classes, lenses and the closed sets of sections and cards. The registry is generated from api/configs/asset-types.yaml and holds no tenant data. The response carries a strong ETag; If-None-Match with it answers 304. The data/total/page/per_page/total_pages fields are the legacy asset_types rows (deprecated, kept for one release); the query parameters below filter only those.
// @Tags         Asset Types
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        If-None-Match header string false "ETag from a previous response"
// @Param        active_only query bool false "Legacy rows: only active asset types, without pagination"
// @Param        include_category query bool false "Legacy rows: include category details"
// @Param        search query string false "Legacy rows: search by name or code"
// @Param        category_id query string false "Legacy rows: filter by category ID"
// @Param        code query string false "Legacy rows: filter by exact code"
// @Param        is_system query bool false "Legacy rows: filter by system type"
// @Param        is_scannable query bool false "Legacy rows: filter by scannable flag"
// @Param        is_discoverable query bool false "Legacy rows: filter by discoverable flag"
// @Param        sort query string false "Legacy rows: sort field (e.g., 'name', '-display_order')"
// @Param        page query int false "Legacy rows: page number" default(1)
// @Param        per_page query int false "Legacy rows: items per page" default(50)
// @Success      200  {object}  AssetTypeRegistryResponse
// @Success      304  "Not modified (If-None-Match matched the ETag)"
// @Failure      400  {object}  apierror.Error
// @Failure      401  {object}  apierror.Error
// @Failure      500  {object}  apierror.Error
// @Router       /asset-types [get]
func (h *AssetTypeHandler) ListAssetTypes(w http.ResponseWriter, r *http.Request) {
	reg := asset.RegistryDocument()
	resp := AssetTypeRegistryResponse{
		Version:    reg.Version,
		Lenses:     reg.Lenses,
		Classes:    reg.Classes,
		Types:      reg.Types,
		Sections:   reg.Sections,
		Cards:      reg.Cards,
		CoreFields: reg.CoreFields,
	}
	if err := h.legacyAssetTypeRows(r, &resp); err != nil {
		h.handleServiceError(w, err)
		return
	}

	body, err := json.Marshal(resp)
	if err != nil {
		h.logger.Error("encode asset type registry", "error", err)
		apierror.InternalError(err).WriteJSON(w)
		return
	}
	sum := sha256.Sum256(body)
	etag := `"` + hex.EncodeToString(sum[:16]) + `"`
	w.Header().Set("ETag", etag)
	w.Header().Set("Cache-Control", "private, no-cache")
	if etagMatches(r.Header.Get("If-None-Match"), etag) {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(append(body, '\n'))
}

// legacyAssetTypeRows fills the deprecated data/total/page fields from the
// asset_types table, exactly as this route did before the registry.
func (h *AssetTypeHandler) legacyAssetTypeRows(r *http.Request, resp *AssetTypeRegistryResponse) error {
	query := r.URL.Query()

	if query.Get("active_only") == queryParamTrue {
		types, err := h.service.ListActiveAssetTypes(r.Context())
		if err != nil {
			return err
		}
		resp.Data = make([]AssetTypeResponse, len(types))
		for i, t := range types {
			resp.Data[i] = toAssetTypeResponse(t)
		}
		resp.Total = int64(len(resp.Data))
		return nil
	}

	pageNum := 1
	perPage := 50
	if p := query.Get("page"); p != "" {
		if parsed, err := strconv.Atoi(p); err == nil && parsed > 0 {
			pageNum = parsed
		}
	}
	if pp := query.Get("per_page"); pp != "" {
		if parsed, err := strconv.Atoi(pp); err == nil && parsed > 0 {
			perPage = parsed
		}
	}
	page := pagination.New(pageNum, perPage)

	filter := assettype.NewFilter()
	if search := query.Get("search"); search != "" {
		filter = filter.WithSearch(search)
	}
	if categoryID := query.Get("category_id"); categoryID != "" {
		filter = filter.WithCategoryID(categoryID)
	}
	if code := query.Get("code"); code != "" {
		filter = filter.WithCode(code)
	}
	if query.Get("is_system") != "" {
		filter = filter.WithIsSystem(query.Get("is_system") == queryParamTrue)
	}
	if query.Get("is_scannable") != "" {
		filter = filter.WithIsScannable(query.Get("is_scannable") == queryParamTrue)
	}
	if query.Get("is_discoverable") != "" {
		filter = filter.WithIsDiscoverable(query.Get("is_discoverable") == queryParamTrue)
	}

	opts := assettype.NewListOptions()
	if sortStr := query.Get("sort"); sortStr != "" {
		opts = opts.WithSort(pagination.NewSortOption(assettype.AllowedSortFields()).Parse(sortStr))
	}

	if query.Get("include_category") == queryParamTrue {
		result, err := h.service.ListAssetTypesWithCategory(r.Context(), filter, opts, page)
		if err != nil {
			return err
		}
		resp.Data = make([]AssetTypeResponse, len(result.Data))
		for i, t := range result.Data {
			resp.Data[i] = toAssetTypeWithCategoryResponse(t)
		}
		resp.Total, resp.Page, resp.PerPage, resp.TotalPages = result.Total, result.Page, result.PerPage, result.TotalPages
		return nil
	}

	result, err := h.service.ListAssetTypes(r.Context(), filter, opts, page)
	if err != nil {
		return err
	}
	resp.Data = make([]AssetTypeResponse, len(result.Data))
	for i, t := range result.Data {
		resp.Data[i] = toAssetTypeResponse(t)
	}
	resp.Total, resp.Page, resp.PerPage, resp.TotalPages = result.Total, result.Page, result.PerPage, result.TotalPages
	return nil
}

// GetAssetType handles GET /api/v1/asset-types/{id}
// @Summary      Get an asset type by ID
// @Description  Retrieves a single system asset type by its unique identifier
// @Tags         Asset Types
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        id path string true "Asset Type ID (UUID)"
// @Success      200  {object}  AssetTypeResponse
// @Failure      400  {object}  apierror.Error
// @Failure      401  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Failure      500  {object}  apierror.Error
// @Router       /asset-types/{id} [get]
func (h *AssetTypeHandler) GetAssetType(w http.ResponseWriter, r *http.Request) {
	assetTypeID := r.PathValue("id")
	if assetTypeID == "" {
		apierror.BadRequest("Asset Type ID is required").WriteJSON(w)
		return
	}

	at, err := h.service.GetAssetType(r.Context(), assetTypeID)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(toAssetTypeResponse(at))
}
