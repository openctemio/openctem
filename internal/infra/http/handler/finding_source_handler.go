package handler

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/openctemio/api/internal/app"
	"github.com/openctemio/api/pkg/apierror"
	"github.com/openctemio/api/pkg/domain/findingsource"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/logger"
	"github.com/openctemio/api/pkg/pagination"
	"github.com/openctemio/api/pkg/validator"
)

// FindingSourceHandler handles finding source-related HTTP requests.
// Finding sources are read-only system configuration.
type FindingSourceHandler struct {
	service      *app.FindingSourceService
	cacheService *app.FindingSourceCacheService
	validator    *validator.Validator
	logger       *logger.Logger
}

// NewFindingSourceHandler creates a new finding source handler.
func NewFindingSourceHandler(svc *app.FindingSourceService, cacheSvc *app.FindingSourceCacheService, v *validator.Validator, log *logger.Logger) *FindingSourceHandler {
	return &FindingSourceHandler{
		service:      svc,
		cacheService: cacheSvc,
		validator:    v,
		logger:       log,
	}
}

// FindingSourceCategoryResponse represents a category in API responses.
type FindingSourceCategoryResponse struct {
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

// FindingSourceResponse represents a finding source in API responses.
type FindingSourceResponse struct {
	ID           string                         `json:"id"`
	CategoryID   string                         `json:"category_id,omitempty"`
	Category     *FindingSourceCategoryResponse `json:"category,omitempty"`
	Code         string                         `json:"code"`
	Name         string                         `json:"name"`
	Description  string                         `json:"description,omitempty"`
	Icon         string                         `json:"icon,omitempty"`
	Color        string                         `json:"color,omitempty"`
	DisplayOrder int                            `json:"display_order"`
	IsSystem     bool                           `json:"is_system"`
	IsActive     bool                           `json:"is_active"`
	CreatedAt    time.Time                      `json:"created_at"`
	UpdatedAt    time.Time                      `json:"updated_at"`
}

// toFindingSourceCategoryResponse converts a domain category to API response.
func toFindingSourceCategoryResponse(c *findingsource.Category) FindingSourceCategoryResponse {
	return FindingSourceCategoryResponse{
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

// toFindingSourceResponse converts a domain finding source to API response.
func toFindingSourceResponse(fs *findingsource.FindingSource) FindingSourceResponse {
	resp := FindingSourceResponse{
		ID:           fs.ID().String(),
		Code:         fs.Code(),
		Name:         fs.Name(),
		Description:  fs.Description(),
		Icon:         fs.Icon(),
		Color:        fs.Color(),
		DisplayOrder: fs.DisplayOrder(),
		IsSystem:     fs.IsSystem(),
		IsActive:     fs.IsActive(),
		CreatedAt:    fs.CreatedAt(),
		UpdatedAt:    fs.UpdatedAt(),
	}

	if fs.CategoryID() != nil {
		resp.CategoryID = fs.CategoryID().String()
	}

	return resp
}

// toFindingSourceWithCategoryResponse converts a domain finding source with category to API response.
func toFindingSourceWithCategoryResponse(fsc *findingsource.FindingSourceWithCategory) FindingSourceResponse {
	resp := toFindingSourceResponse(fsc.FindingSource)
	if fsc.Category != nil {
		cat := toFindingSourceCategoryResponse(fsc.Category)
		resp.Category = &cat
	}
	return resp
}

// cachedToFindingSourceResponse converts a cached finding source to API response.
func cachedToFindingSourceResponse(cached *app.CachedFindingSource, includeCategory bool) FindingSourceResponse {
	resp := FindingSourceResponse{
		ID:           cached.ID,
		Code:         cached.Code,
		Name:         cached.Name,
		Description:  cached.Description,
		Icon:         cached.Icon,
		Color:        cached.Color,
		DisplayOrder: cached.DisplayOrder,
		IsSystem:     cached.IsSystem,
		IsActive:     true, // Cached sources are always active
	}

	if cached.CategoryID != "" {
		resp.CategoryID = cached.CategoryID
	}

	if includeCategory && cached.CategoryCode != "" {
		resp.Category = &FindingSourceCategoryResponse{
			Code: cached.CategoryCode,
			Name: cached.CategoryName,
		}
	}

	return resp
}

// handleServiceError converts service errors to API errors.
func (h *FindingSourceHandler) handleServiceError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, findingsource.ErrFindingSourceNotFound):
		apierror.NotFound("Finding Source").WriteJSON(w)
	case errors.Is(err, findingsource.ErrCategoryNotFound):
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

// ListCategories handles GET /api/v1/config/finding-sources/categories
// @Summary      List finding source categories
// @Description  Retrieves a paginated list of finding source categories. Use active_only=true to get all active categories without pagination.
// @Tags         Configuration
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        active_only query bool false "Return only active categories (bypasses pagination)"
// @Param        search query string false "Search by name or code"
// @Param        page query int false "Page number" default(1)
// @Param        per_page query int false "Items per page" default(20)
// @Success      200  {object}  object{data=[]FindingSourceCategoryResponse,total=int,page=int,per_page=int,total_pages=int}
// @Failure      400  {object}  apierror.Error
// @Failure      401  {object}  apierror.Error
// @Failure      500  {object}  apierror.Error
// @Router       /config/finding-sources/categories [get]
func (h *FindingSourceHandler) ListCategories(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	activeOnly := query.Get("active_only") == queryParamTrue

	if activeOnly {
		categories, err := h.service.ListActiveCategories(r.Context())
		if err != nil {
			h.handleServiceError(w, err)
			return
		}

		data := make([]FindingSourceCategoryResponse, len(categories))
		for i, c := range categories {
			data[i] = toFindingSourceCategoryResponse(c)
		}

		response := struct {
			Data  []FindingSourceCategoryResponse `json:"data"`
			Total int                             `json:"total"`
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
	filter := findingsource.NewCategoryFilter()
	if search := query.Get("search"); search != "" {
		filter = filter.WithSearch(search)
	}

	categories, err := h.service.ListCategories(r.Context(), filter, page)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	data := make([]FindingSourceCategoryResponse, len(categories.Data))
	for i, c := range categories.Data {
		data[i] = toFindingSourceCategoryResponse(c)
	}

	response := struct {
		Data       []FindingSourceCategoryResponse `json:"data"`
		Total      int64                           `json:"total"`
		Page       int                             `json:"page"`
		PerPage    int                             `json:"per_page"`
		TotalPages int                             `json:"total_pages"`
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

// GetCategory handles GET /api/v1/config/finding-sources/categories/{categoryId}
// @Summary      Get a category by ID
// @Description  Retrieves a single finding source category by its unique identifier
// @Tags         Configuration
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        categoryId path string true "Category ID (UUID)"
// @Success      200  {object}  FindingSourceCategoryResponse
// @Failure      400  {object}  apierror.Error
// @Failure      401  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Failure      500  {object}  apierror.Error
// @Router       /config/finding-sources/categories/{categoryId} [get]
func (h *FindingSourceHandler) GetCategory(w http.ResponseWriter, r *http.Request) {
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
	_ = json.NewEncoder(w).Encode(toFindingSourceCategoryResponse(c))
}

// ===== Finding Source Handlers =====

// ListFindingSources handles GET /api/v1/config/finding-sources
// @Summary      List finding sources
// @Description  Retrieves a paginated list of system finding sources. Finding sources are read-only configuration. Use active_only=true to get all active sources without pagination.
// @Tags         Configuration
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        active_only query bool false "Return only active finding sources (bypasses pagination)"
// @Param        include_category query bool false "Include category details in response"
// @Param        search query string false "Search by name or code"
// @Param        category_id query string false "Filter by category ID"
// @Param        category_code query string false "Filter by category code"
// @Param        code query string false "Filter by exact code"
// @Param        is_system query bool false "Filter by system type"
// @Param        sort query string false "Sort field (e.g., 'name', '-display_order')"
// @Param        page query int false "Page number" default(1)
// @Param        per_page query int false "Items per page" default(50)
// @Success      200  {object}  object{data=[]FindingSourceResponse,total=int,page=int,per_page=int,total_pages=int}
// @Failure      400  {object}  apierror.Error
// @Failure      401  {object}  apierror.Error
// @Failure      500  {object}  apierror.Error
// @Router       /config/finding-sources [get]
func (h *FindingSourceHandler) ListFindingSources(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()

	// Check if active only
	activeOnly := query.Get("active_only") == queryParamTrue
	includeCategory := query.Get("include_category") == queryParamTrue

	if activeOnly {
		// Use cached service for active sources (most common case - used by UI dropdowns)
		if h.cacheService != nil {
			cached, err := h.cacheService.GetAll(r.Context())
			if err != nil {
				h.handleServiceError(w, err)
				return
			}

			data := make([]FindingSourceResponse, len(cached.Sources))
			for i, s := range cached.Sources {
				data[i] = cachedToFindingSourceResponse(s, includeCategory)
			}

			// Set cache headers for CDN/browser caching
			w.Header().Set("Cache-Control", "public, max-age=3600") // 1 hour browser cache
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(struct {
				Data  []FindingSourceResponse `json:"data"`
				Total int                     `json:"total"`
			}{
				Data:  data,
				Total: len(data),
			})
			return
		}

		// Fallback to direct service call if cache service not initialized
		if includeCategory {
			sources, err := h.service.ListActiveFindingSourcesWithCategory(r.Context())
			if err != nil {
				h.handleServiceError(w, err)
				return
			}

			data := make([]FindingSourceResponse, len(sources))
			for i, s := range sources {
				data[i] = toFindingSourceWithCategoryResponse(s)
			}

			response := struct {
				Data  []FindingSourceResponse `json:"data"`
				Total int                     `json:"total"`
			}{
				Data:  data,
				Total: len(data),
			}

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(response)
			return
		}

		sources, err := h.service.ListActiveFindingSources(r.Context())
		if err != nil {
			h.handleServiceError(w, err)
			return
		}

		data := make([]FindingSourceResponse, len(sources))
		for i, s := range sources {
			data[i] = toFindingSourceResponse(s)
		}

		response := struct {
			Data  []FindingSourceResponse `json:"data"`
			Total int                     `json:"total"`
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

	// Build filter
	filter := findingsource.NewFilter()

	if search := query.Get("search"); search != "" {
		filter = filter.WithSearch(search)
	}
	if categoryID := query.Get("category_id"); categoryID != "" {
		filter = filter.WithCategoryID(categoryID)
	}
	if categoryCode := query.Get("category_code"); categoryCode != "" {
		filter = filter.WithCategoryCode(categoryCode)
	}
	if code := query.Get("code"); code != "" {
		filter = filter.WithCode(code)
	}
	if query.Get("is_system") != "" {
		isSystem := query.Get("is_system") == queryParamTrue
		filter = filter.WithIsSystem(isSystem)
	}

	opts := findingsource.NewListOptions()
	if sortStr := query.Get("sort"); sortStr != "" {
		allowedFields := findingsource.AllowedSortFields()
		opts = opts.WithSort(pagination.NewSortOption(allowedFields).Parse(sortStr))
	}

	if includeCategory {
		result, err := h.service.ListFindingSourcesWithCategory(r.Context(), filter, opts, page)
		if err != nil {
			h.handleServiceError(w, err)
			return
		}

		data := make([]FindingSourceResponse, len(result.Data))
		for i, s := range result.Data {
			data[i] = toFindingSourceWithCategoryResponse(s)
		}

		response := struct {
			Data       []FindingSourceResponse `json:"data"`
			Total      int64                   `json:"total"`
			Page       int                     `json:"page"`
			PerPage    int                     `json:"per_page"`
			TotalPages int                     `json:"total_pages"`
		}{
			Data:       data,
			Total:      result.Total,
			Page:       result.Page,
			PerPage:    result.PerPage,
			TotalPages: result.TotalPages,
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(response)
		return
	}

	result, err := h.service.ListFindingSources(r.Context(), filter, opts, page)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	data := make([]FindingSourceResponse, len(result.Data))
	for i, s := range result.Data {
		data[i] = toFindingSourceResponse(s)
	}

	response := struct {
		Data       []FindingSourceResponse `json:"data"`
		Total      int64                   `json:"total"`
		Page       int                     `json:"page"`
		PerPage    int                     `json:"per_page"`
		TotalPages int                     `json:"total_pages"`
	}{
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

// GetFindingSource handles GET /api/v1/config/finding-sources/{id}
// @Summary      Get a finding source by ID
// @Description  Retrieves a single system finding source by its unique identifier
// @Tags         Configuration
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        id path string true "Finding Source ID (UUID)"
// @Success      200  {object}  FindingSourceResponse
// @Failure      400  {object}  apierror.Error
// @Failure      401  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Failure      500  {object}  apierror.Error
// @Router       /config/finding-sources/{id} [get]
func (h *FindingSourceHandler) GetFindingSource(w http.ResponseWriter, r *http.Request) {
	findingSourceID := r.PathValue("id")
	if findingSourceID == "" {
		apierror.BadRequest("Finding Source ID is required").WriteJSON(w)
		return
	}

	fs, err := h.service.GetFindingSource(r.Context(), findingSourceID)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(toFindingSourceResponse(fs))
}

// GetFindingSourceByCode handles GET /api/v1/config/finding-sources/code/{code}
// @Summary      Get a finding source by code
// @Description  Retrieves a single system finding source by its code (e.g., 'sast', 'dast', 'pentest')
// @Tags         Configuration
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        code path string true "Finding Source Code"
// @Success      200  {object}  FindingSourceResponse
// @Failure      400  {object}  apierror.Error
// @Failure      401  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Failure      500  {object}  apierror.Error
// @Router       /config/finding-sources/code/{code} [get]
func (h *FindingSourceHandler) GetFindingSourceByCode(w http.ResponseWriter, r *http.Request) {
	code := r.PathValue("code")
	if code == "" {
		apierror.BadRequest("Finding Source code is required").WriteJSON(w)
		return
	}

	fs, err := h.service.GetFindingSourceByCode(r.Context(), code)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(toFindingSourceResponse(fs))
}
