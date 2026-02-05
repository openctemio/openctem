package handler

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/openctemio/api/internal/app"
	"github.com/openctemio/api/internal/infra/http/middleware"
	"github.com/openctemio/api/pkg/apierror"
	"github.com/openctemio/api/pkg/domain/branch"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/logger"
	"github.com/openctemio/api/pkg/validator"
)

// BranchHandler handles branch-related HTTP requests.
type BranchHandler struct {
	service   *app.BranchService
	validator *validator.Validator
	logger    *logger.Logger
}

// NewBranchHandler creates a new branch handler.
func NewBranchHandler(svc *app.BranchService, v *validator.Validator, log *logger.Logger) *BranchHandler {
	return &BranchHandler{
		service:   svc,
		validator: v,
		logger:    log,
	}
}

// BranchResponse represents a branch in API responses.
type BranchResponse struct {
	ID                     string     `json:"id"`
	RepositoryID           string     `json:"repository_id"`
	Name                   string     `json:"name"`
	Type                   string     `json:"type"`
	IsDefault              bool       `json:"is_default"`
	IsProtected            bool       `json:"is_protected"`
	LastCommitSHA          string     `json:"last_commit_sha,omitempty"`
	LastCommitMessage      string     `json:"last_commit_message,omitempty"`
	LastCommitAuthor       string     `json:"last_commit_author,omitempty"`
	LastCommitAuthorAvatar string     `json:"last_commit_author_avatar,omitempty"`
	LastCommitAt           *time.Time `json:"last_commit_at,omitempty"`
	ScanOnPush             bool       `json:"scan_on_push"`
	ScanOnPR               bool       `json:"scan_on_pr"`
	LastScanID             string     `json:"last_scan_id,omitempty"`
	LastScannedAt          *time.Time `json:"last_scanned_at,omitempty"`
	ScanStatus             string     `json:"scan_status"`
	QualityGateStatus      string     `json:"quality_gate_status"`
	FindingsTotal          int        `json:"findings_total"`
	FindingsCritical       int        `json:"findings_critical"`
	FindingsHigh           int        `json:"findings_high"`
	FindingsMedium         int        `json:"findings_medium"`
	FindingsLow            int        `json:"findings_low"`
	KeepWhenInactive       bool       `json:"keep_when_inactive"`
	RetentionDays          *int       `json:"retention_days,omitempty"`
	CreatedAt              time.Time  `json:"created_at"`
	UpdatedAt              time.Time  `json:"updated_at"`
}

// toBranchResponse converts a domain branch to API response.
func toBranchResponse(b *branch.Branch) BranchResponse {
	resp := BranchResponse{
		ID:                     b.ID().String(),
		RepositoryID:           b.RepositoryID().String(),
		Name:                   b.Name(),
		Type:                   b.Type().String(),
		IsDefault:              b.IsDefault(),
		IsProtected:            b.IsProtected(),
		LastCommitSHA:          b.LastCommitSHA(),
		LastCommitMessage:      b.LastCommitMessage(),
		LastCommitAuthor:       b.LastCommitAuthor(),
		LastCommitAuthorAvatar: b.LastCommitAuthorAvatar(),
		LastCommitAt:           b.LastCommitAt(),
		ScanOnPush:             b.ScanOnPush(),
		ScanOnPR:               b.ScanOnPR(),
		LastScannedAt:          b.LastScannedAt(),
		ScanStatus:             b.ScanStatus().String(),
		QualityGateStatus:      b.QualityGateStatus().String(),
		FindingsTotal:          b.FindingsTotal(),
		FindingsCritical:       b.FindingsCritical(),
		FindingsHigh:           b.FindingsHigh(),
		FindingsMedium:         b.FindingsMedium(),
		FindingsLow:            b.FindingsLow(),
		KeepWhenInactive:       b.KeepWhenInactive(),
		RetentionDays:          b.RetentionDays(),
		CreatedAt:              b.CreatedAt(),
		UpdatedAt:              b.UpdatedAt(),
	}
	if b.LastScanID() != nil {
		resp.LastScanID = b.LastScanID().String()
	}
	return resp
}

// CreateBranchRequest represents the request to create a branch.
type CreateBranchRequest struct {
	Name          string `json:"name" validate:"required,min=1,max=255"`
	BranchType    string `json:"type" validate:"required,branch_type"`
	IsDefault     bool   `json:"is_default"`
	IsProtected   bool   `json:"is_protected"`
	LastCommitSHA string `json:"last_commit_sha" validate:"max=40"`
}

// UpdateBranchRequest represents the request to update a branch.
type UpdateBranchRequest struct {
	IsProtected            *bool   `json:"is_protected"`
	LastCommitSHA          *string `json:"last_commit_sha" validate:"omitempty,max=40"`
	LastCommitMessage      *string `json:"last_commit_message" validate:"omitempty,max=1000"`
	LastCommitAuthor       *string `json:"last_commit_author" validate:"omitempty,max=100"`
	LastCommitAuthorAvatar *string `json:"last_commit_author_avatar" validate:"omitempty,max=500"`
	ScanOnPush             *bool   `json:"scan_on_push"`
	ScanOnPR               *bool   `json:"scan_on_pr"`
	KeepWhenInactive       *bool   `json:"keep_when_inactive"`
	RetentionDays          *int    `json:"retention_days" validate:"omitempty,min=0,max=365"`
}

// handleValidationError converts validation errors to API errors.
func (h *BranchHandler) handleValidationError(w http.ResponseWriter, err error) {
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

// handleServiceError converts service errors to API errors.
func (h *BranchHandler) handleServiceError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, shared.ErrNotFound):
		apierror.NotFound("Branch").WriteJSON(w)
	case errors.Is(err, shared.ErrAlreadyExists):
		apierror.Conflict("Branch already exists").WriteJSON(w)
	case errors.Is(err, shared.ErrValidation):
		apierror.BadRequest(err.Error()).WriteJSON(w)
	default:
		h.logger.Error("service error", "error", err)
		apierror.InternalError(err).WriteJSON(w)
	}
}

// List handles GET /api/v1/repositories/{repository_id}/branches
// @Summary      List branches
// @Description  Retrieves all branches for a repository
// @Tags         Branches
// @Produce      json
// @Security     BearerAuth
// @Param        repository_id path      string  true   "Repository ID"
// @Param        name          query     string  false  "Filter by name"
// @Param        types         query     string  false  "Filter by types (comma-separated)"
// @Param        is_default    query     bool    false  "Filter by default branch"
// @Param        scan_status   query     string  false  "Filter by scan status"
// @Param        sort          query     string  false  "Sort field"
// @Param        page          query     int     false  "Page number"  default(1)
// @Param        per_page      query     int     false  "Items per page"  default(20)
// @Success      200  {object}  map[string]interface{}
// @Failure      400  {object}  map[string]string
// @Failure      401  {object}  map[string]string
// @Failure      404  {object}  map[string]string
// @Router       /repositories/{repository_id}/branches [get]
func (h *BranchHandler) List(w http.ResponseWriter, r *http.Request) {
	repositoryID := r.PathValue("repositoryId")
	if repositoryID == "" {
		apierror.BadRequest("Repository ID is required").WriteJSON(w)
		return
	}

	query := r.URL.Query()
	input := app.ListBranchesInput{
		RepositoryID: repositoryID,
		Name:         query.Get("name"),
		BranchTypes:  parseQueryArray(query.Get("types")),
		IsDefault:    parseQueryBoolPtr(query.Get("is_default")),
		ScanStatus:   query.Get("scan_status"),
		Sort:         query.Get("sort"),
		Page:         parseQueryInt(query.Get("page"), 1),
		PerPage:      parseQueryInt(query.Get("per_page"), 20),
	}

	if err := h.validator.Validate(input); err != nil {
		h.handleValidationError(w, err)
		return
	}

	result, err := h.service.ListBranches(r.Context(), input)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	data := make([]BranchResponse, len(result.Data))
	for i, b := range result.Data {
		data[i] = toBranchResponse(b)
	}

	response := ListResponse[BranchResponse]{
		Data:       data,
		Total:      result.Total,
		Page:       result.Page,
		PerPage:    result.PerPage,
		TotalPages: result.TotalPages,
		Links:      NewPaginationLinks(r, result.Page, result.PerPage, result.TotalPages),
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(response)
}

// Create handles POST /api/v1/repositories/{repository_id}/branches
// @Summary      Create branch
// @Description  Creates a new branch for a repository
// @Tags         Branches
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        repository_id path      string               true  "Repository ID"
// @Param        request       body      CreateBranchRequest  true  "Branch data"
// @Success      201  {object}  BranchResponse
// @Failure      400  {object}  map[string]string
// @Failure      401  {object}  map[string]string
// @Failure      409  {object}  map[string]string
// @Router       /repositories/{repository_id}/branches [post]
func (h *BranchHandler) Create(w http.ResponseWriter, r *http.Request) {
	repositoryID := r.PathValue("repositoryId")
	if repositoryID == "" {
		apierror.BadRequest("Repository ID is required").WriteJSON(w)
		return
	}

	var req CreateBranchRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}

	if err := h.validator.Validate(req); err != nil {
		h.handleValidationError(w, err)
		return
	}

	input := app.CreateBranchInput{
		RepositoryID:  repositoryID,
		Name:          req.Name,
		BranchType:    req.BranchType,
		IsDefault:     req.IsDefault,
		IsProtected:   req.IsProtected,
		LastCommitSHA: req.LastCommitSHA,
	}

	b, err := h.service.CreateBranch(r.Context(), input)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(toBranchResponse(b))
}

// Get handles GET /api/v1/repositories/{repository_id}/branches/{id}
// @Summary      Get branch
// @Description  Retrieves a branch by ID
// @Tags         Branches
// @Produce      json
// @Security     BearerAuth
// @Param        repository_id path      string  true  "Repository ID"
// @Param        id            path      string  true  "Branch ID"
// @Success      200  {object}  BranchResponse
// @Failure      400  {object}  map[string]string
// @Failure      404  {object}  map[string]string
// @Router       /repositories/{repository_id}/branches/{id} [get]
func (h *BranchHandler) Get(w http.ResponseWriter, r *http.Request) {
	repositoryID := r.PathValue("repositoryId")
	branchID := r.PathValue("branchId")
	if repositoryID == "" || branchID == "" {
		apierror.BadRequest("Repository ID and Branch ID are required").WriteJSON(w)
		return
	}

	b, err := h.service.GetBranch(r.Context(), branchID)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	// IDOR prevention
	if b.RepositoryID().String() != repositoryID {
		apierror.NotFound("Branch").WriteJSON(w)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(toBranchResponse(b))
}

// Update handles PUT /api/v1/repositories/{repository_id}/branches/{id}
// @Summary      Update branch
// @Description  Updates a branch
// @Tags         Branches
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        repository_id path      string               true  "Repository ID"
// @Param        id            path      string               true  "Branch ID"
// @Param        request       body      UpdateBranchRequest  true  "Branch data"
// @Success      200  {object}  BranchResponse
// @Failure      400  {object}  map[string]string
// @Failure      404  {object}  map[string]string
// @Router       /repositories/{repository_id}/branches/{id} [put]
func (h *BranchHandler) Update(w http.ResponseWriter, r *http.Request) {
	repositoryID := r.PathValue("repositoryId")
	branchID := r.PathValue("branchId")
	if repositoryID == "" || branchID == "" {
		apierror.BadRequest("Repository ID and Branch ID are required").WriteJSON(w)
		return
	}

	var req UpdateBranchRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}

	if err := h.validator.Validate(req); err != nil {
		h.handleValidationError(w, err)
		return
	}

	input := app.UpdateBranchInput{
		IsProtected:            req.IsProtected,
		LastCommitSHA:          req.LastCommitSHA,
		LastCommitMessage:      req.LastCommitMessage,
		LastCommitAuthor:       req.LastCommitAuthor,
		LastCommitAuthorAvatar: req.LastCommitAuthorAvatar,
		ScanOnPush:             req.ScanOnPush,
		ScanOnPR:               req.ScanOnPR,
		KeepWhenInactive:       req.KeepWhenInactive,
		RetentionDays:          req.RetentionDays,
	}

	b, err := h.service.UpdateBranch(r.Context(), branchID, repositoryID, input)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(toBranchResponse(b))
}

// Delete handles DELETE /api/v1/repositories/{repository_id}/branches/{id}
// @Summary      Delete branch
// @Description  Deletes a branch
// @Tags         Branches
// @Security     BearerAuth
// @Param        repository_id path      string  true  "Repository ID"
// @Param        id            path      string  true  "Branch ID"
// @Success      204  "No Content"
// @Failure      400  {object}  map[string]string
// @Failure      404  {object}  map[string]string
// @Router       /repositories/{repository_id}/branches/{id} [delete]
func (h *BranchHandler) Delete(w http.ResponseWriter, r *http.Request) {
	repositoryID := r.PathValue("repositoryId")
	branchID := r.PathValue("branchId")
	if repositoryID == "" || branchID == "" {
		apierror.BadRequest("Repository ID and Branch ID are required").WriteJSON(w)
		return
	}

	if err := h.service.DeleteBranch(r.Context(), branchID, repositoryID); err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// SetDefault handles PUT /api/v1/repositories/{repository_id}/branches/{id}/default
// @Summary      Set default branch
// @Description  Sets a branch as the default for a repository
// @Tags         Branches
// @Produce      json
// @Security     BearerAuth
// @Param        repository_id path      string  true  "Repository ID"
// @Param        id            path      string  true  "Branch ID"
// @Success      200  {object}  BranchResponse
// @Failure      400  {object}  map[string]string
// @Failure      404  {object}  map[string]string
// @Router       /repositories/{repository_id}/branches/{id}/default [put]
func (h *BranchHandler) SetDefault(w http.ResponseWriter, r *http.Request) {
	repositoryID := r.PathValue("repositoryId")
	branchID := r.PathValue("branchId")
	if repositoryID == "" || branchID == "" {
		apierror.BadRequest("Repository ID and Branch ID are required").WriteJSON(w)
		return
	}

	b, err := h.service.SetDefaultBranch(r.Context(), branchID, repositoryID)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(toBranchResponse(b))
}

// GetDefault handles GET /api/v1/repositories/{repository_id}/branches/default
// @Summary      Get default branch
// @Description  Gets the default branch for a repository
// @Tags         Branches
// @Produce      json
// @Security     BearerAuth
// @Param        repository_id path      string  true  "Repository ID"
// @Success      200  {object}  BranchResponse
// @Failure      400  {object}  map[string]string
// @Failure      404  {object}  map[string]string
// @Router       /repositories/{repository_id}/branches/default [get]
func (h *BranchHandler) GetDefault(w http.ResponseWriter, r *http.Request) {
	repositoryID := r.PathValue("repositoryId")
	if repositoryID == "" {
		apierror.BadRequest("Repository ID is required").WriteJSON(w)
		return
	}

	b, err := h.service.GetDefaultBranch(r.Context(), repositoryID)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(toBranchResponse(b))
}

// Ensure middleware import is used
var _ = middleware.MustGetTenantID
