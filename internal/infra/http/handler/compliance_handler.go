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
	"github.com/openctemio/api/pkg/domain/compliance"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/logger"
	"github.com/openctemio/api/pkg/pagination"
)

// ComplianceHandler handles compliance HTTP requests.
type ComplianceHandler struct {
	service *app.ComplianceService
	logger  *logger.Logger
}

// NewComplianceHandler creates a new compliance handler.
func NewComplianceHandler(svc *app.ComplianceService, log *logger.Logger) *ComplianceHandler {
	return &ComplianceHandler{service: svc, logger: log}
}

// =============================================
// FRAMEWORK ENDPOINTS
// =============================================

// ListFrameworks lists compliance frameworks with optional search filter.
func (h *ComplianceHandler) ListFrameworks(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())

	perPage := parseQueryInt(r.URL.Query().Get("per_page"), 20)
	if perPage > 100 {
		perPage = 100
	}
	page := pagination.New(
		parseQueryInt(r.URL.Query().Get("page"), 1),
		perPage,
	)

	result, err := h.service.ListFrameworks(r.Context(), tenantID, page)
	if err != nil {
		h.handleError(w, err)
		return
	}

	items := make([]ComplianceFrameworkResponse, len(result.Data))
	for i, f := range result.Data {
		items[i] = toComplianceFrameworkResponse(f)
	}

	writeJSON(w, http.StatusOK, pagination.Result[ComplianceFrameworkResponse]{
		Data:       items,
		Total:      result.Total,
		Page:       result.Page,
		PerPage:    result.PerPage,
		TotalPages: result.TotalPages,
	})
}

// GetFramework returns a single compliance framework.
func (h *ComplianceHandler) GetFramework(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())
	id := chi.URLParam(r, "id")

	framework, err := h.service.GetFramework(r.Context(), tenantID, id)
	if err != nil {
		h.handleError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, toComplianceFrameworkResponse(framework))
}

// ListControls lists controls for a framework.
func (h *ComplianceHandler) ListControls(w http.ResponseWriter, r *http.Request) {
	frameworkID := chi.URLParam(r, "id")

	perPage := parseQueryInt(r.URL.Query().Get("per_page"), 50)
	if perPage > 100 {
		perPage = 100
	}
	page := pagination.New(
		parseQueryInt(r.URL.Query().Get("page"), 1),
		perPage,
	)

	result, err := h.service.ListControls(r.Context(), frameworkID, page)
	if err != nil {
		h.handleError(w, err)
		return
	}

	items := make([]ComplianceControlResponse, len(result.Data))
	for i, c := range result.Data {
		items[i] = toComplianceControlResponse(c)
	}

	writeJSON(w, http.StatusOK, pagination.Result[ComplianceControlResponse]{
		Data:       items,
		Total:      result.Total,
		Page:       result.Page,
		PerPage:    result.PerPage,
		TotalPages: result.TotalPages,
	})
}

// GetFrameworkStats returns compliance statistics for a framework.
func (h *ComplianceHandler) GetFrameworkStats(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())
	id := chi.URLParam(r, "id")

	stats, err := h.service.GetFrameworkStats(r.Context(), tenantID, id)
	if err != nil {
		h.handleError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, stats)
}

// =============================================
// CONTROL ENDPOINTS
// =============================================

// GetControl returns a single compliance control.
func (h *ComplianceHandler) GetControl(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())
	id := chi.URLParam(r, "id")

	control, err := h.service.GetControl(r.Context(), tenantID, id)
	if err != nil {
		h.handleError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, toComplianceControlResponse(control))
}

// =============================================
// ASSESSMENT ENDPOINTS
// =============================================

// UpdateAssessment creates or updates a control assessment.
func (h *ComplianceHandler) UpdateAssessment(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())
	controlID := chi.URLParam(r, "id")
	actorID := middleware.GetUserID(r.Context())

	var req UpdateAssessmentRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("invalid request body").WriteJSON(w)
		return
	}

	assessment, err := h.service.UpdateAssessment(r.Context(), app.UpdateAssessmentInput{
		TenantID:    tenantID,
		FrameworkID: req.FrameworkID,
		ControlID:   controlID,
		Status:      req.Status,
		Priority:    req.Priority,
		Owner:       req.Owner,
		Notes:       req.Notes,
		DueDate:     req.DueDate,
		ActorID:     actorID,
	})
	if err != nil {
		h.handleError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, toComplianceAssessmentResponse(assessment))
}

// ListAssessments lists assessments for a framework.
func (h *ComplianceHandler) ListAssessments(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())
	frameworkID := r.URL.Query().Get("framework_id")

	perPage := parseQueryInt(r.URL.Query().Get("per_page"), 50)
	if perPage > 100 {
		perPage = 100
	}
	page := pagination.New(
		parseQueryInt(r.URL.Query().Get("page"), 1),
		perPage,
	)

	result, err := h.service.ListAssessments(r.Context(), tenantID, frameworkID, page)
	if err != nil {
		h.handleError(w, err)
		return
	}

	items := make([]ComplianceAssessmentResponse, len(result.Data))
	for i, a := range result.Data {
		items[i] = toComplianceAssessmentResponse(a)
	}

	writeJSON(w, http.StatusOK, pagination.Result[ComplianceAssessmentResponse]{
		Data:       items,
		Total:      result.Total,
		Page:       result.Page,
		PerPage:    result.PerPage,
		TotalPages: result.TotalPages,
	})
}

// GetComplianceStats returns overall compliance statistics.
func (h *ComplianceHandler) GetComplianceStats(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())

	stats, err := h.service.GetComplianceStats(r.Context(), tenantID)
	if err != nil {
		h.handleError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, stats)
}

// =============================================
// MAPPING ENDPOINTS
// =============================================

// GetFindingControls lists controls mapped to a finding.
func (h *ComplianceHandler) GetFindingControls(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())
	findingID := chi.URLParam(r, "findingId")

	mappings, err := h.service.GetFindingControls(r.Context(), tenantID, findingID)
	if err != nil {
		h.handleError(w, err)
		return
	}

	items := make([]ComplianceMappingResponse, len(mappings))
	for i, m := range mappings {
		items[i] = toComplianceMappingResponse(m)
	}

	writeJSON(w, http.StatusOK, map[string]any{"data": items, "total": len(items)})
}

// MapFindingToControl maps a finding to a compliance control.
func (h *ComplianceHandler) MapFindingToControl(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())
	findingID := chi.URLParam(r, "findingId")
	actorID := middleware.GetUserID(r.Context())

	var req MapFindingRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("invalid request body").WriteJSON(w)
		return
	}

	mapping, err := h.service.MapFindingToControl(r.Context(), tenantID, findingID, req.ControlID, actorID, req.Impact)
	if err != nil {
		h.handleError(w, err)
		return
	}

	writeJSON(w, http.StatusCreated, toComplianceMappingResponse(mapping))
}

// UnmapFindingFromControl removes a finding-to-control mapping.
func (h *ComplianceHandler) UnmapFindingFromControl(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())
	mappingID := chi.URLParam(r, "mappingId")

	if err := h.service.UnmapFindingFromControl(r.Context(), tenantID, mappingID); err != nil {
		h.handleError(w, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// =============================================
// REQUEST TYPES
// =============================================

// UpdateAssessmentRequest is the API request for updating an assessment.
type UpdateAssessmentRequest struct {
	FrameworkID string  `json:"framework_id"`
	Status      string  `json:"status"`
	Priority    string  `json:"priority"`
	Owner       string  `json:"owner"`
	Notes       string  `json:"notes"`
	DueDate     *string `json:"due_date"`
}

// MapFindingRequest is the API request for mapping a finding to a control.
type MapFindingRequest struct {
	ControlID string `json:"control_id"`
	Impact    string `json:"impact"`
}

// =============================================
// RESPONSE TYPES
// =============================================

// ComplianceFrameworkResponse is the API response for a compliance framework.
type ComplianceFrameworkResponse struct {
	ID            string    `json:"id"`
	Name          string    `json:"name"`
	Slug          string    `json:"slug"`
	Version       string    `json:"version"`
	Description   string    `json:"description"`
	Category      string    `json:"category"`
	TotalControls int       `json:"total_controls"`
	IsSystem      bool      `json:"is_system"`
	IsActive      bool      `json:"is_active"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}

// ComplianceControlResponse is the API response for a compliance control.
type ComplianceControlResponse struct {
	ID              string  `json:"id"`
	FrameworkID     string  `json:"framework_id"`
	ControlID       string  `json:"control_id"`
	Title           string  `json:"title"`
	Description     string  `json:"description"`
	Category        string  `json:"category"`
	ParentControlID *string `json:"parent_control_id,omitempty"`
	SortOrder       int     `json:"sort_order"`
	CreatedAt       time.Time `json:"created_at"`
}

// ComplianceAssessmentResponse is the API response for a compliance assessment.
type ComplianceAssessmentResponse struct {
	ID            string     `json:"id"`
	TenantID      string     `json:"tenant_id"`
	FrameworkID   string     `json:"framework_id"`
	ControlID     string     `json:"control_id"`
	Status        string     `json:"status"`
	Priority      string     `json:"priority"`
	Owner         string     `json:"owner"`
	Notes         string     `json:"notes"`
	EvidenceCount int        `json:"evidence_count"`
	FindingCount  int        `json:"finding_count"`
	AssessedBy    *string    `json:"assessed_by,omitempty"`
	AssessedAt    *time.Time `json:"assessed_at,omitempty"`
	DueDate       *time.Time `json:"due_date,omitempty"`
	CreatedAt     time.Time  `json:"created_at"`
	UpdatedAt     time.Time  `json:"updated_at"`
}

// ComplianceMappingResponse is the API response for a finding-to-control mapping.
type ComplianceMappingResponse struct {
	ID        string    `json:"id"`
	FindingID string    `json:"finding_id"`
	ControlID string    `json:"control_id"`
	Impact    string    `json:"impact"`
	Notes     string    `json:"notes"`
	CreatedAt time.Time `json:"created_at"`
	CreatedBy *string   `json:"created_by,omitempty"`
}

// =============================================
// MAPPERS
// =============================================

func toComplianceFrameworkResponse(f *compliance.Framework) ComplianceFrameworkResponse {
	return ComplianceFrameworkResponse{
		ID:            f.ID().String(),
		Name:          f.Name(),
		Slug:          f.Slug(),
		Version:       f.Version(),
		Description:   f.Description(),
		Category:      string(f.Category()),
		TotalControls: f.TotalControls(),
		IsSystem:      f.IsSystem(),
		IsActive:      f.IsActive(),
		CreatedAt:     f.CreatedAt(),
		UpdatedAt:     f.UpdatedAt(),
	}
}

func toComplianceControlResponse(c *compliance.Control) ComplianceControlResponse {
	resp := ComplianceControlResponse{
		ID:          c.ID().String(),
		FrameworkID: c.FrameworkID().String(),
		ControlID:   c.ControlID(),
		Title:       c.Title(),
		Description: c.Description(),
		Category:    c.Category(),
		SortOrder:   c.SortOrder(),
		CreatedAt:   c.CreatedAt(),
	}
	if c.ParentControlID() != nil {
		s := c.ParentControlID().String()
		resp.ParentControlID = &s
	}
	return resp
}

func toComplianceAssessmentResponse(a *compliance.Assessment) ComplianceAssessmentResponse {
	resp := ComplianceAssessmentResponse{
		ID:            a.ID().String(),
		TenantID:      a.TenantID().String(),
		FrameworkID:   a.FrameworkID().String(),
		ControlID:     a.ControlID().String(),
		Status:        string(a.Status()),
		Priority:      string(a.Priority()),
		Owner:         a.Owner(),
		Notes:         a.Notes(),
		EvidenceCount: a.EvidenceCount(),
		FindingCount:  a.FindingCount(),
		AssessedAt:    a.AssessedAt(),
		DueDate:       a.DueDate(),
		CreatedAt:     a.CreatedAt(),
		UpdatedAt:     a.UpdatedAt(),
	}
	if a.AssessedBy() != nil {
		s := a.AssessedBy().String()
		resp.AssessedBy = &s
	}
	return resp
}

func toComplianceMappingResponse(m *compliance.FindingControlMapping) ComplianceMappingResponse {
	resp := ComplianceMappingResponse{
		ID:        m.ID().String(),
		FindingID: m.FindingID().String(),
		ControlID: m.ControlID().String(),
		Impact:    string(m.Impact()),
		Notes:     m.Notes(),
		CreatedAt: m.CreatedAt(),
	}
	if m.CreatedBy() != nil {
		s := m.CreatedBy().String()
		resp.CreatedBy = &s
	}
	return resp
}

// =============================================
// ERROR HANDLING
// =============================================

func (h *ComplianceHandler) handleError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, compliance.ErrFrameworkNotFound),
		errors.Is(err, compliance.ErrControlNotFound),
		errors.Is(err, compliance.ErrAssessmentNotFound),
		errors.Is(err, compliance.ErrMappingNotFound):
		apierror.NotFound(err.Error()).WriteJSON(w)
	case errors.Is(err, compliance.ErrSystemFrameworkReadOnly):
		apierror.Forbidden(err.Error()).WriteJSON(w)
	case errors.Is(err, compliance.ErrMappingAlreadyExists):
		apierror.Conflict(err.Error()).WriteJSON(w)
	case errors.Is(err, shared.ErrValidation):
		apierror.BadRequest(err.Error()).WriteJSON(w)
	default:
		h.logger.Error("compliance handler error", "error", err)
		apierror.InternalServerError("internal server error").WriteJSON(w)
	}
}
