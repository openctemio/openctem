package handler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	scansvc "github.com/openctemio/api/internal/app/scan"
	"github.com/openctemio/api/internal/infra/http/middleware"
	"github.com/openctemio/api/pkg/apierror"
	"github.com/openctemio/api/pkg/domain/scan"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/domain/user"
	"github.com/openctemio/api/pkg/logger"
	"github.com/openctemio/api/pkg/validator"
)

// ScanHandler handles HTTP requests for scans.
type ScanHandler struct {
	service   *scansvc.Service
	userRepo  user.Repository
	validator *validator.Validator
	logger    *logger.Logger
}

// NewScanHandler creates a new ScanHandler.
func NewScanHandler(service *scansvc.Service, userRepo user.Repository, v *validator.Validator, log *logger.Logger) *ScanHandler {
	return &ScanHandler{
		service:   service,
		userRepo:  userRepo,
		validator: v,
		logger:    log.With("handler", "scan"),
	}
}

// --- Request/Response Types ---

// CreateScanRequest represents the request body for creating a scan.
// Either asset_group_id OR asset_group_ids OR targets must be provided (can have all).
type CreateScanRequest struct {
	Name          string         `json:"name" validate:"required,min=1,max=200"`
	Description   string         `json:"description" validate:"max=1000"`
	AssetGroupID  string         `json:"asset_group_id" validate:"omitempty,uuid"`       // Single asset group (legacy)
	AssetGroupIDs []string       `json:"asset_group_ids" validate:"omitempty,dive,uuid"` // Multiple asset groups (NEW)
	Targets       []string       `json:"targets" validate:"omitempty,max=1000"`          // Direct targets
	ScanType      string         `json:"scan_type" validate:"required,oneof=workflow single"`
	PipelineID    string         `json:"pipeline_id" validate:"omitempty,uuid"`
	ScannerName   string         `json:"scanner_name" validate:"max=100"`
	ScannerConfig map[string]any `json:"scanner_config"`
	TargetsPerJob int            `json:"targets_per_job"`
	ScheduleType  string         `json:"schedule_type" validate:"omitempty,oneof=manual daily weekly monthly crontab"`
	ScheduleCron  string         `json:"schedule_cron" validate:"max=100"`
	ScheduleDay   *int           `json:"schedule_day"`
	ScheduleTime  *string        `json:"schedule_time"`
	Timezone      string         `json:"timezone" validate:"max=50"`
	Tags          []string       `json:"tags" validate:"max=20,dive,max=50"`
	TenantRunner  bool           `json:"run_on_tenant_runner"`
}

// UpdateScanRequest represents the request body for updating a scan.
type UpdateScanRequest struct {
	Name          string         `json:"name" validate:"omitempty,min=1,max=200"`
	Description   string         `json:"description" validate:"max=1000"`
	PipelineID    string         `json:"pipeline_id" validate:"omitempty,uuid"`
	ScannerName   string         `json:"scanner_name" validate:"max=100"`
	ScannerConfig map[string]any `json:"scanner_config"`
	TargetsPerJob *int           `json:"targets_per_job"`
	ScheduleType  string         `json:"schedule_type" validate:"omitempty,oneof=manual daily weekly monthly crontab"`
	ScheduleCron  string         `json:"schedule_cron" validate:"max=100"`
	ScheduleDay   *int           `json:"schedule_day"`
	ScheduleTime  *string        `json:"schedule_time"`
	Timezone      string         `json:"timezone" validate:"max=50"`
	Tags          []string       `json:"tags" validate:"max=20,dive,max=50"`
	TenantRunner  *bool          `json:"run_on_tenant_runner"`
}

// TriggerScanRequest represents the request body for triggering a scan.
type TriggerScanExecRequest struct {
	Context map[string]any `json:"context"`
}

// CloneScanRequest represents the request body for cloning a scan.
type CloneScanRequest struct {
	Name string `json:"name" validate:"required,min=1,max=200"`
}

// BulkActionRequest represents the request body for bulk scan operations.
type BulkActionRequest struct {
	ScanIDs []string `json:"scan_ids" validate:"required,min=1,max=100,dive,uuid"`
}

// BulkActionResponse represents the response for bulk scan operations.
type BulkActionResponse struct {
	Successful []string `json:"successful"`
	Failed     []struct {
		ID    string `json:"id"`
		Error string `json:"error"`
	} `json:"failed"`
	Message string `json:"message"`
}

// QuickScanRequest represents the request body for quick scan.
type QuickScanRequest struct {
	Targets     []string       `json:"targets" validate:"required,min=1,max=1000"`
	ScannerName string         `json:"scanner_name" validate:"omitempty,max=100"`
	WorkflowID  string         `json:"workflow_id" validate:"omitempty,uuid"`
	Config      map[string]any `json:"config"`
	Tags        []string       `json:"tags" validate:"max=20,dive,max=50"`
}

// QuickScanResponse represents the response for quick scan.
type QuickScanResponse struct {
	PipelineRunID string `json:"pipeline_run_id"`
	ScanID        string `json:"scan_id"`
	AssetGroupID  string `json:"asset_group_id"`
	Status        string `json:"status"`
	TargetCount   int    `json:"target_count"`
}

// CreateScanResponse wraps scan detail with optional compatibility warning.
// Used only for POST /scans to show warnings about asset-scanner compatibility.
type CreateScanResponse struct {
	*ScanDetailResponse
	CompatibilityWarning *AssetCompatibilityPreviewResponse `json:"compatibility_warning,omitempty"`
}

// AssetCompatibilityPreviewResponse represents asset-scanner compatibility info.
type AssetCompatibilityPreviewResponse struct {
	IsFullyCompatible    bool     `json:"is_fully_compatible"`
	CompatibilityPercent float64  `json:"compatibility_percent"`
	CompatibleCount      int      `json:"compatible_count"`
	IncompatibleCount    int      `json:"incompatible_count"`
	UnclassifiedCount    int      `json:"unclassified_count"`
	TotalCount           int      `json:"total_count"`
	CompatibleTypes      []string `json:"compatible_types,omitempty"`
	IncompatibleTypes    []string `json:"incompatible_types,omitempty"`
	Message              string   `json:"message"`
}

// ScanResponse represents the response for a scan.
type ScanDetailResponse struct {
	ID                string         `json:"id"`
	TenantID          string         `json:"tenant_id"`
	Name              string         `json:"name"`
	Description       string         `json:"description,omitempty"`
	AssetGroupID      string         `json:"asset_group_id,omitempty"`  // Primary asset group (legacy)
	AssetGroupIDs     []string       `json:"asset_group_ids,omitempty"` // Multiple asset groups
	Targets           []string       `json:"targets,omitempty"`         // Direct targets
	ScanType          string         `json:"scan_type"`
	PipelineID        *string        `json:"pipeline_id,omitempty"`
	ScannerName       string         `json:"scanner_name,omitempty"`
	ScannerConfig     map[string]any `json:"scanner_config,omitempty"`
	TargetsPerJob     int            `json:"targets_per_job"`
	ScheduleType      string         `json:"schedule_type"`
	ScheduleCron      string         `json:"schedule_cron,omitempty"`
	ScheduleDay       *int           `json:"schedule_day,omitempty"`
	ScheduleTime      *string        `json:"schedule_time,omitempty"`
	ScheduleTimezone  string         `json:"schedule_timezone"`
	NextRunAt         *string        `json:"next_run_at,omitempty"`
	Tags              []string       `json:"tags,omitempty"`
	RunOnTenantRunner bool           `json:"run_on_tenant_runner"`
	Status            string         `json:"status"`
	LastRunID         *string        `json:"last_run_id,omitempty"`
	LastRunAt         *string        `json:"last_run_at,omitempty"`
	LastRunStatus     string         `json:"last_run_status,omitempty"`
	TotalRuns         int            `json:"total_runs"`
	SuccessfulRuns    int            `json:"successful_runs"`
	FailedRuns        int            `json:"failed_runs"`
	CreatedBy         *string        `json:"created_by,omitempty"`
	CreatedByName     *string        `json:"created_by_name,omitempty"`
	CreatedAt         string         `json:"created_at"`
	UpdatedAt         string         `json:"updated_at"`
}

// ScanStatsResponse represents the response for scan statistics.
type ScanStatsResponse struct {
	Total          int64            `json:"total"`
	Active         int64            `json:"active"`
	Paused         int64            `json:"paused"`
	Disabled       int64            `json:"disabled"`
	ByScheduleType map[string]int64 `json:"by_schedule_type"`
	ByScanType     map[string]int64 `json:"by_scan_type"`
}

// --- CRUD Handlers ---

// CreateScan handles POST /api/v1/scans
// @Summary      Create scan
// @Description  Create a new scan configuration with scheduling options
// @Tags         Scans
// @Accept       json
// @Produce      json
// @Param        request  body      CreateScanRequest  true  "Scan configuration"
// @Success      201  {object}  ScanDetailResponse
// @Failure      400  {object}  apierror.Error
// @Failure      401  {object}  apierror.Error
// @Failure      500  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /scans [post]
func (h *ScanHandler) CreateScan(w http.ResponseWriter, r *http.Request) {
	var req CreateScanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}

	if err := h.validator.Validate(req); err != nil {
		h.handleValidationError(w, err)
		return
	}

	tenantID := middleware.GetTenantID(r.Context())
	userID := middleware.GetUserID(r.Context())

	// Parse schedule time if provided
	var scheduleTime *time.Time
	if req.ScheduleTime != nil && *req.ScheduleTime != "" {
		t, err := time.Parse("15:04", *req.ScheduleTime)
		if err != nil {
			apierror.BadRequest("Invalid schedule_time format, expected HH:MM").WriteJSON(w)
			return
		}
		scheduleTime = &t
	}

	// Support both singular asset_group_id (legacy) and plural asset_group_ids (new)
	// Merge them into a single list for the service layer
	assetGroupIDs := req.AssetGroupIDs
	if req.AssetGroupID != "" {
		// If singular is provided, add it to the list (avoiding duplicates)
		found := false
		for _, id := range assetGroupIDs {
			if id == req.AssetGroupID {
				found = true
				break
			}
		}
		if !found {
			assetGroupIDs = append([]string{req.AssetGroupID}, assetGroupIDs...)
		}
	}

	// Validate: must have either asset_group_ids or targets
	if len(assetGroupIDs) == 0 && len(req.Targets) == 0 {
		apierror.BadRequest("Either asset_group_id/asset_group_ids or targets must be provided").WriteJSON(w)
		return
	}

	// For backward compatibility, pass the first asset group as AssetGroupID
	// and the full list as AssetGroupIDs
	primaryAssetGroupID := ""
	if len(assetGroupIDs) > 0 {
		primaryAssetGroupID = assetGroupIDs[0]
	}

	input := scansvc.CreateScanInput{
		TenantID:      tenantID,
		Name:          req.Name,
		Description:   req.Description,
		AssetGroupID:  primaryAssetGroupID, // Primary for backward compat
		AssetGroupIDs: assetGroupIDs,       // Full list for new scans
		Targets:       req.Targets,
		ScanType:      req.ScanType,
		PipelineID:    req.PipelineID,
		ScannerName:   req.ScannerName,
		ScannerConfig: req.ScannerConfig,
		TargetsPerJob: req.TargetsPerJob,
		ScheduleType:  req.ScheduleType,
		ScheduleCron:  req.ScheduleCron,
		ScheduleDay:   req.ScheduleDay,
		ScheduleTime:  scheduleTime,
		Timezone:      req.Timezone,
		Tags:          req.Tags,
		TenantRunner:  req.TenantRunner,
		CreatedBy:     userID,
	}

	s, err := h.service.CreateScan(r.Context(), input)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	// Build response
	response := &CreateScanResponse{
		ScanDetailResponse: h.toScanResponse(r.Context(), s),
	}

	// Check compatibility for single scanner scans with asset groups
	if req.ScanType == "single" && req.ScannerName != "" && len(assetGroupIDs) > 0 {
		// Convert string IDs to shared.ID
		groupIDs := make([]shared.ID, 0, len(assetGroupIDs))
		for _, idStr := range assetGroupIDs {
			if id, err := shared.IDFromString(idStr); err == nil {
				groupIDs = append(groupIDs, id)
			}
		}

		if preview, err := h.service.PreviewScanCompatibility(r.Context(), req.ScannerName, groupIDs); err == nil && preview != nil {
			response.CompatibilityWarning = &AssetCompatibilityPreviewResponse{
				IsFullyCompatible:    preview.IsFullyCompatible,
				CompatibilityPercent: preview.CompatibilityPercent,
				CompatibleCount:      preview.CompatibleCount,
				IncompatibleCount:    preview.IncompatibleCount,
				UnclassifiedCount:    preview.UnclassifiedCount,
				TotalCount:           preview.TotalCount,
				CompatibleTypes:      preview.CompatibleTypes,
				IncompatibleTypes:    preview.IncompatibleTypes,
				Message:              preview.Message,
			}
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(response)
}

// GetScan handles GET /api/v1/scans/{id}
// @Summary      Get scan
// @Description  Get a single scan by ID
// @Tags         Scans
// @Accept       json
// @Produce      json
// @Param        id   path      string  true  "Scan ID"
// @Success      200  {object}  ScanDetailResponse
// @Failure      400  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Failure      500  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /scans/{id} [get]
func (h *ScanHandler) GetScan(w http.ResponseWriter, r *http.Request) {
	scanID := chi.URLParam(r, "id")
	tenantID := middleware.GetTenantID(r.Context())

	s, err := h.service.GetScan(r.Context(), tenantID, scanID)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(h.toScanResponse(r.Context(), s))
}

// ListScans handles GET /api/v1/scans
// @Summary      List scans
// @Description  Get a paginated list of scans
// @Tags         Scans
// @Accept       json
// @Produce      json
// @Param        asset_group_id  query     string  false  "Filter by asset group"
// @Param        pipeline_id     query     string  false  "Filter by pipeline"
// @Param        scan_type       query     string  false  "Filter by scan type (workflow, single)"
// @Param        schedule_type   query     string  false  "Filter by schedule type"
// @Param        status          query     string  false  "Filter by status"
// @Param        search          query     string  false  "Search by name"
// @Param        page            query     int     false  "Page number" default(1)
// @Param        per_page        query     int     false  "Items per page" default(20)
// @Success      200  {object}  ListResponse[ScanDetailResponse]
// @Failure      400  {object}  apierror.Error
// @Failure      500  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /scans [get]
func (h *ScanHandler) ListScans(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.GetTenantID(r.Context())

	input := scansvc.ListScansInput{
		TenantID:     tenantID,
		AssetGroupID: r.URL.Query().Get("asset_group_id"),
		PipelineID:   r.URL.Query().Get("pipeline_id"),
		ScanType:     r.URL.Query().Get("scan_type"),
		ScheduleType: r.URL.Query().Get("schedule_type"),
		Status:       r.URL.Query().Get("status"),
		Tags:         parseQueryArray(r.URL.Query().Get("tags")),
		Search:       r.URL.Query().Get("search"),
		Page:         parseQueryInt(r.URL.Query().Get("page"), 1),
		PerPage:      parseQueryInt(r.URL.Query().Get("per_page"), 20),
	}

	result, err := h.service.ListScans(r.Context(), input)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	ctx := r.Context()
	items := make([]*ScanDetailResponse, len(result.Data))
	for i, s := range result.Data {
		items[i] = h.toScanResponse(ctx, s)
	}

	resp := map[string]any{
		"items":       items,
		"total":       result.Total,
		"page":        result.Page,
		"per_page":    result.PerPage,
		"total_pages": result.TotalPages,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// UpdateScan handles PUT /api/v1/scans/{id}
// @Summary      Update scan
// @Description  Update an existing scan configuration
// @Tags         Scans
// @Accept       json
// @Produce      json
// @Param        id       path      string             true  "Scan ID"
// @Param        request  body      UpdateScanRequest  true  "Update data"
// @Success      200  {object}  ScanDetailResponse
// @Failure      400  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Failure      500  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /scans/{id} [put]
func (h *ScanHandler) UpdateScan(w http.ResponseWriter, r *http.Request) {
	scanID := chi.URLParam(r, "id")
	tenantID := middleware.GetTenantID(r.Context())

	var req UpdateScanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}

	if err := h.validator.Validate(req); err != nil {
		h.handleValidationError(w, err)
		return
	}

	// Parse schedule time if provided
	var scheduleTime *time.Time
	if req.ScheduleTime != nil && *req.ScheduleTime != "" {
		t, err := time.Parse("15:04", *req.ScheduleTime)
		if err != nil {
			apierror.BadRequest("Invalid schedule_time format, expected HH:MM").WriteJSON(w)
			return
		}
		scheduleTime = &t
	}

	input := scansvc.UpdateScanInput{
		TenantID:      tenantID,
		ScanID:        scanID,
		Name:          req.Name,
		Description:   req.Description,
		PipelineID:    req.PipelineID,
		ScannerName:   req.ScannerName,
		ScannerConfig: req.ScannerConfig,
		TargetsPerJob: req.TargetsPerJob,
		ScheduleType:  req.ScheduleType,
		ScheduleCron:  req.ScheduleCron,
		ScheduleDay:   req.ScheduleDay,
		ScheduleTime:  scheduleTime,
		Timezone:      req.Timezone,
		Tags:          req.Tags,
		TenantRunner:  req.TenantRunner,
	}

	s, err := h.service.UpdateScan(r.Context(), input)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(h.toScanResponse(r.Context(), s))
}

// DeleteScan handles DELETE /api/v1/scans/{id}
// @Summary      Delete scan
// @Description  Delete a scan configuration
// @Tags         Scans
// @Accept       json
// @Produce      json
// @Param        id   path      string  true  "Scan ID"
// @Success      204  "No Content"
// @Failure      400  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Failure      500  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /scans/{id} [delete]
func (h *ScanHandler) DeleteScan(w http.ResponseWriter, r *http.Request) {
	scanID := chi.URLParam(r, "id")
	tenantID := middleware.GetTenantID(r.Context())

	if err := h.service.DeleteScan(r.Context(), tenantID, scanID); err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// --- Status Handlers ---

// ActivateScan handles POST /api/v1/scans/{id}/activate
// @Summary      Activate scan
// @Description  Activate a paused or disabled scan
// @Tags         Scans
// @Accept       json
// @Produce      json
// @Param        id   path      string  true  "Scan ID"
// @Success      200  {object}  ScanDetailResponse
// @Failure      400  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Failure      500  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /scans/{id}/activate [post]
func (h *ScanHandler) ActivateScan(w http.ResponseWriter, r *http.Request) {
	scanID := chi.URLParam(r, "id")
	tenantID := middleware.GetTenantID(r.Context())

	s, err := h.service.ActivateScan(r.Context(), tenantID, scanID)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(h.toScanResponse(r.Context(), s))
}

// PauseScan handles POST /api/v1/scans/{id}/pause
// @Summary      Pause scan
// @Description  Pause an active scan
// @Tags         Scans
// @Accept       json
// @Produce      json
// @Param        id   path      string  true  "Scan ID"
// @Success      200  {object}  ScanDetailResponse
// @Failure      400  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Failure      500  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /scans/{id}/pause [post]
func (h *ScanHandler) PauseScan(w http.ResponseWriter, r *http.Request) {
	scanID := chi.URLParam(r, "id")
	tenantID := middleware.GetTenantID(r.Context())

	s, err := h.service.PauseScan(r.Context(), tenantID, scanID)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(h.toScanResponse(r.Context(), s))
}

// DisableScan handles POST /api/v1/scans/{id}/disable
// @Summary      Disable scan
// @Description  Disable a scan completely
// @Tags         Scans
// @Accept       json
// @Produce      json
// @Param        id   path      string  true  "Scan ID"
// @Success      200  {object}  ScanDetailResponse
// @Failure      400  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Failure      500  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /scans/{id}/disable [post]
func (h *ScanHandler) DisableScan(w http.ResponseWriter, r *http.Request) {
	scanID := chi.URLParam(r, "id")
	tenantID := middleware.GetTenantID(r.Context())

	s, err := h.service.DisableScan(r.Context(), tenantID, scanID)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(h.toScanResponse(r.Context(), s))
}

// --- Bulk Operation Handlers ---

// BulkActivate handles POST /api/v1/scans/bulk/activate
// @Summary      Bulk activate scans
// @Description  Activate multiple scan configurations at once
// @Tags         Scans
// @Accept       json
// @Produce      json
// @Param        request  body      BulkActionRequest  true  "Scan IDs to activate"
// @Success      200  {object}  BulkActionResponse
// @Failure      400  {object}  apierror.Error
// @Failure      401  {object}  apierror.Error
// @Failure      500  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /scans/bulk/activate [post]
func (h *ScanHandler) BulkActivate(w http.ResponseWriter, r *http.Request) {
	h.handleBulkAction(w, r, "activate")
}

// BulkPause handles POST /api/v1/scans/bulk/pause
// @Summary      Bulk pause scans
// @Description  Pause multiple scan configurations at once
// @Tags         Scans
// @Accept       json
// @Produce      json
// @Param        request  body      BulkActionRequest  true  "Scan IDs to pause"
// @Success      200  {object}  BulkActionResponse
// @Failure      400  {object}  apierror.Error
// @Failure      401  {object}  apierror.Error
// @Failure      500  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /scans/bulk/pause [post]
func (h *ScanHandler) BulkPause(w http.ResponseWriter, r *http.Request) {
	h.handleBulkAction(w, r, "pause")
}

// BulkDisable handles POST /api/v1/scans/bulk/disable
// @Summary      Bulk disable scans
// @Description  Disable multiple scan configurations at once
// @Tags         Scans
// @Accept       json
// @Produce      json
// @Param        request  body      BulkActionRequest  true  "Scan IDs to disable"
// @Success      200  {object}  BulkActionResponse
// @Failure      400  {object}  apierror.Error
// @Failure      401  {object}  apierror.Error
// @Failure      500  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /scans/bulk/disable [post]
func (h *ScanHandler) BulkDisable(w http.ResponseWriter, r *http.Request) {
	h.handleBulkAction(w, r, "disable")
}

// BulkDelete handles POST /api/v1/scans/bulk/delete
// @Summary      Bulk delete scans
// @Description  Delete multiple scan configurations at once
// @Tags         Scans
// @Accept       json
// @Produce      json
// @Param        request  body      BulkActionRequest  true  "Scan IDs to delete"
// @Success      200  {object}  BulkActionResponse
// @Failure      400  {object}  apierror.Error
// @Failure      401  {object}  apierror.Error
// @Failure      500  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /scans/bulk/delete [post]
func (h *ScanHandler) BulkDelete(w http.ResponseWriter, r *http.Request) {
	h.handleBulkAction(w, r, "delete")
}

// handleBulkAction is a helper function for bulk operations.
func (h *ScanHandler) handleBulkAction(w http.ResponseWriter, r *http.Request, action string) {
	var req BulkActionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}

	if err := h.validator.Validate(req); err != nil {
		h.handleValidationError(w, err)
		return
	}

	tenantID := middleware.GetTenantID(r.Context())

	var result *scansvc.BulkActionResult
	var err error

	switch action {
	case "activate":
		result, err = h.service.BulkActivate(r.Context(), tenantID, req.ScanIDs)
	case "pause":
		result, err = h.service.BulkPause(r.Context(), tenantID, req.ScanIDs)
	case "disable":
		result, err = h.service.BulkDisable(r.Context(), tenantID, req.ScanIDs)
	case "delete":
		result, err = h.service.BulkDelete(r.Context(), tenantID, req.ScanIDs)
	default:
		apierror.BadRequest("Invalid bulk action").WriteJSON(w)
		return
	}

	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	resp := BulkActionResponse{
		Successful: result.Successful,
		Failed:     result.Failed,
		Message:    formatBulkMessage(action, len(result.Successful), len(result.Failed)),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// formatBulkMessage creates a human-readable message for bulk operations.
func formatBulkMessage(action string, successful, failed int) string {
	total := successful + failed
	if failed == 0 {
		return fmt.Sprintf("Successfully %sd %d scan(s)", action, successful)
	}
	return fmt.Sprintf("%sd %d of %d scan(s), %d failed", action, successful, total, failed)
}

// --- Trigger Handlers ---

// TriggerScan handles POST /api/v1/scans/{id}/trigger
// @Summary      Trigger scan
// @Description  Manually trigger a scan execution. Returns run details with optional filtering_result showing which assets will be scanned vs skipped based on scanner compatibility.
// @Tags         Scans
// @Accept       json
// @Produce      json
// @Param        id       path      string                  true   "Scan ID"
// @Param        request  body      TriggerScanExecRequest  false  "Trigger context"
// @Success      201  {object}  RunResponse
// @Failure      400  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Failure      500  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /scans/{id}/trigger [post]
func (h *ScanHandler) TriggerScan(w http.ResponseWriter, r *http.Request) {
	scanID := chi.URLParam(r, "id")
	tenantID := middleware.GetTenantID(r.Context())
	userID := middleware.GetUserID(r.Context())

	var req TriggerScanExecRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil && err.Error() != "EOF" {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}

	input := scansvc.TriggerScanExecInput{
		TenantID:    tenantID,
		ScanID:      scanID,
		TriggeredBy: userID,
		Context:     req.Context,
	}

	run, err := h.service.TriggerScan(r.Context(), input)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(toRunResponse(run))
}

// --- Stats Handlers ---

// GetStats handles GET /api/v1/scans/stats
// @Summary      Get scan statistics
// @Description  Get aggregated statistics for all scans
// @Tags         Scans
// @Accept       json
// @Produce      json
// @Success      200  {object}  ScanStatsResponse
// @Failure      401  {object}  apierror.Error
// @Failure      500  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /scans/stats [get]
func (h *ScanHandler) GetStats(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.GetTenantID(r.Context())

	stats, err := h.service.GetStats(r.Context(), tenantID)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	resp := toScanStatsResponse(stats)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// --- Clone Handler ---

// CloneScan handles POST /api/v1/scans/{id}/clone
// @Summary      Clone scan
// @Description  Create a copy of an existing scan with a new name
// @Tags         Scans
// @Accept       json
// @Produce      json
// @Param        id       path      string           true  "Scan ID to clone"
// @Param        request  body      CloneScanRequest true  "New scan name"
// @Success      201  {object}  ScanDetailResponse
// @Failure      400  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Failure      500  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /scans/{id}/clone [post]
func (h *ScanHandler) CloneScan(w http.ResponseWriter, r *http.Request) {
	scanID := chi.URLParam(r, "id")
	tenantID := middleware.GetTenantID(r.Context())

	var req CloneScanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}

	if err := h.validator.Validate(req); err != nil {
		h.handleValidationError(w, err)
		return
	}

	s, err := h.service.CloneScan(r.Context(), tenantID, scanID, req.Name)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(h.toScanResponse(r.Context(), s))
}

// --- Scan Runs Handlers ---

// ListScanRuns handles GET /api/v1/scans/{id}/runs
// @Summary      List scan runs
// @Description  Get a paginated list of runs for a scan
// @Tags         Scans
// @Accept       json
// @Produce      json
// @Param        id        path      string  true   "Scan ID"
// @Param        page      query     int     false  "Page number" default(1)
// @Param        per_page  query     int     false  "Items per page" default(20)
// @Success      200  {object}  object
// @Failure      400  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Failure      500  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /scans/{id}/runs [get]
func (h *ScanHandler) ListScanRuns(w http.ResponseWriter, r *http.Request) {
	scanID := chi.URLParam(r, "id")
	tenantID := middleware.GetTenantID(r.Context())

	page := parseQueryInt(r.URL.Query().Get("page"), 1)
	perPage := parseQueryInt(r.URL.Query().Get("per_page"), 20)

	result, err := h.service.ListScanRuns(r.Context(), tenantID, scanID, page, perPage)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

// GetLatestScanRun handles GET /api/v1/scans/{id}/runs/latest
// @Summary      Get latest scan run
// @Description  Get the most recent run for a scan
// @Tags         Scans
// @Accept       json
// @Produce      json
// @Param        id   path      string  true  "Scan ID"
// @Success      200  {object}  map[string]interface{}
// @Failure      400  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Failure      500  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /scans/{id}/runs/latest [get]
func (h *ScanHandler) GetLatestScanRun(w http.ResponseWriter, r *http.Request) {
	scanID := chi.URLParam(r, "id")
	tenantID := middleware.GetTenantID(r.Context())

	run, err := h.service.GetLatestScanRun(r.Context(), tenantID, scanID)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(toRunResponse(run))
}

// GetScanRun handles GET /api/v1/scans/{id}/runs/{runId}
// @Summary      Get scan run
// @Description  Get a specific run for a scan
// @Tags         Scans
// @Accept       json
// @Produce      json
// @Param        id      path      string  true  "Scan ID"
// @Param        runId   path      string  true  "Run ID"
// @Success      200  {object}  map[string]interface{}
// @Failure      400  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Failure      500  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /scans/{id}/runs/{runId} [get]
func (h *ScanHandler) GetScanRun(w http.ResponseWriter, r *http.Request) {
	scanID := chi.URLParam(r, "id")
	runID := chi.URLParam(r, "runId")
	tenantID := middleware.GetTenantID(r.Context())

	run, err := h.service.GetScanRun(r.Context(), tenantID, scanID, runID)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(toRunResponse(run))
}

// --- Conversion Helpers ---

// toScanResponse converts a domain scan to API response, enriching with user name if available.
func (h *ScanHandler) toScanResponse(ctx context.Context, s *scan.Scan) *ScanDetailResponse {
	// Handle nullable AssetGroupID
	assetGroupID := ""
	if !s.AssetGroupID.IsZero() {
		assetGroupID = s.AssetGroupID.String()
	}

	// Convert AssetGroupIDs to string slice
	assetGroupIDs := make([]string, 0, len(s.AssetGroupIDs))
	for _, id := range s.AssetGroupIDs {
		if !id.IsZero() {
			assetGroupIDs = append(assetGroupIDs, id.String())
		}
	}

	resp := &ScanDetailResponse{
		ID:                s.ID.String(),
		TenantID:          s.TenantID.String(),
		Name:              s.Name,
		Description:       s.Description,
		AssetGroupID:      assetGroupID,
		AssetGroupIDs:     assetGroupIDs,
		Targets:           s.Targets,
		ScanType:          string(s.ScanType),
		ScannerName:       s.ScannerName,
		ScannerConfig:     s.ScannerConfig,
		TargetsPerJob:     s.TargetsPerJob,
		ScheduleType:      string(s.ScheduleType),
		ScheduleCron:      s.ScheduleCron,
		ScheduleDay:       s.ScheduleDay,
		ScheduleTimezone:  s.ScheduleTimezone,
		Tags:              s.Tags,
		RunOnTenantRunner: s.RunOnTenantRunner,
		Status:            string(s.Status),
		LastRunStatus:     s.LastRunStatus,
		TotalRuns:         s.TotalRuns,
		SuccessfulRuns:    s.SuccessfulRuns,
		FailedRuns:        s.FailedRuns,
		CreatedAt:         s.CreatedAt.Format(time.RFC3339),
		UpdatedAt:         s.UpdatedAt.Format(time.RFC3339),
	}

	if s.PipelineID != nil {
		pid := s.PipelineID.String()
		resp.PipelineID = &pid
	}

	if s.ScheduleTime != nil {
		st := s.ScheduleTime.Format("15:04")
		resp.ScheduleTime = &st
	}

	if s.NextRunAt != nil {
		nra := s.NextRunAt.Format(time.RFC3339)
		resp.NextRunAt = &nra
	}

	if s.LastRunID != nil {
		lrid := s.LastRunID.String()
		resp.LastRunID = &lrid
	}

	if s.LastRunAt != nil {
		lra := s.LastRunAt.Format(time.RFC3339)
		resp.LastRunAt = &lra
	}

	if s.CreatedBy != nil {
		cb := s.CreatedBy.String()
		resp.CreatedBy = &cb

		// Lookup user name if userRepo is available
		if h.userRepo != nil {
			if u, err := h.userRepo.GetByID(ctx, *s.CreatedBy); err == nil && u != nil {
				name := u.Name()
				resp.CreatedByName = &name
			}
		}
	}

	return resp
}

func toScanStatsResponse(s *scan.Stats) *ScanStatsResponse {
	byScheduleType := make(map[string]int64)
	for k, v := range s.ByScheduleType {
		byScheduleType[string(k)] = v
	}

	byScanType := make(map[string]int64)
	for k, v := range s.ByScanType {
		byScanType[string(k)] = v
	}

	return &ScanStatsResponse{
		Total:          s.Total,
		Active:         s.Active,
		Paused:         s.Paused,
		Disabled:       s.Disabled,
		ByScheduleType: byScheduleType,
		ByScanType:     byScanType,
	}
}

// handleValidationError converts validation errors to API errors.
func (h *ScanHandler) handleValidationError(w http.ResponseWriter, err error) {
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
func (h *ScanHandler) handleServiceError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, shared.ErrNotFound):
		apierror.NotFound("Scan").WriteJSON(w)
	case errors.Is(err, shared.ErrAlreadyExists):
		apierror.Conflict("Scan already exists").WriteJSON(w)
	case errors.Is(err, shared.ErrValidation):
		apierror.BadRequest(err.Error()).WriteJSON(w)
	case errors.Is(err, shared.ErrUnauthorized):
		apierror.Unauthorized("").WriteJSON(w)
	case errors.Is(err, shared.ErrForbidden):
		apierror.Forbidden("").WriteJSON(w)
	default:
		h.logger.Error("service error", "error", err)
		apierror.InternalError(err).WriteJSON(w)
	}
}

// QuickScan performs an immediate scan on provided targets.
// POST /api/v1/quick-scan
func (h *ScanHandler) QuickScan(w http.ResponseWriter, r *http.Request) {
	var req QuickScanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}

	if err := h.validator.Validate(req); err != nil {
		h.handleValidationError(w, err)
		return
	}

	// Get tenant ID from context
	tenantID := middleware.GetTenantID(r.Context())
	if tenantID == "" {
		apierror.BadRequest("tenant_id is required").WriteJSON(w)
		return
	}

	// Get user ID from context
	userID := middleware.GetUserID(r.Context())

	result, err := h.service.QuickScan(r.Context(), scansvc.QuickScanInput{
		TenantID:    tenantID,
		Targets:     req.Targets,
		ScannerName: req.ScannerName,
		WorkflowID:  req.WorkflowID,
		Config:      req.Config,
		Tags:        req.Tags,
		CreatedBy:   userID,
	})
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(QuickScanResponse{
		PipelineRunID: result.PipelineRunID,
		ScanID:        result.ScanID,
		AssetGroupID:  result.AssetGroupID,
		Status:        result.Status,
		TargetCount:   result.TargetCount,
	})
}

// OverviewStatsResponse represents the response for scan management overview stats.
type OverviewStatsResponse struct {
	Pipelines StatusCountsResponse `json:"pipelines"`
	Scans     StatusCountsResponse `json:"scans"`
	Jobs      StatusCountsResponse `json:"jobs"`
}

// StatusCountsResponse represents counts by status.
type StatusCountsResponse struct {
	Total     int64 `json:"total"`
	Running   int64 `json:"running"`
	Pending   int64 `json:"pending"`
	Completed int64 `json:"completed"`
	Failed    int64 `json:"failed"`
	Canceled  int64 `json:"canceled"`
}

// GetOverviewStats handles GET /api/v1/scan-management/stats
func (h *ScanHandler) GetOverviewStats(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.GetTenantID(r.Context())
	if tenantID == "" {
		apierror.BadRequest("tenant_id is required").WriteJSON(w)
		return
	}

	stats, err := h.service.GetOverviewStats(r.Context(), tenantID)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	resp := OverviewStatsResponse{
		Pipelines: StatusCountsResponse{
			Total:     stats.Pipelines.Total,
			Running:   stats.Pipelines.Running,
			Pending:   stats.Pipelines.Pending,
			Completed: stats.Pipelines.Completed,
			Failed:    stats.Pipelines.Failed,
			Canceled:  stats.Pipelines.Canceled,
		},
		Scans: StatusCountsResponse{
			Total:     stats.Scans.Total,
			Running:   stats.Scans.Running,
			Pending:   stats.Scans.Pending,
			Completed: stats.Scans.Completed,
			Failed:    stats.Scans.Failed,
			Canceled:  stats.Scans.Canceled,
		},
		Jobs: StatusCountsResponse{
			Total:     stats.Jobs.Total,
			Running:   stats.Jobs.Running,
			Pending:   stats.Jobs.Pending,
			Completed: stats.Jobs.Completed,
			Failed:    stats.Jobs.Failed,
			Canceled:  stats.Jobs.Canceled,
		},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}
