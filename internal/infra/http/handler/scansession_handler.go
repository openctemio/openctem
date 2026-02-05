package handler

import (
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/openctemio/api/internal/app"
	"github.com/openctemio/api/internal/infra/http/middleware"
	"github.com/openctemio/api/pkg/apierror"
	"github.com/openctemio/api/pkg/domain/scansession"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/logger"
	"github.com/openctemio/api/pkg/pagination"
	"github.com/openctemio/api/pkg/validator"
)

// ScanSessionHandler handles scan session HTTP requests.
type ScanSessionHandler struct {
	service   *app.ScanSessionService
	validator *validator.Validator
	logger    *logger.Logger
}

// NewScanSessionHandler creates a new ScanSessionHandler.
func NewScanSessionHandler(svc *app.ScanSessionService, v *validator.Validator, log *logger.Logger) *ScanSessionHandler {
	return &ScanSessionHandler{
		service:   svc,
		validator: v,
		logger:    log,
	}
}

// ScanSessionResponse represents a scan session in API responses.
type ScanSessionResponse struct {
	ID             string         `json:"id"`
	TenantID       string         `json:"tenant_id,omitempty"`
	AgentID        string         `json:"agent_id,omitempty"`
	ScannerName    string         `json:"scanner_name"`
	ScannerVersion string         `json:"scanner_version,omitempty"`
	ScannerType    string         `json:"scanner_type,omitempty"`
	AssetType      string         `json:"asset_type"`
	AssetValue     string         `json:"asset_value"`
	AssetID        string         `json:"asset_id,omitempty"`
	CommitSha      string         `json:"commit_sha,omitempty"`
	Branch         string         `json:"branch,omitempty"`
	BaseCommitSha  string         `json:"base_commit_sha,omitempty"`
	Status         string         `json:"status"`
	ErrorMessage   string         `json:"error_message,omitempty"`
	FindingsTotal  int            `json:"findings_total"`
	FindingsNew    int            `json:"findings_new"`
	FindingsFixed  int            `json:"findings_fixed"`
	FindingsBySev  map[string]int `json:"findings_by_severity,omitempty"`
	StartedAt      *time.Time     `json:"started_at,omitempty"`
	CompletedAt    *time.Time     `json:"completed_at,omitempty"`
	DurationMs     int64          `json:"duration_ms,omitempty"`
	CreatedAt      time.Time      `json:"created_at"`
}

func toScanSessionResponse(s *scansession.ScanSession) ScanSessionResponse {
	resp := ScanSessionResponse{
		ID:             s.ID.String(),
		TenantID:       s.TenantID.String(),
		ScannerName:    s.ScannerName,
		ScannerVersion: s.ScannerVersion,
		ScannerType:    s.ScannerType,
		AssetType:      s.AssetType,
		AssetValue:     s.AssetValue,
		CommitSha:      s.CommitSha,
		Branch:         s.Branch,
		BaseCommitSha:  s.BaseCommitSha,
		Status:         string(s.Status),
		ErrorMessage:   s.ErrorMessage,
		FindingsTotal:  s.FindingsTotal,
		FindingsNew:    s.FindingsNew,
		FindingsFixed:  s.FindingsFixed,
		FindingsBySev:  s.FindingsBySeverity,
		StartedAt:      s.StartedAt,
		CompletedAt:    s.CompletedAt,
		DurationMs:     s.DurationMs,
		CreatedAt:      s.CreatedAt,
	}

	if s.AgentID != nil {
		resp.AgentID = s.AgentID.String()
	}
	if s.AssetID != nil {
		resp.AssetID = s.AssetID.String()
	}

	return resp
}

// RegisterScanRequest represents the request to register a scan.
type RegisterScanRequest struct {
	ScannerName    string `json:"scanner_name" validate:"required"`
	ScannerVersion string `json:"scanner_version"`
	ScannerType    string `json:"scanner_type"`
	AssetType      string `json:"asset_type" validate:"required"`
	AssetValue     string `json:"asset_value" validate:"required"`
	CommitSha      string `json:"commit_sha"`
	Branch         string `json:"branch"`
}

// RegisterScanResponse represents the response from registering a scan.
type RegisterScanResponse struct {
	ScanID        string `json:"scan_id"`
	BaseCommitSha string `json:"base_commit_sha,omitempty"`
	ScanURL       string `json:"scan_url,omitempty"`
}

// RegisterScan handles POST /api/v1/agent/scans
// @Summary      Register scan session
// @Description  Agent registers a new scan session before starting a scan
// @Tags         Agent
// @Accept       json
// @Produce      json
// @Param        request  body      RegisterScanRequest  true  "Scan registration data"
// @Success      201  {object}  RegisterScanResponse
// @Failure      400  {object}  apierror.Error
// @Failure      401  {object}  apierror.Error
// @Failure      500  {object}  apierror.Error
// @Security     ApiKeyAuth
// @Router       /agent/scans [post]
func (h *ScanSessionHandler) RegisterScan(w http.ResponseWriter, r *http.Request) {
	agt := AgentFromContext(r.Context())
	if agt == nil {
		apierror.Unauthorized("Agent not authenticated").WriteJSON(w)
		return
	}

	var req RegisterScanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}

	if err := h.validator.Validate(req); err != nil {
		apierror.BadRequest(err.Error()).WriteJSON(w)
		return
	}

	output, err := h.service.RegisterScan(r.Context(), agt, app.RegisterScanInput{
		ScannerName:    req.ScannerName,
		ScannerVersion: req.ScannerVersion,
		ScannerType:    req.ScannerType,
		AssetType:      req.AssetType,
		AssetValue:     req.AssetValue,
		CommitSha:      req.CommitSha,
		Branch:         req.Branch,
	})
	if err != nil {
		h.logger.Error("failed to register scan", "error", err)
		apierror.InternalError(err).WriteJSON(w)
		return
	}

	resp := RegisterScanResponse{
		ScanID:        output.ScanID,
		BaseCommitSha: output.BaseCommitSha,
		ScanURL:       output.ScanURL,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(resp)
}

// UpdateScanSessionRequest represents the request to update a scan session.
type UpdateScanSessionRequest struct {
	Status             string         `json:"status" validate:"required,oneof=completed failed canceled"`
	ErrorMessage       string         `json:"error_message"`
	FindingsTotal      int            `json:"findings_total"`
	FindingsNew        int            `json:"findings_new"`
	FindingsFixed      int            `json:"findings_fixed"`
	FindingsBySeverity map[string]int `json:"findings_by_severity"`
}

// UpdateScan handles PATCH /api/v1/agent/scans/{id}
// @Summary      Update scan session
// @Description  Agent updates scan status after completion
// @Tags         Agent
// @Accept       json
// @Produce      json
// @Param        id       path      string                    true  "Scan session ID"
// @Param        request  body      UpdateScanSessionRequest  true  "Update data"
// @Success      200  {object}  map[string]string
// @Failure      400  {object}  apierror.Error
// @Failure      401  {object}  apierror.Error
// @Failure      500  {object}  apierror.Error
// @Security     ApiKeyAuth
// @Router       /agent/scans/{id} [patch]
func (h *ScanSessionHandler) UpdateScan(w http.ResponseWriter, r *http.Request) {
	agt := AgentFromContext(r.Context())
	if agt == nil {
		apierror.Unauthorized("Agent not authenticated").WriteJSON(w)
		return
	}

	scanID := chi.URLParam(r, "id")
	if scanID == "" {
		apierror.BadRequest("scan_id is required").WriteJSON(w)
		return
	}

	var req UpdateScanSessionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}

	if err := h.validator.Validate(req); err != nil {
		apierror.BadRequest(err.Error()).WriteJSON(w)
		return
	}

	err := h.service.UpdateScanSession(r.Context(), agt, scanID, app.UpdateScanSessionInput{
		Status:             req.Status,
		ErrorMessage:       req.ErrorMessage,
		FindingsTotal:      req.FindingsTotal,
		FindingsNew:        req.FindingsNew,
		FindingsFixed:      req.FindingsFixed,
		FindingsBySeverity: req.FindingsBySeverity,
	})
	if err != nil {
		h.logger.Error("failed to update scan", "error", err)
		apierror.InternalError(err).WriteJSON(w)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "updated"})
}

// GetScan handles GET /api/v1/agent/scans/{id}
// @Summary      Get scan session (agent)
// @Description  Agent retrieves scan session details
// @Tags         Agent
// @Accept       json
// @Produce      json
// @Param        id   path      string  true  "Scan session ID"
// @Success      200  {object}  ScanSessionResponse
// @Failure      400  {object}  apierror.Error
// @Failure      401  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Failure      500  {object}  apierror.Error
// @Security     ApiKeyAuth
// @Router       /agent/scans/{id} [get]
func (h *ScanSessionHandler) GetScan(w http.ResponseWriter, r *http.Request) {
	agt := AgentFromContext(r.Context())
	if agt == nil {
		apierror.Unauthorized("Agent not authenticated").WriteJSON(w)
		return
	}

	// Platform agents must have tenant context
	if agt.TenantID == nil {
		apierror.Forbidden("Platform agents require job context for this operation").WriteJSON(w)
		return
	}
	tenantID := *agt.TenantID

	scanID := chi.URLParam(r, "id")
	if scanID == "" {
		apierror.BadRequest("scan_id is required").WriteJSON(w)
		return
	}

	session, err := h.service.GetScan(r.Context(), tenantID, scanID)
	if err != nil {
		h.logger.Error("failed to get scan", "error", err)
		apierror.InternalError(err).WriteJSON(w)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(toScanSessionResponse(session))
}

// List handles GET /api/v1/scan-sessions (admin interface)
// @Summary      List scan sessions
// @Description  Get a paginated list of scan sessions for the tenant
// @Tags         Scan Sessions
// @Accept       json
// @Produce      json
// @Param        scanner_name  query     string  false  "Filter by scanner name"
// @Param        asset_type    query     string  false  "Filter by asset type"
// @Param        status        query     string  false  "Filter by status"
// @Param        page          query     int     false  "Page number" default(1)
// @Param        per_page      query     int     false  "Items per page" default(20)
// @Success      200  {object}  ListResponse[ScanSessionResponse]
// @Failure      400  {object}  apierror.Error
// @Failure      500  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /scan-sessions [get]
func (h *ScanSessionHandler) List(w http.ResponseWriter, r *http.Request) {
	tenantIDStr := middleware.GetTenantID(r.Context())
	tenantID, err := shared.IDFromString(tenantIDStr)
	if err != nil {
		apierror.BadRequest("Invalid tenant ID").WriteJSON(w)
		return
	}

	query := r.URL.Query()
	input := app.ListScanSessionsInput{
		ScannerName: query.Get("scanner_name"),
		AssetType:   query.Get("asset_type"),
		AssetValue:  query.Get("asset_value"),
		Branch:      query.Get("branch"),
		Status:      query.Get("status"),
	}

	page := pagination.New(
		parseInt(query.Get("page"), 1),
		parseInt(query.Get("per_page"), 20),
	)

	result, err := h.service.ListScanSessions(r.Context(), tenantID, input, page)
	if err != nil {
		h.logger.Error("failed to list scan sessions", "error", err)
		apierror.InternalError(err).WriteJSON(w)
		return
	}

	// Convert to response
	items := make([]ScanSessionResponse, len(result.Data))
	for i, s := range result.Data {
		items[i] = toScanSessionResponse(s)
	}

	resp := pagination.NewResult(items, result.Total, page)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// Get handles GET /api/v1/scan-sessions/{id} (admin interface)
// @Summary      Get scan session
// @Description  Get a single scan session by ID
// @Tags         Scan Sessions
// @Accept       json
// @Produce      json
// @Param        id   path      string  true  "Scan session ID"
// @Success      200  {object}  ScanSessionResponse
// @Failure      400  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Failure      500  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /scan-sessions/{id} [get]
func (h *ScanSessionHandler) Get(w http.ResponseWriter, r *http.Request) {
	tenantIDStr := middleware.GetTenantID(r.Context())
	tenantID, err := shared.IDFromString(tenantIDStr)
	if err != nil {
		apierror.BadRequest("Invalid tenant ID").WriteJSON(w)
		return
	}

	scanID := chi.URLParam(r, "id")

	session, err := h.service.GetScan(r.Context(), tenantID, scanID)
	if err != nil {
		h.logger.Error("failed to get scan session", "error", err)
		apierror.InternalError(err).WriteJSON(w)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(toScanSessionResponse(session))
}

// GetStats handles GET /api/v1/scan-sessions/stats (admin interface)
// @Summary      Get scan session statistics
// @Description  Get aggregated scan session statistics
// @Tags         Scan Sessions
// @Accept       json
// @Produce      json
// @Param        since  query     string  false  "Start date (RFC3339 format)"
// @Success      200  {object}  map[string]interface{}
// @Failure      400  {object}  apierror.Error
// @Failure      500  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /scan-sessions/stats [get]
func (h *ScanSessionHandler) GetStats(w http.ResponseWriter, r *http.Request) {
	tenantIDStr := middleware.GetTenantID(r.Context())
	tenantID, err := shared.IDFromString(tenantIDStr)
	if err != nil {
		apierror.BadRequest("Invalid tenant ID").WriteJSON(w)
		return
	}

	// Default to last 30 days
	since := time.Now().AddDate(0, 0, -30)
	if sinceStr := r.URL.Query().Get("since"); sinceStr != "" {
		if t, err := time.Parse(time.RFC3339, sinceStr); err == nil {
			since = t
		}
	}

	stats, err := h.service.GetStats(r.Context(), tenantID, since)
	if err != nil {
		h.logger.Error("failed to get stats", "error", err)
		apierror.InternalError(err).WriteJSON(w)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats)
}

// Delete handles DELETE /api/v1/scan-sessions/{id} (admin interface)
// @Summary      Delete scan session
// @Description  Delete a scan session
// @Tags         Scan Sessions
// @Accept       json
// @Produce      json
// @Param        id   path      string  true  "Scan session ID"
// @Success      204  "No Content"
// @Failure      400  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Failure      500  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /scan-sessions/{id} [delete]
func (h *ScanSessionHandler) Delete(w http.ResponseWriter, r *http.Request) {
	tenantIDStr := middleware.GetTenantID(r.Context())
	tenantID, err := shared.IDFromString(tenantIDStr)
	if err != nil {
		apierror.BadRequest("Invalid tenant ID").WriteJSON(w)
		return
	}

	scanID := chi.URLParam(r, "id")

	err = h.service.DeleteScan(r.Context(), tenantID, scanID)
	if err != nil {
		h.logger.Error("failed to delete scan session", "error", err)
		apierror.InternalError(err).WriteJSON(w)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// parseInt parses an integer with a default value.
func parseInt(s string, defaultVal int) int {
	if s == "" {
		return defaultVal
	}
	v, err := strconv.Atoi(s)
	if err != nil {
		return defaultVal
	}
	return v
}
