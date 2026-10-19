package handler

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"

	"github.com/openctemio/openctem/api/internal/app/aitriage"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/apierror"
	aitriagedom "github.com/openctemio/openctem/api/pkg/domain/aitriage"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// AITriageHandler handles AI triage HTTP requests.
// The handler can work with a nil triageService - in that case, it returns 503 Service Unavailable.
// This allows routes to be always registered while feature availability is controlled by:
// 1. Module middleware (checks is_active in database)
// 2. Service availability (checks if LLM provider is configured)
type AITriageHandler struct {
	triageService *aitriage.AITriageService // May be nil if AI triage is not configured
	logger        *logger.Logger
	// bulkAllowance spends one rate-limit unit per finding of a bulk
	// request beyond the first (nil: no limit).
	bulkAllowance func(tenantID string, n int) bool
}

// SetBulkAllowance makes a bulk request count each finding against the
// tenant's AI triage rate limit.
func (h *AITriageHandler) SetBulkAllowance(f func(tenantID string, n int) bool) { h.bulkAllowance = f }

// NewAITriageHandler creates a new AI triage handler.
// triageService can be nil - handler will return 503 for operations that require the service.
func NewAITriageHandler(triageSvc *aitriage.AITriageService, log *logger.Logger) *AITriageHandler {
	return &AITriageHandler{
		triageService: triageSvc,
		logger:        log,
	}
}

// checkServiceAvailable returns true if the AI triage service is available.
// If not available, writes a 200 response with null data and returns false.
// This prevents noisy 503/404 errors when AI triage is simply not configured.
func (h *AITriageHandler) checkServiceAvailable(w http.ResponseWriter) bool {
	if h.triageService == nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"data": nil, "ai_configured": false})
		return false
	}
	return true
}

// =============================================================================
// Request/Response Types
// =============================================================================

// RequestTriageRequest represents a request to trigger AI triage.
type RequestTriageRequest struct {
	Mode string `json:"mode"` // "quick" or "detailed" (optional, defaults to quick)
}

// RequestTriageResponse represents the response from triggering AI triage.
type RequestTriageResponse struct {
	JobID  string `json:"job_id"`
	Status string `json:"status"`
}

// BulkTriageRequest represents a request to triage multiple findings.
type BulkTriageRequest struct {
	FindingIDs []string `json:"finding_ids"`
	Mode       string   `json:"mode"` // "quick" or "detailed" (optional)
}

// BulkTriageResponse represents the response from bulk triage.
type BulkTriageResponse struct {
	Jobs       []BulkTriageJob `json:"jobs"`
	TotalCount int             `json:"total_count"`
	Queued     int             `json:"queued"`
	Failed     int             `json:"failed"`
}

// BulkTriageJob represents a single job in bulk triage response.
type BulkTriageJob struct {
	FindingID string `json:"finding_id"`
	JobID     string `json:"job_id,omitempty"`
	Status    string `json:"status"`
	Error     string `json:"error,omitempty"`
}

// TriageResultResponse represents a triage result in API responses.
type TriageResultResponse struct {
	ID                      string  `json:"id"`
	Status                  string  `json:"status"`
	SeverityAssessment      string  `json:"severity_assessment,omitempty"`
	SeverityJustification   string  `json:"severity_justification,omitempty"`
	RiskScore               float64 `json:"risk_score,omitempty"`
	Exploitability          string  `json:"exploitability,omitempty"`
	ExploitabilityDetails   string  `json:"exploitability_details,omitempty"`
	BusinessImpact          string  `json:"business_impact,omitempty"`
	PriorityRank            int     `json:"priority_rank,omitempty"`
	FalsePositiveLikelihood float64 `json:"false_positive_likelihood,omitempty"`
	FalsePositiveReason     string  `json:"false_positive_reason,omitempty"`
	Summary                 string  `json:"summary,omitempty"`
	CreatedAt               string  `json:"created_at"`
	CompletedAt             string  `json:"completed_at,omitempty"`
	// ErrorCode is the failure code of a failed triage (internal_error,
	// ai_policy_restricted, provider_rate_limited, ...); the web UI
	// translates it. Raw internal error text is never returned.
	ErrorCode string `json:"error_code,omitempty"`
}

// =============================================================================
// Handlers
// =============================================================================

// RequestTriage handles POST /api/v1/findings/{id}/ai-triage
// Triggers AI triage for a finding.
func (h *AITriageHandler) RequestTriage(w http.ResponseWriter, r *http.Request) {
	if !h.checkServiceAvailable(w) {
		return
	}

	tenantID := middleware.MustGetTenantID(r.Context())
	// Use local user ID for activity recording (works with users table JOIN)
	localUserID := middleware.GetLocalUserID(r.Context())
	var userID string
	if !localUserID.IsZero() {
		userID = localUserID.String()
	}

	findingID := r.PathValue("id")
	if findingID == "" {
		apierror.BadRequest("Finding ID is required").WriteJSON(w)
		return
	}

	// Parse optional request body
	var req RequestTriageRequest
	if r.ContentLength > 0 {
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			apierror.BadRequest("Invalid request body").WriteJSON(w)
			return
		}
	}

	// Validate mode field if provided
	if req.Mode != "" && req.Mode != "quick" && req.Mode != "detailed" {
		apierror.BadRequest("Invalid mode: must be 'quick' or 'detailed'").WriteJSON(w)
		return
	}

	h.logger.Info("AI triage requested",
		"tenant_id", logger.SanitizeValue(tenantID),
		"finding_id", logger.SanitizeValue(findingID),
		"user_id", logger.SanitizeValue(userID),
		"mode", logger.SanitizeValue(req.Mode),
	)

	// Request triage
	triageReq := aitriage.TriageRequest{
		TenantID:   tenantID,
		FindingID:  findingID,
		TriageType: "manual",
		UserID:     &userID,
	}

	result, err := h.triageService.RequestTriage(r.Context(), triageReq)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	_ = json.NewEncoder(w).Encode(RequestTriageResponse{
		JobID:  result.JobID,
		Status: result.Status,
	})
}

// GetTriageResult handles GET /api/v1/findings/{id}/ai-triage
// Gets the latest triage result for a finding.
func (h *AITriageHandler) GetTriageResult(w http.ResponseWriter, r *http.Request) {
	if !h.checkServiceAvailable(w) {
		return
	}

	tenantID := middleware.MustGetTenantID(r.Context())

	findingID := r.PathValue("id")
	if findingID == "" {
		apierror.BadRequest("Finding ID is required").WriteJSON(w)
		return
	}

	result, err := h.triageService.GetLatestTriageByFinding(r.Context(), tenantID, findingID)
	if err != nil {
		// "Not found" means no triage has been run yet — return 200 with null data
		// instead of 404, since the finding exists but just hasn't been triaged.
		if errors.Is(err, shared.ErrNotFound) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"data": nil})
			return
		}
		h.handleServiceError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(h.toTriageResponse(result))
}

// GetTriageResultByID handles GET /api/v1/findings/{id}/ai-triage/{triage_id}
// Gets a specific triage result by ID.
func (h *AITriageHandler) GetTriageResultByID(w http.ResponseWriter, r *http.Request) {
	if !h.checkServiceAvailable(w) {
		return
	}

	tenantID := middleware.MustGetTenantID(r.Context())

	findingID := r.PathValue("id")
	triageID := r.PathValue("triageId")
	if findingID == "" || triageID == "" {
		apierror.BadRequest("Finding ID and Triage ID are required").WriteJSON(w)
		return
	}

	result, err := h.triageService.GetTriageResult(r.Context(), tenantID, triageID)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(h.toTriageResponse(result))
}

// ListTriageHistory handles GET /api/v1/findings/{id}/ai-triage/history
// Gets the triage history for a finding.
func (h *AITriageHandler) ListTriageHistory(w http.ResponseWriter, r *http.Request) {
	if !h.checkServiceAvailable(w) {
		return
	}

	tenantID := middleware.MustGetTenantID(r.Context())

	findingID := r.PathValue("id")
	if findingID == "" {
		apierror.BadRequest("Finding ID is required").WriteJSON(w)
		return
	}

	paging, ok := listPage(w, r, 20)
	if !ok {
		return
	}
	limit, offset := paging.Limit(), paging.Offset()

	results, total, err := h.triageService.ListTriageHistory(r.Context(), tenantID, findingID, limit, offset)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	data := make([]TriageResultResponse, len(results))
	for i, r := range results {
		data[i] = h.toTriageResponse(r)
	}

	response := struct {
		Data    []TriageResultResponse `json:"data"`
		Total   int                    `json:"total"`
		Page    int                    `json:"page"`
		PerPage int                    `json:"per_page"`
	}{
		Data:    data,
		Total:   total,
		Page:    paging.Page,
		PerPage: paging.PerPage,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(response)
}

// RequestBulkTriage handles POST /api/v1/findings/ai-triage/bulk
// Triggers AI triage for multiple findings.
// Limits: max 100 findings, max 64KB payload size.
func (h *AITriageHandler) RequestBulkTriage(w http.ResponseWriter, r *http.Request) {
	if !h.checkServiceAvailable(w) {
		return
	}

	tenantID := middleware.MustGetTenantID(r.Context())
	// Use local user ID for activity recording (works with users table JOIN)
	localUserID := middleware.GetLocalUserID(r.Context())
	var userID string
	if !localUserID.IsZero() {
		userID = localUserID.String()
	}

	// SECURITY: Limit payload size to prevent DoS (64KB should be enough for 100 UUIDs)
	const maxBulkPayloadSize = 64 * 1024 // 64KB
	if r.ContentLength > maxBulkPayloadSize {
		apierror.BadRequest("Request payload too large. Maximum size is 64KB.").WriteJSON(w)
		return
	}

	// Use LimitReader as additional protection (ContentLength can be spoofed)
	limitedReader := http.MaxBytesReader(w, r.Body, maxBulkPayloadSize)
	var req BulkTriageRequest
	if err := json.NewDecoder(limitedReader).Decode(&req); err != nil {
		if err.Error() == "http: request body too large" {
			apierror.BadRequest("Request payload too large. Maximum size is 64KB.").WriteJSON(w)
			return
		}
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}

	if len(req.FindingIDs) == 0 {
		apierror.BadRequest("At least one finding ID is required").WriteJSON(w)
		return
	}

	if len(req.FindingIDs) > 100 {
		apierror.BadRequest("Maximum 100 findings per bulk request").WriteJSON(w)
		return
	}

	// Validate mode field if provided
	if req.Mode != "" && req.Mode != "quick" && req.Mode != "detailed" {
		apierror.BadRequest("Invalid mode: must be 'quick' or 'detailed'").WriteJSON(w)
		return
	}

	// Validate all finding IDs are valid UUIDs (prevents injection)
	for i, id := range req.FindingIDs {
		if len(id) != 36 { // UUID format: 8-4-4-4-12 = 36 chars
			apierror.BadRequest("Invalid finding ID format at index " + strconv.Itoa(i)).WriteJSON(w)
			return
		}
	}

	// Each finding is one AI call: the request spent one unit of the
	// tenant's allowance, the other findings spend the rest.
	if h.bulkAllowance != nil && !h.bulkAllowance(tenantID, len(req.FindingIDs)-1) {
		w.Header().Set("Retry-After", "60")
		apierror.TooManyRequests("Too many AI triage requests: each finding of a bulk request counts toward the limit. Send fewer findings, or wait a minute.").WriteJSON(w)
		return
	}

	h.logger.Info("Bulk AI triage requested",
		"tenant_id", tenantID,
		"count", len(req.FindingIDs),
		"user_id", userID,
	)

	// Request bulk triage
	bulkReq := aitriage.BulkTriageRequest{
		TenantID:   tenantID,
		FindingIDs: req.FindingIDs,
		UserID:     &userID,
	}

	result, err := h.triageService.RequestBulkTriage(r.Context(), bulkReq)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	// Convert to response
	resp := BulkTriageResponse{
		Jobs:       make([]BulkTriageJob, len(result.Jobs)),
		TotalCount: result.TotalCount,
		Queued:     result.Queued,
		Failed:     result.Failed,
	}
	for i, job := range result.Jobs {
		resp.Jobs[i] = BulkTriageJob{
			FindingID: job.FindingID,
			JobID:     job.JobID,
			Status:    job.Status,
			Error:     job.Error,
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	_ = json.NewEncoder(w).Encode(resp)
}

// =============================================================================
// Helpers
// =============================================================================

func (h *AITriageHandler) toTriageResponse(r *aitriage.TriageResultResponse) TriageResultResponse {
	resp := TriageResultResponse{
		ID:                      r.ID,
		Status:                  r.Status,
		SeverityAssessment:      r.SeverityAssessment,
		SeverityJustification:   r.SeverityJustification,
		RiskScore:               r.RiskScore,
		Exploitability:          r.Exploitability,
		ExploitabilityDetails:   r.ExploitabilityDetails,
		BusinessImpact:          r.BusinessImpact,
		PriorityRank:            r.PriorityRank,
		FalsePositiveLikelihood: r.FalsePositiveLikelihood,
		FalsePositiveReason:     r.FalsePositiveReason,
		Summary:                 r.Summary,
		CreatedAt:               r.CreatedAt.Format("2006-01-02T15:04:05Z"),
		ErrorCode:               r.ErrorCode,
	}
	if r.CompletedAt != nil {
		resp.CompletedAt = r.CompletedAt.Format("2006-01-02T15:04:05Z")
	}
	return resp
}

// Error codes of the AI triage answers the web UI acts on (it shows the
// reason and the place to fix it).
const (
	// aiErrPlatformNotConfigured: platform AI is not set up (the platform
	// administrator sets it up in the console).
	aiErrPlatformNotConfigured apierror.Code = "AI_PLATFORM_NOT_CONFIGURED"
	// aiErrDisabled: AI triage is off for the organization (an organization
	// administrator turns it on in Settings > AI).
	aiErrDisabled apierror.Code = "AI_DISABLED"
	// aiErrPolicyRestricted: the organization's AI data policy keeps this
	// finding on the platform (pentest TLP limit, campaign with AI off).
	aiErrPolicyRestricted apierror.Code = "AI_POLICY_RESTRICTED"
)

func (h *AITriageHandler) handleServiceError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, aitriage.ErrPlatformAINotSetUp):
		apierror.New(http.StatusServiceUnavailable, aiErrPlatformNotConfigured,
			"AI is not set up on this installation. A platform administrator sets up the AI provider in the console.").WriteJSON(w)

	case errors.Is(err, aitriage.ErrAIDisabled):
		apierror.New(http.StatusForbidden, aiErrDisabled,
			"AI triage is turned off for this organization. An organization administrator turns it on in Settings > AI.").WriteJSON(w)

	case errors.Is(err, aitriage.ErrPolicyRestricted):
		apierror.New(http.StatusForbidden, aiErrPolicyRestricted,
			"Your organization's AI data policy keeps this finding away from AI (pentest campaign above the TLP limit for AI, or AI turned off for the campaign).").WriteJSON(w)

	case errors.Is(err, aitriagedom.ErrDuplicateRequest):
		apierror.Conflict("A triage request is already in progress for this finding").WriteJSON(w)

	case errors.Is(err, shared.ErrNotFound):
		apierror.NotFound("Triage result").WriteJSON(w)

	case errors.Is(err, shared.ErrValidation):
		apierror.BadRequest("Invalid request").WriteJSON(w)

	case errors.Is(err, shared.ErrForbidden):
		apierror.Forbidden("You don't have permission to access AI triage for this resource").WriteJSON(w)

	default:
		h.logger.Error("service error", "error", err)
		apierror.InternalServerError("AI triage failed. Please try again later.").WriteJSON(w)
	}
}

// GetConfig handles GET /api/v1/ai-triage/config
// Returns the AI configuration info for the current tenant.
// If service is not available, returns a disabled config instead of error.
func (h *AITriageHandler) GetConfig(w http.ResponseWriter, r *http.Request) {
	// For config endpoint, if service is not available, return disabled config
	// This allows UI to check feature availability without getting an error
	if h.triageService == nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"mode":                   "disabled",
			"provider":               "",
			"model":                  "",
			"is_enabled":             false,
			"auto_triage_enabled":    false,
			"auto_triage_severities": nil,
			"monthly_token_limit":    0,
			"tokens_used_this_month": 0,
		})
		return
	}

	tenantID := middleware.MustGetTenantID(r.Context())

	config, err := h.triageService.GetAIConfig(r.Context(), tenantID)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(config)
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsImpl(s, substr))
}

func containsImpl(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
