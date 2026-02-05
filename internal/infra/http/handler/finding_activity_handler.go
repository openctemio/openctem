package handler

import (
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/openctemio/api/internal/app"
	"github.com/openctemio/api/internal/infra/http/middleware"
	"github.com/openctemio/api/pkg/apierror"
	"github.com/openctemio/api/pkg/domain/vulnerability"
	"github.com/openctemio/api/pkg/logger"
)

// FindingActivityHandler handles finding activity HTTP requests.
type FindingActivityHandler struct {
	activityService      *app.FindingActivityService
	vulnerabilityService *app.VulnerabilityService
	logger               *logger.Logger
}

// NewFindingActivityHandler creates a new finding activity handler.
func NewFindingActivityHandler(
	actSvc *app.FindingActivityService,
	vulnSvc *app.VulnerabilityService,
	log *logger.Logger,
) *FindingActivityHandler {
	return &FindingActivityHandler{
		activityService:      actSvc,
		vulnerabilityService: vulnSvc,
		logger:               log,
	}
}

// FindingActivityResponse represents a finding activity in API responses.
type FindingActivityResponse struct {
	ID             string                 `json:"id"`
	FindingID      string                 `json:"finding_id"`
	ActivityType   string                 `json:"activity_type"`
	ActorID        *string                `json:"actor_id,omitempty"`
	ActorType      string                 `json:"actor_type"`
	ActorName      string                 `json:"actor_name,omitempty"`
	ActorEmail     string                 `json:"actor_email,omitempty"`
	Changes        map[string]interface{} `json:"changes"`
	Source         string                 `json:"source,omitempty"`
	SourceMetadata map[string]interface{} `json:"source_metadata,omitempty"`
	CreatedAt      time.Time              `json:"created_at"`
}

// toFindingActivityResponse converts a domain activity to API response.
func toFindingActivityResponse(a *vulnerability.FindingActivity) FindingActivityResponse {
	var actorID *string
	if a.ActorID() != nil {
		s := a.ActorID().String()
		actorID = &s
	}

	return FindingActivityResponse{
		ID:             a.ID().String(),
		FindingID:      a.FindingID().String(),
		ActivityType:   string(a.ActivityType()),
		ActorID:        actorID,
		ActorType:      string(a.ActorType()),
		ActorName:      a.ActorName(),
		ActorEmail:     a.ActorEmail(),
		Changes:        a.Changes(),
		Source:         string(a.Source()),
		SourceMetadata: a.SourceMetadata(),
		CreatedAt:      a.CreatedAt(),
	}
}

// ListActivities handles GET /api/v1/findings/{id}/activities
func (h *FindingActivityHandler) ListActivities(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())

	findingID := r.PathValue("id")
	if findingID == "" {
		apierror.BadRequest("Finding ID is required").WriteJSON(w)
		return
	}

	// Security: Pass tenantID for tenant-scoped query (IDOR prevention)
	_, err := h.vulnerabilityService.GetFinding(r.Context(), tenantID, findingID)
	if err != nil {
		h.handleServiceError(w, err, "Finding")
		return
	}

	// Security: Log access for audit trail
	userID := middleware.GetUserID(r.Context())
	h.logger.Info("finding activities accessed",
		"user_id", userID,
		"finding_id", findingID,
		"tenant_id", tenantID,
		"client_ip", r.RemoteAddr,
	)

	// Parse pagination
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	if page < 0 {
		page = 0
	}
	pageSize, _ := strconv.Atoi(r.URL.Query().Get("page_size"))
	if pageSize <= 0 || pageSize > 100 {
		pageSize = 20
	}

	// Parse activity type filter
	var activityTypes []string
	if types := r.URL.Query().Get("activity_types"); types != "" {
		activityTypes = append(activityTypes, types)
	}

	input := app.ListActivitiesInput{
		TenantID:      tenantID, // Security: Required for tenant isolation
		FindingID:     findingID,
		ActivityTypes: activityTypes,
		Page:          page,
		PageSize:      pageSize,
	}

	result, err := h.activityService.ListActivities(r.Context(), input)
	if err != nil {
		h.handleServiceError(w, err, "Activity")
		return
	}

	data := make([]FindingActivityResponse, len(result.Data))
	for i, a := range result.Data {
		data[i] = toFindingActivityResponse(a)
	}

	response := struct {
		Data       []FindingActivityResponse `json:"data"`
		Total      int64                     `json:"total"`
		Page       int                       `json:"page"`
		PageSize   int                       `json:"page_size"`
		TotalPages int                       `json:"total_pages"`
	}{
		Data:       data,
		Total:      result.Total,
		Page:       result.Page,
		PageSize:   result.PerPage,
		TotalPages: result.TotalPages,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(response)
}

// GetActivity handles GET /api/v1/findings/{id}/activities/{activity_id}
func (h *FindingActivityHandler) GetActivity(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())

	findingID := r.PathValue("id")
	activityID := r.PathValue("activity_id")
	if findingID == "" || activityID == "" {
		apierror.BadRequest("Finding ID and Activity ID are required").WriteJSON(w)
		return
	}

	// Security: Pass tenantID for tenant-scoped query (IDOR prevention)
	_, err := h.vulnerabilityService.GetFinding(r.Context(), tenantID, findingID)
	if err != nil {
		h.handleServiceError(w, err, "Finding")
		return
	}

	activity, err := h.activityService.GetActivity(r.Context(), activityID)
	if err != nil {
		h.handleServiceError(w, err, "Activity")
		return
	}

	// Verify activity belongs to the finding
	if activity.FindingID().String() != findingID {
		apierror.NotFound("Activity").WriteJSON(w)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(toFindingActivityResponse(activity))
}

// handleServiceError handles errors from service layer.
func (h *FindingActivityHandler) handleServiceError(w http.ResponseWriter, err error, resource string) {
	// Check for not found errors
	if err.Error() == "activity not found" || err.Error() == "finding not found" {
		apierror.NotFound(resource).WriteJSON(w)
		return
	}

	// Log unexpected errors
	h.logger.Error("service error", "error", err, "resource", resource)
	apierror.InternalServerError("An unexpected error occurred").WriteJSON(w)
}
