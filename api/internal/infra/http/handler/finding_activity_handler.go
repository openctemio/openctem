package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/openctemio/openctem/api/internal/app/activity"
	"github.com/openctemio/openctem/api/internal/app/finding"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// FindingActivityHandler handles finding activity HTTP requests.
type FindingActivityHandler struct {
	activityService      *activity.FindingActivityService
	vulnerabilityService *finding.VulnerabilityService
	logger               *logger.Logger
}

// NewFindingActivityHandler creates a new finding activity handler.
func NewFindingActivityHandler(
	actSvc *activity.FindingActivityService,
	vulnSvc *finding.VulnerabilityService,
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

// clientActivityKeys are the change details a pentest campaign client sees
// per activity type: the status move, and a client-visible comment's text.
// Reasons, notes, assignees and source metadata are the team's.
var clientActivityKeys = map[string][]string{
	"comment_added":   {"comment_id", "content", "preview", "visibility", "deleted"},
	"comment_updated": {"comment_id", "content", "visibility", "deleted"},
	"comment_deleted": {"comment_id", "visibility"},
}

var clientStatusKeys = []string{"old_status", "new_status", "status"}

// clientSafeActivity trims an activity to what a campaign client may read.
func clientSafeActivity(a FindingActivityResponse) FindingActivityResponse {
	keys, ok := clientActivityKeys[a.ActivityType]
	if !ok {
		keys = clientStatusKeys
	}
	changes := make(map[string]any, len(keys))
	for _, k := range keys {
		if v, ok := a.Changes[k]; ok {
			changes[k] = v
		}
	}
	a.Changes = changes
	a.SourceMetadata = nil
	return a
}

// ListActivities handles GET /api/v1/findings/{id}/activities
func (h *FindingActivityHandler) ListActivities(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())

	findingID := r.PathValue("id")
	if findingID == "" {
		apierror.BadRequest("Finding ID is required").WriteJSON(w)
		return
	}

	// Security: scope the existence check to the real caller — GetFinding runs as
	// admin (isAdmin=true, no acting user), which bypasses both the pentest
	// campaign-membership gate and the Layer-2 data-scope check, leaking another
	// campaign's / out-of-scope finding's activity trail to any findings:read user.
	userID := middleware.GetUserID(r.Context())
	// A campaign client of a pentest finding reads the client view of the
	// feed only (no team-only comments or team activity).
	_, access, err := h.vulnerabilityService.AuthorizeFindingRead(r.Context(), tenantID, findingID, userID, middleware.IsAdmin(r.Context()))
	if err != nil {
		h.handleServiceError(w, err, "Finding")
		return
	}

	// Security: Log access for audit trail
	h.logger.Info("finding activities accessed",
		"user_id", userID,
		"finding_id", findingID,
		"tenant_id", tenantID,
		"client_ip", getClientIP(r),
	)

	paging, ok := listPage(w, r, 20)
	if !ok {
		return
	}
	page, pageSize := paging.Page, paging.PerPage

	// Parse activity type filter
	var activityTypes []string
	if types := r.URL.Query().Get("activity_types"); types != "" {
		activityTypes = append(activityTypes, types)
	}

	input := activity.ListActivitiesInput{
		TenantID:      tenantID, // Security: Required for tenant isolation
		FindingID:     findingID,
		ActivityTypes: activityTypes,
		Page:          page,
		PageSize:      pageSize,
		ClientView:    access.ClientOnly,
	}

	result, err := h.activityService.ListActivities(r.Context(), input)
	if err != nil {
		h.handleServiceError(w, err, "Activity")
		return
	}

	data := make([]FindingActivityResponse, len(result.Data))
	deleted := h.deletedComments(r.Context(), tenantID, findingID, result.Data)
	for i, a := range result.Data {
		data[i] = hideDeletedCommentText(toFindingActivityResponse(a), deleted)
		if access.ClientOnly {
			data[i] = clientSafeActivity(data[i])
		}
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

// handleServiceError handles errors from service layer.
func (h *FindingActivityHandler) handleServiceError(w http.ResponseWriter, err error, resource string) {
	switch {
	// FindingNotFoundError / scope-denied wrap shared.ErrNotFound; the activity
	// repo still returns a bare "activity not found" error (legacy) — handle both.
	case errors.Is(err, shared.ErrNotFound), err.Error() == "activity not found":
		apierror.NotFound(resource).WriteJSON(w)
	case errors.Is(err, shared.ErrValidation):
		apierror.BadRequest(cleanErrorMessage(err, "Invalid request")).WriteJSON(w)
	default:
		h.logger.Error("service error", "error", err, "resource", resource)
		apierror.InternalServerError("An unexpected error occurred").WriteJSON(w)
	}
}

// deletedComments returns the ids of the comments on this page of the feed
// that were deleted. On a lookup failure it returns nil and logs: the entries
// then show as stored, never fewer than the caller may read.
func (h *FindingActivityHandler) deletedComments(ctx context.Context, tenantID, findingID string, acts []*vulnerability.FindingActivity) map[string]bool {
	var ids []string
	for _, a := range acts {
		switch a.ActivityType() {
		case vulnerability.ActivityCommentAdded, vulnerability.ActivityCommentUpdated:
			if id, ok := a.Changes()["comment_id"].(string); ok && id != "" {
				ids = append(ids, id)
			}
		}
	}
	if len(ids) == 0 {
		return nil
	}
	set, err := h.activityService.DeletedCommentIDs(ctx, tenantID, findingID, ids)
	if err != nil {
		h.logger.Warn("failed to look up deleted comments", "error", err)
		return nil
	}
	return set
}

// hideDeletedCommentText replaces the text of a deleted comment's original and
// revision entries with a marker. The stored entries are not changed.
func hideDeletedCommentText(a FindingActivityResponse, deleted map[string]bool) FindingActivityResponse {
	if len(deleted) == 0 || (a.ActivityType != "comment_added" && a.ActivityType != "comment_updated") {
		return a
	}
	id, _ := a.Changes["comment_id"].(string)
	if !deleted[id] {
		return a
	}
	changes := make(map[string]any, len(a.Changes))
	for k, v := range a.Changes {
		switch k {
		case "content", "preview", "previous_content":
		default:
			changes[k] = v
		}
	}
	changes["deleted"] = true
	a.Changes = changes
	return a
}
