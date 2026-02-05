package handler

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/openctemio/api/internal/app"
	"github.com/openctemio/api/internal/infra/http/middleware"
	"github.com/openctemio/api/pkg/apierror"
	"github.com/openctemio/api/pkg/domain/exposure"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/logger"
	"github.com/openctemio/api/pkg/validator"
)

// ExposureHandler handles exposure event HTTP requests.
type ExposureHandler struct {
	service     *app.ExposureService
	userService *app.UserService
	validator   *validator.Validator
	logger      *logger.Logger
}

// NewExposureHandler creates a new exposure handler.
func NewExposureHandler(svc *app.ExposureService, userSvc *app.UserService, v *validator.Validator, log *logger.Logger) *ExposureHandler {
	return &ExposureHandler{
		service:     svc,
		userService: userSvc,
		validator:   v,
		logger:      log,
	}
}

// ExposureResponse represents an exposure event in API responses.
type ExposureResponse struct {
	ID string `json:"id"`

	AssetID         string         `json:"asset_id,omitempty"`
	EventType       string         `json:"event_type"`
	Severity        string         `json:"severity"`
	State           string         `json:"state"`
	Title           string         `json:"title"`
	Description     string         `json:"description,omitempty"`
	Details         map[string]any `json:"details,omitempty"`
	Fingerprint     string         `json:"fingerprint"`
	Source          string         `json:"source"`
	FirstSeenAt     time.Time      `json:"first_seen_at"`
	LastSeenAt      time.Time      `json:"last_seen_at"`
	ResolvedAt      *time.Time     `json:"resolved_at,omitempty"`
	ResolvedBy      string         `json:"resolved_by,omitempty"`
	ResolutionNotes string         `json:"resolution_notes,omitempty"`
	CreatedAt       time.Time      `json:"created_at"`
	UpdatedAt       time.Time      `json:"updated_at"`
}

// CreateExposureRequest represents the request to create an exposure event.
type CreateExposureRequest struct {
	AssetID     string         `json:"asset_id" validate:"omitempty,uuid"`
	EventType   string         `json:"event_type" validate:"required"`
	Severity    string         `json:"severity" validate:"required"`
	Title       string         `json:"title" validate:"required,min=1,max=500"`
	Description string         `json:"description" validate:"max=2000"`
	Source      string         `json:"source" validate:"required,max=100"`
	Details     map[string]any `json:"details"`
}

// ChangeStateRequest represents the request to change exposure state.
type ChangeStateRequest struct {
	Reason string `json:"reason" validate:"max=500"`
}

// BulkIngestRequest represents the request to bulk ingest exposures.
type BulkIngestRequest struct {
	Exposures []CreateExposureRequest `json:"exposures" validate:"required,min=1,max=1000,dive"`
}

// StateHistoryResponse represents a state history entry in API responses.
type StateHistoryResponse struct {
	ID            string            `json:"id"`
	PreviousState string            `json:"previous_state"`
	NewState      string            `json:"new_state"`
	ChangedBy     string            `json:"changed_by,omitempty"`
	ChangedByUser *StateHistoryUser `json:"changed_by_user,omitempty"`
	Reason        string            `json:"reason,omitempty"`
	CreatedAt     time.Time         `json:"created_at"`
}

// StateHistoryUser represents the user who changed the state.
type StateHistoryUser struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Email     string `json:"email"`
	AvatarURL string `json:"avatar_url,omitempty"`
}

func toExposureResponse(e *exposure.ExposureEvent) ExposureResponse {
	assetID := ""
	if e.AssetID() != nil {
		assetID = e.AssetID().String()
	}
	resolvedBy := ""
	if e.ResolvedBy() != nil {
		resolvedBy = e.ResolvedBy().String()
	}
	return ExposureResponse{
		ID: e.ID().String(),

		AssetID:         assetID,
		EventType:       e.EventType().String(),
		Severity:        e.Severity().String(),
		State:           e.State().String(),
		Title:           e.Title(),
		Description:     e.Description(),
		Details:         e.Details(),
		Fingerprint:     e.Fingerprint(),
		Source:          e.Source(),
		FirstSeenAt:     e.FirstSeenAt(),
		LastSeenAt:      e.LastSeenAt(),
		ResolvedAt:      e.ResolvedAt(),
		ResolvedBy:      resolvedBy,
		ResolutionNotes: e.ResolutionNotes(),
		CreatedAt:       e.CreatedAt(),
		UpdatedAt:       e.UpdatedAt(),
	}
}

func toStateHistoryResponse(h *exposure.StateHistory) StateHistoryResponse {
	changedBy := ""
	if h.ChangedBy() != nil {
		changedBy = h.ChangedBy().String()
	}
	return StateHistoryResponse{
		ID:            h.ID().String(),
		PreviousState: h.PreviousState().String(),
		NewState:      h.NewState().String(),
		ChangedBy:     changedBy,
		Reason:        h.Reason(),
		CreatedAt:     h.CreatedAt(),
	}
}

// handleValidationError converts validation errors to API errors and writes response.
func (h *ExposureHandler) handleValidationError(w http.ResponseWriter, err error) {
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

// handleServiceError converts service errors to API errors and writes response.
func (h *ExposureHandler) handleServiceError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, shared.ErrNotFound),
		exposure.IsExposureEventNotFound(err):
		apierror.NotFound("exposure event").WriteJSON(w)
	case exposure.IsExposureEventExists(err):
		apierror.Conflict("exposure event already exists").WriteJSON(w)
	case exposure.IsInvalidStateTransition(err):
		apierror.BadRequest(err.Error()).WriteJSON(w)
	case errors.Is(err, shared.ErrValidation):
		apierror.BadRequest(err.Error()).WriteJSON(w)
	default:
		h.logger.Error("exposure handler error", "error", err)
		apierror.InternalError(err).WriteJSON(w)
	}
}

// parseQueryInt64 parses a query parameter as an int64.
// Returns defaultVal if the input is empty or invalid.
func parseQueryInt64(s string, defaultVal int64) int64 {
	if s == "" {
		return defaultVal
	}
	val, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return defaultVal
	}
	return val
}

// Create handles POST /api/v1/exposures
// @Summary      Create exposure
// @Description  Create a new exposure event
// @Tags         Exposures
// @Accept       json
// @Produce      json
// @Param        request  body      CreateExposureRequest  true  "Exposure data"
// @Success      201  {object}  ExposureResponse
// @Failure      400  {object}  apierror.Error
// @Failure      401  {object}  apierror.Error
// @Failure      500  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /exposures [post]
func (h *ExposureHandler) Create(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())

	var req CreateExposureRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}

	if err := h.validator.Validate(req); err != nil {
		h.handleValidationError(w, err)
		return
	}

	input := app.CreateExposureInput{
		TenantID: tenantID,

		AssetID:     req.AssetID,
		EventType:   req.EventType,
		Severity:    req.Severity,
		Title:       req.Title,
		Description: req.Description,
		Source:      req.Source,
		Details:     req.Details,
	}

	event, err := h.service.CreateExposure(r.Context(), input)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(toExposureResponse(event))
}

// Get handles GET /api/v1/exposures/{id}
// @Summary      Get exposure
// @Description  Get a single exposure event by ID
// @Tags         Exposures
// @Accept       json
// @Produce      json
// @Param        id   path      string  true  "Exposure ID"
// @Success      200  {object}  ExposureResponse
// @Failure      400  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Failure      500  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /exposures/{id} [get]
func (h *ExposureHandler) Get(w http.ResponseWriter, r *http.Request) {
	exposureID := chi.URLParam(r, "id")

	event, err := h.service.GetExposure(r.Context(), exposureID)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(toExposureResponse(event))
}

// Delete handles DELETE /api/v1/exposures/{id}
// @Summary      Delete exposure
// @Description  Delete an exposure event
// @Tags         Exposures
// @Accept       json
// @Produce      json
// @Param        id   path      string  true  "Exposure ID"
// @Success      204  "No Content"
// @Failure      400  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Failure      500  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /exposures/{id} [delete]
func (h *ExposureHandler) Delete(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())
	exposureID := chi.URLParam(r, "id")

	if err := h.service.DeleteExposure(r.Context(), exposureID, tenantID); err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// List handles GET /api/v1/exposures
// @Summary      List exposures
// @Description  Get a paginated list of exposure events
// @Tags         Exposures
// @Accept       json
// @Produce      json
// @Param        asset_id    query     string  false  "Filter by asset ID"
// @Param        event_type  query     []string false "Filter by event types"
// @Param        severity    query     []string false "Filter by severities"
// @Param        state       query     []string false "Filter by states"
// @Param        search      query     string  false  "Search term"
// @Param        page        query     int     false  "Page number" default(1)
// @Param        per_page    query     int     false  "Items per page" default(20)
// @Success      200  {object}  ListResponse[ExposureResponse]
// @Failure      400  {object}  apierror.Error
// @Failure      500  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /exposures [get]
func (h *ExposureHandler) List(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())

	query := r.URL.Query()
	input := app.ListExposuresInput{
		TenantID: tenantID,

		AssetID:         query.Get("asset_id"),
		Search:          query.Get("search"),
		FirstSeenAfter:  parseQueryInt64(query.Get("first_seen_after"), 0),
		FirstSeenBefore: parseQueryInt64(query.Get("first_seen_before"), 0),
		LastSeenAfter:   parseQueryInt64(query.Get("last_seen_after"), 0),
		LastSeenBefore:  parseQueryInt64(query.Get("last_seen_before"), 0),
		Page:            parseQueryInt(query.Get("page"), 1),
		PerPage:         parseQueryInt(query.Get("per_page"), 20),
		SortBy:          query.Get("sort_by"),
		SortOrder:       query.Get("sort_order"),
	}

	if types := query["event_type"]; len(types) > 0 {
		input.EventTypes = types
	}
	if sevs := query["severity"]; len(sevs) > 0 {
		input.Severities = sevs
	}
	if states := query["state"]; len(states) > 0 {
		input.States = states
	}
	if sources := query["source"]; len(sources) > 0 {
		input.Sources = sources
	}

	result, err := h.service.ListExposures(r.Context(), input)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	items := make([]ExposureResponse, 0, len(result.Data))
	for _, e := range result.Data {
		items = append(items, toExposureResponse(e))
	}

	response := ListResponse[ExposureResponse]{
		Data:       items,
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

// BulkIngest handles POST /api/v1/exposures/ingest
// @Summary      Bulk ingest exposures
// @Description  Ingest multiple exposure events at once
// @Tags         Exposures
// @Accept       json
// @Produce      json
// @Param        request  body      BulkIngestRequest  true  "Exposures to ingest"
// @Success      201  {object}  map[string]interface{}
// @Failure      400  {object}  apierror.Error
// @Failure      500  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /exposures/ingest [post]
func (h *ExposureHandler) BulkIngest(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())

	var req BulkIngestRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}

	if err := h.validator.Validate(req); err != nil {
		h.handleValidationError(w, err)
		return
	}

	inputs := make([]app.CreateExposureInput, 0, len(req.Exposures))
	for _, exp := range req.Exposures {
		inputs = append(inputs, app.CreateExposureInput{
			TenantID: tenantID,

			AssetID:     exp.AssetID,
			EventType:   exp.EventType,
			Severity:    exp.Severity,
			Title:       exp.Title,
			Description: exp.Description,
			Source:      exp.Source,
			Details:     exp.Details,
		})
	}

	events, err := h.service.BulkIngestExposures(r.Context(), inputs)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	items := make([]ExposureResponse, 0, len(events))
	for _, e := range events {
		items = append(items, toExposureResponse(e))
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"ingested": len(items),
		"items":    items,
	})
}

// Resolve handles POST /api/v1/exposures/{id}/resolve
// @Summary      Resolve exposure
// @Description  Mark an exposure as resolved
// @Tags         Exposures
// @Accept       json
// @Produce      json
// @Param        id       path      string             true   "Exposure ID"
// @Param        request  body      ChangeStateRequest false  "Resolution reason"
// @Success      200  {object}  ExposureResponse
// @Failure      400  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Failure      500  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /exposures/{id}/resolve [post]
func (h *ExposureHandler) Resolve(w http.ResponseWriter, r *http.Request) {
	exposureID := chi.URLParam(r, "id")
	userID := middleware.GetUserID(r.Context())

	var req ChangeStateRequest
	_ = json.NewDecoder(r.Body).Decode(&req) // Optional body

	event, err := h.service.ResolveExposure(r.Context(), exposureID, userID, req.Reason)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(toExposureResponse(event))
}

// Accept handles POST /api/v1/exposures/{id}/accept
// @Summary      Accept exposure
// @Description  Accept an exposure as a known risk
// @Tags         Exposures
// @Accept       json
// @Produce      json
// @Param        id       path      string             true   "Exposure ID"
// @Param        request  body      ChangeStateRequest false  "Accept reason"
// @Success      200  {object}  ExposureResponse
// @Failure      400  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Failure      500  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /exposures/{id}/accept [post]
func (h *ExposureHandler) Accept(w http.ResponseWriter, r *http.Request) {
	exposureID := chi.URLParam(r, "id")
	userID := middleware.GetUserID(r.Context())

	var req ChangeStateRequest
	_ = json.NewDecoder(r.Body).Decode(&req) // Optional body

	event, err := h.service.AcceptExposure(r.Context(), exposureID, userID, req.Reason)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(toExposureResponse(event))
}

// MarkFalsePositive handles POST /api/v1/exposures/{id}/false-positive
// @Summary      Mark as false positive
// @Description  Mark an exposure as a false positive
// @Tags         Exposures
// @Accept       json
// @Produce      json
// @Param        id       path      string             true   "Exposure ID"
// @Param        request  body      ChangeStateRequest false  "Reason"
// @Success      200  {object}  ExposureResponse
// @Failure      400  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Failure      500  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /exposures/{id}/false-positive [post]
func (h *ExposureHandler) MarkFalsePositive(w http.ResponseWriter, r *http.Request) {
	exposureID := chi.URLParam(r, "id")
	userID := middleware.GetUserID(r.Context())

	var req ChangeStateRequest
	_ = json.NewDecoder(r.Body).Decode(&req) // Optional body

	event, err := h.service.MarkFalsePositive(r.Context(), exposureID, userID, req.Reason)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(toExposureResponse(event))
}

// Reactivate handles POST /api/v1/exposures/{id}/reactivate
// @Summary      Reactivate exposure
// @Description  Reactivate a resolved or accepted exposure
// @Tags         Exposures
// @Accept       json
// @Produce      json
// @Param        id   path      string  true  "Exposure ID"
// @Success      200  {object}  ExposureResponse
// @Failure      400  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Failure      500  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /exposures/{id}/reactivate [post]
func (h *ExposureHandler) Reactivate(w http.ResponseWriter, r *http.Request) {
	exposureID := chi.URLParam(r, "id")
	userID := middleware.GetUserID(r.Context())

	event, err := h.service.ReactivateExposure(r.Context(), exposureID, userID)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(toExposureResponse(event))
}

// GetHistory handles GET /api/v1/exposures/{id}/history
// @Summary      Get exposure history
// @Description  Get state change history for an exposure
// @Tags         Exposures
// @Accept       json
// @Produce      json
// @Param        id   path      string  true  "Exposure ID"
// @Success      200  {object}  map[string]interface{}
// @Failure      400  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Failure      500  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /exposures/{id}/history [get]
func (h *ExposureHandler) GetHistory(w http.ResponseWriter, r *http.Request) {
	exposureID := chi.URLParam(r, "id")

	history, err := h.service.GetStateHistory(r.Context(), exposureID)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	// Collect unique user IDs from history entries
	userIDMap := make(map[string]bool)
	var userIDs []shared.ID
	for _, entry := range history {
		if entry.ChangedBy() != nil {
			idStr := entry.ChangedBy().String()
			if !userIDMap[idStr] {
				userIDMap[idStr] = true
				userIDs = append(userIDs, *entry.ChangedBy())
			}
		}
	}

	// Fetch users to enrich history with user info
	userMap := make(map[string]*StateHistoryUser)
	if len(userIDs) > 0 && h.userService != nil {
		users, err := h.userService.GetByIDs(r.Context(), userIDs)
		if err != nil {
			h.logger.Warn("failed to fetch users for history", "error", err)
			// Continue without user info rather than failing
		} else {
			for _, u := range users {
				userMap[u.ID().String()] = &StateHistoryUser{
					ID:        u.ID().String(),
					Name:      u.Name(),
					Email:     u.Email(),
					AvatarURL: u.AvatarURL(),
				}
			}
		}
	}

	// Build response with enriched user info
	items := make([]StateHistoryResponse, 0, len(history))
	for _, entry := range history {
		resp := toStateHistoryResponse(entry)
		if entry.ChangedBy() != nil {
			if userInfo, ok := userMap[entry.ChangedBy().String()]; ok {
				resp.ChangedByUser = userInfo
			}
		}
		items = append(items, resp)
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"items": items,
		"total": len(items),
	})
}

// GetStats handles GET /api/v1/exposures/stats
// @Summary      Get exposure statistics
// @Description  Get aggregated statistics for exposure events
// @Tags         Exposures
// @Accept       json
// @Produce      json
// @Success      200  {object}  map[string]interface{}
// @Failure      401  {object}  apierror.Error
// @Failure      500  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /exposures/stats [get]
func (h *ExposureHandler) GetStats(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())

	stats, err := h.service.GetExposureStats(r.Context(), tenantID)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(stats)
}
