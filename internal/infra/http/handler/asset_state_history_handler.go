package handler

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/openctemio/api/internal/infra/http/middleware"
	"github.com/openctemio/api/pkg/apierror"
	"github.com/openctemio/api/pkg/domain/asset"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/logger"
	"github.com/openctemio/api/pkg/validator"
)

// AssetStateHistoryHandler handles asset state history-related HTTP requests.
type AssetStateHistoryHandler struct {
	repo      asset.StateHistoryRepository
	assetRepo asset.Repository
	validator *validator.Validator
	logger    *logger.Logger
}

// NewAssetStateHistoryHandler creates a new asset state history handler.
func NewAssetStateHistoryHandler(repo asset.StateHistoryRepository, assetRepo asset.Repository, v *validator.Validator, log *logger.Logger) *AssetStateHistoryHandler {
	return &AssetStateHistoryHandler{
		repo:      repo,
		assetRepo: assetRepo,
		validator: v,
		logger:    log,
	}
}

// =============================================================================
// Response Types
// =============================================================================

// StateChangeResponse represents a state change in API responses.
type StateChangeResponse struct {
	ID         string    `json:"id"`
	TenantID   string    `json:"tenant_id,omitempty"`
	AssetID    string    `json:"asset_id"`
	ChangeType string    `json:"change_type"`
	Field      string    `json:"field,omitempty"`
	OldValue   string    `json:"old_value,omitempty"`
	NewValue   string    `json:"new_value,omitempty"`
	Reason     string    `json:"reason,omitempty"`
	Source     string    `json:"source"`
	ChangedBy  *string   `json:"changed_by,omitempty"`
	ChangedAt  time.Time `json:"changed_at"`
	Metadata   string    `json:"metadata,omitempty"`
	CreatedAt  time.Time `json:"created_at"`
}

// DailyActivityResponse represents daily activity counts.
type DailyActivityResponse struct {
	Date           string `json:"date"`
	Appeared       int    `json:"appeared"`
	Disappeared    int    `json:"disappeared"`
	Recovered      int    `json:"recovered"`
	ExposureChange int    `json:"exposure_change"`
	OtherChanges   int    `json:"other_changes"`
	Total          int    `json:"total"`
}

// StateHistoryStatsResponse represents state history statistics.
type StateHistoryStatsResponse struct {
	TypeCounts   map[string]int `json:"type_counts"`
	SourceCounts map[string]int `json:"source_counts"`
}

// =============================================================================
// Handlers
// =============================================================================

// ListByAsset handles GET /api/v1/assets/{id}/state-history
// @Summary      List state history for an asset
// @Description  Retrieves all state changes for a specific asset with optional filtering
// @Tags         Asset State History
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        id path string true "Asset ID (UUID)"
// @Param        change_type query string false "Filter by change type"
// @Param        source query string false "Filter by source"
// @Param        from query string false "Start time (RFC3339)"
// @Param        to query string false "End time (RFC3339)"
// @Param        limit query int false "Maximum results (max 1000)" default(50)
// @Param        offset query int false "Pagination offset" default(0)
// @Success      200  {object}  object{data=[]StateChangeResponse,total=int,limit=int,offset=int}
// @Failure      400  {object}  apierror.Error
// @Failure      401  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Failure      500  {object}  apierror.Error
// @Router       /assets/{id}/state-history [get]
func (h *AssetStateHistoryHandler) ListByAsset(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	tenantIDStr := middleware.MustGetTenantID(ctx)
	tenantID, err := shared.IDFromString(tenantIDStr)
	if err != nil {
		apierror.Unauthorized("Invalid tenant ID").WriteJSON(w)
		return
	}

	assetIDStr := r.PathValue("id")
	assetID, err := shared.IDFromString(assetIDStr)
	if err != nil {
		apierror.BadRequest("Invalid asset ID").WriteJSON(w)
		return
	}

	// Security: Verify asset exists and belongs to the tenant (tenant-scoped query)
	_, err = h.assetRepo.GetByID(ctx, tenantID, assetID)
	if err != nil {
		if errors.Is(err, shared.ErrNotFound) {
			apierror.NotFound("Asset").WriteJSON(w)
			return
		}
		h.logger.Error("failed to verify asset existence", "error", err, "asset_id", assetIDStr)
		apierror.InternalError(err).WriteJSON(w)
		return
	}

	opts := h.parseListOptions(r)

	changes, total, err := h.repo.GetByAssetID(ctx, tenantID, assetID, opts)
	if err != nil {
		h.logger.Error("failed to get state history by asset", "error", err, "asset_id", assetIDStr)
		apierror.InternalError(err).WriteJSON(w)
		return
	}

	response := make([]StateChangeResponse, len(changes))
	for i, change := range changes {
		response[i] = toStateChangeResponse(change)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"data":   response,
		"total":  total,
		"limit":  opts.Limit,
		"offset": opts.Offset,
	})
}

// List handles GET /api/v1/state-history
// @Summary      List all state history
// @Description  Retrieves a paginated list of all state changes for the tenant with optional filtering
// @Tags         Asset State History
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        change_type query string false "Filter by change type"
// @Param        source query string false "Filter by source"
// @Param        from query string false "Start time (RFC3339)"
// @Param        to query string false "End time (RFC3339)"
// @Param        limit query int false "Maximum results (max 1000)" default(50)
// @Param        offset query int false "Pagination offset" default(0)
// @Success      200  {object}  object{data=[]StateChangeResponse,total=int,limit=int,offset=int}
// @Failure      401  {object}  apierror.Error
// @Failure      500  {object}  apierror.Error
// @Router       /state-history [get]
func (h *AssetStateHistoryHandler) List(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	tenantIDStr := middleware.MustGetTenantID(ctx)
	tenantID, err := shared.IDFromString(tenantIDStr)
	if err != nil {
		apierror.Unauthorized("Invalid tenant ID").WriteJSON(w)
		return
	}

	opts := h.parseListOptions(r)

	changes, total, err := h.repo.List(ctx, tenantID, opts)
	if err != nil {
		h.logger.Error("failed to list state history", "error", err)
		apierror.InternalError(err).WriteJSON(w)
		return
	}

	response := make([]StateChangeResponse, len(changes))
	for i, change := range changes {
		response[i] = toStateChangeResponse(change)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"data":   response,
		"total":  total,
		"limit":  opts.Limit,
		"offset": opts.Offset,
	})
}

// Get handles GET /api/v1/state-history/{id}
// @Summary      Get state change by ID
// @Description  Retrieves a specific state change entry by its unique identifier
// @Tags         Asset State History
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        id path string true "State change ID (UUID)"
// @Success      200  {object}  StateChangeResponse
// @Failure      400  {object}  apierror.Error
// @Failure      401  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Failure      500  {object}  apierror.Error
// @Router       /state-history/{id} [get]
func (h *AssetStateHistoryHandler) Get(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	tenantIDStr := middleware.MustGetTenantID(ctx)
	tenantID, err := shared.IDFromString(tenantIDStr)
	if err != nil {
		apierror.Unauthorized("Invalid tenant ID").WriteJSON(w)
		return
	}

	changeIDStr := r.PathValue("id")
	changeID, err := shared.IDFromString(changeIDStr)
	if err != nil {
		apierror.BadRequest("Invalid change ID").WriteJSON(w)
		return
	}

	change, err := h.repo.GetByID(ctx, tenantID, changeID)
	if err != nil {
		if errors.Is(err, shared.ErrNotFound) {
			apierror.NotFound("State change").WriteJSON(w)
			return
		}
		h.logger.Error("failed to get state change", "error", err)
		apierror.InternalError(err).WriteJSON(w)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(toStateChangeResponse(change))
}

// RecentAppearances handles GET /api/v1/state-history/appearances
// @Summary      Get recent asset appearances
// @Description  Retrieves recently discovered assets (new assets appearing in scans)
// @Tags         Asset State History
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        since query string false "Start time (RFC3339, default: 7 days ago)"
// @Param        limit query int false "Maximum results (max 1000)" default(100)
// @Success      200  {object}  object{data=[]StateChangeResponse,total=int,since=string}
// @Failure      401  {object}  apierror.Error
// @Failure      500  {object}  apierror.Error
// @Router       /state-history/appearances [get]
func (h *AssetStateHistoryHandler) RecentAppearances(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	tenantIDStr := middleware.MustGetTenantID(ctx)
	tenantID, err := shared.IDFromString(tenantIDStr)
	if err != nil {
		apierror.Unauthorized("Invalid tenant ID").WriteJSON(w)
		return
	}

	since, limit := h.parseSinceAndLimit(r)

	changes, err := h.repo.GetRecentAppearances(ctx, tenantID, since, limit)
	if err != nil {
		h.logger.Error("failed to get recent appearances", "error", err)
		apierror.InternalError(err).WriteJSON(w)
		return
	}

	response := make([]StateChangeResponse, len(changes))
	for i, change := range changes {
		response[i] = toStateChangeResponse(change)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"data":  response,
		"total": len(response),
		"since": since.Format(time.RFC3339),
	})
}

// RecentDisappearances handles GET /api/v1/state-history/disappearances
// @Summary      Get recent asset disappearances
// @Description  Retrieves assets that have disappeared (no longer seen in scans)
// @Tags         Asset State History
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        since query string false "Start time (RFC3339, default: 7 days ago)"
// @Param        limit query int false "Maximum results (max 1000)" default(100)
// @Success      200  {object}  object{data=[]StateChangeResponse,total=int,since=string}
// @Failure      401  {object}  apierror.Error
// @Failure      500  {object}  apierror.Error
// @Router       /state-history/disappearances [get]
func (h *AssetStateHistoryHandler) RecentDisappearances(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	tenantIDStr := middleware.MustGetTenantID(ctx)
	tenantID, err := shared.IDFromString(tenantIDStr)
	if err != nil {
		apierror.Unauthorized("Invalid tenant ID").WriteJSON(w)
		return
	}

	since, limit := h.parseSinceAndLimit(r)

	changes, err := h.repo.GetRecentDisappearances(ctx, tenantID, since, limit)
	if err != nil {
		h.logger.Error("failed to get recent disappearances", "error", err)
		apierror.InternalError(err).WriteJSON(w)
		return
	}

	response := make([]StateChangeResponse, len(changes))
	for i, change := range changes {
		response[i] = toStateChangeResponse(change)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"data":  response,
		"total": len(response),
		"since": since.Format(time.RFC3339),
	})
}

// ShadowITCandidates handles GET /api/v1/state-history/shadow-it
// @Summary      Get Shadow IT candidates
// @Description  Retrieves assets identified as potential Shadow IT (unexpected or unauthorized resources)
// @Tags         Asset State History
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        since query string false "Start time (RFC3339, default: 7 days ago)"
// @Param        limit query int false "Maximum results (max 1000)" default(100)
// @Success      200  {object}  object{data=[]StateChangeResponse,total=int,since=string}
// @Failure      401  {object}  apierror.Error
// @Failure      500  {object}  apierror.Error
// @Router       /state-history/shadow-it [get]
func (h *AssetStateHistoryHandler) ShadowITCandidates(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	tenantIDStr := middleware.MustGetTenantID(ctx)
	tenantID, err := shared.IDFromString(tenantIDStr)
	if err != nil {
		apierror.Unauthorized("Invalid tenant ID").WriteJSON(w)
		return
	}

	since, limit := h.parseSinceAndLimit(r)

	changes, err := h.repo.GetShadowITCandidates(ctx, tenantID, since, limit)
	if err != nil {
		h.logger.Error("failed to get shadow IT candidates", "error", err)
		apierror.InternalError(err).WriteJSON(w)
		return
	}

	response := make([]StateChangeResponse, len(changes))
	for i, change := range changes {
		response[i] = toStateChangeResponse(change)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"data":  response,
		"total": len(response),
		"since": since.Format(time.RFC3339),
	})
}

// ExposureChanges handles GET /api/v1/state-history/exposure-changes
// @Summary      Get exposure changes
// @Description  Retrieves assets that have changed exposure status (public/private/restricted)
// @Tags         Asset State History
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        since query string false "Start time (RFC3339, default: 7 days ago)"
// @Param        limit query int false "Maximum results (max 1000)" default(100)
// @Success      200  {object}  object{data=[]StateChangeResponse,total=int,since=string}
// @Failure      401  {object}  apierror.Error
// @Failure      500  {object}  apierror.Error
// @Router       /state-history/exposure-changes [get]
func (h *AssetStateHistoryHandler) ExposureChanges(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	tenantIDStr := middleware.MustGetTenantID(ctx)
	tenantID, err := shared.IDFromString(tenantIDStr)
	if err != nil {
		apierror.Unauthorized("Invalid tenant ID").WriteJSON(w)
		return
	}

	since, limit := h.parseSinceAndLimit(r)

	changes, err := h.repo.GetExposureChanges(ctx, tenantID, since, limit)
	if err != nil {
		h.logger.Error("failed to get exposure changes", "error", err)
		apierror.InternalError(err).WriteJSON(w)
		return
	}

	response := make([]StateChangeResponse, len(changes))
	for i, change := range changes {
		response[i] = toStateChangeResponse(change)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"data":  response,
		"total": len(response),
		"since": since.Format(time.RFC3339),
	})
}

// NewlyExposed handles GET /api/v1/state-history/newly-exposed
// @Summary      Get newly exposed assets
// @Description  Retrieves assets that have recently become publicly exposed
// @Tags         Asset State History
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        since query string false "Start time (RFC3339, default: 7 days ago)"
// @Param        limit query int false "Maximum results (max 1000)" default(100)
// @Success      200  {object}  object{data=[]StateChangeResponse,total=int,since=string}
// @Failure      401  {object}  apierror.Error
// @Failure      500  {object}  apierror.Error
// @Router       /state-history/newly-exposed [get]
func (h *AssetStateHistoryHandler) NewlyExposed(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	tenantIDStr := middleware.MustGetTenantID(ctx)
	tenantID, err := shared.IDFromString(tenantIDStr)
	if err != nil {
		apierror.Unauthorized("Invalid tenant ID").WriteJSON(w)
		return
	}

	since, limit := h.parseSinceAndLimit(r)

	changes, err := h.repo.GetNewlyExposedAssets(ctx, tenantID, since, limit)
	if err != nil {
		h.logger.Error("failed to get newly exposed assets", "error", err)
		apierror.InternalError(err).WriteJSON(w)
		return
	}

	response := make([]StateChangeResponse, len(changes))
	for i, change := range changes {
		response[i] = toStateChangeResponse(change)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"data":  response,
		"total": len(response),
		"since": since.Format(time.RFC3339),
	})
}

// ComplianceChanges handles GET /api/v1/state-history/compliance
// @Summary      Get compliance-related changes
// @Description  Retrieves state changes that may affect compliance status
// @Tags         Asset State History
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        since query string false "Start time (RFC3339, default: 7 days ago)"
// @Param        limit query int false "Maximum results (max 1000)" default(100)
// @Success      200  {object}  object{data=[]StateChangeResponse,total=int,since=string}
// @Failure      401  {object}  apierror.Error
// @Failure      500  {object}  apierror.Error
// @Router       /state-history/compliance [get]
func (h *AssetStateHistoryHandler) ComplianceChanges(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	tenantIDStr := middleware.MustGetTenantID(ctx)
	tenantID, err := shared.IDFromString(tenantIDStr)
	if err != nil {
		apierror.Unauthorized("Invalid tenant ID").WriteJSON(w)
		return
	}

	since, limit := h.parseSinceAndLimit(r)

	changes, err := h.repo.GetComplianceChanges(ctx, tenantID, since, limit)
	if err != nil {
		h.logger.Error("failed to get compliance changes", "error", err)
		apierror.InternalError(err).WriteJSON(w)
		return
	}

	response := make([]StateChangeResponse, len(changes))
	for i, change := range changes {
		response[i] = toStateChangeResponse(change)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"data":  response,
		"total": len(response),
		"since": since.Format(time.RFC3339),
	})
}

// Timeline handles GET /api/v1/state-history/timeline
// @Summary      Get activity timeline
// @Description  Retrieves daily activity counts for visualization (appearances, disappearances, exposure changes)
// @Tags         Asset State History
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        from query string false "Start time (RFC3339, default: 30 days ago)"
// @Param        to query string false "End time (RFC3339, default: now)"
// @Success      200  {object}  object{data=[]DailyActivityResponse,from=string,to=string}
// @Failure      401  {object}  apierror.Error
// @Failure      500  {object}  apierror.Error
// @Router       /state-history/timeline [get]
func (h *AssetStateHistoryHandler) Timeline(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	tenantIDStr := middleware.MustGetTenantID(ctx)
	tenantID, err := shared.IDFromString(tenantIDStr)
	if err != nil {
		apierror.Unauthorized("Invalid tenant ID").WriteJSON(w)
		return
	}

	// Default: last 30 days
	to := time.Now().UTC()
	from := to.AddDate(0, 0, -30)

	if v := r.URL.Query().Get("from"); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			from = t
		}
	}
	if v := r.URL.Query().Get("to"); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			to = t
		}
	}

	timeline, err := h.repo.GetActivityTimeline(ctx, tenantID, from, to)
	if err != nil {
		h.logger.Error("failed to get activity timeline", "error", err)
		apierror.InternalError(err).WriteJSON(w)
		return
	}

	response := make([]DailyActivityResponse, len(timeline))
	for i, day := range timeline {
		response[i] = DailyActivityResponse{
			Date:           day.Date.Format("2006-01-02"),
			Appeared:       day.Appeared,
			Disappeared:    day.Disappeared,
			Recovered:      day.Recovered,
			ExposureChange: day.ExposureChange,
			OtherChanges:   day.OtherChanges,
			Total:          day.Total,
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"data": response,
		"from": from.Format(time.RFC3339),
		"to":   to.Format(time.RFC3339),
	})
}

// Stats handles GET /api/v1/state-history/stats
// @Summary      Get state history statistics
// @Description  Retrieves aggregate statistics about state changes by type and source
// @Tags         Asset State History
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        since query string false "Start time (RFC3339, default: 30 days ago)"
// @Success      200  {object}  StateHistoryStatsResponse
// @Failure      401  {object}  apierror.Error
// @Failure      500  {object}  apierror.Error
// @Router       /state-history/stats [get]
func (h *AssetStateHistoryHandler) Stats(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	tenantIDStr := middleware.MustGetTenantID(ctx)
	tenantID, err := shared.IDFromString(tenantIDStr)
	if err != nil {
		apierror.Unauthorized("Invalid tenant ID").WriteJSON(w)
		return
	}

	// Default: last 30 days
	since := time.Now().UTC().AddDate(0, 0, -30)
	if v := r.URL.Query().Get("since"); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			since = t
		}
	}

	typeCounts, err := h.repo.CountByType(ctx, tenantID, since)
	if err != nil {
		h.logger.Error("failed to count by type", "error", err)
		apierror.InternalError(err).WriteJSON(w)
		return
	}

	sourceCounts, err := h.repo.CountBySource(ctx, tenantID, since)
	if err != nil {
		h.logger.Error("failed to count by source", "error", err)
		apierror.InternalError(err).WriteJSON(w)
		return
	}

	// Convert to string keys
	typeCountsStr := make(map[string]int)
	for k, v := range typeCounts {
		typeCountsStr[string(k)] = v
	}
	sourceCountsStr := make(map[string]int)
	for k, v := range sourceCounts {
		sourceCountsStr[string(k)] = v
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(StateHistoryStatsResponse{
		TypeCounts:   typeCountsStr,
		SourceCounts: sourceCountsStr,
	})
}

// =============================================================================
// Helper Methods
// =============================================================================

func (h *AssetStateHistoryHandler) parseListOptions(r *http.Request) asset.ListStateHistoryOptions {
	opts := asset.DefaultListStateHistoryOptions()

	if v := r.URL.Query().Get("change_type"); v != "" {
		ct := asset.StateChangeType(v)
		opts.ChangeType = &ct
	}
	if v := r.URL.Query().Get("source"); v != "" {
		s := asset.ChangeSource(v)
		opts.Source = &s
	}
	if v := r.URL.Query().Get("from"); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			opts.From = &t
		}
	}
	if v := r.URL.Query().Get("to"); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			opts.To = &t
		}
	}
	if v := r.URL.Query().Get("limit"); v != "" {
		if limit, err := strconv.Atoi(v); err == nil && limit > 0 {
			opts.Limit = limit
		}
	}
	if v := r.URL.Query().Get("offset"); v != "" {
		if offset, err := strconv.Atoi(v); err == nil && offset >= 0 {
			opts.Offset = offset
		}
	}

	// Security: Enforce max limit to prevent DoS via large queries
	const maxLimit = 1000
	if opts.Limit > maxLimit {
		opts.Limit = maxLimit
	}

	return opts
}

func (h *AssetStateHistoryHandler) parseSinceAndLimit(r *http.Request) (time.Time, int) {
	// Default: last 7 days
	since := time.Now().UTC().AddDate(0, 0, -7)
	limit := 100

	if v := r.URL.Query().Get("since"); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			since = t
		}
	}
	if v := r.URL.Query().Get("limit"); v != "" {
		if l, err := strconv.Atoi(v); err == nil && l > 0 {
			limit = l
		}
	}

	// Security: Enforce max limit to prevent DoS via large queries
	const maxLimit = 1000
	if limit > maxLimit {
		limit = maxLimit
	}

	return since, limit
}

func toStateChangeResponse(change *asset.AssetStateChange) StateChangeResponse {
	resp := StateChangeResponse{
		ID:         change.ID().String(),
		TenantID:   change.TenantID().String(),
		AssetID:    change.AssetID().String(),
		ChangeType: change.ChangeType().String(),
		Field:      change.Field(),
		OldValue:   change.OldValue(),
		NewValue:   change.NewValue(),
		Reason:     change.Reason(),
		Source:     change.Source().String(),
		ChangedAt:  change.ChangedAt(),
		Metadata:   change.Metadata(),
		CreatedAt:  change.CreatedAt(),
	}
	if change.ChangedBy() != nil {
		s := change.ChangedBy().String()
		resp.ChangedBy = &s
	}
	return resp
}
