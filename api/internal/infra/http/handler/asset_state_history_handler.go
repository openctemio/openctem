package handler

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/pagination"
	"github.com/openctemio/openctem/api/pkg/validator"
)

// AssetStateHistoryHandler handles asset state history-related HTTP requests.
type AssetStateHistoryHandler struct {
	repo      asset.StateHistoryRepository
	assetRepo asset.Repository
	validator *validator.Validator
	logger    *logger.Logger
	dataScope DataScopeEnforcer
}

// SetDataScope wires the Layer 2 data scope: a scoped member sees only the
// history of assets in their scope. Returns h for chaining.
func (h *AssetStateHistoryHandler) SetDataScope(e DataScopeEnforcer) *AssetStateHistoryHandler {
	h.dataScope = e
	return h
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

	// Current state of the asset the change refers to (absent when the asset
	// no longer exists), so a change list can show what changed without one
	// asset lookup per row.
	AssetName               string `json:"asset_name,omitempty"`
	AssetType               string `json:"asset_type,omitempty"`
	AssetExposure           string `json:"asset_exposure,omitempty"`
	AssetScope              string `json:"asset_scope,omitempty"`
	AssetInternetAccessible *bool  `json:"asset_internet_accessible,omitempty"`
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
// @Param        page query int false "Page (1-based)" default(1)
// @Param        per_page query int false "Page size (max 100)" default(50)
// @Success      200  {object}  object{data=[]StateChangeResponse,total=int,page=int,per_page=int,total_pages=int}
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

	opts, paging, ok := h.parseListOptions(w, r)
	if !ok {
		return
	}

	changes, total, err := h.repo.GetByAssetID(ctx, tenantID, assetID, opts)
	if err != nil {
		h.logger.Error("failed to get state history by asset", "error", err, "asset_id", assetIDStr)
		apierror.InternalError(err).WriteJSON(w)
		return
	}

	h.writeChangePage(w, r, tenantID, changes, total, paging)
}

// writeChangePage enriches a page of changes with the current state of their
// assets (one tenant-scoped query per page) and writes the list envelope.
func (h *AssetStateHistoryHandler) writeChangePage(
	w http.ResponseWriter,
	r *http.Request,
	tenantID shared.ID,
	changes []*asset.AssetStateChange,
	total int,
	paging pagination.Pagination,
) {
	response := make([]StateChangeResponse, len(changes))
	ids := make([]shared.ID, 0, len(changes))
	seen := make(map[shared.ID]bool, len(changes))
	for i, change := range changes {
		response[i] = toStateChangeResponse(change)
		if !seen[change.AssetID()] {
			seen[change.AssetID()] = true
			ids = append(ids, change.AssetID())
		}
	}

	// Best-effort: the change list is still correct without asset names.
	refs, err := h.repo.GetAssetRefs(r.Context(), tenantID, ids)
	if err != nil {
		h.logger.Warn("failed to load asset refs for state history", "error", err)
	}
	for i, change := range changes {
		ref, ok := refs[change.AssetID()]
		if !ok {
			continue
		}
		internet := ref.InternetAccessible
		response[i].AssetName = ref.Name
		response[i].AssetType = ref.Type
		response[i].AssetExposure = ref.Exposure
		response[i].AssetScope = ref.Scope
		response[i].AssetInternetAccessible = &internet
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(pagination.NewResult(response, int64(total), paging))
}

// List handles GET /api/v1/state-history
// @Summary      List all state history
// @Description  Retrieves a paginated list of all state changes for the tenant with optional filtering.
// @Description  Use ?event_type= with comma-separated values to filter by one or more change types
// @Description  (e.g. ?event_type=appeared,disappeared replaces the old /appearances and /disappearances endpoints).
// @Tags         Asset State History
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        event_type query string false "Comma-separated change types (appeared,disappeared,shadow_it,exposure_changed,...)"
// @Param        change_type query string false "Filter by single change type (deprecated: use event_type)"
// @Param        source query string false "Filter by source"
// @Param        from query string false "Start time (RFC3339)"
// @Param        to query string false "End time (RFC3339)"
// @Param        internet_facing query bool false "Only assets that are (true) or are not (false) internet-facing now"
// @Param        page query int false "Page (1-based)" default(1)
// @Param        per_page query int false "Page size (max 100)" default(50)
// @Success      200  {object}  object{data=[]StateChangeResponse,total=int,page=int,per_page=int,total_pages=int}
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

	opts, paging, ok := h.parseListOptions(w, r)
	if !ok {
		return
	}

	opts.Scope, err = resolveDataScope(ctx, h.dataScope, tenantID)
	if err != nil {
		h.logger.Error("failed to resolve data scope", "error", err)
		apierror.InternalError(err).WriteJSON(w)
		return
	}

	changes, total, err := h.repo.List(ctx, tenantID, opts)
	if err != nil {
		h.logger.Error("failed to list state history", "error", err)
		apierror.InternalError(err).WriteJSON(w)
		return
	}

	h.writeChangePage(w, r, tenantID, changes, total, paging)
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
	if err == nil && !assetInDataScope(ctx, h.dataScope, tenantID, change.AssetID()) {
		err = shared.ErrNotFound
	}
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

// The change-list endpoints below share one parameter set:
//   - since (legacy, default 7 days ago) is used only when from is absent;
//   - from / to bound changed_at; page / per_page paginate; total is the full
//     count, so they can back a server-paginated table;
//   - internet_facing=true|false keeps changes of assets that are (not)
//     currently internet-facing (is_internet_accessible or exposure=public).

// RecentAppearances handles GET /api/v1/state-history/appearances
// @Summary      Get recent asset appearances
// @Description  Assets that appeared (newly discovered by a scan or created) in the window.
// @Description  Equivalent to GET /state-history?event_type=appeared.
// @Tags         Asset State History
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        since query string false "Start time (RFC3339, default: 7 days ago; ignored when from is set)"
// @Param        from query string false "Start time (RFC3339)"
// @Param        to query string false "End time (RFC3339)"
// @Param        internet_facing query bool false "Only assets that are (true) or are not (false) internet-facing now"
// @Param        page query int false "Page (1-based)" default(1)
// @Param        per_page query int false "Page size (max 100)" default(50)
// @Success      200  {object}  object{data=[]StateChangeResponse,total=int,page=int,per_page=int,total_pages=int}
// @Failure      401  {object}  apierror.Error
// @Failure      500  {object}  apierror.Error
// @Router       /state-history/appearances [get]
func (h *AssetStateHistoryHandler) RecentAppearances(w http.ResponseWriter, r *http.Request) {
	h.listWithPresetEventTypes(w, r, listPreset{types: []asset.StateChangeType{asset.StateChangeAppeared}})
}

// RecentDisappearances handles GET /api/v1/state-history/disappearances
// @Summary      Get recent asset disappearances
// @Description  Assets that disappeared (no scan has seen them within the stale threshold) in the window.
// @Description  Equivalent to GET /state-history?event_type=disappeared.
// @Tags         Asset State History
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        since query string false "Start time (RFC3339, default: 7 days ago; ignored when from is set)"
// @Param        from query string false "Start time (RFC3339)"
// @Param        to query string false "End time (RFC3339)"
// @Param        internet_facing query bool false "Only assets that are (true) or are not (false) internet-facing now"
// @Param        page query int false "Page (1-based)" default(1)
// @Param        per_page query int false "Page size (max 100)" default(50)
// @Success      200  {object}  object{data=[]StateChangeResponse,total=int,page=int,per_page=int,total_pages=int}
// @Failure      401  {object}  apierror.Error
// @Failure      500  {object}  apierror.Error
// @Router       /state-history/disappearances [get]
func (h *AssetStateHistoryHandler) RecentDisappearances(w http.ResponseWriter, r *http.Request) {
	h.listWithPresetEventTypes(w, r, listPreset{types: []asset.StateChangeType{asset.StateChangeDisappeared}})
}

// ShadowITCandidates handles GET /api/v1/state-history/shadow-it
// @Summary      Get Shadow IT candidates
// @Description  Appearances of assets currently in the `shadow` scope (potential shadow IT).
// @Tags         Asset State History
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        since query string false "Start time (RFC3339, default: 7 days ago; ignored when from is set)"
// @Param        from query string false "Start time (RFC3339)"
// @Param        to query string false "End time (RFC3339)"
// @Param        internet_facing query bool false "Only assets that are (true) or are not (false) internet-facing now"
// @Param        page query int false "Page (1-based)" default(1)
// @Param        per_page query int false "Page size (max 100)" default(50)
// @Success      200  {object}  object{data=[]StateChangeResponse,total=int,page=int,per_page=int,total_pages=int}
// @Failure      401  {object}  apierror.Error
// @Failure      500  {object}  apierror.Error
// @Router       /state-history/shadow-it [get]
func (h *AssetStateHistoryHandler) ShadowITCandidates(w http.ResponseWriter, r *http.Request) {
	// Goes through the paginated List (tenant-scoped EXISTS on assets) so
	// `total` is the real count — it used to be len(page) — and page/from/to
	// work like the other change lists.
	shadow := asset.ScopeShadow
	h.listWithPresetEventTypes(w, r, listPreset{
		types:      []asset.StateChangeType{asset.StateChangeAppeared},
		assetScope: &shadow,
		forced:     true,
	})
}

// ExposureChanges handles GET /api/v1/state-history/exposure-changes
// @Summary      Get exposure changes
// @Description  Every exposure transition (exposure level or internet reachability, either direction) in the window.
// @Description  Equivalent to GET /state-history?event_type=exposure_changed,internet_exposure_changed.
// @Tags         Asset State History
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        since query string false "Start time (RFC3339, default: 7 days ago; ignored when from is set)"
// @Param        from query string false "Start time (RFC3339)"
// @Param        to query string false "End time (RFC3339)"
// @Param        internet_facing query bool false "Only assets that are (true) or are not (false) internet-facing now"
// @Param        page query int false "Page (1-based)" default(1)
// @Param        per_page query int false "Page size (max 100)" default(50)
// @Success      200  {object}  object{data=[]StateChangeResponse,total=int,page=int,per_page=int,total_pages=int}
// @Failure      401  {object}  apierror.Error
// @Failure      500  {object}  apierror.Error
// @Router       /state-history/exposure-changes [get]
func (h *AssetStateHistoryHandler) ExposureChanges(w http.ResponseWriter, r *http.Request) {
	h.listWithPresetEventTypes(w, r, listPreset{types: []asset.StateChangeType{
		asset.StateChangeExposureChanged, asset.StateChangeInternetExposureChanged,
	}})
}

// NewlyExposed handles GET /api/v1/state-history/newly-exposed
// @Summary      Get newly exposed assets
// @Description  Assets that BECAME internet-facing in the window: exposure changed to public, or
// @Description  internet reachability changed to true. Transitions away from public are excluded.
// @Tags         Asset State History
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        since query string false "Start time (RFC3339, default: 7 days ago; ignored when from is set)"
// @Param        from query string false "Start time (RFC3339)"
// @Param        to query string false "End time (RFC3339)"
// @Param        page query int false "Page (1-based)" default(1)
// @Param        per_page query int false "Page size (max 100)" default(50)
// @Success      200  {object}  object{data=[]StateChangeResponse,total=int,page=int,per_page=int,total_pages=int}
// @Failure      401  {object}  apierror.Error
// @Failure      500  {object}  apierror.Error
// @Router       /state-history/newly-exposed [get]
func (h *AssetStateHistoryHandler) NewlyExposed(w http.ResponseWriter, r *http.Request) {
	// It used to return every internet_exposure_changed row, including
	// true -> false, i.e. assets that stopped being exposed.
	h.listWithPresetEventTypes(w, r, listPreset{
		types: []asset.StateChangeType{
			asset.StateChangeExposureChanged, asset.StateChangeInternetExposureChanged,
		},
		newValues: []string{string(asset.ExposurePublic), "true"},
		forced:    true,
	})
}

// ComplianceChanges handles GET /api/v1/state-history/compliance
// @Summary      Get compliance-related changes (deprecated)
// @Description  Deprecated: use GET /state-history?event_type=compliance_changed,classification_changed,owner_changed instead.
// @Description  Retrieves state changes that may affect compliance status.
// @Tags         Asset State History
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        since query string false "Start time (RFC3339, default: 7 days ago)"
// @Param        page query int false "Page (1-based)" default(1)
// @Param        per_page query int false "Page size (max 100)" default(50)
// @Success      200  {object}  object{data=[]StateChangeResponse,total=int,page=int,per_page=int,total_pages=int}
// @Failure      401  {object}  apierror.Error
// @Failure      500  {object}  apierror.Error
// @Router       /state-history/compliance [get]
func (h *AssetStateHistoryHandler) ComplianceChanges(w http.ResponseWriter, r *http.Request) {
	// Deprecated: delegates to List with compliance event types pre-set.
	// Use GET /state-history?event_type=compliance_changed,classification_changed,owner_changed instead.
	h.listWithPresetEventTypes(w, r, listPreset{types: []asset.StateChangeType{
		asset.StateChangeComplianceChanged,
		asset.StateChangeClassificationChanged,
		asset.StateChangeOwnerChanged,
	}})
}

// listPreset is what a specialised change-list endpoint fixes on top of the
// generic List query.
type listPreset struct {
	types      []asset.StateChangeType
	newValues  []string
	assetScope *asset.Scope
	// forced: the preset defines the endpoint (shadow-it, newly-exposed), so a
	// caller's ?event_type= cannot widen it. Otherwise the preset types are
	// only defaults the caller may override.
	forced bool
}

// listWithPresetEventTypes serves the specialised change-list endpoints on top
// of the generic, paginated List query.
func (h *AssetStateHistoryHandler) listWithPresetEventTypes(w http.ResponseWriter, r *http.Request, preset listPreset) {
	ctx := r.Context()
	tenantIDStr := middleware.MustGetTenantID(ctx)
	tenantID, err := shared.IDFromString(tenantIDStr)
	if err != nil {
		apierror.Unauthorized("Invalid tenant ID").WriteJSON(w)
		return
	}

	opts, paging, ok := h.parseListOptions(w, r)
	if !ok {
		return
	}

	if preset.forced || (opts.ChangeType == nil && len(opts.ChangeTypes) == 0) {
		opts.ChangeType = nil
		opts.ChangeTypes = preset.types
	}
	if len(preset.newValues) > 0 {
		opts.NewValues = preset.newValues
	}
	if preset.assetScope != nil {
		opts.AssetScope = preset.assetScope
	}

	// Apply ?since= as a From bound when no explicit ?from= was given (backward compat).
	if opts.From == nil {
		since := h.parseSince(r)
		opts.From = &since
	}

	opts.Scope, err = resolveDataScope(ctx, h.dataScope, tenantID)
	if err != nil {
		h.logger.Error("failed to resolve data scope", "error", err)
		apierror.InternalError(err).WriteJSON(w)
		return
	}

	changes, total, err := h.repo.List(ctx, tenantID, opts)
	if err != nil {
		h.logger.Error("failed to list state history", "error", err)
		apierror.InternalError(err).WriteJSON(w)
		return
	}

	h.writeChangePage(w, r, tenantID, changes, total, paging)
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

	scope, err := resolveDataScope(ctx, h.dataScope, tenantID)
	if err != nil {
		h.logger.Error("failed to resolve data scope", "error", err)
		apierror.InternalError(err).WriteJSON(w)
		return
	}

	timeline, err := h.repo.GetActivityTimeline(ctx, tenantID, from, to, scope)
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

	scope, err := resolveDataScope(ctx, h.dataScope, tenantID)
	if err != nil {
		h.logger.Error("failed to resolve data scope", "error", err)
		apierror.InternalError(err).WriteJSON(w)
		return
	}

	typeCounts, err := h.repo.CountByType(ctx, tenantID, since, scope)
	if err != nil {
		h.logger.Error("failed to count by type", "error", err)
		apierror.InternalError(err).WriteJSON(w)
		return
	}

	sourceCounts, err := h.repo.CountBySource(ctx, tenantID, since, scope)
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

func (h *AssetStateHistoryHandler) parseListOptions(w http.ResponseWriter, r *http.Request) (asset.ListStateHistoryOptions, pagination.Pagination, bool) {
	opts := asset.DefaultListStateHistoryOptions()
	paging, ok := listPage(w, r, 50)
	if !ok {
		return opts, paging, false
	}
	opts.Limit, opts.Offset = paging.Limit(), paging.Offset()

	// event_type supports comma-separated list of change types, e.g. ?event_type=appeared,disappeared
	// This is the preferred param going forward; change_type is kept for backward compatibility.
	if v := r.URL.Query().Get("event_type"); v != "" {
		parts := strings.Split(v, ",")
		types := make([]asset.StateChangeType, 0, len(parts))
		for _, p := range parts {
			p = strings.TrimSpace(p)
			if p != "" {
				types = append(types, asset.StateChangeType(p))
			}
		}
		if len(types) == 1 {
			opts.ChangeType = &types[0]
		} else if len(types) > 1 {
			opts.ChangeTypes = types
		}
	} else if v := r.URL.Query().Get("change_type"); v != "" {
		ct := asset.StateChangeType(v)
		opts.ChangeType = &ct
	}
	if v := r.URL.Query().Get("source"); v != "" {
		s := asset.ChangeSource(v)
		opts.Source = &s
	}
	if v := r.URL.Query().Get("internet_facing"); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			opts.AssetInternetFacing = &b
		}
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
	return opts, paging, true
}

func (h *AssetStateHistoryHandler) parseSince(r *http.Request) time.Time {
	// Default: last 7 days
	since := time.Now().UTC().AddDate(0, 0, -7)

	if v := r.URL.Query().Get("since"); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			since = t
		}
	}
	return since
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
