package handler

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/openctemio/api/internal/app"
	"github.com/openctemio/api/internal/infra/http/middleware"
	"github.com/openctemio/api/pkg/apierror"
	"github.com/openctemio/api/pkg/domain/rule"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/logger"
	"github.com/openctemio/api/pkg/validator"
)

const timeFormat = "2006-01-02T15:04:05Z"

// RuleHandler handles HTTP requests for rule management.
type RuleHandler struct {
	service   *app.RuleService
	validator *validator.Validator
	logger    *logger.Logger
}

// NewRuleHandler creates a new RuleHandler.
func NewRuleHandler(service *app.RuleService, v *validator.Validator, log *logger.Logger) *RuleHandler {
	return &RuleHandler{
		service:   service,
		validator: v,
		logger:    log.With("handler", "rule"),
	}
}

// =============================================================================
// Request/Response Types
// =============================================================================

// CreateSourceRequest represents the request body for creating a rule source.
type CreateSourceRequest struct {
	ToolID              string          `json:"tool_id" validate:"omitempty,uuid"`
	Name                string          `json:"name" validate:"required,min=1,max=255"`
	Description         string          `json:"description" validate:"max=1000"`
	SourceType          string          `json:"source_type" validate:"required,oneof=git http local"`
	Config              json.RawMessage `json:"config" validate:"required"`
	CredentialsID       string          `json:"credentials_id" validate:"omitempty,uuid"`
	SyncEnabled         bool            `json:"sync_enabled"`
	SyncIntervalMinutes int             `json:"sync_interval_minutes" validate:"min=5,max=10080"`
	Priority            int             `json:"priority" validate:"min=0,max=1000"`
}

// UpdateSourceRequest represents the request body for updating a rule source.
type UpdateSourceRequest struct {
	Name                string          `json:"name" validate:"omitempty,min=1,max=255"`
	Description         string          `json:"description" validate:"max=1000"`
	Config              json.RawMessage `json:"config"`
	CredentialsID       string          `json:"credentials_id" validate:"omitempty,uuid"`
	SyncEnabled         *bool           `json:"sync_enabled"`
	SyncIntervalMinutes int             `json:"sync_interval_minutes" validate:"omitempty,min=5,max=10080"`
	Priority            int             `json:"priority" validate:"omitempty,min=0,max=1000"`
	Enabled             *bool           `json:"enabled"`
}

// SourceResponse represents the response for a rule source.
type SourceResponse struct {
	ID                  string  `json:"id"`
	TenantID            string  `json:"tenant_id"`
	ToolID              *string `json:"tool_id,omitempty"`
	Name                string  `json:"name"`
	Description         string  `json:"description,omitempty"`
	SourceType          string  `json:"source_type"`
	Config              any     `json:"config,omitempty"`
	CredentialsID       *string `json:"credentials_id,omitempty"`
	SyncEnabled         bool    `json:"sync_enabled"`
	SyncIntervalMinutes int     `json:"sync_interval_minutes"`
	LastSyncAt          *string `json:"last_sync_at,omitempty"`
	LastSyncStatus      string  `json:"last_sync_status"`
	LastSyncError       string  `json:"last_sync_error,omitempty"`
	ContentHash         string  `json:"content_hash,omitempty"`
	RuleCount           int     `json:"rule_count"`
	Priority            int     `json:"priority"`
	IsPlatformDefault   bool    `json:"is_platform_default"`
	Enabled             bool    `json:"enabled"`
	CreatedAt           string  `json:"created_at"`
	UpdatedAt           string  `json:"updated_at"`
}

// RuleResponse represents the response for a rule.
type RuleResponse struct {
	ID             string   `json:"id"`
	SourceID       string   `json:"source_id"`
	TenantID       string   `json:"tenant_id"`
	ToolID         *string  `json:"tool_id,omitempty"`
	RuleID         string   `json:"rule_id"`
	Name           string   `json:"name,omitempty"`
	Severity       string   `json:"severity,omitempty"`
	Category       string   `json:"category,omitempty"`
	Subcategory    string   `json:"subcategory,omitempty"`
	Tags           []string `json:"tags,omitempty"`
	Description    string   `json:"description,omitempty"`
	Recommendation string   `json:"recommendation,omitempty"`
	References     []string `json:"references,omitempty"`
	CWEIDs         []string `json:"cwe_ids,omitempty"`
	OWASPIDs       []string `json:"owasp_ids,omitempty"`
	FilePath       string   `json:"file_path,omitempty"`
	ContentHash    string   `json:"content_hash,omitempty"`
	CreatedAt      string   `json:"created_at"`
	UpdatedAt      string   `json:"updated_at"`
}

// CreateOverrideRequest represents the request body for creating a rule override.
type CreateOverrideRequest struct {
	ToolID           string  `json:"tool_id" validate:"omitempty,uuid"`
	RulePattern      string  `json:"rule_pattern" validate:"required,min=1,max=500"`
	IsPattern        bool    `json:"is_pattern"`
	Enabled          bool    `json:"enabled"`
	SeverityOverride string  `json:"severity_override" validate:"omitempty,oneof=critical high medium low info"`
	AssetGroupID     string  `json:"asset_group_id" validate:"omitempty,uuid"`
	ScanProfileID    string  `json:"scan_profile_id" validate:"omitempty,uuid"`
	Reason           string  `json:"reason" validate:"max=1000"`
	ExpiresAt        *string `json:"expires_at"`
}

// UpdateOverrideRequest represents the request body for updating a rule override.
type UpdateOverrideRequest struct {
	RulePattern      string  `json:"rule_pattern" validate:"omitempty,min=1,max=500"`
	IsPattern        *bool   `json:"is_pattern"`
	Enabled          *bool   `json:"enabled"`
	SeverityOverride string  `json:"severity_override" validate:"omitempty,oneof=critical high medium low info"`
	AssetGroupID     string  `json:"asset_group_id" validate:"omitempty,uuid"`
	ScanProfileID    string  `json:"scan_profile_id" validate:"omitempty,uuid"`
	Reason           string  `json:"reason" validate:"max=1000"`
	ExpiresAt        *string `json:"expires_at"`
}

// OverrideResponse represents the response for a rule override.
type OverrideResponse struct {
	ID               string  `json:"id"`
	TenantID         string  `json:"tenant_id"`
	ToolID           *string `json:"tool_id,omitempty"`
	RulePattern      string  `json:"rule_pattern"`
	IsPattern        bool    `json:"is_pattern"`
	Enabled          bool    `json:"enabled"`
	SeverityOverride string  `json:"severity_override,omitempty"`
	AssetGroupID     *string `json:"asset_group_id,omitempty"`
	ScanProfileID    *string `json:"scan_profile_id,omitempty"`
	Reason           string  `json:"reason,omitempty"`
	CreatedBy        *string `json:"created_by,omitempty"`
	CreatedAt        string  `json:"created_at"`
	UpdatedAt        string  `json:"updated_at"`
	ExpiresAt        *string `json:"expires_at,omitempty"`
}

// BundleResponse represents the response for a rule bundle.
type BundleResponse struct {
	ID               string            `json:"id"`
	TenantID         string            `json:"tenant_id"`
	ToolID           string            `json:"tool_id"`
	Version          string            `json:"version"`
	ContentHash      string            `json:"content_hash"`
	RuleCount        int               `json:"rule_count"`
	SourceCount      int               `json:"source_count"`
	SizeBytes        int64             `json:"size_bytes"`
	SourceIDs        []string          `json:"source_ids"`
	SourceHashes     map[string]string `json:"source_hashes,omitempty"`
	StoragePath      string            `json:"storage_path"`
	Status           string            `json:"status"`
	BuildError       string            `json:"build_error,omitempty"`
	BuildStartedAt   *string           `json:"build_started_at,omitempty"`
	BuildCompletedAt *string           `json:"build_completed_at,omitempty"`
	CreatedAt        string            `json:"created_at"`
	ExpiresAt        *string           `json:"expires_at,omitempty"`
}

// SyncHistoryResponse represents a sync history entry.
type SyncHistoryResponse struct {
	ID           string `json:"id"`
	SourceID     string `json:"source_id"`
	Status       string `json:"status"`
	RulesAdded   int    `json:"rules_added"`
	RulesUpdated int    `json:"rules_updated"`
	RulesRemoved int    `json:"rules_removed"`
	DurationMs   int64  `json:"duration_ms"`
	ErrorMessage string `json:"error_message,omitempty"`
	PreviousHash string `json:"previous_hash,omitempty"`
	NewHash      string `json:"new_hash,omitempty"`
	CreatedAt    string `json:"created_at"`
}

// =============================================================================
// Source Handlers
// =============================================================================

// CreateSource handles POST /sources
func (h *RuleHandler) CreateSource(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.GetTenantID(r.Context())
	if tenantID == "" {
		apierror.Unauthorized("tenant context required").WriteJSON(w)
		return
	}

	var req CreateSourceRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("invalid request body").WriteJSON(w)
		return
	}

	if err := h.validator.Validate(req); err != nil {
		apierror.BadRequest(err.Error()).WriteJSON(w)
		return
	}

	input := app.CreateSourceInput{
		TenantID:            tenantID,
		ToolID:              req.ToolID,
		Name:                req.Name,
		Description:         req.Description,
		SourceType:          req.SourceType,
		Config:              req.Config,
		CredentialsID:       req.CredentialsID,
		SyncEnabled:         req.SyncEnabled,
		SyncIntervalMinutes: req.SyncIntervalMinutes,
		Priority:            req.Priority,
	}

	source, err := h.service.CreateSource(r.Context(), input)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(h.toSourceResponse(source))
}

// GetSource handles GET /sources/{sourceId}
func (h *RuleHandler) GetSource(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.GetTenantID(r.Context())
	sourceID := chi.URLParam(r, "sourceId")

	source, err := h.service.GetSourceByTenantAndID(r.Context(), tenantID, sourceID)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(h.toSourceResponse(source))
}

// ListSources handles GET /sources
func (h *RuleHandler) ListSources(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.GetTenantID(r.Context())

	page := parseQueryInt(r.URL.Query().Get("page"), 1)
	perPage := parseQueryInt(r.URL.Query().Get("per_page"), 20)

	input := app.ListSourcesInput{
		TenantID:   tenantID,
		ToolID:     r.URL.Query().Get("tool_id"),
		SourceType: r.URL.Query().Get("source_type"),
		SyncStatus: r.URL.Query().Get("sync_status"),
		Search:     r.URL.Query().Get("search"),
		Page:       page,
		PerPage:    perPage,
	}

	if enabled := r.URL.Query().Get("enabled"); enabled != "" {
		b := enabled == queryParamTrue
		input.Enabled = &b
	}

	result, err := h.service.ListSources(r.Context(), input)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	items := make([]SourceResponse, 0, len(result.Data))
	for _, source := range result.Data {
		items = append(items, h.toSourceResponse(source))
	}

	resp := map[string]any{
		"items":    items,
		"total":    result.Total,
		"page":     result.Page,
		"per_page": result.PerPage,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// UpdateSource handles PUT /sources/{sourceId}
func (h *RuleHandler) UpdateSource(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.GetTenantID(r.Context())
	sourceID := chi.URLParam(r, "sourceId")

	var req UpdateSourceRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("invalid request body").WriteJSON(w)
		return
	}

	if err := h.validator.Validate(req); err != nil {
		apierror.BadRequest(err.Error()).WriteJSON(w)
		return
	}

	input := app.UpdateSourceInput{
		TenantID:            tenantID,
		SourceID:            sourceID,
		Name:                req.Name,
		Description:         req.Description,
		Config:              req.Config,
		CredentialsID:       req.CredentialsID,
		SyncEnabled:         req.SyncEnabled,
		SyncIntervalMinutes: req.SyncIntervalMinutes,
		Priority:            req.Priority,
		Enabled:             req.Enabled,
	}

	source, err := h.service.UpdateSource(r.Context(), input)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(h.toSourceResponse(source))
}

// DeleteSource handles DELETE /sources/{sourceId}
func (h *RuleHandler) DeleteSource(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.GetTenantID(r.Context())
	sourceID := chi.URLParam(r, "sourceId")

	if err := h.service.DeleteSource(r.Context(), tenantID, sourceID); err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// EnableSource handles POST /sources/{sourceId}/enable
func (h *RuleHandler) EnableSource(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.GetTenantID(r.Context())
	sourceID := chi.URLParam(r, "sourceId")

	source, err := h.service.EnableSource(r.Context(), tenantID, sourceID)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(h.toSourceResponse(source))
}

// DisableSource handles POST /sources/{sourceId}/disable
func (h *RuleHandler) DisableSource(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.GetTenantID(r.Context())
	sourceID := chi.URLParam(r, "sourceId")

	source, err := h.service.DisableSource(r.Context(), tenantID, sourceID)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(h.toSourceResponse(source))
}

// GetSyncHistory handles GET /sources/{sourceId}/sync-history
func (h *RuleHandler) GetSyncHistory(w http.ResponseWriter, r *http.Request) {
	sourceID := chi.URLParam(r, "sourceId")
	limit := parseQueryInt(r.URL.Query().Get("limit"), 20)

	history, err := h.service.GetSyncHistory(r.Context(), sourceID, limit)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	items := make([]SyncHistoryResponse, 0, len(history))
	for _, h := range history {
		items = append(items, SyncHistoryResponse{
			ID:           h.ID.String(),
			SourceID:     h.SourceID.String(),
			Status:       string(h.Status),
			RulesAdded:   h.RulesAdded,
			RulesUpdated: h.RulesUpdated,
			RulesRemoved: h.RulesRemoved,
			DurationMs:   h.Duration.Milliseconds(),
			ErrorMessage: h.ErrorMessage,
			PreviousHash: h.PreviousHash,
			NewHash:      h.NewHash,
			CreatedAt:    h.CreatedAt.Format(timeFormat),
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"items": items})
}

// =============================================================================
// Rule Handlers
// =============================================================================

// ListRules handles GET /rules
func (h *RuleHandler) ListRules(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.GetTenantID(r.Context())
	page := parseQueryInt(r.URL.Query().Get("page"), 1)
	perPage := parseQueryInt(r.URL.Query().Get("per_page"), 20)

	input := app.ListRulesInput{
		TenantID: tenantID,
		ToolID:   r.URL.Query().Get("tool_id"),
		SourceID: r.URL.Query().Get("source_id"),
		Severity: r.URL.Query().Get("severity"),
		Category: r.URL.Query().Get("category"),
		Search:   r.URL.Query().Get("search"),
		Page:     page,
		PerPage:  perPage,
	}

	result, err := h.service.ListRules(r.Context(), input)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	items := make([]RuleResponse, 0, len(result.Data))
	for _, rul := range result.Data {
		items = append(items, h.toRuleResponse(rul))
	}

	resp := map[string]any{
		"items":    items,
		"total":    result.Total,
		"page":     result.Page,
		"per_page": result.PerPage,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// GetRule handles GET /rules/{ruleId}
func (h *RuleHandler) GetRule(w http.ResponseWriter, r *http.Request) {
	ruleID := chi.URLParam(r, "ruleId")

	rul, err := h.service.GetRule(r.Context(), ruleID)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(h.toRuleResponse(rul))
}

// =============================================================================
// Override Handlers
// =============================================================================

// CreateOverride handles POST /overrides
func (h *RuleHandler) CreateOverride(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.GetTenantID(r.Context())
	userID := middleware.GetUserID(r.Context())

	var req CreateOverrideRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("invalid request body").WriteJSON(w)
		return
	}

	if err := h.validator.Validate(req); err != nil {
		apierror.BadRequest(err.Error()).WriteJSON(w)
		return
	}

	input := app.CreateOverrideInput{
		TenantID:         tenantID,
		ToolID:           req.ToolID,
		RulePattern:      req.RulePattern,
		IsPattern:        req.IsPattern,
		Enabled:          req.Enabled,
		SeverityOverride: req.SeverityOverride,
		AssetGroupID:     req.AssetGroupID,
		ScanProfileID:    req.ScanProfileID,
		Reason:           req.Reason,
		CreatedBy:        userID,
		ExpiresAt:        req.ExpiresAt,
	}

	override, err := h.service.CreateOverride(r.Context(), input)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(h.toOverrideResponse(override))
}

// GetOverride handles GET /overrides/{overrideId}
func (h *RuleHandler) GetOverride(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.GetTenantID(r.Context())
	overrideID := chi.URLParam(r, "overrideId")

	override, err := h.service.GetOverrideByTenantAndID(r.Context(), tenantID, overrideID)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(h.toOverrideResponse(override))
}

// ListOverrides handles GET /overrides
func (h *RuleHandler) ListOverrides(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.GetTenantID(r.Context())
	page := parseQueryInt(r.URL.Query().Get("page"), 1)
	perPage := parseQueryInt(r.URL.Query().Get("per_page"), 20)

	input := app.ListOverridesInput{
		TenantID:      tenantID,
		ToolID:        r.URL.Query().Get("tool_id"),
		AssetGroupID:  r.URL.Query().Get("asset_group_id"),
		ScanProfileID: r.URL.Query().Get("scan_profile_id"),
		Page:          page,
		PerPage:       perPage,
	}

	if enabled := r.URL.Query().Get("enabled"); enabled != "" {
		b := enabled == queryParamTrue
		input.Enabled = &b
	}

	result, err := h.service.ListOverrides(r.Context(), input)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	items := make([]OverrideResponse, 0, len(result.Data))
	for _, override := range result.Data {
		items = append(items, h.toOverrideResponse(override))
	}

	resp := map[string]any{
		"items":    items,
		"total":    result.Total,
		"page":     result.Page,
		"per_page": result.PerPage,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// UpdateOverride handles PUT /overrides/{overrideId}
func (h *RuleHandler) UpdateOverride(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.GetTenantID(r.Context())
	overrideID := chi.URLParam(r, "overrideId")

	var req UpdateOverrideRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("invalid request body").WriteJSON(w)
		return
	}

	if err := h.validator.Validate(req); err != nil {
		apierror.BadRequest(err.Error()).WriteJSON(w)
		return
	}

	input := app.UpdateOverrideInput{
		TenantID:         tenantID,
		OverrideID:       overrideID,
		RulePattern:      req.RulePattern,
		IsPattern:        req.IsPattern,
		Enabled:          req.Enabled,
		SeverityOverride: req.SeverityOverride,
		AssetGroupID:     req.AssetGroupID,
		ScanProfileID:    req.ScanProfileID,
		Reason:           req.Reason,
		ExpiresAt:        req.ExpiresAt,
	}

	override, err := h.service.UpdateOverride(r.Context(), input)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(h.toOverrideResponse(override))
}

// DeleteOverride handles DELETE /overrides/{overrideId}
func (h *RuleHandler) DeleteOverride(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.GetTenantID(r.Context())
	overrideID := chi.URLParam(r, "overrideId")

	if err := h.service.DeleteOverride(r.Context(), tenantID, overrideID); err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// =============================================================================
// Bundle Handlers
// =============================================================================

// GetLatestBundle handles GET /bundles/latest
func (h *RuleHandler) GetLatestBundle(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.GetTenantID(r.Context())
	toolID := r.URL.Query().Get("tool_id")

	if toolID == "" {
		apierror.BadRequest("tool_id is required").WriteJSON(w)
		return
	}

	bundle, err := h.service.GetLatestBundle(r.Context(), tenantID, toolID)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(h.toBundleResponse(bundle))
}

// GetBundle handles GET /bundles/{bundleId}
func (h *RuleHandler) GetBundle(w http.ResponseWriter, r *http.Request) {
	bundleID := chi.URLParam(r, "bundleId")

	bundle, err := h.service.GetBundleByID(r.Context(), bundleID)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(h.toBundleResponse(bundle))
}

// ListBundles handles GET /bundles
func (h *RuleHandler) ListBundles(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.GetTenantID(r.Context())

	input := app.ListBundlesInput{
		TenantID: tenantID,
		ToolID:   r.URL.Query().Get("tool_id"),
		Status:   r.URL.Query().Get("status"),
	}

	bundles, err := h.service.ListBundles(r.Context(), input)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	items := make([]BundleResponse, 0, len(bundles))
	for _, bundle := range bundles {
		items = append(items, h.toBundleResponse(bundle))
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"items": items})
}

// =============================================================================
// Helper Methods
// =============================================================================

func (h *RuleHandler) toSourceResponse(source *rule.Source) SourceResponse {
	resp := SourceResponse{
		ID:                  source.ID.String(),
		TenantID:            source.TenantID.String(),
		Name:                source.Name,
		Description:         source.Description,
		SourceType:          string(source.SourceType),
		SyncEnabled:         source.SyncEnabled,
		SyncIntervalMinutes: source.SyncIntervalMinutes,
		LastSyncStatus:      string(source.LastSyncStatus),
		LastSyncError:       source.LastSyncError,
		ContentHash:         source.ContentHash,
		RuleCount:           source.RuleCount,
		Priority:            source.Priority,
		IsPlatformDefault:   source.IsPlatformDefault,
		Enabled:             source.Enabled,
		CreatedAt:           source.CreatedAt.Format(timeFormat),
		UpdatedAt:           source.UpdatedAt.Format(timeFormat),
	}

	if source.ToolID != nil {
		s := source.ToolID.String()
		resp.ToolID = &s
	}

	if source.CredentialsID != nil {
		s := source.CredentialsID.String()
		resp.CredentialsID = &s
	}

	if source.LastSyncAt != nil {
		s := source.LastSyncAt.Format(timeFormat)
		resp.LastSyncAt = &s
	}

	// Parse config based on source type
	if len(source.Config) > 0 {
		var config any
		_ = json.Unmarshal(source.Config, &config)
		resp.Config = config
	}

	return resp
}

func (h *RuleHandler) toRuleResponse(r *rule.Rule) RuleResponse {
	resp := RuleResponse{
		ID:             r.ID.String(),
		SourceID:       r.SourceID.String(),
		TenantID:       r.TenantID.String(),
		RuleID:         r.RuleID,
		Name:           r.Name,
		Severity:       string(r.Severity),
		Category:       r.Category,
		Subcategory:    r.Subcategory,
		Tags:           r.Tags,
		Description:    r.Description,
		Recommendation: r.Recommendation,
		References:     r.References,
		CWEIDs:         r.CWEIDs,
		OWASPIDs:       r.OWASPIDs,
		FilePath:       r.FilePath,
		ContentHash:    r.ContentHash,
		CreatedAt:      r.CreatedAt.Format(timeFormat),
		UpdatedAt:      r.UpdatedAt.Format(timeFormat),
	}

	if r.ToolID != nil {
		s := r.ToolID.String()
		resp.ToolID = &s
	}

	return resp
}

func (h *RuleHandler) toOverrideResponse(o *rule.Override) OverrideResponse {
	resp := OverrideResponse{
		ID:               o.ID.String(),
		TenantID:         o.TenantID.String(),
		RulePattern:      o.RulePattern,
		IsPattern:        o.IsPattern,
		Enabled:          o.Enabled,
		SeverityOverride: string(o.SeverityOverride),
		Reason:           o.Reason,
		CreatedAt:        o.CreatedAt.Format(timeFormat),
		UpdatedAt:        o.UpdatedAt.Format(timeFormat),
	}

	if o.ToolID != nil {
		s := o.ToolID.String()
		resp.ToolID = &s
	}

	if o.AssetGroupID != nil {
		s := o.AssetGroupID.String()
		resp.AssetGroupID = &s
	}

	if o.ScanProfileID != nil {
		s := o.ScanProfileID.String()
		resp.ScanProfileID = &s
	}

	if o.CreatedBy != nil {
		s := o.CreatedBy.String()
		resp.CreatedBy = &s
	}

	if o.ExpiresAt != nil {
		s := o.ExpiresAt.Format(timeFormat)
		resp.ExpiresAt = &s
	}

	return resp
}

func (h *RuleHandler) toBundleResponse(b *rule.Bundle) BundleResponse {
	resp := BundleResponse{
		ID:           b.ID.String(),
		TenantID:     b.TenantID.String(),
		ToolID:       b.ToolID.String(),
		Version:      b.Version,
		ContentHash:  b.ContentHash,
		RuleCount:    b.RuleCount,
		SourceCount:  b.SourceCount,
		SizeBytes:    b.SizeBytes,
		SourceHashes: b.SourceHashes,
		StoragePath:  b.StoragePath,
		Status:       string(b.Status),
		BuildError:   b.BuildError,
		CreatedAt:    b.CreatedAt.Format(timeFormat),
	}

	sourceIDs := make([]string, len(b.SourceIDs))
	for i, id := range b.SourceIDs {
		sourceIDs[i] = id.String()
	}
	resp.SourceIDs = sourceIDs

	if b.BuildStartedAt != nil {
		s := b.BuildStartedAt.Format(timeFormat)
		resp.BuildStartedAt = &s
	}

	if b.BuildCompletedAt != nil {
		s := b.BuildCompletedAt.Format(timeFormat)
		resp.BuildCompletedAt = &s
	}

	if b.ExpiresAt != nil {
		s := b.ExpiresAt.Format(timeFormat)
		resp.ExpiresAt = &s
	}

	return resp
}

func (h *RuleHandler) handleServiceError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, shared.ErrNotFound):
		apierror.NotFound("Rule resource").WriteJSON(w)
	case errors.Is(err, shared.ErrAlreadyExists):
		apierror.Conflict("resource already exists").WriteJSON(w)
	case errors.Is(err, shared.ErrValidation):
		apierror.BadRequest(err.Error()).WriteJSON(w)
	default:
		h.logger.Error("service error", "error", err)
		apierror.InternalError(err).WriteJSON(w)
	}
}
