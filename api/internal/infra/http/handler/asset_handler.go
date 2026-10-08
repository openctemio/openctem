package handler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	assetapp "github.com/openctemio/openctem/api/internal/app/asset"
	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	integrationapp "github.com/openctemio/openctem/api/internal/app/integration"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/internal/infra/scm"
	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/domain/accesscontrol"
	"github.com/openctemio/openctem/api/pkg/domain/asset"
	auditdom "github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/validator"
)

// AssetHandler handles asset-related HTTP requests.
type AssetHandler struct {
	service            *assetapp.AssetService
	integrationService *integrationapp.IntegrationService
	accessControlRepo  accesscontrol.Repository
	auditService       *auditapp.AuditService
	snoozeRateLimiter  *snoozeRateLimiter
	validator          *validator.Validator
	logger             *logger.Logger
}

// NewAssetHandler creates a new asset handler.
func NewAssetHandler(svc *assetapp.AssetService, v *validator.Validator, log *logger.Logger) *AssetHandler {
	return &AssetHandler{
		service:           svc,
		validator:         v,
		logger:            log,
		snoozeRateLimiter: newSnoozeRateLimiter(),
	}
}

// SetAccessControlRepo sets the access control repository for owner resolution.
func (h *AssetHandler) SetAccessControlRepo(repo accesscontrol.Repository) {
	h.accessControlRepo = repo
}

// SetIntegrationService sets the integration service for sync operations.
func (h *AssetHandler) SetIntegrationService(svc *integrationapp.IntegrationService) {
	h.integrationService = svc
}

// SetAuditService wires the audit logger. When set, snooze/unsnooze
// actions emit non-repudiable audit events so operators cannot silently
// hide stale assets from lifecycle sweeps. When nil, the handler
// behaves identically minus the audit — tests and stub builds do not
// need to provide one.
func (h *AssetHandler) SetAuditService(svc *auditapp.AuditService) {
	h.auditService = svc
}

// snoozeRateLimiter throttles lifecycle-snooze actions per tenant.
// Attack shape: a compromised operator token could snooze every asset
// in a single loop, hiding the entire estate from the stale-detection
// worker. 60/min keeps room for legitimate bulk operators (UI
// multi-select) without allowing a full-estate sweep.
type snoozeRateLimiter struct {
	mu       sync.Mutex
	requests map[string][]time.Time
	limit    int
	window   time.Duration
}

func newSnoozeRateLimiter() *snoozeRateLimiter {
	rl := &snoozeRateLimiter{
		requests: make(map[string][]time.Time),
		limit:    60,
		window:   time.Minute,
	}
	go rl.cleanup()
	return rl
}

func (rl *snoozeRateLimiter) allow(tenantID string) (bool, time.Duration) {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-rl.window)

	recent := rl.requests[tenantID][:0:0]
	for _, t := range rl.requests[tenantID] {
		if t.After(cutoff) {
			recent = append(recent, t)
		}
	}
	if len(recent) >= rl.limit {
		retry := recent[0].Add(rl.window).Sub(now)
		if retry < time.Second {
			retry = time.Second
		}
		rl.requests[tenantID] = recent
		return false, retry
	}
	rl.requests[tenantID] = append(recent, now)
	return true, 0
}

func (rl *snoozeRateLimiter) cleanup() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		rl.mu.Lock()
		cutoff := time.Now().Add(-rl.window)
		for k, times := range rl.requests {
			kept := times[:0]
			for _, t := range times {
				if t.After(cutoff) {
					kept = append(kept, t)
				}
			}
			if len(kept) == 0 {
				delete(rl.requests, k)
			} else {
				rl.requests[k] = kept
			}
		}
		rl.mu.Unlock()
	}
}

// buildAuditContext extracts audit context from the authenticated
// request. Mirrors SensorHandler's helper — kept local so the audit
// dependency is opt-in per handler.
func (h *AssetHandler) buildAuditContext(r *http.Request) auditapp.AuditContext {
	// Forwarding headers count only from a trusted proxy (S-4); a client
	// must not be able to write any IP it likes into the audit log.
	clientIP := getClientIP(r)
	return auditapp.AuditContext{
		TenantID:   middleware.GetTenantID(r.Context()),
		ActorID:    middleware.GetUserID(r.Context()),
		ActorEmail: auditActorEmail(r.Context()),
		ActorIP:    clientIP,
		UserAgent:  r.UserAgent(),
		RequestID:  r.Header.Get("X-Request-ID"),
	}
}

// auditCreateMerged records that a create request updated an existing asset
// instead of creating one. Only field names are recorded, never values.
func (h *AssetHandler) auditCreateMerged(r *http.Request, a *asset.Asset, changed []string) {
	if h.auditService == nil {
		return
	}
	if changed == nil {
		changed = []string{}
	}
	event := auditapp.NewSuccessEvent(auditdom.ActionAssetCreateMerged, auditdom.ResourceTypeAsset, a.ID().String()).
		WithResourceName(a.Name()).
		WithMessage("Create request matched an existing asset and updated it").
		WithMetadata("changed_fields", changed).
		WithSeverity(auditdom.SeverityMedium)
	_ = h.auditService.LogEvent(r.Context(), h.buildAuditContext(r), event)
}

// DuplicateAssetDetails is the details object of the 409 a create returns
// when the asset already exists. ExistingAssetID is present only when the
// caller may see that asset.
type DuplicateAssetDetails struct {
	ExistingAssetID string `json:"existing_asset_id,omitempty"`
}

// writeDuplicateAsset writes the 409 for a create that matched an existing
// asset. The body names the existing asset only when the service set its id
// (the asset is in the caller's data scope); otherwise it is the same generic
// conflict for every match, so it reveals nothing about the asset.
func writeDuplicateAsset(w http.ResponseWriter, dup *assetapp.DuplicateAssetError) {
	e := apierror.Conflict("Asset already exists")
	if !dup.ExistingID.IsZero() {
		e = e.WithDetails(DuplicateAssetDetails{ExistingAssetID: dup.ExistingID.String()})
	}
	e.WriteJSON(w)
}

// SnoozeLifecycleRequest is the body for POST /assets/{id}/lifecycle/snooze.
// Duration is expressed in days so the HTTP contract is simple;
// service layer converts to an absolute timestamp on the server
// side. 365 is the upper bound — beyond a year the snooze is
// effectively "forever" and operators should use manual_status_
// override instead (coming in a later phase).
type SnoozeLifecycleRequest struct {
	Days       int  `json:"days"`
	Reactivate bool `json:"reactivate"`
}

// SnoozeAssetLifecycle handles POST /api/v1/assets/{id}/lifecycle/snooze.
// The operator is expressing "do not let the background worker
// change this asset's status for N days." Optionally the same call
// also flips the asset back to active if it was already stale or
// inactive (reactivate=true). Setting days<=0 via DELETE endpoint
// clears the snooze — this endpoint rejects non-positive days to
// keep the two actions separate and obvious.
func (h *AssetHandler) SnoozeAssetLifecycle(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())
	if tenantID == "" {
		apierror.BadRequest("Tenant context required").WriteJSON(w)
		return
	}
	assetID := r.PathValue("id")
	if assetID == "" {
		apierror.BadRequest("Asset ID required").WriteJSON(w)
		return
	}

	if allowed, retry := h.snoozeRateLimiter.allow(tenantID); !allowed {
		w.Header().Set("Retry-After", strconv.Itoa(int(retry.Seconds())))
		apierror.TooManyRequests("snooze rate limit exceeded").WriteJSON(w)
		return
	}

	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	var req SnoozeLifecycleRequest
	if err := decoder.Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}
	if req.Days <= 0 || req.Days > 365 {
		apierror.BadRequest("days must be between 1 and 365; use DELETE to clear").WriteJSON(w)
		return
	}

	duration := time.Duration(req.Days) * 24 * time.Hour
	if err := h.service.SnoozeLifecycle(r.Context(), tenantID, assetID, duration, req.Reactivate); err != nil {
		h.handleServiceError(w, err)
		return
	}

	if h.auditService != nil {
		event := auditapp.NewSuccessEvent(auditdom.ActionAssetLifecycleSnoozed, auditdom.ResourceTypeAsset, assetID).
			WithMessage(fmt.Sprintf("Lifecycle snoozed for %d day(s)", req.Days)).
			WithMetadata("days", req.Days).
			WithMetadata("reactivate", req.Reactivate).
			WithSeverity(auditdom.SeverityLow)
		_ = h.auditService.LogEvent(r.Context(), h.buildAuditContext(r), event)
	}

	w.WriteHeader(http.StatusNoContent)
}

// UnsnoozeAssetLifecycle handles DELETE /api/v1/assets/{id}/lifecycle/snooze.
// Clearing a snooze is a neutral operation — the worker will take
// over on its next run. Reactivation is NOT implied here; an
// operator who wants the asset active clicks the regular status
// toggle.
func (h *AssetHandler) UnsnoozeAssetLifecycle(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())
	if tenantID == "" {
		apierror.BadRequest("Tenant context required").WriteJSON(w)
		return
	}
	assetID := r.PathValue("id")
	if assetID == "" {
		apierror.BadRequest("Asset ID required").WriteJSON(w)
		return
	}

	if allowed, retry := h.snoozeRateLimiter.allow(tenantID); !allowed {
		w.Header().Set("Retry-After", strconv.Itoa(int(retry.Seconds())))
		apierror.TooManyRequests("snooze rate limit exceeded").WriteJSON(w)
		return
	}

	// Duration 0 clears the snooze; reactivate is ignored in that
	// path (documented on the service method).
	if err := h.service.SnoozeLifecycle(r.Context(), tenantID, assetID, 0, false); err != nil {
		h.handleServiceError(w, err)
		return
	}

	if h.auditService != nil {
		event := auditapp.NewSuccessEvent(auditdom.ActionAssetLifecycleUnsnoozed, auditdom.ResourceTypeAsset, assetID).
			WithMessage("Lifecycle snooze cleared").
			WithSeverity(auditdom.SeverityLow)
		_ = h.auditService.LogEvent(r.Context(), h.buildAuditContext(r), event)
	}

	w.WriteHeader(http.StatusNoContent)
}

// AssetResponse represents an asset in API responses.
type AssetResponse struct {
	ID                    string                   `json:"id"`
	TenantID              string                   `json:"tenant_id,omitempty"`
	ParentID              string                   `json:"parent_id,omitempty"`
	OwnerRef              string                   `json:"owner_ref,omitempty"`
	Name                  string                   `json:"name"`
	Type                  string                   `json:"type"`
	SubType               string                   `json:"sub_type,omitempty"`
	Category              string                   `json:"category"`
	Provider              string                   `json:"provider,omitempty"`
	ExternalID            string                   `json:"external_id,omitempty"`
	Criticality           string                   `json:"criticality"`
	Status                string                   `json:"status"`
	Scope                 string                   `json:"scope"`
	Exposure              string                   `json:"exposure"`
	RiskScore             int                      `json:"risk_score"`
	FindingCount          int                      `json:"finding_count"`
	FindingSeverityCounts *FindingSeverityResponse `json:"finding_severity_counts,omitempty"`
	Description           string                   `json:"description,omitempty"`
	Tags                  []string                 `json:"tags,omitempty"`
	Properties            map[string]any           `json:"properties,omitempty"`
	PrimaryOwner          *OwnerBriefResponse      `json:"primary_owner,omitempty"`
	// IsCrownJewel is the crown-jewel flag, set by PATCH /assets/{id}/crown-jewel.
	IsCrownJewel bool `json:"is_crown_jewel"`

	// Discovery
	DiscoverySource string     `json:"discovery_source,omitempty"`
	DiscoveryTool   string     `json:"discovery_tool,omitempty"`
	DiscoveredAt    *time.Time `json:"discovered_at,omitempty"`

	// CTEM
	ComplianceScope      []string `json:"compliance_scope,omitempty"`
	DataClassification   string   `json:"data_classification,omitempty"`
	PIIDataExposed       bool     `json:"pii_data_exposed"`
	PHIDataExposed       bool     `json:"phi_data_exposed"`
	IsInternetAccessible bool     `json:"is_internet_accessible"`

	// CTEM Scoping: CIA impact rating (low | moderate | high; empty = not rated)
	ImpactConfidentiality string `json:"impact_confidentiality,omitempty"`
	ImpactIntegrity       string `json:"impact_integrity,omitempty"`
	ImpactAvailability    string `json:"impact_availability,omitempty"`

	// Sync
	SyncStatus   string     `json:"sync_status,omitempty"`
	LastSyncedAt *time.Time `json:"last_synced_at,omitempty"`

	// Timestamps
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`

	// Lifecycle state. Null LifecyclePausedUntil is the common case
	// (most assets have never been snoozed). ManualStatusOverride =
	// true tells the UI that the status was set by an operator and
	// the background worker is not allowed to change it.
	LifecyclePausedUntil *time.Time `json:"lifecycle_paused_until,omitempty"`
	ManualStatusOverride bool       `json:"manual_status_override"`
}

// FindingSeverityResponse represents finding counts by severity level.
type FindingSeverityResponse struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Info     int `json:"info"`
}

// OwnerBriefResponse is a lightweight owner representation for asset list responses.
type OwnerBriefResponse struct {
	ID    string `json:"id"`
	Type  string `json:"type"`
	Name  string `json:"name"`
	Email string `json:"email,omitempty"`
}

// ListResponse is defined in common.go

// CreateAssetRequest represents the request to create an asset.
type CreateAssetRequest struct {
	Name string `json:"name" validate:"required,min=1,max=255"`
	Type string `json:"type" validate:"required,asset_type"`
	// SubType is the kind within the type, from the registry's closed list
	// (GET /asset-types). A legacy value of the type is mapped; anything
	// else is a 400.
	SubType     string         `json:"sub_type,omitempty" validate:"omitempty,max=50"`
	Criticality string         `json:"criticality" validate:"required,criticality"`
	Scope       string         `json:"scope" validate:"omitempty,scope"`
	Exposure    string         `json:"exposure" validate:"omitempty,exposure"`
	Description string         `json:"description" validate:"max=1000"`
	Tags        []string       `json:"tags" validate:"max=50,dive,max=50"`
	OwnerRef    string         `json:"owner_ref" validate:"max=500"`
	Properties  map[string]any `json:"properties,omitempty"`
}

// UpdateAssetRequest represents the request to update an asset.
type UpdateAssetRequest struct {
	Name        *string        `json:"name" validate:"omitempty,min=1,max=255"`
	Criticality *string        `json:"criticality" validate:"omitempty,criticality"`
	Scope       *string        `json:"scope" validate:"omitempty,scope"`
	Exposure    *string        `json:"exposure" validate:"omitempty,exposure"`
	Description *string        `json:"description" validate:"omitempty,max=1000"`
	OwnerRef    *string        `json:"owner_ref" validate:"omitempty,max=500"`
	Tags        []string       `json:"tags" validate:"omitempty,max=50,dive,max=50"`
	Properties  map[string]any `json:"properties,omitempty"`
	// SubType changes the kind within the asset's type (closed list from
	// GET /asset-types); "" clears it. The type itself cannot change.
	SubType *string `json:"sub_type,omitempty" validate:"omitempty,max=50"`

	// CTEM Scoping: CIA impact rating (low | moderate | high). Empty string clears.
	ImpactConfidentiality *string `json:"impact_confidentiality" validate:"omitempty,impact_rating"`
	ImpactIntegrity       *string `json:"impact_integrity" validate:"omitempty,impact_rating"`
	ImpactAvailability    *string `json:"impact_availability" validate:"omitempty,impact_rating"`
}

// toAssetResponse converts a domain asset to API response.
func toAssetResponse(a *asset.Asset) AssetResponse {
	var tenantID string
	if !a.TenantID().IsZero() {
		tenantID = a.TenantID().String()
	}

	var parentID string
	if pid := a.ParentID(); pid != nil {
		parentID = pid.String()
	}

	resp := AssetResponse{
		ID:           a.ID().String(),
		TenantID:     tenantID,
		ParentID:     parentID,
		OwnerRef:     a.OwnerRef(),
		Name:         a.Name(),
		Type:         a.Type().String(),
		SubType:      a.SubType(),
		Category:     string(a.Category()),
		Provider:     a.Provider().String(),
		ExternalID:   a.ExternalID(),
		Criticality:  a.Criticality().String(),
		Status:       a.Status().String(),
		Scope:        a.Scope().String(),
		Exposure:     a.Exposure().String(),
		RiskScore:    a.RiskScore(),
		FindingCount: a.FindingCount(),
		Description:  a.Description(),
		Tags:         a.Tags(),
		Properties:   a.Properties(),
		IsCrownJewel: a.IsCrownJewel(),

		// Discovery
		DiscoverySource: a.DiscoverySource(),
		DiscoveryTool:   a.DiscoveryTool(),
		DiscoveredAt:    a.DiscoveredAt(),

		// CTEM
		ComplianceScope:      a.ComplianceScope(),
		DataClassification:   a.DataClassification().String(),
		PIIDataExposed:       a.PIIDataExposed(),
		PHIDataExposed:       a.PHIDataExposed(),
		IsInternetAccessible: a.IsInternetAccessible(),

		// CTEM Scoping: CIA impact rating
		ImpactConfidentiality: a.ImpactConfidentiality().String(),
		ImpactIntegrity:       a.ImpactIntegrity().String(),
		ImpactAvailability:    a.ImpactAvailability().String(),

		// Sync
		SyncStatus:   a.SyncStatus().String(),
		LastSyncedAt: a.LastSyncedAt(),

		// Timestamps
		FirstSeen: a.FirstSeen(),
		LastSeen:  a.LastSeen(),
		CreatedAt: a.CreatedAt(),
		UpdatedAt: a.UpdatedAt(),

		// Lifecycle
		LifecyclePausedUntil: a.LifecyclePausedUntil(),
		ManualStatusOverride: a.ManualStatusOverride(),
	}

	// Include finding severity breakdown if available
	if counts := a.FindingSeverityCounts(); counts != nil {
		resp.FindingSeverityCounts = &FindingSeverityResponse{
			Critical: counts.Critical,
			High:     counts.High,
			Medium:   counts.Medium,
			Low:      counts.Low,
			Info:     counts.Info,
		}
	}

	return resp
}

// toOwnerBriefResponse converts a domain OwnerBrief to API response.
func toOwnerBriefResponse(brief *accesscontrol.OwnerBrief) *OwnerBriefResponse {
	if brief == nil {
		return nil
	}
	return &OwnerBriefResponse{
		ID:    brief.ID,
		Type:  brief.Type,
		Name:  brief.Name,
		Email: brief.Email,
	}
}

// batchFetchPrimaryOwners fetches primary owners for a list of assets in a single query.
func (h *AssetHandler) batchFetchPrimaryOwners(ctx context.Context, tenantID string, assets []*asset.Asset) map[string]*accesscontrol.OwnerBrief {
	if h.accessControlRepo == nil || len(assets) == 0 {
		return make(map[string]*accesscontrol.OwnerBrief)
	}

	assetIDs := make([]shared.ID, len(assets))
	for i, a := range assets {
		assetIDs[i] = a.ID()
	}

	owners, err := h.accessControlRepo.GetPrimaryOwnersByAssetIDs(ctx, shared.MustIDFromString(tenantID), assetIDs)
	if err != nil {
		h.logger.Error("failed to batch fetch primary owners", "error", err)
		return make(map[string]*accesscontrol.OwnerBrief)
	}

	return owners
}

// handleValidationError converts validation errors to API errors and writes response.
func (h *AssetHandler) handleValidationError(w http.ResponseWriter, err error) {
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
func (h *AssetHandler) handleServiceError(w http.ResponseWriter, err error) {
	if WritePlanLimitError(w, err) {
		return
	}
	switch {
	case errors.Is(err, shared.ErrNotFound):
		apierror.NotFound("Asset").WriteJSON(w)
	case errors.Is(err, shared.ErrForbidden):
		apierror.Forbidden("Access denied").WriteJSON(w)
	case errors.Is(err, shared.ErrAlreadyExists):
		apierror.Conflict("Asset already exists").WriteJSON(w)
	case errors.Is(err, shared.ErrValidation):
		apierror.BadRequest(err.Error()).WriteJSON(w)
	default:
		h.logger.Error("service error", "error", err)
		apierror.InternalError(err).WriteJSON(w)
	}
}

// List handles GET /api/v1/assets
// @Summary      List assets
// @Description  Retrieves a paginated list of assets for the current tenant
// @Tags         Assets
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        name          query     string  false  "Filter by name (partial match)"
// @Param        types         query     string  false  "Filter by types (comma-separated)"
// @Param        criticalities query     string  false  "Filter by criticalities (comma-separated)"
// @Param        statuses      query     string  false  "Filter by statuses (comma-separated)"
// @Param        scopes        query     string  false  "Filter by scopes (comma-separated)"
// @Param        exposures     query     string  false  "Filter by exposures (comma-separated)"
// @Param        tags          query     string  false  "Filter by tags (comma-separated)"
// @Param        search        query     string  false  "Full-text search across name and description"
// @Param        min_risk_score  query   int     false  "Minimum risk score (0-100)"
// @Param        max_risk_score  query   int     false  "Maximum risk score (0-100)"
// @Param        has_findings  query     bool    false  "Filter by whether asset has findings"
// @Param        is_crown_jewel query    bool    false  "Filter crown-jewel assets"
// @Param        sub_type      query     string  false  "Filter by sub_type"
// @Param        business_unit_ids     query string false "Filter by business unit membership (comma-separated UUIDs)"
// @Param        has_owner             query bool   false "Filter assets with (true) / without (false) an assigned owner"
// @Param        data_classifications  query string false "Filter by data classification (comma-separated: public,internal,confidential,restricted,secret)"
// @Param        is_control_plane      query bool   false "Filter assets that are a control-plane dependency"
// @Param        is_internet_accessible query bool  false "Filter internet-reachable assets"
// @Param        environments          query string false "Filter by environment (comma-separated: production,staging,development,testing,dr)"
// @Param        providers             query string false "Filter by provider/source (comma-separated)"
// @Param        last_seen_after       query string false "Filter assets last seen at/after this time (RFC3339 or YYYY-MM-DD)"
// @Param        last_seen_before      query string false "Filter assets last seen at/before this time (RFC3339 or YYYY-MM-DD)"
// @Param        attribution           query string false "Filter by attribution (comma-separated): confirmed (includes assets with no record), needs_review, candidate, dependency, monitor_only, rejected, unknown (no record), unconfirmed (needs_review+candidate), approved (confirmed+unknown+dependency+monitor_only)"
// @Param        covered_by            query string false "Scope entry id: the assets the scope join confirmed through it"
// @Param        sort          query     string  false  "Sort field (e.g., -created_at, name, -risk_score)"
// @Param        page          query     int     false  "Page number"  default(1)
// @Param        per_page      query     int     false  "Items per page"  default(20)  maximum(100)
// @Success      200  {object}  map[string]interface{}
// @Failure      400  {object}  map[string]string
// @Failure      401  {object}  map[string]string
// @Failure      500  {object}  map[string]string
// @Router       /assets [get]
func (h *AssetHandler) List(w http.ResponseWriter, r *http.Request) {
	// Get tenant ID from JWT token (RequireTenant middleware guarantees this exists)
	tenantID := middleware.MustGetTenantID(r.Context())

	query := r.URL.Query()

	paging, ok := listPage(w, r, 20)
	if !ok {
		return
	}
	input := assetapp.ListAssetsInput{
		TenantID:         tenantID,
		Name:             query.Get("name"),
		Types:            parseQueryArray(query.Get("types")),
		Criticalities:    parseQueryArray(query.Get("criticalities")),
		Statuses:         parseQueryArray(query.Get("statuses")),
		Scopes:           parseQueryArray(query.Get("scopes")),
		Exposures:        parseQueryArray(query.Get("exposures")),
		Tags:             parseQueryArray(query.Get("tags")),
		Search:           query.Get("search"),
		MinRiskScore:     parseQueryIntPtr(query.Get("min_risk_score")),
		MaxRiskScore:     parseQueryIntPtr(query.Get("max_risk_score")),
		HasFindings:      parseQueryBoolPtr(query.Get("has_findings")),
		IsCrownJewel:     parseQueryBoolPtr(query.Get("is_crown_jewel")),
		SubType:          nilIfEmpty(query.Get("sub_type")),
		PropertiesFilter: ParsePropertiesFilter(query.Get("properties")),
		// CTEM inventory dimensions
		BusinessUnitIDs:      parseQueryArray(query.Get("business_unit_ids")),
		HasOwner:             parseQueryBoolPtr(query.Get("has_owner")),
		DataClassifications:  parseQueryArray(query.Get("data_classifications")),
		IsControlPlane:       parseQueryBoolPtr(query.Get("is_control_plane")),
		IsInternetAccessible: parseQueryBoolPtr(query.Get("is_internet_accessible")),
		Environments:         parseQueryArray(query.Get("environments")),
		Providers:            parseQueryArray(query.Get("providers")),
		LastSeenAfter:        parseQueryTimePtr(query.Get("last_seen_after")),
		LastSeenBefore:       parseQueryTimePtr(query.Get("last_seen_before")),
		Attribution:          parseQueryArray(query.Get("attribution")),
		CoveredBy:            query.Get("covered_by"),
		Sort:                 query.Get("sort"),
		Page:                 paging.Page,
		PerPage:              paging.PerPage,
		ActingUserID:         middleware.GetUserID(r.Context()),
		IsAdmin:              middleware.IsAdmin(r.Context()),
	}

	if err := h.validator.Validate(input); err != nil {
		h.handleValidationError(w, err)
		return
	}

	result, err := h.service.ListAssets(r.Context(), input)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	// Batch-fetch primary owners for all assets
	owners := h.batchFetchPrimaryOwners(r.Context(), input.TenantID, result.Data)

	// Check if we're filtering by repository type to include extensions
	isRepositoryTypeFilter := len(input.Types) == 1 && input.Types[0] == "repository"

	// If filtering by repository type, batch-fetch extensions and return combined response
	if isRepositoryTypeFilter && h.service.HasRepositoryExtensionRepository() {
		// Collect all asset IDs for batch fetch (single query instead of N+1)
		assetIDs := make([]shared.ID, len(result.Data))
		for i, a := range result.Data {
			assetIDs[i] = a.ID()
		}

		extensions, err := h.service.GetRepositoryExtensionsByAssetIDs(r.Context(), assetIDs)
		if err != nil {
			h.logger.Error("failed to batch fetch repository extensions", "error", err)
			extensions = make(map[shared.ID]*asset.RepositoryExtension)
		}

		data := make([]AssetWithRepositoryResponse, len(result.Data))
		for i, a := range result.Data {
			resp := AssetWithRepositoryResponse{
				AssetResponse: toAssetResponse(a),
			}
			resp.AssetResponse.PrimaryOwner = toOwnerBriefResponse(owners[a.ID().String()])
			if ext, ok := extensions[a.ID()]; ok {
				resp.Repository = toRepositoryExtensionResponse(ext)
			}
			data[i] = resp
		}

		response := ListResponse[AssetWithRepositoryResponse]{
			Data:       data,
			Total:      result.Total,
			Page:       result.Page,
			PerPage:    result.PerPage,
			TotalPages: result.TotalPages,
			Links:      NewPaginationLinks(r, result.Page, result.PerPage, result.TotalPages),
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(response)
		return
	}

	// Default response without extensions
	data := make([]AssetResponse, len(result.Data))
	for i, a := range result.Data {
		resp := toAssetResponse(a)
		resp.PrimaryOwner = toOwnerBriefResponse(owners[a.ID().String()])
		data[i] = resp
	}

	response := ListResponse[AssetResponse]{
		Data:       data,
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

// Create handles POST /api/v1/assets
// @Summary      Create asset
// @Description  Creates a new asset for the current tenant. A name (or a correlated address) that matches an existing asset is a 409 and nothing is changed; details.existing_asset_id names the existing asset only when it is in the caller's data scope.
// @Tags         Assets
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        request  body      CreateAssetRequest  true  "Asset data"
// @Success      201  {object}  AssetResponse
// @Failure      400  {object}  map[string]string
// @Failure      401  {object}  map[string]string
// @Failure      409  {object}  map[string]string
// @Failure      500  {object}  map[string]string
// @Router       /assets [post]
func (h *AssetHandler) Create(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())

	var req CreateAssetRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}

	if err := h.validator.Validate(req); err != nil {
		h.handleValidationError(w, err)
		return
	}

	input := assetapp.CreateAssetInput{
		TenantID:    tenantID,
		Name:        req.Name,
		Type:        req.Type,
		SubType:     req.SubType,
		Criticality: req.Criticality,
		Scope:       req.Scope,
		Exposure:    req.Exposure,
		Description: req.Description,
		Tags:        req.Tags,
		OwnerRef:    req.OwnerRef,
		Properties:  req.Properties,
	}

	a, err := h.service.CreateAsset(r.Context(), input)
	if err != nil {
		var dup *assetapp.DuplicateAssetError
		if errors.As(err, &dup) {
			writeDuplicateAsset(w, dup)
			return
		}
		h.handleServiceError(w, err)
		return
	}
	h.auditAsset(r, auditdom.ActionAssetCreated, a.ID().String(), a.Name(), "Asset created",
		map[string]any{"type": a.Type().String(), "criticality": a.Criticality().String()})

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(toAssetResponse(a))
}

// Get handles GET /api/v1/assets/{id}
// @Summary      Get asset
// @Description  Retrieves an asset by ID
// @Tags         Assets
// @Produce      json
// @Security     BearerAuth
// @Param        id   path      string  true  "Asset ID"
// @Success      200  {object}  AssetResponse
// @Failure      400  {object}  map[string]string
// @Failure      401  {object}  map[string]string
// @Failure      404  {object}  map[string]string
// @Failure      500  {object}  map[string]string
// @Router       /assets/{id} [get]
func (h *AssetHandler) Get(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())

	id := r.PathValue("id")
	if id == "" {
		apierror.BadRequest("Asset ID is required").WriteJSON(w)
		return
	}

	// GetAssetWithScope enforces tenant isolation + Layer 2 data scope
	a, err := h.service.GetAssetWithScope(r.Context(), tenantID, id, middleware.GetUserID(r.Context()), middleware.IsAdmin(r.Context()))
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	resp := toAssetResponse(a)

	// Fetch primary owner
	if h.accessControlRepo != nil {
		owner, ownerErr := h.accessControlRepo.GetPrimaryOwnerBrief(r.Context(), shared.MustIDFromString(tenantID), a.ID())
		if ownerErr != nil {
			h.logger.Error("failed to fetch primary owner", "asset_id", id, "error", ownerErr)
		} else {
			resp.PrimaryOwner = toOwnerBriefResponse(owner)
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)
}

// Update handles PUT /api/v1/assets/{id}
// @Summary      Update asset
// @Description  Updates an existing asset
// @Tags         Assets
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        id       path      string              true  "Asset ID"
// @Param        request  body      UpdateAssetRequest  true  "Asset data"
// @Success      200  {object}  AssetResponse
// @Failure      400  {object}  map[string]string
// @Failure      401  {object}  map[string]string
// @Failure      404  {object}  map[string]string
// @Failure      500  {object}  map[string]string
// @Router       /assets/{id} [put]
func (h *AssetHandler) Update(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())

	id := r.PathValue("id")
	if id == "" {
		apierror.BadRequest("Asset ID is required").WriteJSON(w)
		return
	}

	var req UpdateAssetRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}

	if err := h.validator.Validate(req); err != nil {
		h.handleValidationError(w, err)
		return
	}

	input := assetapp.UpdateAssetInput{
		Name:                  req.Name,
		Criticality:           req.Criticality,
		Scope:                 req.Scope,
		Exposure:              req.Exposure,
		Description:           req.Description,
		OwnerRef:              req.OwnerRef,
		Tags:                  req.Tags,
		SubType:               req.SubType,
		Properties:            req.Properties,
		ImpactConfidentiality: req.ImpactConfidentiality,
		ImpactIntegrity:       req.ImpactIntegrity,
		ImpactAvailability:    req.ImpactAvailability,
	}

	// The version before the change, for the audit trail's changed-field list.
	before, err := h.service.GetAsset(r.Context(), tenantID, id)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	a, err := h.service.UpdateAsset(r.Context(), id, tenantID, input)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}
	h.auditAsset(r, auditdom.ActionAssetUpdated, a.ID().String(), a.Name(), "Asset updated",
		map[string]any{"changed_fields": assetChangedFields(before, a)})

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(toAssetResponse(a))
}

// AssetDeleteRefusedDetails is the details object of the 409 returned when an
// asset that has findings is deleted.
type AssetDeleteRefusedDetails struct {
	Reason       string `json:"reason" example:"asset_has_findings"`
	FindingCount int64  `json:"finding_count"`
	// ArchivePath is the request that archives the asset instead.
	ArchivePath string `json:"archive_path" example:"/api/v1/assets/{id}/archive"`
}

// Delete handles DELETE /api/v1/assets/{id}
// @Summary      Delete asset
// @Description  Deletes an asset that has no findings (soft delete: it disappears from every list and its name can be used again; it is purged after the retention period). An asset that has findings, whatever their status, is refused with 409 (details.reason "asset_has_findings"): archive it instead (POST /assets/{id}/archive), so its finding history is kept.
// @Tags         Assets
// @Security     BearerAuth
// @Param        id   path      string  true  "Asset ID"
// @Success      204  "No Content"
// @Failure      400  {object}  map[string]string
// @Failure      401  {object}  map[string]string
// @Failure      404  {object}  map[string]string
// @Failure      409  {object}  apierror.Error{details=AssetDeleteRefusedDetails}
// @Failure      500  {object}  map[string]string
// @Router       /assets/{id} [delete]
func (h *AssetHandler) Delete(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())

	id := r.PathValue("id")
	if id == "" {
		apierror.BadRequest("Asset ID is required").WriteJSON(w)
		return
	}

	// Read it first (data scope applies): the audit entry keeps the name the
	// soft delete replaces with a tombstone.
	existing, err := h.service.GetAsset(r.Context(), tenantID, id)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	if err := h.service.DeleteAsset(r.Context(), id, tenantID, middleware.GetUserID(r.Context())); err != nil {
		var hasFindings *asset.HasFindingsError
		if errors.As(err, &hasFindings) {
			apierror.Conflict("This asset has findings, so it cannot be deleted: archive it instead to keep its finding history").
				WithDetails(AssetDeleteRefusedDetails{
					Reason:       "asset_has_findings",
					FindingCount: hasFindings.FindingCount,
					ArchivePath:  "/api/v1/assets/" + id + "/archive",
				}).WriteJSON(w)
			return
		}
		h.handleServiceError(w, err)
		return
	}
	h.auditAsset(r, auditdom.ActionAssetDeleted, existing.ID().String(), existing.Name(), "Asset deleted (soft delete; it had no findings)",
		map[string]any{"type": existing.Type().String()})

	w.WriteHeader(http.StatusNoContent)
}

// RepositoryExtensionResponse represents a repository extension in API responses.
type RepositoryExtensionResponse struct {
	AssetID              string           `json:"asset_id"`
	RepoID               string           `json:"repo_id,omitempty"`
	FullName             string           `json:"full_name"`
	SCMOrganization      string           `json:"scm_organization,omitempty"`
	CloneURL             string           `json:"clone_url,omitempty"`
	WebURL               string           `json:"web_url,omitempty"`
	SSHURL               string           `json:"ssh_url,omitempty"`
	DefaultBranch        string           `json:"default_branch,omitempty"`
	Visibility           string           `json:"visibility"`
	Language             string           `json:"language,omitempty"`
	Languages            map[string]int64 `json:"languages,omitempty"`
	Topics               []string         `json:"topics,omitempty"`
	Stars                int              `json:"stars"`
	Forks                int              `json:"forks"`
	Watchers             int              `json:"watchers"`
	OpenIssues           int              `json:"open_issues"`
	ContributorsCount    int              `json:"contributors_count"`
	SizeKB               int              `json:"size_kb"`
	BranchCount          int              `json:"branch_count"`
	ProtectedBranchCount int              `json:"protected_branch_count"`
	ComponentCount       int              `json:"component_count"`
	VulnComponentCount   int              `json:"vulnerable_component_count"`
	FindingCount         int              `json:"finding_count"`
	ScanEnabled          bool             `json:"scan_enabled"`
	ScanSchedule         string           `json:"scan_schedule,omitempty"`
	LastScannedAt        *time.Time       `json:"last_scanned_at,omitempty"`
	RepoCreatedAt        *time.Time       `json:"repo_created_at,omitempty"`
	RepoUpdatedAt        *time.Time       `json:"repo_updated_at,omitempty"`
	RepoPushedAt         *time.Time       `json:"repo_pushed_at,omitempty"`
}

// AssetWithRepositoryResponse combines asset and repository extension.
type AssetWithRepositoryResponse struct {
	AssetResponse
	Repository *RepositoryExtensionResponse `json:"repository,omitempty"`
}

// CreateRepositoryAssetRequest represents the request to create a repository asset.
type CreateRepositoryAssetRequest struct {
	// Basic info
	Name        string   `json:"name" validate:"required,min=1,max=255"`
	Description string   `json:"description" validate:"max=1000"`
	Criticality string   `json:"criticality" validate:"required,criticality"`
	Scope       string   `json:"scope" validate:"omitempty,scope"`
	Exposure    string   `json:"exposure" validate:"omitempty,exposure"`
	Tags        []string `json:"tags" validate:"max=50,dive,max=50"`
	// SCM connection info
	Provider        string `json:"provider" validate:"omitempty"`
	ExternalID      string `json:"external_id" validate:"omitempty,max=255"`
	RepoID          string `json:"repo_id" validate:"omitempty,max=255"`
	FullName        string `json:"full_name" validate:"required,max=500"`
	SCMOrganization string `json:"scm_organization" validate:"omitempty,max=255"`
	// URLs
	CloneURL string `json:"clone_url" validate:"omitempty,url"`
	WebURL   string `json:"web_url" validate:"omitempty,url"`
	SSHURL   string `json:"ssh_url" validate:"omitempty,max=500"`
	// Repository settings
	DefaultBranch string           `json:"default_branch" validate:"omitempty,max=100"`
	Visibility    string           `json:"visibility" validate:"omitempty"`
	Language      string           `json:"language" validate:"omitempty,max=50"`
	Languages     map[string]int64 `json:"languages" validate:"omitempty"`
	Topics        []string         `json:"topics" validate:"max=50,dive,max=100"`
	// Stats
	Stars      int `json:"stars" validate:"min=0"`
	Forks      int `json:"forks" validate:"min=0"`
	Watchers   int `json:"watchers" validate:"min=0"`
	OpenIssues int `json:"open_issues" validate:"min=0"`
	SizeKB     int `json:"size_kb" validate:"min=0"`
	// Scan settings
	ScanEnabled  bool   `json:"scan_enabled"`
	ScanSchedule string `json:"scan_schedule" validate:"omitempty,max=100"`
	// Timestamps from SCM (ISO 8601 format)
	RepoCreatedAt string `json:"repo_created_at" validate:"omitempty"`
	RepoUpdatedAt string `json:"repo_updated_at" validate:"omitempty"`
	RepoPushedAt  string `json:"repo_pushed_at" validate:"omitempty"`
}

// UpdateRepositoryExtensionRequest represents the request to update a repository extension.
type UpdateRepositoryExtensionRequest struct {
	RepoID               *string          `json:"repo_id" validate:"omitempty,max=255"`
	FullName             *string          `json:"full_name" validate:"omitempty,max=500"`
	SCMOrganization      *string          `json:"scm_organization" validate:"omitempty,max=255"`
	CloneURL             *string          `json:"clone_url" validate:"omitempty,url"`
	WebURL               *string          `json:"web_url" validate:"omitempty,url"`
	SSHURL               *string          `json:"ssh_url" validate:"omitempty,max=500"`
	DefaultBranch        *string          `json:"default_branch" validate:"omitempty,max=100"`
	Visibility           *string          `json:"visibility" validate:"omitempty"`
	Language             *string          `json:"language" validate:"omitempty,max=50"`
	Languages            map[string]int64 `json:"languages" validate:"omitempty"`
	Topics               []string         `json:"topics" validate:"omitempty,max=50,dive,max=100"`
	Stars                *int             `json:"stars" validate:"omitempty,min=0"`
	Forks                *int             `json:"forks" validate:"omitempty,min=0"`
	Watchers             *int             `json:"watchers" validate:"omitempty,min=0"`
	OpenIssues           *int             `json:"open_issues" validate:"omitempty,min=0"`
	ContributorsCount    *int             `json:"contributors_count" validate:"omitempty,min=0"`
	SizeKB               *int             `json:"size_kb" validate:"omitempty,min=0"`
	BranchCount          *int             `json:"branch_count" validate:"omitempty,min=0"`
	ProtectedBranchCount *int             `json:"protected_branch_count" validate:"omitempty,min=0"`
	ComponentCount       *int             `json:"component_count" validate:"omitempty,min=0"`
}

// toRepositoryExtensionResponse converts a domain repository extension to API response.
func toRepositoryExtensionResponse(ext *asset.RepositoryExtension) *RepositoryExtensionResponse {
	if ext == nil {
		return nil
	}
	return &RepositoryExtensionResponse{
		AssetID:              ext.AssetID().String(),
		RepoID:               ext.RepoID(),
		FullName:             ext.FullName(),
		SCMOrganization:      ext.SCMOrganization(),
		CloneURL:             ext.CloneURL(),
		WebURL:               ext.WebURL(),
		SSHURL:               ext.SSHURL(),
		DefaultBranch:        ext.DefaultBranch(),
		Visibility:           ext.Visibility().String(),
		Language:             ext.Language(),
		Languages:            ext.Languages(),
		Topics:               ext.Topics(),
		Stars:                ext.Stars(),
		Forks:                ext.Forks(),
		Watchers:             ext.Watchers(),
		OpenIssues:           ext.OpenIssues(),
		ContributorsCount:    ext.ContributorsCount(),
		SizeKB:               ext.SizeKB(),
		BranchCount:          ext.BranchCount(),
		ProtectedBranchCount: ext.ProtectedBranchCount(),
		ComponentCount:       ext.ComponentCount(),
		VulnComponentCount:   ext.VulnerableComponentCount(),
		FindingCount:         ext.FindingCount(),
		ScanEnabled:          ext.ScanEnabled(),
		ScanSchedule:         ext.ScanSchedule(),
		LastScannedAt:        ext.LastScannedAt(),
		RepoCreatedAt:        ext.RepoCreatedAt(),
		RepoUpdatedAt:        ext.RepoUpdatedAt(),
		RepoPushedAt:         ext.RepoPushedAt(),
	}
}

// CreateRepository handles POST /api/v1/assets/repository
// @Summary      Create repository asset
// @Description  Creates a new repository asset with its extension data
// @Tags         Assets
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        request  body      CreateRepositoryAssetRequest  true  "Repository asset data"
// @Success      201  {object}  AssetWithRepositoryResponse
// @Failure      400  {object}  map[string]string
// @Failure      401  {object}  map[string]string
// @Failure      409  {object}  map[string]string
// @Failure      500  {object}  map[string]string
// @Router       /assets/repository [post]
func (h *AssetHandler) CreateRepository(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())

	var req CreateRepositoryAssetRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}

	if err := h.validator.Validate(req); err != nil {
		h.handleValidationError(w, err)
		return
	}

	input := assetapp.CreateRepositoryAssetInput{
		TenantID:        tenantID,
		Name:            req.Name,
		Description:     req.Description,
		Criticality:     req.Criticality,
		Scope:           req.Scope,
		Exposure:        req.Exposure,
		Tags:            req.Tags,
		Provider:        req.Provider,
		ExternalID:      req.ExternalID,
		RepoID:          req.RepoID,
		FullName:        req.FullName,
		SCMOrganization: req.SCMOrganization,
		CloneURL:        req.CloneURL,
		WebURL:          req.WebURL,
		SSHURL:          req.SSHURL,
		DefaultBranch:   req.DefaultBranch,
		Visibility:      req.Visibility,
		Language:        req.Language,
		Languages:       req.Languages,
		Topics:          req.Topics,
		Stars:           req.Stars,
		Forks:           req.Forks,
		Watchers:        req.Watchers,
		OpenIssues:      req.OpenIssues,
		SizeKB:          req.SizeKB,
		ScanEnabled:     req.ScanEnabled,
		ScanSchedule:    req.ScanSchedule,
		RepoCreatedAt:   req.RepoCreatedAt,
		RepoUpdatedAt:   req.RepoUpdatedAt,
		RepoPushedAt:    req.RepoPushedAt,
	}

	a, ext, outcome, err := h.service.CreateRepositoryAssetWithOutcome(r.Context(), input)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}
	if outcome.Merged {
		h.auditCreateMerged(r, a, outcome.ChangedFields)
	}

	response := AssetWithRepositoryResponse{
		AssetResponse: toAssetResponse(a),
		Repository:    toRepositoryExtensionResponse(ext),
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(response)
}

// GetRepository handles GET /api/v1/assets/{id}/repository
// @Summary      Get repository extension
// @Description  Retrieves the repository extension for an asset
// @Tags         Assets
// @Produce      json
// @Security     BearerAuth
// @Param        id   path      string  true  "Asset ID"
// @Success      200  {object}  RepositoryExtensionResponse
// @Failure      400  {object}  map[string]string
// @Failure      401  {object}  map[string]string
// @Failure      404  {object}  map[string]string
// @Failure      500  {object}  map[string]string
// @Router       /assets/{id}/repository [get]
func (h *AssetHandler) GetRepository(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())

	id := r.PathValue("id")
	if id == "" {
		apierror.BadRequest("Asset ID is required").WriteJSON(w)
		return
	}

	// GetAsset now enforces tenant isolation internally
	a, err := h.service.GetAsset(r.Context(), tenantID, id)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	// Check if asset is a repository type - return 404 to avoid leaking asset type info
	if a.Type() != asset.AssetTypeRepository {
		apierror.NotFound("Repository").WriteJSON(w)
		return
	}

	ext, err := h.service.GetRepositoryExtension(r.Context(), tenantID, id)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(toRepositoryExtensionResponse(ext))
}

// GetWithRepository handles GET /api/v1/assets/{id}/full
// @Summary      Get asset with repository
// @Description  Retrieves an asset with its repository extension (if applicable)
// @Tags         Assets
// @Produce      json
// @Security     BearerAuth
// @Param        id   path      string  true  "Asset ID"
// @Success      200  {object}  AssetWithRepositoryResponse
// @Failure      400  {object}  map[string]string
// @Failure      401  {object}  map[string]string
// @Failure      404  {object}  map[string]string
// @Failure      500  {object}  map[string]string
// @Router       /assets/{id}/full [get]
func (h *AssetHandler) GetWithRepository(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())

	id := r.PathValue("id")
	if id == "" {
		apierror.BadRequest("Asset ID is required").WriteJSON(w)
		return
	}

	// GetAssetWithRepository now enforces tenant isolation internally
	a, ext, err := h.service.GetAssetWithRepository(r.Context(), tenantID, id)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	response := AssetWithRepositoryResponse{
		AssetResponse: toAssetResponse(a),
		Repository:    toRepositoryExtensionResponse(ext),
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(response)
}

// UpdateRepository handles PUT /api/v1/assets/{id}/repository
// @Summary      Update repository extension
// @Description  Updates the repository extension for an asset
// @Tags         Assets
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        id       path      string                          true  "Asset ID"
// @Param        request  body      UpdateRepositoryExtensionRequest  true  "Repository extension data"
// @Success      200  {object}  RepositoryExtensionResponse
// @Failure      400  {object}  map[string]string
// @Failure      401  {object}  map[string]string
// @Failure      404  {object}  map[string]string
// @Failure      500  {object}  map[string]string
// @Router       /assets/{id}/repository [put]
func (h *AssetHandler) UpdateRepository(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())

	id := r.PathValue("id")
	if id == "" {
		apierror.BadRequest("Asset ID is required").WriteJSON(w)
		return
	}

	// GetAsset now enforces tenant isolation internally
	a, err := h.service.GetAsset(r.Context(), tenantID, id)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	// Check if asset is a repository type - return 404 to avoid leaking asset type info
	if a.Type() != asset.AssetTypeRepository {
		apierror.NotFound("Repository").WriteJSON(w)
		return
	}

	var req UpdateRepositoryExtensionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}

	if err := h.validator.Validate(req); err != nil {
		h.handleValidationError(w, err)
		return
	}

	input := assetapp.UpdateRepositoryExtensionInput{
		RepoID:               req.RepoID,
		FullName:             req.FullName,
		SCMOrganization:      req.SCMOrganization,
		CloneURL:             req.CloneURL,
		WebURL:               req.WebURL,
		SSHURL:               req.SSHURL,
		DefaultBranch:        req.DefaultBranch,
		Visibility:           req.Visibility,
		Language:             req.Language,
		Languages:            req.Languages,
		Topics:               req.Topics,
		Stars:                req.Stars,
		Forks:                req.Forks,
		Watchers:             req.Watchers,
		OpenIssues:           req.OpenIssues,
		ContributorsCount:    req.ContributorsCount,
		SizeKB:               req.SizeKB,
		BranchCount:          req.BranchCount,
		ProtectedBranchCount: req.ProtectedBranchCount,
		ComponentCount:       req.ComponentCount,
	}

	ext, err := h.service.UpdateRepositoryExtension(r.Context(), tenantID, id, input)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(toRepositoryExtensionResponse(ext))
}

// Activate handles POST /api/v1/assets/{id}/activate
// @Summary      Activate asset
// @Description  Activates an asset
// @Tags         Assets
// @Produce      json
// @Security     BearerAuth
// @Param        id   path      string  true  "Asset ID"
// @Success      200  {object}  AssetResponse
// @Failure      400  {object}  map[string]string
// @Failure      401  {object}  map[string]string
// @Failure      404  {object}  map[string]string
// @Failure      500  {object}  map[string]string
// @Router       /assets/{id}/activate [post]
func (h *AssetHandler) Activate(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())

	id := r.PathValue("id")
	if id == "" {
		apierror.BadRequest("Asset ID is required").WriteJSON(w)
		return
	}

	// ActivateAsset now enforces tenant isolation internally
	before, err := h.service.GetAsset(r.Context(), tenantID, id)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}
	a, err := h.service.ActivateAsset(r.Context(), tenantID, id)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}
	h.auditAsset(r, auditdom.ActionAssetStatusChanged, a.ID().String(), a.Name(), "Asset status changed",
		map[string]any{"from": before.Status().String(), "to": a.Status().String()})

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(toAssetResponse(a))
}

// Deactivate handles POST /api/v1/assets/{id}/deactivate
// @Summary      Deactivate asset
// @Description  Deactivates an asset
// @Tags         Assets
// @Produce      json
// @Security     BearerAuth
// @Param        id   path      string  true  "Asset ID"
// @Success      200  {object}  AssetResponse
// @Failure      400  {object}  map[string]string
// @Failure      401  {object}  map[string]string
// @Failure      404  {object}  map[string]string
// @Failure      500  {object}  map[string]string
// @Router       /assets/{id}/deactivate [post]
func (h *AssetHandler) Deactivate(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())

	id := r.PathValue("id")
	if id == "" {
		apierror.BadRequest("Asset ID is required").WriteJSON(w)
		return
	}

	// DeactivateAsset now enforces tenant isolation internally
	before, err := h.service.GetAsset(r.Context(), tenantID, id)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}
	a, err := h.service.DeactivateAsset(r.Context(), tenantID, id)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}
	h.auditAsset(r, auditdom.ActionAssetStatusChanged, a.ID().String(), a.Name(), "Asset status changed",
		map[string]any{"from": before.Status().String(), "to": a.Status().String()})

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(toAssetResponse(a))
}

// Archive handles POST /api/v1/assets/{id}/archive
// @Summary      Archive asset
// @Description  Archives an asset
// @Tags         Assets
// @Produce      json
// @Security     BearerAuth
// @Param        id   path      string  true  "Asset ID"
// @Success      200  {object}  AssetResponse
// @Failure      400  {object}  map[string]string
// @Failure      401  {object}  map[string]string
// @Failure      404  {object}  map[string]string
// @Failure      500  {object}  map[string]string
// @Router       /assets/{id}/archive [post]
func (h *AssetHandler) Archive(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())

	id := r.PathValue("id")
	if id == "" {
		apierror.BadRequest("Asset ID is required").WriteJSON(w)
		return
	}

	// ArchiveAsset now enforces tenant isolation internally
	before, err := h.service.GetAsset(r.Context(), tenantID, id)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}
	a, err := h.service.ArchiveAsset(r.Context(), tenantID, id)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}
	h.auditAsset(r, auditdom.ActionAssetStatusChanged, a.ID().String(), a.Name(), "Asset status changed",
		map[string]any{"from": before.Status().String(), "to": a.Status().String()})

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(toAssetResponse(a))
}

// AssetBulkStatusRequest represents a bulk asset status update request.
type AssetBulkStatusRequest struct {
	AssetIDs []string `json:"asset_ids" validate:"required,min=1,max=100,dive,uuid"`
	Status   string   `json:"status" validate:"required,oneof=active inactive archived"`
}

// AssetBulkStatusResponse represents a bulk asset status update response.
type AssetBulkStatusResponse struct {
	Updated int      `json:"updated"`
	Failed  int      `json:"failed"`
	Errors  []string `json:"errors,omitempty"`
}

// BulkUpdateStatus handles POST /api/v1/assets/bulk/status
// @Summary      Bulk update asset status
// @Description  Updates the status of multiple assets at once
// @Tags         Assets
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        request  body      AssetBulkStatusRequest  true  "Bulk update data"
// @Success      200  {object}  AssetBulkStatusResponse
// @Failure      400  {object}  map[string]string
// @Failure      401  {object}  map[string]string
// @Failure      500  {object}  map[string]string
// @Router       /assets/bulk/status [post]
func (h *AssetHandler) BulkUpdateStatus(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())

	var req AssetBulkStatusRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("Invalid JSON body").WriteJSON(w)
		return
	}

	if len(req.AssetIDs) == 0 {
		apierror.BadRequest("asset_ids is required").WriteJSON(w)
		return
	}

	if len(req.AssetIDs) > 100 {
		apierror.BadRequest("Cannot update more than 100 assets at once").WriteJSON(w)
		return
	}

	input := assetapp.BulkUpdateAssetStatusInput{
		AssetIDs: req.AssetIDs,
		Status:   req.Status,
	}

	result, err := h.service.BulkUpdateAssetStatus(r.Context(), tenantID, input)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}
	h.auditAsset(r, auditdom.ActionAssetBulkStatusChanged, "", "", "Bulk asset status change",
		map[string]any{"status": req.Status, "asset_ids": req.AssetIDs, "updated": result.Updated, "failed": result.Failed})

	resp := AssetBulkStatusResponse{
		Updated: result.Updated,
		Failed:  result.Failed,
		Errors:  result.Errors,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)
}

// AssetStatsResponse represents asset statistics in API responses.
type AssetStatsResponse struct {
	Total          int                       `json:"total"`
	ByType         map[string]int            `json:"by_type"`
	BySubType      map[string]int            `json:"by_sub_type"`
	ByStatus       map[string]int            `json:"by_status"`
	ByCriticality  map[string]int            `json:"by_criticality"`
	ByScope        map[string]int            `json:"by_scope"`
	ByExposure     map[string]int            `json:"by_exposure"`
	WithFindings   int                       `json:"with_findings"`
	RiskScoreAvg   float64                   `json:"risk_score_avg"`
	FindingsTotal  int                       `json:"findings_total"`
	HighRiskCount  int                       `json:"high_risk_count"`
	MetadataCounts map[string]map[string]int `json:"metadata_counts,omitempty"`
	// CTEM inventory facet counts.
	ByDataClassification map[string]int `json:"by_data_classification,omitempty"`
	ByEnvironment        map[string]int `json:"by_environment,omitempty"`
	ByProvider           map[string]int `json:"by_provider,omitempty"`
	ByInternetAccessible map[string]int `json:"by_internet_accessible,omitempty"`
	ByHasOwner           map[string]int `json:"by_has_owner,omitempty"`
	ByControlPlane       map[string]int `json:"by_control_plane,omitempty"`
	ByBusinessUnit       map[string]int `json:"by_business_unit,omitempty"`
}

// GetStats handles GET /api/v1/assets/stats
// @Summary      Get asset statistics
// @Description  Returns aggregated statistics for assets
// @Tags         Assets
// @Produce      json
// @Security     BearerAuth
// @Param        types         query     string  false  "Filter by types (comma-separated)"
// @Param        tags          query     string  false  "Filter by tags (comma-separated, overlap)"
// @Success      200  {object}  AssetStatsResponse
// @Failure      401  {object}  map[string]string
// @Failure      500  {object}  map[string]string
// @Router       /assets/stats [get]
func (h *AssetHandler) GetStats(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())

	query := r.URL.Query()
	typesFilter := parseQueryArray(query.Get("types"))
	tagsFilter := parseQueryArray(query.Get("tags"))
	subTypeFilter := query.Get("sub_type")

	// Property keys to count values of (e.g. ?count_by=is_virtual,os_name).
	countByFields := statsCountByFields(parseQueryArray(query.Get("count_by")))

	// Use service method with SQL aggregation for efficient stats
	aggStats, err := h.service.GetAssetStats(r.Context(), tenantID,
		middleware.GetUserID(r.Context()), middleware.IsAdmin(r.Context()), typesFilter, tagsFilter, subTypeFilter, countByFields...)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	stats := AssetStatsResponse{
		Total:                aggStats.Total,
		ByType:               aggStats.ByType,
		BySubType:            aggStats.BySubType,
		ByStatus:             aggStats.ByStatus,
		ByCriticality:        aggStats.ByCriticality,
		ByScope:              aggStats.ByScope,
		ByExposure:           aggStats.ByExposure,
		WithFindings:         aggStats.WithFindings,
		FindingsTotal:        aggStats.FindingsTotal,
		HighRiskCount:        aggStats.HighRiskCount,
		RiskScoreAvg:         aggStats.RiskScoreAvg,
		MetadataCounts:       aggStats.MetadataCounts,
		ByDataClassification: aggStats.ByDataClassification,
		ByEnvironment:        aggStats.ByEnvironment,
		ByProvider:           aggStats.ByProvider,
		ByInternetAccessible: aggStats.ByInternetAccessible,
		ByHasOwner:           aggStats.ByHasOwner,
		ByControlPlane:       aggStats.ByControlPlane,
		ByBusinessUnit:       aggStats.ByBusinessUnit,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(stats)
}

// maxStatsCountBy caps ?count_by: each field adds one GROUP BY over the
// caller's assets to the stats query.
const maxStatsCountBy = 10

// statsCountByFields keeps the count_by fields that are property keys of the
// schema (a synonym counts as its canonical key), without duplicates, up to
// maxStatsCountBy. Anything else is dropped: it would only ever count keys
// the schema does not have.
func statsCountByFields(fields []string) []string {
	out := make([]string, 0, len(fields))
	for _, f := range fields {
		key := asset.CanonicalPropertyKey(strings.TrimSpace(f))
		if _, ok := asset.LookupProperty(key); !ok || slices.Contains(out, key) {
			continue
		}
		out = append(out, key)
		if len(out) == maxStatsCountBy {
			break
		}
	}
	return out
}

// ListTags returns distinct tags across all assets for the tenant.
// Supports prefix filtering for autocomplete via ?prefix= query parameter.
func (h *AssetHandler) ListTags(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())

	prefix := r.URL.Query().Get("prefix")
	types := r.URL.Query()["type"]
	limit, ok := listLimit(w, r, 50, 100)
	if !ok {
		return
	}

	tags, err := h.service.ListTags(r.Context(), tenantID, prefix, types, limit)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string][]string{"tags": tags})
}

// InventoryOverviewResponse is GET /assets/overview: the inventory counted
// per (lens, type, sub-type).
type InventoryOverviewResponse struct {
	Data []asset.InventoryOverviewRow `json:"data"`
}

// GetInventoryOverview handles GET /api/v1/assets/overview
// @Summary      Inventory overview
// @Description  Counts the caller's assets per lens, type and sub-type in one aggregate: the assets the default inventory lists (total), the unowned, high-risk (risk score 70 or more) and first-seen-in-the-last-7-days ones among them, and the names waiting in the attribution review queue. Counted over the assets the caller may list (data scope), within the caller's tenant.
// @Tags         Assets
// @Produce      json
// @Security     BearerAuth
// @Success      200  {object}  InventoryOverviewResponse
// @Failure      401  {object}  map[string]string
// @Failure      500  {object}  map[string]string
// @Router       /assets/overview [get]
func (h *AssetHandler) GetInventoryOverview(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())
	rows, err := h.service.GetInventoryOverview(r.Context(), tenantID,
		middleware.GetUserID(r.Context()), middleware.IsAdmin(r.Context()))
	if err != nil {
		h.handleServiceError(w, err)
		return
	}
	if rows == nil {
		rows = []asset.InventoryOverviewRow{}
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(InventoryOverviewResponse{Data: rows})
}

// GetFacets returns distinct property keys and their values for faceted filtering.
// Scoped to tenant, the caller's data scope (as the list) and an optional
// type filter. Returns top 20 values per key.
func (h *AssetHandler) GetFacets(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())
	query := r.URL.Query()
	types := parseQueryArray(query.Get("types"))
	subType := query.Get("sub_type")

	facets, err := h.service.GetPropertyFacets(r.Context(), tenantID,
		middleware.GetUserID(r.Context()), middleware.IsAdmin(r.Context()), types, subType)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(facets)
}

// SyncResponse represents the response from a sync operation.
type SyncResponse struct {
	Success       bool      `json:"success"`
	Message       string    `json:"message"`
	SyncedAt      time.Time `json:"synced_at"`
	UpdatedFields []string  `json:"updated_fields,omitempty"`
}

// BulkSyncRequest represents the request to sync multiple assets.
type BulkSyncRequest struct {
	AssetIDs []string `json:"asset_ids" validate:"required,min=1,max=100,dive,uuid"`
}

// BulkSyncResultItem represents the sync result for a single asset.
type BulkSyncResultItem struct {
	AssetID       string   `json:"asset_id"`
	Success       bool     `json:"success"`
	Message       string   `json:"message,omitempty"`
	UpdatedFields []string `json:"updated_fields,omitempty"`
	Error         string   `json:"error,omitempty"`
}

// BulkSyncResponse represents the response from a bulk sync operation.
type BulkSyncResponse struct {
	TotalCount   int                  `json:"total_count"`
	SuccessCount int                  `json:"success_count"`
	FailedCount  int                  `json:"failed_count"`
	SyncedAt     time.Time            `json:"synced_at"`
	Results      []BulkSyncResultItem `json:"results"`
}

// scmConnectionMatch holds matching integration info
type scmConnectionMatch struct {
	ID              string
	SCMOrganization string
}

// findMatchingSCMConnection finds an SCM integration matching the repository's provider/organization
func (h *AssetHandler) findMatchingSCMConnection(
	ctx context.Context,
	tenantID, provider, scmOrg string,
) (*scmConnectionMatch, error) {
	integration, err := h.integrationService.FindSCMIntegration(ctx, integrationapp.FindSCMIntegrationInput{
		TenantID: tenantID,
		Provider: provider,
		SCMOrg:   scmOrg,
	})
	if err != nil {
		return nil, err
	}

	scmOrgResult := ""
	if integration.SCM != nil {
		scmOrgResult = integration.SCM.SCMOrganization()
	}

	return &scmConnectionMatch{
		ID:              integration.ID().String(),
		SCMOrganization: scmOrgResult,
	}, nil
}

// buildSyncUpdateInput compares SCM data with current extension and builds update input
func buildSyncUpdateInput(scmRepo *scm.Repository, repoExt *asset.RepositoryExtension) (assetapp.UpdateRepositoryExtensionInput, []string) {
	var updatedFields []string
	updateInput := assetapp.UpdateRepositoryExtensionInput{}

	if scmRepo.DefaultBranch != "" && scmRepo.DefaultBranch != repoExt.DefaultBranch() {
		branch := scmRepo.DefaultBranch
		updateInput.DefaultBranch = &branch
		updatedFields = append(updatedFields, "default_branch")
	}
	if scmRepo.Language != "" && scmRepo.Language != repoExt.Language() {
		lang := scmRepo.Language
		updateInput.Language = &lang
		updatedFields = append(updatedFields, "language")
	}
	if scmRepo.Stars != repoExt.Stars() {
		stars := scmRepo.Stars
		updateInput.Stars = &stars
		updatedFields = append(updatedFields, "stars")
	}
	if scmRepo.Forks != repoExt.Forks() {
		forks := scmRepo.Forks
		updateInput.Forks = &forks
		updatedFields = append(updatedFields, "forks")
	}
	if scmRepo.Size != repoExt.SizeKB() {
		size := scmRepo.Size
		updateInput.SizeKB = &size
		updatedFields = append(updatedFields, "size_kb")
	}
	if len(scmRepo.Topics) > 0 {
		updateInput.Topics = scmRepo.Topics
		updatedFields = append(updatedFields, "topics")
	}
	if len(scmRepo.Languages) > 0 {
		languages := make(map[string]int64, len(scmRepo.Languages))
		for lang, bytes := range scmRepo.Languages {
			languages[lang] = int64(bytes)
		}
		updateInput.Languages = languages
		updatedFields = append(updatedFields, "languages")
	}

	visibility := "public"
	if scmRepo.IsPrivate {
		visibility = "private"
	}
	if visibility != repoExt.Visibility().String() {
		updateInput.Visibility = &visibility
		updatedFields = append(updatedFields, "visibility")
	}

	return updateInput, updatedFields
}

// validateSyncAsset validates the asset for sync operation
func (h *AssetHandler) validateSyncAsset(
	ctx context.Context,
	id, tenantID string,
) (*asset.Asset, *asset.RepositoryExtension, error) {
	// Tenant isolation + Layer 2 data scope (bulk sync names assets by id).
	a, err := h.service.GetAssetWithScope(ctx, tenantID, id, middleware.GetUserID(ctx), middleware.IsAdmin(ctx))
	if err != nil {
		return nil, nil, err
	}

	if a.Type() != asset.AssetTypeRepository {
		return nil, nil, fmt.Errorf("%w: only repository assets can be synced", shared.ErrValidation)
	}

	repoExt, err := h.service.GetRepositoryExtension(ctx, tenantID, id)
	if err != nil {
		return nil, nil, err
	}

	return a, repoExt, nil
}

// performSync fetches data from SCM and updates the repository extension
func (h *AssetHandler) performSync(
	ctx context.Context,
	assetID, tenantID, integrationID string,
	repoExt *asset.RepositoryExtension,
	a *asset.Asset,
) ([]string, error) {
	scmRepo, err := h.integrationService.GetSCMRepository(ctx, integrationapp.GetSCMRepositoryInput{
		IntegrationID: integrationID,
		TenantID:      tenantID,
		FullName:      repoExt.FullName(),
	})
	if err != nil {
		h.logger.Error("failed to get repository from SCM", "error", err)
		return nil, err
	}

	updateInput, updatedFields := buildSyncUpdateInput(scmRepo, repoExt)

	if len(updatedFields) > 0 {
		_, err = h.service.UpdateRepositoryExtension(ctx, tenantID, assetID, updateInput)
		if err != nil {
			h.logger.Error("failed to update repository extension", "error", err)
			return nil, err
		}
	}

	if a.Description() == "" && scmRepo.Description != "" {
		desc := scmRepo.Description
		_, err = h.service.UpdateAsset(ctx, assetID, tenantID, assetapp.UpdateAssetInput{Description: &desc})
		if err != nil {
			h.logger.Warn("failed to update asset description", "error", err)
		} else {
			updatedFields = append(updatedFields, "description")
		}
	}

	h.logger.Info("repository synced",
		"asset_id", assetID,
		"repository", repoExt.FullName(),
		"updated_fields", updatedFields,
	)

	return updatedFields, nil
}

// Sync handles POST /api/v1/assets/{id}/sync
// @Summary      Sync repository from SCM
// @Description  Syncs repository metadata from the connected SCM provider
// @Tags         Assets
// @Produce      json
// @Security     BearerAuth
// @Param        id   path      string  true  "Asset ID"
// @Success      200  {object}  SyncResponse
// @Failure      400  {object}  map[string]string
// @Failure      401  {object}  map[string]string
// @Failure      404  {object}  map[string]string
// @Failure      500  {object}  map[string]string
// @Router       /assets/{id}/sync [post]
func (h *AssetHandler) Sync(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())
	ctx := r.Context()

	id := r.PathValue("id")
	if id == "" {
		apierror.BadRequest("Asset ID is required").WriteJSON(w)
		return
	}

	if h.integrationService == nil {
		apierror.InternalError(errors.New("integration service not configured")).WriteJSON(w)
		return
	}

	// Validate asset
	a, repoExt, err := h.validateSyncAsset(ctx, id, tenantID)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}
	if a == nil {
		return // Error already written
	}

	provider := string(a.Provider())
	if provider == "" {
		apierror.BadRequest("Repository has no SCM provider configured").WriteJSON(w)
		return
	}

	// Find matching connection
	matchingConn, err := h.findMatchingSCMConnection(ctx, tenantID, provider, repoExt.SCMOrganization())
	if err != nil {
		h.logger.Error("failed to list SCM connections", "error", err)
		apierror.InternalError(err).WriteJSON(w)
		return
	}
	if matchingConn == nil {
		apierror.BadRequest("No matching SCM connection found for this repository").WriteJSON(w)
		return
	}

	// Perform sync
	updatedFields, err := h.performSync(ctx, id, tenantID, matchingConn.ID, repoExt, a)
	if err != nil {
		apierror.InternalError(err).WriteJSON(w)
		return
	}

	response := SyncResponse{
		Success:       true,
		Message:       "Repository synced successfully",
		SyncedAt:      time.Now(),
		UpdatedFields: updatedFields,
	}

	if len(updatedFields) == 0 {
		response.Message = "Repository is already up to date"
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(response)
}

// BulkSync handles POST /api/v1/assets/bulk-sync
// @Summary      Bulk sync repositories
// @Description  Syncs multiple repository assets from their SCM providers in a single request
// @Tags         Assets
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        request  body      BulkSyncRequest  true  "Asset IDs to sync"
// @Success      200      {object}  BulkSyncResponse
// @Failure      400      {object}  map[string]string
// @Failure      401      {object}  map[string]string
// @Failure      500      {object}  map[string]string
// @Router       /assets/bulk/sync [post]
func (h *AssetHandler) BulkSync(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())
	ctx := r.Context()

	if h.integrationService == nil {
		apierror.InternalError(errors.New("integration service not configured")).WriteJSON(w)
		return
	}

	var req BulkSyncRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}

	if err := h.validator.Validate(req); err != nil {
		h.handleValidationError(w, err)
		return
	}

	results := make([]BulkSyncResultItem, 0, len(req.AssetIDs))
	successCount := 0
	failedCount := 0

	for _, assetID := range req.AssetIDs {
		result := BulkSyncResultItem{
			AssetID: assetID,
		}

		// Validate asset
		a, repoExt, err := h.validateSyncAsset(ctx, assetID, tenantID)
		if err != nil {
			result.Success = false
			result.Error = err.Error()
			failedCount++
			results = append(results, result)
			continue
		}
		if a == nil {
			result.Success = false
			result.Error = "Asset validation failed"
			failedCount++
			results = append(results, result)
			continue
		}

		provider := string(a.Provider())
		if provider == "" {
			result.Success = false
			result.Error = "Repository has no SCM provider configured"
			failedCount++
			results = append(results, result)
			continue
		}

		// Find matching connection
		matchingConn, err := h.findMatchingSCMConnection(ctx, tenantID, provider, repoExt.SCMOrganization())
		if err != nil {
			result.Success = false
			result.Error = "Failed to find SCM connection"
			failedCount++
			results = append(results, result)
			continue
		}
		if matchingConn == nil {
			result.Success = false
			result.Error = "No matching SCM connection found for this repository"
			failedCount++
			results = append(results, result)
			continue
		}

		// Perform sync
		updatedFields, err := h.performSync(ctx, assetID, tenantID, matchingConn.ID, repoExt, a)
		if err != nil {
			result.Success = false
			result.Error = err.Error()
			failedCount++
			results = append(results, result)
			continue
		}

		result.Success = true
		result.UpdatedFields = updatedFields
		if len(updatedFields) == 0 {
			result.Message = "Already up to date"
		} else {
			result.Message = "Synced successfully"
		}
		successCount++
		results = append(results, result)
	}

	response := BulkSyncResponse{
		TotalCount:   len(req.AssetIDs),
		SuccessCount: successCount,
		FailedCount:  failedCount,
		SyncedAt:     time.Now(),
		Results:      results,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(response)
}

// ScanResponse represents the response from a scan trigger.
type ScanResponse struct {
	Success  bool      `json:"success"`
	Message  string    `json:"message"`
	ScanID   string    `json:"scan_id,omitempty"`
	QueuedAt time.Time `json:"queued_at"`
}

// TriggerScan handles POST /api/v1/assets/{id}/scan
// @Summary      Trigger security scan
// @Description  Triggers a security scan for the repository asset
// @Tags         Assets
// @Produce      json
// @Security     BearerAuth
// @Param        id   path      string  true  "Asset ID"
// @Success      202  {object}  ScanResponse
// @Failure      400  {object}  map[string]string
// @Failure      401  {object}  map[string]string
// @Failure      404  {object}  map[string]string
// @Failure      500  {object}  map[string]string
// @Router       /assets/{id}/scan [post]
func (h *AssetHandler) TriggerScan(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())

	id := r.PathValue("id")
	if id == "" {
		apierror.BadRequest("Asset ID is required").WriteJSON(w)
		return
	}

	// GetAsset now enforces tenant isolation internally
	a, err := h.service.GetAsset(r.Context(), tenantID, id)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	// Verify it's a repository asset
	if a.Type() != asset.AssetTypeRepository {
		apierror.BadRequest("Asset is not a repository").WriteJSON(w)
		return
	}

	// Get repository extension to check if scanning is enabled
	repoExt, err := h.service.GetRepositoryExtension(r.Context(), tenantID, id)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	// Record the scan request
	err = h.service.RecordRepositoryScan(r.Context(), id)
	if err != nil {
		h.logger.Error("failed to record scan", "error", err)
		apierror.InternalError(err).WriteJSON(w)
		return
	}

	// Scan jobs are queued via the scan workflow system (POST /scans/{id}/trigger).
	// This endpoint records the ad-hoc scan request and returns success.

	response := ScanResponse{
		Success:  true,
		Message:  "Scan queued successfully",
		QueuedAt: time.Now(),
	}

	// Add note about scan status
	if !repoExt.ScanEnabled() {
		response.Message = "Scan queued. Note: Automatic scanning is disabled for this repository."
	}

	h.logger.Info("scan triggered for repository",
		"asset_id", id,
		"repository", repoExt.FullName(),
		"scan_enabled", repoExt.ScanEnabled(),
	)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	_ = json.NewEncoder(w).Encode(response)
}

// UpdateCrownJewel marks/unmarks an asset as a crown jewel with business impact scoring.
func (h *AssetHandler) UpdateCrownJewel(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())
	assetID := r.PathValue("id")

	var req struct {
		IsCrownJewel        bool    `json:"is_crown_jewel"`
		BusinessImpactScore float64 `json:"business_impact_score"`
		BusinessImpactNotes string  `json:"business_impact_notes"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("Invalid JSON body").WriteJSON(w)
		return
	}

	// Bound the business impact score to 0–100 (same range as risk_score);
	// the inline struct isn't run through the validator, so check explicitly.
	if req.BusinessImpactScore < 0 || req.BusinessImpactScore > 100 {
		apierror.BadRequest("business_impact_score must be between 0 and 100").WriteJSON(w)
		return
	}
	if len(req.BusinessImpactNotes) > 2000 {
		apierror.BadRequest("business_impact_notes must be at most 2000 characters").WriteJSON(w)
		return
	}

	// The previous state, for the audit event. The route's data-scope guard
	// has already refused an asset outside the caller's scope.
	before, err := h.service.GetAsset(r.Context(), tenantID, assetID)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	// The flag is the assets.is_crown_jewel column; business impact stays in
	// properties. One statement writes both.
	a, err := h.service.UpdateCrownJewel(r.Context(), tenantID, assetID,
		req.IsCrownJewel, req.BusinessImpactScore, req.BusinessImpactNotes)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	changed := []string{}
	if before.IsCrownJewel() != a.IsCrownJewel() {
		changed = append(changed, "is_crown_jewel")
	}
	for _, k := range changedPropertyKeys(
		pickProperties(before.Properties(), asset.PropKeyBusinessImpactScore, asset.PropKeyBusinessImpactNotes),
		pickProperties(a.Properties(), asset.PropKeyBusinessImpactScore, asset.PropKeyBusinessImpactNotes),
	) {
		changed = append(changed, k[len("properties."):])
	}
	h.auditAsset(r, auditdom.ActionAssetCrownJewelChanged, a.ID().String(), a.Name(), "Crown-jewel designation changed",
		map[string]any{"is_crown_jewel": a.IsCrownJewel(), "changed_fields": changed})

	writeJSON(w, http.StatusOK, toAssetResponse(a))
}

// Helper functions are defined in common.go
