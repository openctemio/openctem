package handler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/scanrun"
	"github.com/openctemio/openctem/api/pkg/domain/scanworkflow"

	"github.com/go-chi/chi/v5"

	"github.com/openctemio/openctem/api/internal/app/datascope"
	scansvc "github.com/openctemio/openctem/api/internal/app/scan"
	"github.com/openctemio/openctem/api/internal/app/scancoverage"
	"github.com/openctemio/openctem/api/internal/infra/http/filterquery"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/domain/permission"
	"github.com/openctemio/openctem/api/pkg/domain/scan"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/user"
	"github.com/openctemio/openctem/api/pkg/filterspec"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/validator"
)

// ScanHandler handles HTTP requests for scans.
type ScanHandler struct {
	service       *scansvc.Service
	userRepo      user.Repository
	coverageStats scancoverage.CoverageStatsReader
	validator     *validator.Validator
	logger        *logger.Logger
	// approvals: scan approval (RFC-073); nil when not wired.
	approvals *ScanApprovalHandler
	// dataScope narrows the coverage figures to the caller's data scope.
	dataScope *datascope.Enforcer
	// capabilities answers GET /scans/capabilities; nil reads the service.
	capabilities scanCapabilityReader
}

// SetDataScope wires the enforcer that narrows the rolling coverage figures
// to the caller's data scope.
func (h *ScanHandler) SetDataScope(e *datascope.Enforcer) *ScanHandler {
	h.dataScope = e
	return h
}

// SetApprovals wires scan approval: the list badge and the approval routes
// under /scans.
func (h *ScanHandler) SetApprovals(a *ScanApprovalHandler) { h.approvals = a }

// Approvals returns the scan approval handler (nil when not wired).
func (h *ScanHandler) Approvals() *ScanApprovalHandler {
	if h == nil {
		return nil
	}
	return h.approvals
}

// auditCtx is the request context carrying the caller as the actor of the
// scan service's audit entries (see scansvc.WithAuditActor).
func (h *ScanHandler) auditCtx(r *http.Request) context.Context {
	return scansvc.WithAuditActor(r.Context(), middleware.GetUserID(r.Context()))
}

// NewScanHandler creates a new ScanHandler.
func NewScanHandler(service *scansvc.Service, userRepo user.Repository, coverageStats scancoverage.CoverageStatsReader, v *validator.Validator, log *logger.Logger) *ScanHandler {
	return &ScanHandler{
		service:       service,
		userRepo:      userRepo,
		coverageStats: coverageStats,
		validator:     v,
		logger:        log.With("handler", "scan"),
	}
}

// --- Request/Response Types ---

// CreateScanRequest represents the request body for creating a scan.
// Either asset_group_id OR asset_group_ids OR targets must be provided (can have all).
type CreateScanRequest struct {
	Name          string   `json:"name" validate:"required,min=1,max=200"`
	Description   string   `json:"description" validate:"max=1000"`
	AssetGroupID  string   `json:"asset_group_id" validate:"omitempty,uuid"`       // Single asset group (legacy)
	AssetGroupIDs []string `json:"asset_group_ids" validate:"omitempty,dive,uuid"` // Multiple asset groups (NEW)
	Targets       []string `json:"targets" validate:"omitempty,max=1000"`          // Direct targets
	// AssetIDs are inventory assets to scan, each by its name as the server
	// resolves it (at most 1000 targets and assets together). An id that is
	// not the organization's or outside the caller's scope refuses the whole
	// request, without saying which.
	AssetIDs []string `json:"asset_ids" validate:"omitempty,max=1000,dive,uuid"`
	// TargetOptions tunes how each run resolves the dynamic selectors among
	// the targets (*.example.com, CIDRs) from the inventory.
	TargetOptions *scan.TargetOptions `json:"target_options"`
	// Intensity is the probe ceiling of every run: passive (no
	// packets from the sensors to the targets), active (non-intrusive
	// probing) or intrusive. Omitted: the tier the scanner or workflow
	// probes at. A scanner or workflow step above it is refused
	// (INTENSITY_EXCEEDED).
	Intensity string `json:"intensity" validate:"omitempty,oneof=passive active intrusive"`
	// Depth is how much of the workflow each run executes: passive (only
	// steps that send nothing to the targets), standard (default) or deep.
	// A depth at which no first step can run is refused (DEPTH_RUNS_NOTHING).
	Depth string `json:"depth" validate:"omitempty,oneof=passive standard deep"`
	// StepParams override capability standard params per workflow step:
	// {"<step_key>" or "*:<capability>": {"<param>": value}}. Standard
	// params only (INVALID_STEP_PARAMS otherwise).
	StepParams     scan.StepParams `json:"step_params"`
	ScanType       string          `json:"scan_type" validate:"required,oneof=workflow single"`
	ScanWorkflowID string          `json:"scan_workflow_id" validate:"omitempty,uuid"`
	ScannerName    string          `json:"scanner_name" validate:"max=100"`
	ScannerConfig  map[string]any  `json:"scanner_config"`
	TargetsPerJob  int             `json:"targets_per_job"`
	ScheduleType   string          `json:"schedule_type" validate:"omitempty,oneof=manual daily weekly monthly crontab rrule once"`
	ScheduleCron   string          `json:"schedule_cron" validate:"max=100"`
	// ScheduleRRule is an RFC 5545 rule (RRULE parts) for schedule_type rrule,
	// evaluated in timezone; at most every 15 minutes.
	ScheduleRRule string  `json:"schedule_rrule" validate:"max=500"`
	ScheduleDay   *int    `json:"schedule_day"`
	ScheduleTime  *string `json:"schedule_time"`
	// RunAt (RFC 3339) is the one run of schedule_type once: between a
	// minute and a year from now.
	RunAt            *time.Time `json:"run_at"`
	Timezone         string     `json:"timezone" validate:"max=50"`
	Tags             []string   `json:"tags" validate:"max=20,dive,max=50"`
	TenantRunner     bool       `json:"run_on_tenant_runner"`
	SensorPreference string     `json:"sensor_preference" validate:"omitempty,oneof=auto tenant platform"`
	ProfileID        string     `json:"profile_id" validate:"omitempty,uuid"`
	// RuleSources is which detection rules the scan runs: both, platform or
	// tenant; empty inherits the profile's (both without a profile).
	RuleSources string `json:"rule_sources" validate:"omitempty,oneof=both platform tenant"`
	// ScanZoneID pins every target to one scan zone; empty = Automatic routing.
	ScanZoneID          string `json:"scan_zone_id" validate:"omitempty,uuid"`
	TimeoutSeconds      int    `json:"timeout_seconds" validate:"omitempty,min=30,max=86400"`
	MaxRetries          int    `json:"max_retries" validate:"omitempty,min=0,max=10"`
	RetryBackoffSeconds int    `json:"retry_backoff_seconds" validate:"omitempty,min=10,max=86400"`
	// StartWhenScopeApproved saves the scan although some direct targets are
	// refused, when every refused one is covered by a scope entry that waits
	// for approval; the scan starts once those entries are approved, as the
	// caller, and every gate runs again then. Any other refusal still refuses.
	StartWhenScopeApproved bool `json:"start_when_scope_approved"`
	// SkipRefusedTargets saves the scan with only the direct targets the
	// scope check allows now; the others are recorded with their refusal
	// codes in skipped_targets and on every run. Nothing the gate refuses is
	// saved or scanned.
	SkipRefusedTargets bool `json:"skip_refused_targets"`
	// ConfirmLargeRange confirms direct targets that name a range wider than
	// a /16 (scanned live hosts first in /16 chunks). Required for such a
	// scan: without it the request is refused with LARGE_RANGE_UNCONFIRMED,
	// whose message and details carry the ranges and their address and
	// chunk counts.
	ConfirmLargeRange bool `json:"confirm_large_range"`
}

// UpdateScanRequest represents the request body for updating a scan.
type UpdateScanRequest struct {
	Name           string         `json:"name" validate:"omitempty,min=1,max=200"`
	Description    string         `json:"description" validate:"max=1000"`
	ScanWorkflowID string         `json:"scan_workflow_id" validate:"omitempty,uuid"`
	ScannerName    string         `json:"scanner_name" validate:"max=100"`
	ScannerConfig  map[string]any `json:"scanner_config"`
	TargetsPerJob  *int           `json:"targets_per_job"`
	// TargetOptions: omitted = unchanged.
	TargetOptions *scan.TargetOptions `json:"target_options"`
	// Intensity: omitted = unchanged.
	Intensity string `json:"intensity" validate:"omitempty,oneof=passive active intrusive"`
	// Depth: omitted = unchanged.
	Depth string `json:"depth" validate:"omitempty,oneof=passive standard deep"`
	// StepParams: omitted = unchanged, {} clears.
	StepParams   scan.StepParams `json:"step_params"`
	ScheduleType string          `json:"schedule_type" validate:"omitempty,oneof=manual daily weekly monthly crontab rrule once"`
	ScheduleCron string          `json:"schedule_cron" validate:"max=100"`
	// ScheduleRRule is an RFC 5545 rule (RRULE parts) for schedule_type rrule,
	// evaluated in timezone; at most every 15 minutes.
	ScheduleRRule string  `json:"schedule_rrule" validate:"max=500"`
	ScheduleDay   *int    `json:"schedule_day"`
	ScheduleTime  *string `json:"schedule_time"`
	// RunAt (RFC 3339) is the one run of schedule_type once: between a
	// minute and a year from now.
	RunAt            *time.Time `json:"run_at"`
	Timezone         string     `json:"timezone" validate:"max=50"`
	Tags             []string   `json:"tags" validate:"max=20,dive,max=50"`
	TenantRunner     *bool      `json:"run_on_tenant_runner"`
	SensorPreference string     `json:"sensor_preference" validate:"omitempty,oneof=auto tenant platform"`
	ProfileID        *string    `json:"profile_id" validate:"omitempty"`
	// RuleSources: omitted = unchanged, "" = inherit the profile's, else
	// both, platform or tenant. The domain setter validates the value: a
	// oneof tag here would reject "" (validator checks the pointed-to value).
	RuleSources *string `json:"rule_sources" validate:"omitempty"`
	// ScanZoneID: omitted = unchanged, "" = Automatic routing, id = pin to that zone.
	ScanZoneID          *string `json:"scan_zone_id" validate:"omitempty"`
	TimeoutSeconds      *int    `json:"timeout_seconds" validate:"omitempty,min=0,max=86400"`
	MaxRetries          *int    `json:"max_retries" validate:"omitempty,min=0,max=10"`
	RetryBackoffSeconds *int    `json:"retry_backoff_seconds" validate:"omitempty,min=10,max=86400"`
	// Targets: omitted = unchanged; given = the scan's direct targets
	// become these plus the assets of asset_ids. They pass the checks a new
	// scan's targets pass, as the editor (at most 1000 with asset_ids).
	Targets *[]string `json:"targets" validate:"omitempty,max=1000"`
	// AssetIDs are inventory assets to scan, named by the server; given =
	// the direct targets are replaced (with targets). An id that is not the
	// organization's or outside the editor's scope refuses the request.
	AssetIDs []string `json:"asset_ids" validate:"omitempty,max=1000,dive,uuid"`
	// AssetGroupIDs: omitted = unchanged; given = the scan's asset groups
	// ([] = none; the scan must keep a target or a group).
	AssetGroupIDs *[]string `json:"asset_group_ids" validate:"omitempty,max=100,dive,uuid"`
	// ConfirmLargeRange confirms new targets that name a range wider than a
	// /16; required for such an edit (LARGE_RANGE_UNCONFIRMED without it).
	ConfirmLargeRange bool `json:"confirm_large_range"`
}

// TriggerScanRequest represents the request body for triggering a scan.
type TriggerScanExecRequest struct {
	Context map[string]any `json:"context"`
}

// CloneScanRequest represents the request body for cloning a scan.
type CloneScanRequest struct {
	Name string `json:"name" validate:"required,min=1,max=200"`
}

// SaveScanRequest names an ad-hoc quick scan that becomes a configuration.
type SaveScanRequest struct {
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
	// Intensity: the probe ceiling (RFC-071); omitted = the tier the
	// scanner or workflow probes at.
	Intensity string `json:"intensity" validate:"omitempty,oneof=passive active intrusive"`
}

// QuickScanResponse represents the response for quick scan.
type QuickScanResponse struct {
	ScanRunID string `json:"scan_run_id"`
	// ScanID is the run's scan: ad hoc (unsaved) until POST /scans/{id}/save.
	ScanID string `json:"scan_id"`
	// AssetGroupID is always empty: quick scans no longer create an asset group.
	AssetGroupID string `json:"asset_group_id"`
	Status       string `json:"status"`
	TargetCount  int    `json:"target_count"`
}

// CreateScanResponse wraps scan detail with optional compatibility warning.
// Used only for POST /scans to show warnings about asset-scanner compatibility.
type CreateScanResponse struct {
	*ScanDetailResponse
	CompatibilityWarning *AssetCompatibilityPreviewResponse `json:"compatibility_warning,omitempty"`
	// StartsWhenScopeApproved: the scan was saved to start once the pending
	// scope entries covering its targets are approved (do not trigger it now).
	StartsWhenScopeApproved bool `json:"starts_when_scope_approved,omitempty"`
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
	// ApprovalStatus: the newest approval request of the scan (pending,
	// approved, rejected, expired, superseded, canceled); empty when none. On lists only.
	ApprovalStatus string   `json:"approval_status,omitempty"`
	ID             string   `json:"id"`
	TenantID       string   `json:"tenant_id"`
	Name           string   `json:"name"`
	Description    string   `json:"description,omitempty"`
	AssetGroupID   string   `json:"asset_group_id,omitempty"`  // Primary asset group (legacy)
	AssetGroupIDs  []string `json:"asset_group_ids,omitempty"` // Multiple asset groups
	Targets        []string `json:"targets,omitempty"`         // Direct targets
	// SkippedTargets: targets left out when the scan was saved, with the
	// scope refusal code of each.
	SkippedTargets []scan.SkippedTarget `json:"skipped_targets,omitempty"`
	// TargetOptions: how each run resolves the dynamic selectors among
	// Targets from the inventory.
	TargetOptions scan.TargetOptions `json:"target_options"`
	// Intensity is the probe ceiling of every run: passive, active or
	// intrusive.
	Intensity string `json:"intensity" enums:"passive,active,intrusive"`
	// Depth is how much of the workflow each run executes.
	Depth string `json:"depth" enums:"passive,standard,deep"`
	// StepParams are the scan's per-step overrides of standard params.
	StepParams     scan.StepParams `json:"step_params,omitempty"`
	ScanType       string          `json:"scan_type"`
	ScanWorkflowID *string         `json:"scan_workflow_id,omitempty"`
	ScannerName    string          `json:"scanner_name,omitempty"`
	ScannerConfig  map[string]any  `json:"scanner_config,omitempty"`
	// ScannerConfigWarnings lists scanner_config values that look like
	// secrets. A certain credential is refused on save and blocks a run
	// (SCANNER_CONFIG_SECRET); what is listed here is what only looks like
	// one (a random-looking value), or a scan stored before the refusal.
	// The value itself is never echoed.
	ScannerConfigWarnings []scan.ConfigSecretWarning `json:"scanner_config_warnings,omitempty"`
	TargetsPerJob         int                        `json:"targets_per_job"`
	ScheduleType          string                     `json:"schedule_type"`
	ScheduleCron          string                     `json:"schedule_cron,omitempty"`
	ScheduleRRule         string                     `json:"schedule_rrule,omitempty"`
	ScheduleDay           *int                       `json:"schedule_day,omitempty"`
	ScheduleTime          *string                    `json:"schedule_time,omitempty"`
	ScheduleTimezone      string                     `json:"schedule_timezone"`
	ScheduleRunAt         *string                    `json:"schedule_run_at,omitempty"` // schedule_type once
	NextRunAt             *string                    `json:"next_run_at,omitempty"`
	Tags                  []string                   `json:"tags,omitempty"`
	RunOnTenantRunner     bool                       `json:"run_on_tenant_runner"`
	SensorPreference      string                     `json:"sensor_preference"`
	ProfileID             *string                    `json:"profile_id,omitempty"`
	// RuleSources is the scan's own setting; empty inherits the profile's.
	RuleSources         string  `json:"rule_sources"`
	ScanZoneID          *string `json:"scan_zone_id"` // null = Automatic routing
	TimeoutSeconds      int     `json:"timeout_seconds"`
	MaxRetries          int     `json:"max_retries"`
	RetryBackoffSeconds int     `json:"retry_backoff_seconds"`
	Status              string  `json:"status"`
	// AdHoc: an unsaved quick scan (not listed as a configuration until saved).
	AdHoc         bool    `json:"ad_hoc"`
	LastRunID     *string `json:"last_run_id,omitempty"`
	LastRunAt     *string `json:"last_run_at,omitempty"`
	LastRunStatus string  `json:"last_run_status,omitempty"`
	// LastMissedAt/LastMissedReason: the last scheduled occurrence that was
	// skipped because it was missed (reason is a code the UI translates).
	// Cleared when a later scheduled run starts.
	LastMissedAt     *string `json:"last_missed_at,omitempty"`
	LastMissedReason string  `json:"last_missed_reason,omitempty"`
	TotalRuns        int     `json:"total_runs"`
	SuccessfulRuns   int     `json:"successful_runs"`
	FailedRuns       int     `json:"failed_runs"`
	// PartialRuns: runs that kept results but lost some work.
	PartialRuns int `json:"partial_runs"`
	// BlockedRuns: triggers refused before anything was dispatched; each
	// is a run with status blocked and its refusal_code.
	BlockedRuns int `json:"blocked_runs"`
	// LastRun is the scan's latest run: its real state (running with
	// progress, completed, partial, failed, blocked with the reason, ...).
	// Absent before the first run.
	LastRun *ScanLastRunResponse `json:"last_run,omitempty"`
	// RecentRuns are the scan's latest runs (at most 10), newest first: the
	// list's run history and the window its success rate is read over.
	RecentRuns []ScanRecentRunResponse `json:"recent_runs,omitempty"`
	// ScanWorkflowName names the workflow a workflow scan runs.
	ScanWorkflowName string  `json:"scan_workflow_name,omitempty"`
	CreatedBy        *string `json:"created_by,omitempty"`
	CreatedByName    *string `json:"created_by_name,omitempty"`
	// OwnerState: ok, missing (no owner: the account that created the scan
	// was deleted) or inactive (the owner is no longer an active member).
	// A scheduled scan runs only with an active owner; an administrator
	// takes ownership with POST /scans/{id}/take-ownership. Lists report
	// missing only (no per-row membership lookup).
	// managed: a platform policy owns the scan (managed_by names it); it has
	// no owner and is read-only here.
	OwnerState string `json:"owner_state" enums:"ok,missing,inactive,managed"`
	// ManagedBy names the platform policy that owns the scan (coverage,
	// enrichment); absent on a person's scan.
	ManagedBy string `json:"managed_by,omitempty" enums:"coverage,enrichment,web_verify"`
	CreatedAt string `json:"created_at"`
	UpdatedAt string `json:"updated_at"`
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
// @Description  Create a new scan configuration with scheduling options. With start_when_scope_approved, a scan whose direct targets are refused only because pending scope entries cover them is saved and starts once those entries are approved (starts_when_scope_approved in the response). Direct targets that name a range wider than a /16 need confirm_large_range: true and an organization limit that allows them (Scoping settings, max_range_prefix; a /16 by default); without the confirmation the request is refused (400 LARGE_RANGE_UNCONFIRMED, with the address and chunk counts).
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

	// Validate: must have asset groups, targets or assets (asset_ids alone is
	// a scan of picked inventory assets; the service names them).
	if len(assetGroupIDs) == 0 && len(req.Targets) == 0 && len(req.AssetIDs) == 0 {
		apierror.BadRequest("Either asset_group_id/asset_group_ids, targets or asset_ids must be provided").WriteJSON(w)
		return
	}

	// For backward compatibility, pass the first asset group as AssetGroupID
	// and the full list as AssetGroupIDs
	primaryAssetGroupID := ""
	if len(assetGroupIDs) > 0 {
		primaryAssetGroupID = assetGroupIDs[0]
	}

	input := scansvc.CreateScanInput{
		TenantID:            tenantID,
		Name:                req.Name,
		Description:         req.Description,
		AssetGroupID:        primaryAssetGroupID, // Primary for backward compat
		AssetGroupIDs:       assetGroupIDs,       // Full list for new scans
		Targets:             req.Targets,
		AssetIDs:            req.AssetIDs,
		TargetOptions:       req.TargetOptions,
		Intensity:           req.Intensity,
		Depth:               req.Depth,
		StepParams:          req.StepParams,
		ScanType:            req.ScanType,
		ScanWorkflowID:      req.ScanWorkflowID,
		ScannerName:         req.ScannerName,
		ScannerConfig:       req.ScannerConfig,
		TargetsPerJob:       req.TargetsPerJob,
		ScheduleType:        req.ScheduleType,
		ScheduleCron:        req.ScheduleCron,
		ScheduleRRule:       req.ScheduleRRule,
		ScheduleDay:         req.ScheduleDay,
		ScheduleTime:        scheduleTime,
		RunAt:               req.RunAt,
		Timezone:            req.Timezone,
		Tags:                req.Tags,
		TenantRunner:        req.TenantRunner,
		SensorPreference:    req.SensorPreference,
		ProfileID:           req.ProfileID,
		RuleSources:         req.RuleSources,
		ScanZoneID:          req.ScanZoneID,
		TimeoutSeconds:      req.TimeoutSeconds,
		MaxRetries:          req.MaxRetries,
		RetryBackoffSeconds: req.RetryBackoffSeconds,
		CreatedBy:           userID,

		StartWhenScopeApproved: req.StartWhenScopeApproved,
		SkipRefusedTargets:     req.SkipRefusedTargets,
		ConfirmLargeRange:      req.ConfirmLargeRange,
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
	if req.StartWhenScopeApproved {
		response.StartsWhenScopeApproved = h.service.WaitsForScope(r.Context(), s.TenantID, s.ID)
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

		if preview, err := h.service.PreviewScanCompatibility(r.Context(), s.TenantID, req.ScannerName, groupIDs); err == nil && preview != nil {
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

// scansListDeprecatedAt and scansListSunsetAt date the old GET /scans param
// names (search, tags): the list query contract's alias window
// (docs/rfcs/RFC-048-list-query-contract.md).
var (
	scansListDeprecatedAt = time.Date(2026, 11, 8, 0, 0, 0, 0, time.UTC)
	scansListSunsetAt     = time.Date(2027, 5, 8, 0, 0, 0, 0, time.UTC)
)

// scansListRoute is GET /scans (and POST /scans/search) on the list query
// contract: strict params, the old names as aliases. include_ad_hoc is a
// list option, not a filter.
func (h *ScanHandler) scansListRoute(name string) filterquery.Route {
	return filterquery.Route{
		Name:         name,
		Registry:     scan.Fields,
		Options:      filterspec.Options{Unknown: filterspec.UnknownStrict, Extra: []string{"include_ad_hoc"}},
		DeprecatedAt: scansListDeprecatedAt,
		SunsetAt:     scansListSunsetAt,
		Logger:       h.logger,
		NoEchoValues: true,
	}
}

// ListScans handles GET /api/v1/scans
// @Summary      List scans
// @Description  The tenant's saved scans, filtered and sorted by the list query contract: every field accepts
// @Description  a comma list (any of), a _not list (none of) and, where its type allows, _contains, _gte, _lte,
// @Description  _gt and _lt. q searches the name and the description. Quick scans that were never saved are left
// @Description  out unless include_ad_hoc=true or origin=system. The old names search (now q) and tags (now tag)
// @Description  still work and answer with Deprecation, Sunset and Warning headers. An unknown param is 400.
// @Tags         Scans
// @Accept       json
// @Produce      json
// filterspec-params: scans GET /scans
// @Param  id  query  []string  false  "id: any of (comma list)"  collectionFormat(csv)
// @Param  id_not  query  []string  false  "id: none of (comma list)"  collectionFormat(csv)
// @Param  name  query  []string  false  "scan name pattern (* any characters, ? one): any of (comma list)"  collectionFormat(csv)
// @Param  name_contains  query  string  false  "scan name pattern (* any characters, ? one) contains"
// @Param  name_not  query  []string  false  "scan name pattern (* any characters, ? one): none of (comma list)"  collectionFormat(csv)
// @Param  status  query  []string  false  "status: any of (comma list)"  collectionFormat(csv)  Enums(active, paused, disabled)
// @Param  status_not  query  []string  false  "status: none of (comma list)"  collectionFormat(csv)  Enums(active, paused, disabled)
// @Param  scan_type  query  []string  false  "scan type: any of (comma list)"  collectionFormat(csv)  Enums(workflow, single)
// @Param  scan_type_not  query  []string  false  "scan type: none of (comma list)"  collectionFormat(csv)  Enums(workflow, single)
// @Param  schedule_type  query  []string  false  "schedule type: any of (comma list)"  collectionFormat(csv)  Enums(manual, daily, weekly, monthly, crontab, rrule, once)
// @Param  schedule_type_not  query  []string  false  "schedule type: none of (comma list)"  collectionFormat(csv)  Enums(manual, daily, weekly, monthly, crontab, rrule, once)
// @Param  sensor_preference  query  []string  false  "sensor preference: any of (comma list)"  collectionFormat(csv)  Enums(auto, tenant, platform)
// @Param  sensor_preference_not  query  []string  false  "sensor preference: none of (comma list)"  collectionFormat(csv)  Enums(auto, tenant, platform)
// @Param  origin  query  string  false  "origin equals"  Enums(user, system)
// @Param  tag  query  []string  false  "scan tag: any of (comma list)"  collectionFormat(csv)
// @Param  tag_not  query  []string  false  "scan tag: none of (comma list)"  collectionFormat(csv)
// @Param  asset_group_id  query  []string  false  "asset group the scan covers: any of (comma list)"  collectionFormat(csv)
// @Param  asset_group_id_not  query  []string  false  "asset group the scan covers: none of (comma list)"  collectionFormat(csv)
// @Param  scan_workflow_id  query  []string  false  "scan workflow id: any of (comma list)"  collectionFormat(csv)
// @Param  scan_workflow_id_not  query  []string  false  "scan workflow id: none of (comma list)"  collectionFormat(csv)
// @Param  profile_id  query  []string  false  "profile id: any of (comma list)"  collectionFormat(csv)
// @Param  profile_id_not  query  []string  false  "profile id: none of (comma list)"  collectionFormat(csv)
// @Param  scan_zone_id  query  []string  false  "scan zone id: any of (comma list)"  collectionFormat(csv)
// @Param  scan_zone_id_not  query  []string  false  "scan zone id: none of (comma list)"  collectionFormat(csv)
// @Param  scanner_name  query  []string  false  "scanner name: any of (comma list)"  collectionFormat(csv)
// @Param  scanner_name_contains  query  string  false  "scanner name contains"
// @Param  scanner_name_not  query  []string  false  "scanner name: none of (comma list)"  collectionFormat(csv)
// @Param  last_run_status  query  []string  false  "last run status: any of (comma list)"  collectionFormat(csv)
// @Param  last_run_status_not  query  []string  false  "last run status: none of (comma list)"  collectionFormat(csv)
// @Param  created_by  query  []string  false  "created by: any of (comma list)"  collectionFormat(csv)
// @Param  created_by_not  query  []string  false  "created by: none of (comma list)"  collectionFormat(csv)
// @Param  created_at_gte  query  string  false  "created at at least (RFC 3339, YYYY-MM-DD, -P30D ago or P30D ahead)"
// @Param  created_at_lte  query  string  false  "created at at most (RFC 3339, YYYY-MM-DD, -P30D ago or P30D ahead)"
// @Param  created_at_gt  query  string  false  "created at greater than (RFC 3339, YYYY-MM-DD, -P30D ago or P30D ahead)"
// @Param  created_at_lt  query  string  false  "created at less than (RFC 3339, YYYY-MM-DD, -P30D ago or P30D ahead)"
// @Param  last_run_at_gte  query  string  false  "last run at at least (RFC 3339, YYYY-MM-DD, -P30D ago or P30D ahead)"
// @Param  last_run_at_lte  query  string  false  "last run at at most (RFC 3339, YYYY-MM-DD, -P30D ago or P30D ahead)"
// @Param  last_run_at_gt  query  string  false  "last run at greater than (RFC 3339, YYYY-MM-DD, -P30D ago or P30D ahead)"
// @Param  last_run_at_lt  query  string  false  "last run at less than (RFC 3339, YYYY-MM-DD, -P30D ago or P30D ahead)"
// @Param  next_run_at_gte  query  string  false  "next run at at least (RFC 3339, YYYY-MM-DD, -P30D ago or P30D ahead)"
// @Param  next_run_at_lte  query  string  false  "next run at at most (RFC 3339, YYYY-MM-DD, -P30D ago or P30D ahead)"
// @Param  next_run_at_gt  query  string  false  "next run at greater than (RFC 3339, YYYY-MM-DD, -P30D ago or P30D ahead)"
// @Param  next_run_at_lt  query  string  false  "next run at less than (RFC 3339, YYYY-MM-DD, -P30D ago or P30D ahead)"
// @Param  total_runs  query  []integer  false  "total runs: any of (comma list)"  collectionFormat(csv)
// @Param  total_runs_gte  query  integer  false  "total runs at least"
// @Param  total_runs_lte  query  integer  false  "total runs at most"
// @Param  total_runs_gt  query  integer  false  "total runs greater than"
// @Param  total_runs_lt  query  integer  false  "total runs less than"
// @Param  failed_runs  query  []integer  false  "failed runs: any of (comma list)"  collectionFormat(csv)
// @Param  failed_runs_gte  query  integer  false  "failed runs at least"
// @Param  failed_runs_lte  query  integer  false  "failed runs at most"
// @Param  failed_runs_gt  query  integer  false  "failed runs greater than"
// @Param  failed_runs_lt  query  integer  false  "failed runs less than"
// end filterspec-params
// @Param        q               query     string  false  "Search the name and the description"
// @Param        include_ad_hoc  query     bool    false  "Also list unsaved quick scans (ad_hoc)"
// @Param        sort            query     string  false  "One sort key, - for descending: name, created_at, last_run_at, next_run_at, total_runs" default(name)
// @Param        page            query     int     false  "Page number" default(1)
// @Param        per_page        query     int     false  "Items per page" default(20)
// @Success      200  {object}  ListResponse[ScanDetailResponse]
// @Failure      400  {object}  apierror.Error
// @Failure      500  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /scans [get]
func (h *ScanHandler) ListScans(w http.ResponseWriter, r *http.Request) {
	route := h.scansListRoute("GET /scans")
	spec, ok := route.ParseQuery(w, r)
	if !ok {
		return
	}
	h.writeScanList(w, r, route, spec, r.URL.Query().Get("include_ad_hoc") == queryParamTrue)
}

// ScanSearchRequest documents the FilterDocument body of POST /scans/search.
// The server parses the raw body with filterspec.ParseDocument; this type
// exists for the OpenAPI spec.
type ScanSearchRequest struct {
	// V is the document version (1).
	V int `json:"v,omitempty" example:"1"`
	// Filter is a node ({"all":[...]}, {"any":[...]}, {"not":{...}} or a
	// {"field","op","value"} leaf) or the flat-name shorthand
	// ({"status":["active"],"total_runs_gte":3}).
	Filter map[string]any `json:"filter,omitempty"`
	// Q searches the name and the description.
	Q string `json:"q,omitempty"`
	// Sort keys, "-" for descending.
	Sort []string `json:"sort,omitempty"`
	// Page selects the page: {"page": 1, "per_page": 50}.
	Page *FindingSearchPage `json:"page,omitempty"`
}

// SearchScans handles POST /api/v1/scans/search
// @Summary      Search scans with a filter document
// @Description  Lists the scans selected by a FilterDocument: all/any/not groups with field/op/value leaves, for
// @Description  OR, nesting and id lists. Same fields, permission, visibility and response as GET /scans.
// @Description  Limits: 50 leaves, depth 3, 32 KB body. A bad document is 400 INVALID_FILTER with the JSON path
// @Description  of each problem. Read-only.
// @Tags         Scans
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        request         body      ScanSearchRequest  true   "Filter document"
// @Param        include_ad_hoc  query     bool               false  "Also list unsaved quick scans (ad_hoc)"
// @Success      200  {object}  ListResponse[ScanDetailResponse]
// @Failure      400  {object}  apierror.Error
// @Failure      401  {object}  apierror.Error
// @Failure      403  {object}  apierror.Error
// @Router       /scans/search [post]
func (h *ScanHandler) SearchScans(w http.ResponseWriter, r *http.Request) {
	route := h.scansListRoute("POST /scans/search")
	spec, ok := route.ParseBody(w, r)
	if !ok {
		return
	}
	h.writeScanList(w, r, route, spec, r.URL.Query().Get("include_ad_hoc") == queryParamTrue)
}

// writeScanList runs a decoded filter as the caller's tenant and writes the
// list response (shared by GET /scans and POST /scans/search).
func (h *ScanHandler) writeScanList(w http.ResponseWriter, r *http.Request, route filterquery.Route, spec *filterspec.Spec, includeAdHoc bool) {
	ctx := r.Context()
	tenantID := middleware.GetTenantID(ctx)
	result, err := h.service.ListScansBySpec(ctx, tenantID, spec, includeAdHoc)
	if err != nil {
		if _, isFilter := filterspec.AsError(err); isFilter {
			route.WriteError(w, err)
			return
		}
		h.handleServiceError(w, err)
		return
	}

	// Batch-resolve creator names in one query to avoid an N+1 (previously each
	// row triggered its own users lookup inside toScanResponse).
	nameByID := h.resolveScanCreatorNames(ctx, result.Data)
	reveal := canSeeScanConfigSecrets(ctx)
	items := make([]*ScanDetailResponse, len(result.Data))
	for i, s := range result.Data {
		var name *string
		if s.CreatedBy != nil {
			if n, ok := nameByID[s.CreatedBy.String()]; ok {
				name = &n
			}
		}
		items[i] = buildScanResponse(s, name, reveal)
	}
	h.enrichScanResponses(ctx, tenantID, result.Data, items)

	resp := map[string]any{
		"data":        items,
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
// @Description  Update an existing scan configuration. New targets that name a range wider than a /16 need confirm_large_range: true (400 LARGE_RANGE_UNCONFIRMED without it).
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
		TenantID:            tenantID,
		ScanID:              scanID,
		Name:                req.Name,
		Description:         req.Description,
		ScanWorkflowID:      req.ScanWorkflowID,
		ScannerName:         req.ScannerName,
		ScannerConfig:       req.ScannerConfig,
		TargetsPerJob:       req.TargetsPerJob,
		TargetOptions:       req.TargetOptions,
		Intensity:           req.Intensity,
		Depth:               req.Depth,
		StepParams:          req.StepParams,
		ScheduleType:        req.ScheduleType,
		ScheduleCron:        req.ScheduleCron,
		ScheduleRRule:       req.ScheduleRRule,
		ScheduleDay:         req.ScheduleDay,
		ScheduleTime:        scheduleTime,
		RunAt:               req.RunAt,
		Timezone:            req.Timezone,
		Tags:                req.Tags,
		TenantRunner:        req.TenantRunner,
		SensorPreference:    req.SensorPreference,
		ProfileID:           req.ProfileID,
		RuleSources:         req.RuleSources,
		ScanZoneID:          req.ScanZoneID,
		TimeoutSeconds:      req.TimeoutSeconds,
		MaxRetries:          req.MaxRetries,
		RetryBackoffSeconds: req.RetryBackoffSeconds,
		Targets:             req.Targets,
		AssetIDs:            req.AssetIDs,
		AssetGroupIDs:       req.AssetGroupIDs,
		ActorID:             middleware.GetUserID(r.Context()),
		ConfirmLargeRange:   req.ConfirmLargeRange,
	}

	s, err := h.service.UpdateScan(h.auditCtx(r), input)
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

	if err := h.service.DeleteScan(h.auditCtx(r), tenantID, scanID); err != nil {
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

	s, err := h.service.ActivateScan(h.auditCtx(r), tenantID, scanID)
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

	s, err := h.service.PauseScan(h.auditCtx(r), tenantID, scanID)
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

	s, err := h.service.DisableScan(h.auditCtx(r), tenantID, scanID)
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
// @Param        request  body      TriggerScanExecRequest  false  "Trigger context: only the key reason (text, at most 500 characters); any other key is refused with TRIGGER_CONTEXT_REFUSED"
// @Success      201  {object}  RunResponse
// @Failure      400  {object}  apierror.Error  "TRIGGER_CONTEXT_REFUSED: the context sets a key a caller may not set"
// @Failure      403  {object}  apierror.Error  "caller may not start this scan"
// @Failure      404  {object}  apierror.Error
// @Failure      409  {object}  apierror.Error  "SCAN_WINDOW_NEVER_OPENS: a target's scan window never opens"
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
	// The run context reaches the run's sensor jobs and decides its outcome:
	// a caller may only set the allow-listed keys.
	if err := scansvc.ValidateCallerTriggerContext(req.Context); err != nil {
		h.handleServiceError(w, err)
		return
	}

	input := scansvc.TriggerScanExecInput{
		TenantID:    tenantID,
		ScanID:      scanID,
		TriggeredBy: userID,
		Context:     req.Context,
		// A member's own "Run now": allowed on a paused scan (schedule off).
		Interactive: true,
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

// SensorOptInImpact handles GET /api/v1/scans/sensor-opt-in-impact
// @Summary      Scans affected by the sensor opt-ins
// @Description  The organization's switches for out-of-band callbacks (interactsh) and custom templates in sensor jobs (both off unless an owner enabled them), and the scans whose scanner_config asks for either (at most 100; truncated says more exist). While a switch is off, those scans run without interactsh or are refused (custom templates).
// @Tags         Scans
// @Produce      json
// @Success      200  {object}  scansvc.OptInImpact
// @Failure      401  {object}  apierror.Error
// @Failure      403  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /scans/sensor-opt-in-impact [get]
func (h *ScanHandler) SensorOptInImpact(w http.ResponseWriter, r *http.Request) {
	impact, err := h.service.SensorOptInImpact(r.Context(), middleware.GetTenantID(r.Context()))
	if err != nil {
		h.handleServiceError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(impact)
}

// CoverageStatus handles GET /api/v1/scans/coverage
// @Summary      Scan coverage status
// @Description  License-aware rolling coverage summary for the tenant's scannable
// @Description  estate: how much was scanned within the freshness window,
// @Description  what is stale or never scanned, and the critical-asset risk.
// @Tags         Scans
// @Produce      json
// @Param        window_days  query  int  false  "Freshness window in days (default 30, max 3650)"
// @Success      200  {object}  scancoverage.CoverageStats
// @Router       /scans/coverage [get]
func (h *ScanHandler) CoverageStatus(w http.ResponseWriter, r *http.Request) {
	if h.coverageStats == nil {
		apierror.InternalServerError("coverage stats unavailable").WriteJSON(w)
		return
	}
	tenantID, ok := middleware.GetTenantIDFromContext(r.Context())
	if !ok {
		apierror.Unauthorized("missing tenant context").WriteJSON(w)
		return
	}

	windowDays := scancoverage.DefaultCoverageWindowDays
	if v := strings.TrimSpace(r.URL.Query().Get("window_days")); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n <= 0 || n > 3650 {
			apierror.BadRequest("window_days must be an integer between 1 and 3650").WriteJSON(w)
			return
		}
		windowDays = n
	}

	// The estate counted follows the viewer (D6): a restricted member counts
	// the assets of their own scope, dashboards:org:view and unrestricted
	// callers the organization.
	scope, _, err := h.dataScope.ViewerScope(r.Context(), tenantID)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}
	stats, err := h.coverageStats.CoverageStats(r.Context(), tenantID, scope, windowDays)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(stats)
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

	s, err := h.service.CloneScan(r.Context(), tenantID, scanID, req.Name, middleware.GetUserID(r.Context()))
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(h.toScanResponse(r.Context(), s))
}

// TakeScanOwnership handles POST /api/v1/scans/{id}/take-ownership
// @Summary      Take ownership of a scan
// @Description  Makes the calling administrator the owner of a scan whose owner is missing (the account was deleted) or no longer an active member. A scheduled scan runs as its owner, so the caller's act scope must cover the scan's direct targets. The scan is not resumed: resume it afterwards. Refused (409 SCAN_OWNER_ACTIVE) while the owner is an active member. Owners and administrators only; audited.
// @Tags         Scans
// @Produce      json
// @Param        id   path      string  true  "Scan ID"
// @Success      200  {object}  ScanDetailResponse
// @Failure      400  {object}  apierror.Error
// @Failure      403  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Failure      409  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /scans/{id}/take-ownership [post]
func (h *ScanHandler) TakeScanOwnership(w http.ResponseWriter, r *http.Request) {
	s, err := h.service.TakeOwnership(h.auditCtx(r), scansvc.TakeOwnershipInput{
		TenantID: middleware.GetTenantID(r.Context()),
		ScanID:   chi.URLParam(r, "id"),
		ActorID:  middleware.GetUserID(r.Context()),
	})
	if err != nil {
		h.handleServiceError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(h.toScanResponse(r.Context(), s))
}

// SaveScan handles POST /api/v1/scans/{id}/save
// @Summary      Save a quick scan as a configuration
// @Description  Turns an ad-hoc quick scan into a saved scan configuration with the given name ("Save as scan"). Its runs stay attached. Refused for a scan that is already a configuration.
// @Tags         Scans
// @Accept       json
// @Produce      json
// @Param        id       path      string          true  "Quick scan ID"
// @Param        request  body      SaveScanRequest true  "Configuration name"
// @Success      200  {object}  ScanDetailResponse
// @Failure      400  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Failure      409  {object}  apierror.Error
// @Failure      500  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /scans/{id}/save [post]
func (h *ScanHandler) SaveScan(w http.ResponseWriter, r *http.Request) {
	scanID := chi.URLParam(r, "id")
	tenantID := middleware.GetTenantID(r.Context())

	var req SaveScanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}
	if err := h.validator.Validate(req); err != nil {
		h.handleValidationError(w, err)
		return
	}

	s, err := h.service.SaveQuickScan(r.Context(), tenantID, scanID, req.Name)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
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

	// Bound both params: per_page caps the SQL LIMIT (and a downstream
	// slice pre-alloc), page caps the OFFSET — an unbounded per_page is a
	// memory/DoS vector and a negative one is a Postgres syntax error.
	page, ok := listPage(w, r, 20)
	if !ok {
		return
	}

	result, err := h.service.ListScanRuns(r.Context(), tenantID, scanID, page.Page, page.PerPage)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	// The service hands back domain entities. scanrun.Run has exported fields
	// and no json tags, so encoding it directly emits PascalCase keys ("ID",
	// "TriggerType") while every other endpoint emits snake_case — which is why
	// this endpoint had no consumers: anything wired to it reads undefined.
	// Convert through the same DTO GET /scan-runs/{id} already uses, and key
	// the envelope "data" like the rest of our list endpoints.
	if runs, ok := result["items"].([]*scanrun.Run); ok {
		names := h.resolveRunTriggerNames(r.Context(), runs...)
		responses := make([]*RunResponse, 0, len(runs))
		for _, run := range runs {
			responses = append(responses, withTriggerName(toRunResponse(run), names))
		}
		delete(result, "items")
		result["data"] = responses
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
	json.NewEncoder(w).Encode(withTriggerName(toRunResponse(run), h.resolveRunTriggerNames(r.Context(), run)))
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
	json.NewEncoder(w).Encode(withTriggerName(toRunResponse(run), h.resolveRunTriggerNames(r.Context(), run)))
}

// ScanLastRunResponse is a scan's latest run, as the scan list shows it.
type ScanLastRunResponse struct {
	ID          string  `json:"id"`
	Status      string  `json:"status"`
	TriggerType string  `json:"trigger_type"`
	CreatedAt   string  `json:"created_at"`
	StartedAt   *string `json:"started_at,omitempty"`
	CompletedAt *string `json:"completed_at,omitempty"`
	// Progress is 0-100 for a live run: finished steps of the planned steps.
	Progress int `json:"progress"`
	// RefusalCode and ErrorMessage say why a blocked or failed run ended.
	RefusalCode  string                  `json:"refusal_code,omitempty"`
	ErrorMessage string                  `json:"error_message,omitempty"`
	TaskSummary  *RunTaskSummaryResponse `json:"task_summary,omitempty"`
}

// ScanRecentRunResponse is one of a scan's latest runs: its state, the
// refusal code of a blocked one, and when it was created.
type ScanRecentRunResponse struct {
	ID          string `json:"id"`
	Status      string `json:"status"`
	RefusalCode string `json:"refusal_code,omitempty"`
	CreatedAt   string `json:"created_at"`
}

func toScanRecentRunsResponse(runs []scanrun.RecentRun) []ScanRecentRunResponse {
	if len(runs) == 0 {
		return nil
	}
	out := make([]ScanRecentRunResponse, len(runs))
	for i, r := range runs {
		out[i] = ScanRecentRunResponse{
			ID:          r.ID.String(),
			Status:      string(r.Status),
			RefusalCode: r.RefusalCode,
			CreatedAt:   r.CreatedAt.Format(time.RFC3339),
		}
	}
	return out
}

func toScanLastRunResponse(lr scansvc.LastRun) *ScanLastRunResponse {
	r := lr.Run
	if r == nil {
		return nil
	}
	out := &ScanLastRunResponse{
		ID:           r.ID.String(),
		Status:       string(r.Status),
		TriggerType:  string(r.TriggerType),
		CreatedAt:    r.CreatedAt.Format(time.RFC3339),
		Progress:     lr.Progress(),
		RefusalCode:  r.RefusalCode,
		ErrorMessage: r.ErrorMessage,
	}
	if r.StartedAt != nil {
		v := r.StartedAt.Format(time.RFC3339)
		out.StartedAt = &v
	}
	if r.CompletedAt != nil {
		v := r.CompletedAt.Format(time.RFC3339)
		out.CompletedAt = &v
	}
	if lr.Tasks != nil {
		out.TaskSummary = toRunTaskSummaryResponse(*lr.Tasks)
	}
	return out
}

// enrichScanResponses adds each scan's latest run, recent runs and workflow
// name: batch reads for the whole page, scoped to the caller's tenant.
func (h *ScanHandler) enrichScanResponses(ctx context.Context, tenantID string, scans []*scan.Scan, items []*ScanDetailResponse) {
	tid, err := shared.IDFromString(tenantID)
	if err != nil || len(scans) == 0 {
		return
	}
	lastRuns := h.service.LastRuns(ctx, tid, scans)
	recent := h.service.RecentRuns(ctx, tid, scans)
	names := h.service.ScanWorkflowNames(ctx, tid, scans)
	approvals := h.approvals.latestStatuses(ctx, tid, scans)
	for i, s := range scans {
		items[i].ApprovalStatus = approvals[s.ID]
		if lr, ok := lastRuns[s.ID]; ok {
			items[i].LastRun = toScanLastRunResponse(lr)
		}
		items[i].RecentRuns = toScanRecentRunsResponse(recent[s.ID])
		if s.ScanWorkflowID != nil {
			items[i].ScanWorkflowName = names[*s.ScanWorkflowID]
		}
	}
}

// --- Conversion Helpers ---

// toScanResponse converts a domain scan to API response, enriching with the
// creator's name via a single per-scan lookup. Used by single-item endpoints.
// List endpoints must NOT call this in a loop (N+1) — use buildScanResponse with
// a pre-resolved name map instead (see ListScans / resolveScanCreatorNames).
func (h *ScanHandler) toScanResponse(ctx context.Context, s *scan.Scan) *ScanDetailResponse {
	var createdByName *string
	if s.CreatedBy != nil && h.userRepo != nil {
		if u, err := h.userRepo.GetByID(ctx, *s.CreatedBy); err == nil && u != nil {
			name := u.Name()
			createdByName = &name
		}
	}
	resp := buildScanResponse(s, createdByName, canSeeScanConfigSecrets(ctx))
	resp.OwnerState = h.service.OwnerState(ctx, s)
	h.enrichScanResponses(ctx, s.TenantID.String(), []*scan.Scan{s}, []*ScanDetailResponse{resp})
	return resp
}

// scannerConfigFor returns the stored config, or its redacted copy.
func scannerConfigFor(cfg map[string]any, revealSecrets bool) map[string]any {
	if revealSecrets {
		return cfg
	}
	return scan.RedactConfigSecrets(cfg)
}

// canSeeScanConfigSecrets reports whether the caller is shown scanner_config
// values that look like credentials. Only callers who may edit scans
// (scans:write; owners and admins always) see them, because they are the
// ones who type and change them. Everyone else who can read a scan sees
// those values replaced by scan.RedactedSecretValue, with the
// scanner_config_warnings still saying which paths hold one.
func canSeeScanConfigSecrets(ctx context.Context) bool {
	return middleware.HasPermission(ctx, permission.ScansWrite.String())
}

// resolveScanCreatorNames batch-loads creator display names for a page of scans
// in a single query, returning an id→name map. Avoids the N+1 that a per-row
// GetByID inside the response loop would cause on GET /scans.
func (h *ScanHandler) resolveScanCreatorNames(ctx context.Context, scans []*scan.Scan) map[string]string {
	if h.userRepo == nil || len(scans) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(scans))
	ids := make([]shared.ID, 0, len(scans))
	for _, s := range scans {
		if s.CreatedBy == nil {
			continue
		}
		key := s.CreatedBy.String()
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		ids = append(ids, *s.CreatedBy)
	}
	if len(ids) == 0 {
		return nil
	}
	users, err := h.userRepo.GetByIDs(ctx, ids)
	if err != nil {
		h.logger.Warn("failed to batch-resolve scan creator names", "error", err)
		return nil
	}
	nameByID := make(map[string]string, len(users))
	for _, u := range users {
		if u != nil {
			nameByID[u.ID().String()] = u.Name()
		}
	}
	return nameByID
}

// resolveRunTriggerNames batch-loads the display names of the users who
// triggered these runs (runTriggerNames).
func (h *ScanHandler) resolveRunTriggerNames(ctx context.Context, runs ...*scanrun.Run) map[string]string {
	return runTriggerNames(ctx, h.userRepo, h.logger, runs...)
}

// withTriggerName sets the trigger labels from a map built by
// resolveRunTriggerNames. Pure.
func withTriggerName(resp *RunResponse, names map[string]string) *RunResponse {
	return withRunTriggerLabel(resp, names)
}

// buildScanResponse converts a domain scan to API response using a pre-resolved
// creator name (nil = unknown/omitted). Pure — no DB access. Unless
// revealSecrets is set, secret-looking scanner_config values are masked (see
// canSeeScanConfigSecrets); the warnings are always computed from the stored
// values.
func buildScanResponse(s *scan.Scan, createdByName *string, revealSecrets bool) *ScanDetailResponse {
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

	ownerState := scansvc.OwnerStateOK
	if s.CreatedBy == nil || s.CreatedBy.IsZero() {
		ownerState = scansvc.OwnerStateMissing
	}
	if s.IsManaged() {
		ownerState = scansvc.OwnerStateManaged
	}
	resp := &ScanDetailResponse{
		OwnerState:            ownerState,
		ManagedBy:             string(s.ManagedBy),
		ID:                    s.ID.String(),
		TenantID:              s.TenantID.String(),
		Name:                  s.Name,
		Description:           s.Description,
		AssetGroupID:          assetGroupID,
		AssetGroupIDs:         assetGroupIDs,
		Targets:               s.Targets,
		TargetOptions:         s.TargetOptions,
		SkippedTargets:        s.SkippedTargets,
		Intensity:             string(s.EffectiveIntensity()),
		Depth:                 string(s.EffectiveDepth()),
		StepParams:            s.StepParams,
		ScanType:              string(s.ScanType),
		ScannerName:           s.ScannerName,
		ScannerConfig:         scannerConfigFor(s.ScannerConfig, revealSecrets),
		ScannerConfigWarnings: scan.DetectConfigSecrets(s.ScannerConfig),
		TargetsPerJob:         s.TargetsPerJob,
		ScheduleType:          string(s.ScheduleType),
		ScheduleCron:          s.ScheduleCron,
		ScheduleRRule:         s.ScheduleRRule,
		ScheduleDay:           s.ScheduleDay,
		ScheduleTimezone:      s.ScheduleTimezone,
		Tags:                  s.Tags,
		RunOnTenantRunner:     s.RunOnTenantRunner,
		SensorPreference:      string(s.SensorPreference),
		RuleSources:           string(s.RuleSources),
		TimeoutSeconds:        s.TimeoutSeconds,
		MaxRetries:            s.MaxRetries,
		RetryBackoffSeconds:   s.RetryBackoffSeconds,
		Status:                string(s.Status),
		AdHoc:                 s.AdHoc,
		LastRunStatus:         s.LastRunStatus,
		TotalRuns:             s.TotalRuns,
		SuccessfulRuns:        s.SuccessfulRuns,
		FailedRuns:            s.FailedRuns,
		PartialRuns:           s.PartialRuns,
		BlockedRuns:           s.BlockedRuns,
		CreatedAt:             s.CreatedAt.Format(time.RFC3339),
		UpdatedAt:             s.UpdatedAt.Format(time.RFC3339),
	}

	if s.ScanWorkflowID != nil {
		pid := s.ScanWorkflowID.String()
		resp.ScanWorkflowID = &pid
	}

	if s.ScanZoneID != nil {
		zid := s.ScanZoneID.String()
		resp.ScanZoneID = &zid
	}
	if s.ProfileID != nil {
		pid := s.ProfileID.String()
		resp.ProfileID = &pid
	}

	if s.ScheduleTime != nil {
		st := s.ScheduleTime.Format("15:04")
		resp.ScheduleTime = &st
	}

	if s.ScheduleRunAt != nil {
		ra := s.ScheduleRunAt.UTC().Format(time.RFC3339)
		resp.ScheduleRunAt = &ra
	}
	if s.LastMissedAt != nil {
		lma := s.LastMissedAt.Format(time.RFC3339)
		resp.LastMissedAt = &lma
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
		resp.CreatedByName = createdByName
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
	case errors.Is(err, scanworkflow.ErrScanWorkflowRetired):
		// The workflow of the scan was deleted (kept for its run history).
		apierror.New(http.StatusConflict, apierror.Code(scanworkflow.ErrScanWorkflowRetired.Code), scanworkflow.ErrScanWorkflowRetired.Message).WriteJSON(w)
	case errors.Is(err, scanworkflow.ErrScanWorkflowNotFound):
		// The scan's workflow, not the scan, is missing (or another
		// organization's): say so.
		apierror.New(http.StatusNotFound, apierror.Code(scanworkflow.ErrScanWorkflowNotFound.Code), "Scan workflow not found").WriteJSON(w)
	case scanReferenceNotFoundCode(err) != "":
		// The scan was found; something it uses was not (its workflow, a
		// step's tool): say which, never "Scan not found".
		code := scanReferenceNotFoundCode(err)
		spec, _ := apierror.Lookup(code)
		apierror.New(spec.Status, code, cleanErrorMessage(err, spec.Message)).WriteJSON(w)
	case errors.Is(err, shared.ErrNotFound):
		apierror.NotFound("Scan").WriteJSON(w)
	case errors.Is(err, shared.ErrAlreadyExists):
		apierror.Conflict(cleanErrorMessage(err, "Scan already exists")).WriteJSON(w)
	case errors.Is(err, shared.ErrValidation):
		// Trigger refusals (NO_ZONE_COVERAGE, ZONE_SPLIT_REQUIRED, ...) keep
		// their code so the client can explain them.
		e := apierror.New(http.StatusBadRequest, scanZoneErrorCode(err, apierror.CodeBadRequest),
			cleanErrorMessage(err, "Invalid request"))
		// A refusal of targets lists each with its code and fixes (RFC-054 §6.5).
		var de *shared.DomainError
		if errors.As(err, &de) && de.Details != nil {
			e = e.WithDetails(de.Details)
		}
		if d := toolUnavailableDetails(err); d != nil {
			e.Details = d
		}
		e.WriteJSON(w)
	case scanWindowNeverOpens(err) != nil:
		// A target's scan windows never open: 409 with its own code, naming
		// the targets and the windows.
		apierror.New(http.StatusConflict, apierror.Code(scansvc.CodeWindowNeverOpens), scanWindowNeverOpens(err).Error()).WriteJSON(w)
	case errors.Is(err, shared.ErrConflict):
		apierror.New(http.StatusConflict, scanZoneErrorCode(err, apierror.CodeConflict),
			cleanErrorMessage(err, "Conflict")).WriteJSON(w)
	case errors.Is(err, shared.ErrUnauthorized):
		apierror.Unauthorized("").WriteJSON(w)
	case errors.Is(err, shared.ErrForbidden):
		// A governed scan waiting for approval keeps its code and message
		// (the console points to the approval panel); any other refusal
		// stays a plain 403.
		if code := scanZoneErrorCode(err, ""); code != "" {
			apierror.New(http.StatusForbidden, code, cleanErrorMessage(err, "Forbidden")).WriteJSON(w)
			return
		}
		apierror.Forbidden("").WriteJSON(w)
	default:
		h.logger.Error("service error", "error", err)
		apierror.InternalError(err).WriteJSON(w)
	}
}

// scanReferenceNotFoundCode is the registered code of a not-found error that
// is about a reference of a loaded scan (scan trigger), or "".
func scanReferenceNotFoundCode(err error) apierror.Code {
	if !errors.Is(err, shared.ErrNotFound) {
		return ""
	}
	var de *shared.DomainError
	if !errors.As(err, &de) {
		return ""
	}
	switch de.Code {
	case scansvc.CodePipelineNotFound:
		return apierror.CodePipelineNotFound
	case scansvc.CodeScanDependencyMissing:
		return apierror.CodeScanDependencyMissing
	}
	return ""
}

// cleanErrorMessage extracts a user-friendly message from an error.
// Prefers the .Message field on shared.DomainError (without wrapping noise),
// falls back to err.Error() trimmed of internal codes.
func cleanErrorMessage(err error, fallback string) string {
	var de *shared.DomainError
	if errors.As(err, &de) {
		if de.Message != "" {
			return de.Message
		}
	}
	// Try to strip leading "CODE: " prefix and trailing ": validation" / similar
	msg := err.Error()
	// Strip leading "VALIDATION: " or similar code prefix
	if i := strings.Index(msg, ": "); i > 0 && i < 30 {
		head := msg[:i]
		isCode := true
		for _, r := range head {
			if !((r >= 'A' && r <= 'Z') || r == '_') {
				isCode = false
				break
			}
		}
		if isCode {
			msg = msg[i+2:]
		}
	}
	// Strip trailing ": validation" or ": <wrapped err>"
	if i := strings.LastIndex(msg, ": "); i > 0 {
		tail := msg[i+2:]
		if tail == "validation" || tail == "not found" || tail == "already exists" {
			msg = msg[:i]
		}
	}
	if msg == "" {
		return fallback
	}
	return msg
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
		Intensity:   req.Intensity,
		CreatedBy:   userID,
	})
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(QuickScanResponse{
		ScanRunID:    result.ScanRunID,
		ScanID:       result.ScanID,
		AssetGroupID: result.AssetGroupID,
		Status:       result.Status,
		TargetCount:  result.TargetCount,
	})
}

// OverviewStatsResponse represents the response for scan management overview stats.
type OverviewStatsResponse struct {
	ScanRuns StatusCountsResponse `json:"scan_runs"`
	Scans    StatusCountsResponse `json:"scans"`
	Jobs     StatusCountsResponse `json:"jobs"`
}

// StatusCountsResponse represents counts by status.
type StatusCountsResponse struct {
	Total     int64 `json:"total"`
	Running   int64 `json:"running"`
	Pending   int64 `json:"pending"`
	Completed int64 `json:"completed"`
	// Partial: runs or steps that kept results but lost some work.
	Partial  int64 `json:"partial"`
	Failed   int64 `json:"failed"`
	Canceled int64 `json:"canceled"`
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
		ScanRuns: StatusCountsResponse{
			Total:     stats.ScanRuns.Total,
			Running:   stats.ScanRuns.Running,
			Pending:   stats.ScanRuns.Pending,
			Completed: stats.ScanRuns.Completed,
			Partial:   stats.ScanRuns.Partial,
			Failed:    stats.ScanRuns.Failed,
			Canceled:  stats.ScanRuns.Canceled,
		},
		Scans: StatusCountsResponse{
			Total:     stats.Scans.Total,
			Running:   stats.Scans.Running,
			Pending:   stats.Scans.Pending,
			Completed: stats.Scans.Completed,
			Partial:   stats.Scans.Partial,
			Failed:    stats.Scans.Failed,
			Canceled:  stats.Scans.Canceled,
		},
		Jobs: StatusCountsResponse{
			Total:     stats.Jobs.Total,
			Running:   stats.Jobs.Running,
			Pending:   stats.Jobs.Pending,
			Completed: stats.Jobs.Completed,
			Partial:   stats.Jobs.Partial,
			Failed:    stats.Jobs.Failed,
			Canceled:  stats.Jobs.Canceled,
		},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// --- Config Export/Import Handlers ---

// ExportConfig handles GET /api/v1/scans/{id}/export
// @Summary      Export scan configuration
// @Description  Export a scan configuration as a JSON file for sharing or backup
// @Tags         Scans
// @Produce      application/json
// @Param        id   path      string  true  "Scan ID"
// @Success      200  {object}  object  "Scan configuration JSON"
// @Failure      400  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Failure      500  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /scans/{id}/export [get]
func (h *ScanHandler) ExportConfig(w http.ResponseWriter, r *http.Request) {
	scanID := chi.URLParam(r, "id")
	tenantID := middleware.GetTenantID(r.Context())

	tid, err := shared.IDFromString(tenantID)
	if err != nil {
		apierror.BadRequest("Invalid tenant ID").WriteJSON(w)
		return
	}

	sid, err := shared.IDFromString(scanID)
	if err != nil {
		apierror.BadRequest("Invalid scan ID").WriteJSON(w)
		return
	}

	data, err := h.service.ExportConfigWithOptions(h.auditCtx(r), tid, sid, scansvc.ExportOptions{
		RedactSecrets: !canSeeScanConfigSecrets(r.Context()),
	})
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"scan-config-%s.json\"", scanID))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}

// ImportConfig handles POST /api/v1/scans/import
// @Summary      Import scan configuration
// @Description  Create a new scan from an imported JSON configuration. A configuration whose targets name a range wider than a /16 needs ?confirm_large_range=true (400 LARGE_RANGE_UNCONFIRMED without it).
// @Tags         Scans
// @Accept       json
// @Produce      json
// @Param        confirm_large_range  query  bool  false  "Confirm targets wider than a /16"
// @Param        request  body      object  true  "Scan configuration JSON (exported format)"
// @Success      201  {object}  ScanDetailResponse
// @Failure      400  {object}  apierror.Error
// @Failure      500  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /scans/import [post]
func (h *ScanHandler) ImportConfig(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.GetTenantID(r.Context())

	tid, err := shared.IDFromString(tenantID)
	if err != nil {
		apierror.BadRequest("Invalid tenant ID").WriteJSON(w)
		return
	}

	// Read the entire request body as the config JSON
	var data json.RawMessage
	if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
		apierror.BadRequest("Invalid JSON body").WriteJSON(w)
		return
	}

	sc, err := h.service.ImportConfigConfirmed(h.auditCtx(r), tid, data, middleware.GetUserID(r.Context()),
		r.URL.Query().Get("confirm_large_range") == queryParamTrue)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(h.toScanResponse(r.Context(), sc))
}

// ToolUnavailableDetails is the error body's details on a NO_SENSOR_FOR_TOOL
// refusal: the tool, the workflow step that needs it, and the sensor counts
// behind the refusal (docs/architecture/tool-availability.md).
type ToolUnavailableDetails struct {
	Tool            string `json:"tool"`
	Step            string `json:"step,omitempty"`
	Status          string `json:"status"`
	SensorsTotal    int    `json:"sensors_total"`
	SensorsOnline   int    `json:"sensors_online"`
	SensorsExcluded int    `json:"sensors_excluded"`
	ZoneID          string `json:"zone_id,omitempty"`
}

// toolUnavailableDetails returns the details of a NO_SENSOR_FOR_TOOL
// refusal, or nil.
func toolUnavailableDetails(err error) *ToolUnavailableDetails {
	var tu *scansvc.ToolUnavailableError
	if !errors.As(err, &tu) {
		return nil
	}
	return &ToolUnavailableDetails{Tool: tu.Tool, Step: tu.Step, Status: tu.Status,
		SensorsTotal: tu.SensorsTotal, SensorsOnline: tu.SensorsOnline, SensorsExcluded: tu.SensorsExcluded, ZoneID: tu.ZoneID}
}

// scanWindowNeverOpens returns the trigger refusal for targets whose scan
// windows never open, or nil.
func scanWindowNeverOpens(err error) *scansvc.NeverOpensError {
	var ne *scansvc.NeverOpensError
	if errors.As(err, &ne) {
		return ne
	}
	return nil
}
