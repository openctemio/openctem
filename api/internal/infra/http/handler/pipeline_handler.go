package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"

	pipelinesvc "github.com/openctemio/openctem/api/internal/app/pipeline"
	scansvc "github.com/openctemio/openctem/api/internal/app/scan"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/domain/pipeline"
	"github.com/openctemio/openctem/api/pkg/domain/scanprofile"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/stage"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/validator"
)

// PipelineHandler handles HTTP requests for pipelines.
type PipelineHandler struct {
	service   *pipelinesvc.Service
	validator *validator.Validator
	logger    *logger.Logger
	// taskLogs reads a run task's logs (nil: GET .../tasks/{task_id}/logs
	// answers an empty log).
	taskLogs taskLogReader
}

// NewPipelineHandler creates a new PipelineHandler.
func NewPipelineHandler(service *pipelinesvc.Service, v *validator.Validator, log *logger.Logger) *PipelineHandler {
	return &PipelineHandler{
		service:   service,
		validator: v,
		logger:    log.With("handler", "pipeline"),
	}
}

// --- Template Request/Response Types ---

// CreateTemplateRequest represents the request body for creating a pipeline template.
type CreateTemplateRequest struct {
	Name        string                   `json:"name" validate:"required,min=1,max=255"`
	Description string                   `json:"description" validate:"max=1000"`
	Triggers    []TriggerRequest         `json:"triggers" validate:"max=10,dive"`
	Settings    *PipelineSettingsRequest `json:"settings"`
	Tags        []string                 `json:"tags" validate:"max=10,dive,max=50"`
	Steps       []CreateStepRequest      `json:"steps" validate:"max=50,dive"`
}

// TriggerRequest represents a trigger configuration in the request.
type TriggerRequest struct {
	Type     string         `json:"type" validate:"required,oneof=manual schedule webhook api on_asset_discovery"`
	Schedule string         `json:"schedule"`
	Webhook  string         `json:"webhook"`
	Filters  map[string]any `json:"filters"`
}

// PipelineSettingsRequest represents template settings in the request.
type PipelineSettingsRequest struct {
	MaxParallelSteps     int      `json:"max_parallel_steps" validate:"min=0,max=10"`
	FailFast             bool     `json:"fail_fast"`
	RetryFailedSteps     int      `json:"retry_failed_steps" validate:"min=0,max=5"`
	TimeoutSeconds       int      `json:"timeout_seconds" validate:"min=0,max=86400"`
	NotifyOnComplete     bool     `json:"notify_on_complete"`
	NotifyOnFailure      bool     `json:"notify_on_failure"`
	NotificationChannels []string `json:"notification_channels"`
	SensorPreference     string   `json:"sensor_preference" validate:"omitempty,oneof=auto tenant platform"`
}

// UIPositionRequest represents a visual position in the workflow builder.
type UIPositionRequest struct {
	X float64 `json:"x"`
	Y float64 `json:"y"`
}

// CreateStepRequest represents a step in the create template request.
// Capabilities are optional - if not provided and tool is specified, they will be derived from the tool.
type CreateStepRequest struct {
	// ID is the id of the existing step this entry is, when the request saves
	// a whole pipeline (PUT): the step is updated in place and keeps its run
	// history. Optional; an id that is not one of the pipeline's steps (for
	// example a client-side temporary id) makes the entry a new step.
	ID                string                 `json:"id,omitempty" validate:"max=64"`
	StepKey           string                 `json:"step_key" validate:"required,min=1,max=100"`
	Name              string                 `json:"name" validate:"required,min=1,max=255"`
	Description       string                 `json:"description" validate:"max=1000"`
	Order             int                    `json:"order"`
	UIPosition        *UIPositionRequest     `json:"ui_position"`
	Tool              string                 `json:"tool" validate:"max=100"`
	Capabilities      []string               `json:"capabilities" validate:"omitempty,max=10,dive,max=50"`
	Config            map[string]interface{} `json:"config"`
	TimeoutSeconds    int                    `json:"timeout_seconds"`
	DependsOn         []string               `json:"depends_on" validate:"max=20,dive,max=50"`
	Condition         *StepConditionRequest  `json:"condition"`
	MaxRetries        int                    `json:"max_retries"`
	RetryDelaySeconds int                    `json:"retry_delay_seconds"`
}

// StepConditionRequest represents a step condition in the request.
type StepConditionRequest struct {
	Type  string `json:"type" validate:"oneof=always never asset_type expression step_result"`
	Value string `json:"value" validate:"max=500"`
}

// TemplateResponse represents the response for a pipeline template.
type TemplateResponse struct {
	ID               string                   `json:"id"`
	TenantID         string                   `json:"tenant_id"`
	Name             string                   `json:"name"`
	Description      string                   `json:"description,omitempty"`
	Version          int                      `json:"version"`
	IsActive         bool                     `json:"is_active"`
	IsSystemTemplate bool                     `json:"is_system_template"`
	Triggers         []TriggerResponse        `json:"triggers"`
	Settings         PipelineSettingsResponse `json:"settings"`
	Tags             []string                 `json:"tags,omitempty"`
	Steps            []StepResponse           `json:"steps"`
	UIStartPosition  *UIPositionResponse      `json:"ui_start_position,omitempty"`
	UIEndPosition    *UIPositionResponse      `json:"ui_end_position,omitempty"`
	CreatedAt        string                   `json:"created_at"`
	UpdatedAt        string                   `json:"updated_at"`
}

// TriggerResponse represents a trigger in the response.
type TriggerResponse struct {
	Type     string         `json:"type"`
	Schedule string         `json:"schedule,omitempty"`
	Webhook  string         `json:"webhook,omitempty"`
	Filters  map[string]any `json:"filters,omitempty"`
}

// PipelineSettingsResponse represents template settings in the response.
type PipelineSettingsResponse struct {
	MaxParallelSteps     int      `json:"max_parallel_steps"`
	FailFast             bool     `json:"fail_fast"`
	RetryFailedSteps     int      `json:"retry_failed_steps"`
	TimeoutSeconds       int      `json:"timeout_seconds"`
	NotifyOnComplete     bool     `json:"notify_on_complete"`
	NotifyOnFailure      bool     `json:"notify_on_failure"`
	NotificationChannels []string `json:"notification_channels,omitempty"`
	SensorPreference     string   `json:"sensor_preference"`
}

// UIPositionResponse represents a visual position in the workflow builder response.
type UIPositionResponse struct {
	X float64 `json:"x"`
	Y float64 `json:"y"`
}

// StepResponse represents a step in the response.
type StepResponse struct {
	ID                string                 `json:"id"`
	StepKey           string                 `json:"step_key"`
	Name              string                 `json:"name"`
	Description       string                 `json:"description,omitempty"`
	Order             int                    `json:"order"`
	UIPosition        UIPositionResponse     `json:"ui_position"`
	Tool              string                 `json:"tool,omitempty"`
	Capabilities      []string               `json:"capabilities"`
	Config            map[string]interface{} `json:"config,omitempty"`
	TimeoutSeconds    int                    `json:"timeout_seconds,omitempty"`
	DependsOn         []string               `json:"depends_on,omitempty"`
	Condition         *StepConditionResponse `json:"condition,omitempty"`
	MaxRetries        int                    `json:"max_retries"`
	RetryDelaySeconds int                    `json:"retry_delay_seconds"`
}

// StepConditionResponse represents a step condition in the response.
type StepConditionResponse struct {
	Type  string `json:"type"`
	Value string `json:"value,omitempty"`
}

// --- Run Request/Response Types ---

// TriggerRunRequest represents the request body for triggering a pipeline run.
type TriggerRunRequest struct {
	TemplateID  string         `json:"template_id" validate:"required,uuid"`
	AssetID     string         `json:"asset_id" validate:"omitempty,uuid"`
	TriggerType string         `json:"trigger_type" validate:"omitempty,oneof=manual schedule webhook api"`
	Context     map[string]any `json:"context"`
}

// RunResponse represents the response for a pipeline run.
type RunResponse struct {
	ID         string  `json:"id"`
	TenantID   string  `json:"tenant_id"`
	PipelineID string  `json:"pipeline_id"`
	AssetID    *string `json:"asset_id,omitempty"`
	ScanID     *string `json:"scan_id,omitempty"`
	// ScanName names the run's scan (list rows only; empty when the scan was
	// deleted).
	ScanName          string                         `json:"scan_name,omitempty"`
	ScanProfileID     *string                        `json:"scan_profile_id,omitempty"`
	TriggerType       string                         `json:"trigger_type"`
	TriggeredBy       string                         `json:"triggered_by,omitempty"`
	TriggeredByName   string                         `json:"triggered_by_name,omitempty"` // display name, when triggered_by is a user id
	Status            string                         `json:"status"`
	StartedAt         *string                        `json:"started_at,omitempty"`
	CompletedAt       *string                        `json:"completed_at,omitempty"`
	TotalSteps        int                            `json:"total_steps"`
	CompletedSteps    int                            `json:"completed_steps"`
	FailedSteps       int                            `json:"failed_steps"`
	SkippedSteps      int                            `json:"skipped_steps"`
	TotalFindings     int                            `json:"total_findings"`
	QualityGateResult *scanprofile.QualityGateResult `json:"quality_gate_result,omitempty"`
	StepRuns          []StepRunResponse              `json:"step_runs,omitempty"`
	ErrorMessage      string                         `json:"error_message,omitempty"`
	CreatedAt         string                         `json:"created_at"`
	// ScheduledFor is the schedule occurrence this run serves (scheduled runs only).
	ScheduledFor *string `json:"scheduled_for,omitempty"`
	// DeadlineAt is when the run is settled if it is still open (RFC-046 §6.3).
	DeadlineAt *string `json:"deadline_at,omitempty"`
	// UnfinishedTargetCount is how many targets were still open when the run
	// was settled at its deadline; the next scheduled run plans them first.
	UnfinishedTargetCount int                      `json:"unfinished_target_count,omitempty"`
	FilteringResult       *FilteringResultResponse `json:"filtering_result,omitempty"`
	Dispatch              *RunDispatchResponse     `json:"dispatch,omitempty"`
	// TaskSummary counts the run's tasks (the commands it dispatched) by
	// status. Present on list rows and on the run, once it has tasks.
	TaskSummary *RunTaskSummaryResponse `json:"task_summary,omitempty"`
	// Tasks lists the run's tasks (GET /pipeline-runs/{id} only).
	Tasks []RunTaskResponse `json:"tasks,omitempty"`
	// TasksTruncated is true when the run has more tasks than Tasks lists.
	TasksTruncated bool `json:"tasks_truncated,omitempty"`
	// TasksNextCursor continues the task list after Tasks
	// (GET /pipeline-runs/{id}/tasks?cursor=) when TasksTruncated.
	TasksNextCursor string `json:"tasks_next_cursor,omitempty"`
}

// RunTaskPageResponse is one page of a run's tasks.
type RunTaskPageResponse struct {
	Data []RunTaskResponse `json:"data"`
	// NextCursor continues after Data; absent on the last page.
	NextCursor string `json:"next_cursor,omitempty"`
}

// RunTaskSummaryResponse counts a run's tasks by status (RFC-046 §4.1).
type RunTaskSummaryResponse struct {
	Total     int `json:"total"`
	Queued    int `json:"queued"`
	Running   int `json:"running"`
	Completed int `json:"completed"`
	Failed    int `json:"failed"`
	Canceled  int `json:"canceled"`
	// Sensors is how many distinct sensors claimed one of the tasks.
	Sensors int `json:"sensors"`
}

// RunTaskResponse is one task of a run: one command, one tool, a slice of
// targets (counted, not listed), one sensor attempt at a time.
type RunTaskResponse struct {
	ID        string  `json:"id"`
	StepRunID *string `json:"step_run_id,omitempty"`
	StepKey   string  `json:"step_key,omitempty"`
	Tool      string  `json:"tool,omitempty"`
	// Status is queued, running, completed, failed or canceled.
	Status     string  `json:"status"`
	SensorID   *string `json:"sensor_id,omitempty"`
	SensorName string  `json:"sensor_name,omitempty"`
	// Platform is true when a shared platform sensor runs the task; it is
	// never named.
	Platform     bool    `json:"platform,omitempty"`
	Targets      int     `json:"targets"`
	Attempts     int     `json:"attempts"`
	CreatedAt    string  `json:"created_at"`
	StartedAt    *string `json:"started_at,omitempty"`
	CompletedAt  *string `json:"completed_at,omitempty"`
	ErrorMessage string  `json:"error_message,omitempty"`
}

func toRunTaskSummaryResponse(s pipeline.TaskSummary) *RunTaskSummaryResponse {
	if s.Total == 0 {
		return nil
	}
	return &RunTaskSummaryResponse{
		Total: s.Total, Queued: s.Queued, Running: s.Running, Completed: s.Completed,
		Failed: s.Failed, Canceled: s.Canceled, Sensors: s.Sensors,
	}
}

func toRunTaskResponses(tasks []pipeline.Task) []RunTaskResponse {
	out := make([]RunTaskResponse, 0, len(tasks))
	for _, t := range tasks {
		r := RunTaskResponse{
			ID: t.ID.String(), StepKey: t.StepKey, Tool: t.Tool, Status: string(t.Status),
			SensorName: t.SensorName, Platform: t.Platform, Targets: t.Targets, Attempts: t.Attempts,
			CreatedAt: t.CreatedAt.Format(time.RFC3339), ErrorMessage: t.ErrorMessage,
		}
		if t.StepRunID != nil {
			v := t.StepRunID.String()
			r.StepRunID = &v
		}
		if t.SensorID != nil {
			v := t.SensorID.String()
			r.SensorID = &v
		}
		if t.StartedAt != nil {
			v := t.StartedAt.Format(time.RFC3339)
			r.StartedAt = &v
		}
		if t.CompletedAt != nil {
			v := t.CompletedAt.Format(time.RFC3339)
			r.CompletedAt = &v
		}
		out = append(out, r)
	}
	return out
}

// RunDispatchResponse is what a scan run dispatched: targets resolved and
// excluded by scope, every target not scanned and why, and the scan-zone
// routing (RFC-023). Absent for runs that recorded none of it.
type RunDispatchResponse struct {
	ResolvedTargets  int                  `json:"resolved_targets"`
	ExcludedTargets  int                  `json:"excluded_targets"`
	Warnings         []string             `json:"warnings,omitempty"`
	UncoveredTargets []RunUncoveredTarget `json:"uncovered_targets,omitempty"`
	ZoneRouting      *RunZoneRouting      `json:"zone_routing,omitempty"`
	// SensorRouting is where the run's commands were queued: "tenant" or
	// "platform" (shared platform sensors), decided at trigger time.
	SensorRouting string `json:"sensor_routing,omitempty"`
}

// RunUncoveredTarget is a target the run did not scan.
type RunUncoveredTarget struct {
	Target string `json:"target"`
	Reason string `json:"reason"`
}

// RunZoneRouting summarizes how a run's targets were routed to scan zones.
type RunZoneRouting struct {
	Jobs             int            `json:"jobs"`
	TargetsPerJob    int            `json:"targets_per_job"`
	UnzonedTargets   int            `json:"unzoned_targets"`
	UncoveredTargets int            `json:"uncovered_targets"`
	ZoneID           string         `json:"zone_id,omitempty"` // workflow runs: the one zone the run is bound to
	Zones            []RunZoneRoute `json:"zones,omitempty"`
}

// RunZoneRoute is one zone's share of a run.
type RunZoneRoute struct {
	ZoneID     string   `json:"zone_id"`
	ZoneName   string   `json:"zone_name"`
	Targets    int      `json:"targets"`
	Jobs       int      `json:"jobs"`
	QueuedJobs int      `json:"queued_jobs"` // waiting for a healthy sensor of the zone
	SensorIDs  []string `json:"sensor_ids"`  // sensors the jobs were pinned to
}

// FilteringResultResponse represents smart filtering result in API response.
type FilteringResultResponse struct {
	TotalAssets          int                  `json:"total_assets"`
	ScannedAssets        int                  `json:"scanned_assets"`
	SkippedAssets        int                  `json:"skipped_assets"`
	UnclassifiedAssets   int                  `json:"unclassified_assets"`
	CompatibilityPercent float64              `json:"compatibility_percent"`
	ScannedByType        map[string]int       `json:"scanned_by_type,omitempty"`
	SkippedByType        map[string]int       `json:"skipped_by_type,omitempty"`
	SkipReasons          []SkipReasonResponse `json:"skip_reasons,omitempty"`
	WasFiltered          bool                 `json:"was_filtered"`
	ToolName             string               `json:"tool_name,omitempty"`
	SupportedTargets     []string             `json:"supported_targets,omitempty"`
}

// SkipReasonResponse explains why assets of a certain type were skipped.
type SkipReasonResponse struct {
	AssetType string `json:"asset_type"`
	Count     int    `json:"count"`
	Reason    string `json:"reason"`
}

// StepRunResponse represents a step run in the response.
type StepRunResponse struct {
	ID string `json:"id"`
	// StepID is empty once the step was removed from the pipeline; the step
	// run keeps its key, name and tool.
	StepID        string  `json:"step_id,omitempty"`
	StepKey       string  `json:"step_key"`
	StepName      string  `json:"step_name,omitempty"`
	Tool          string  `json:"tool,omitempty"`
	Status        string  `json:"status"`
	StartedAt     *string `json:"started_at,omitempty"`
	CompletedAt   *string `json:"completed_at,omitempty"`
	ErrorMessage  string  `json:"error_message,omitempty"`
	ErrorCode     string  `json:"error_code,omitempty"`
	Attempt       int     `json:"attempt"`
	MaxAttempts   int     `json:"max_attempts"`
	FindingsCount int     `json:"findings_count"`
}

// --- Template Handlers ---

// CreateTemplate handles POST /api/v1/pipelines/templates
func (h *PipelineHandler) CreateTemplate(w http.ResponseWriter, r *http.Request) {
	var req CreateTemplateRequest
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

	input := pipelinesvc.CreateTemplateInput{
		TenantID:    tenantID,
		Name:        req.Name,
		Description: req.Description,
		Triggers:    toTriggers(req.Triggers),
		Settings:    toSettings(req.Settings),
		Tags:        req.Tags,
		CreatedBy:   userID,
	}

	stepInputs := make([]pipelinesvc.AddStepInput, 0, len(req.Steps))
	for i, stepReq := range req.Steps {
		stepInput := toAddStepInput(tenantID, "", stepReq)
		stepInput.ID = "" // a new pipeline has no existing steps
		if stepInput.Order == 0 {
			stepInput.Order = i + 1
		}
		stepInputs = append(stepInputs, stepInput)
	}

	// Validate every step before anything is written: the template and its
	// steps are separate inserts, so a step rejected after the template was
	// created used to leave an empty pipeline behind — and a retry then hit
	// "Pipeline already exists".
	if err := h.service.ValidateSteps(r.Context(), stepInputs); err != nil {
		h.handleServiceError(w, err)
		return
	}

	template, err := h.service.CreateTemplate(pipelineAuditCtx(r), input)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	steps, err := h.service.ReplaceSteps(pipelineAuditCtx(r), pipelinesvc.ReplaceStepsInput{
		TenantID:   tenantID,
		TemplateID: template.ID.String(),
		Steps:      stepInputs,
	})
	if err != nil {
		// A step can still fail past validation. Remove the half-built
		// template rather than leave it behind.
		if delErr := h.service.DeleteTemplate(pipelineAuditCtx(r), tenantID, template.ID.String()); delErr != nil {
			h.logger.Error("failed to remove pipeline template after a step was rejected",
				"template_id", template.ID.String(), "error", delErr)
		}
		h.handleServiceError(w, err)
		return
	}
	template.Steps = steps

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(toTemplateResponse(template))
}

// GetTemplate handles GET /api/v1/pipelines/templates/{id}
func (h *PipelineHandler) GetTemplate(w http.ResponseWriter, r *http.Request) {
	templateID := chi.URLParam(r, "id")
	tenantID := middleware.GetTenantID(r.Context())

	template, err := h.service.GetTemplate(r.Context(), tenantID, templateID)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	// Get steps for template
	steps, err := h.service.GetSteps(r.Context(), templateID)
	if err != nil {
		h.logger.Warn("failed to get steps for template", "error", err, "template_id", templateID)
	} else {
		template.Steps = steps
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(toTemplateResponse(template))
}

// ListTemplates handles GET /api/v1/pipelines/templates
func (h *PipelineHandler) ListTemplates(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.GetTenantID(r.Context())

	var isActive *bool
	if activeStr := r.URL.Query().Get("is_active"); activeStr != "" {
		active := activeStr == queryParamTrue
		isActive = &active
	}

	input := pipelinesvc.ListTemplatesInput{
		TenantID: tenantID,
		IsActive: isActive,
		Tags:     parseQueryArray(r.URL.Query().Get("tags")),
		Search:   r.URL.Query().Get("search"),
		Page:     parseQueryInt(r.URL.Query().Get("page"), 1),
		PerPage:  parseQueryIntBounded(r.URL.Query().Get("per_page"), 20, 1, MaxPerPage),
	}

	result, err := h.service.ListTemplates(r.Context(), input)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	items := make([]*TemplateResponse, len(result.Data))
	for i, t := range result.Data {
		items[i] = toTemplateResponse(t)
	}

	resp := map[string]interface{}{
		"items":       items,
		"total":       result.Total,
		"page":        result.Page,
		"per_page":    result.PerPage,
		"total_pages": result.TotalPages,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// UpdateTemplateRequest represents the request body for updating a template.
type UpdateTemplateRequest struct {
	Name            string                   `json:"name" validate:"omitempty,min=1,max=255"`
	Description     string                   `json:"description" validate:"max=1000"`
	Triggers        []TriggerRequest         `json:"triggers" validate:"max=10,dive"`
	Settings        *PipelineSettingsRequest `json:"settings"`
	Tags            []string                 `json:"tags" validate:"max=10,dive,max=50"`
	IsActive        *bool                    `json:"is_active"`
	Steps           []CreateStepRequest      `json:"steps" validate:"max=50,dive"`
	UIStartPosition *UIPositionRequest       `json:"ui_start_position"`
	UIEndPosition   *UIPositionRequest       `json:"ui_end_position"`
}

// UpdateTemplate handles PUT /api/v1/pipelines/templates/{id}
func (h *PipelineHandler) UpdateTemplate(w http.ResponseWriter, r *http.Request) {
	templateID := chi.URLParam(r, "id")
	tenantID := middleware.GetTenantID(r.Context())

	var req UpdateTemplateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}

	if err := h.validator.Validate(req); err != nil {
		h.handleValidationError(w, err)
		return
	}

	// Steps first: the save validates every step and is refused as a whole
	// (nothing changes) while a run of the pipeline is active, so a refused
	// save does not leave the template's other fields half applied.
	var steps []*pipeline.Step
	if req.Steps != nil {
		stepInputs := make([]pipelinesvc.AddStepInput, 0, len(req.Steps))
		for _, stepReq := range req.Steps {
			stepInputs = append(stepInputs, toAddStepInput(tenantID, templateID, stepReq))
		}
		var err error
		steps, err = h.service.ReplaceSteps(pipelineAuditCtx(r), pipelinesvc.ReplaceStepsInput{
			TenantID:   tenantID,
			TemplateID: templateID,
			Steps:      stepInputs,
		})
		if err != nil {
			h.handleStepError(w, err)
			return
		}
	}

	input := pipelinesvc.UpdateTemplateInput{
		TenantID:        tenantID,
		TemplateID:      templateID,
		Name:            req.Name,
		Description:     req.Description,
		Triggers:        toTriggers(req.Triggers),
		Settings:        toSettings(req.Settings),
		Tags:            req.Tags,
		IsActive:        req.IsActive,
		UIStartPosition: toUIPosition(req.UIStartPosition),
		UIEndPosition:   toUIPosition(req.UIEndPosition),
	}

	template, err := h.service.UpdateTemplate(pipelineAuditCtx(r), input)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	if steps == nil {
		steps, _ = h.service.GetSteps(r.Context(), templateID)
	}
	template.Steps = steps

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(toTemplateResponse(template))
}

// writeGraphInvalid writes a refused workflow graph as 422 with every
// node- and edge-anchored issue in details; false when err is not one.
func writeGraphInvalid(w http.ResponseWriter, err error) bool {
	var ge *pipelinesvc.GraphInvalidError
	if !errors.As(err, &ge) {
		return false
	}
	apierror.ValidationFailed("The workflow is not valid", ge.Report).WriteJSON(w)
	return true
}

// ValidatePipelineRequest is a draft pipeline's steps.
type ValidatePipelineRequest struct {
	Steps []CreateStepRequest `json:"steps" validate:"max=50,dive"`
}

// PipelineGraphIssueResponse is one problem of a workflow graph, anchored to
// a node (step key) or an edge (from → to).
type PipelineGraphIssueResponse struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Node    string `json:"node,omitempty"`
	From    string `json:"from,omitempty"`
	To      string `json:"to,omitempty"`
	// Adapter is the capability that would connect an incompatible edge.
	Adapter string `json:"adapter,omitempty"`
}

// PipelineGraphValidationResponse is the outcome of a graph check. Errors
// refuse a save; warnings do not.
type PipelineGraphValidationResponse struct {
	Valid    bool                         `json:"valid"`
	Errors   []PipelineGraphIssueResponse `json:"errors"`
	Warnings []PipelineGraphIssueResponse `json:"warnings"`
}

// ValidatePipeline handles POST /api/v1/pipelines/verify
// @Summary      Validate a pipeline graph
// @Description  Checks a draft pipeline's steps as a save would (step keys, tools, settings, then the graph against the capability contracts: typed connections, cycles, missing steps, intrusive steps fed derived targets, size). Stores nothing.
// @Tags         Pipelines
// @Accept       json
// @Produce      json
// @Param        body  body      ValidatePipelineRequest  true  "Draft steps"
// @Success      200   {object}  PipelineGraphValidationResponse
// @Failure      400   {object}  apierror.Error
// @Security     BearerAuth
// @Router       /pipelines/verify [post]
func (h *PipelineHandler) ValidatePipeline(w http.ResponseWriter, r *http.Request) {
	var req ValidatePipelineRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}
	if err := h.validator.Validate(req); err != nil {
		h.handleValidationError(w, err)
		return
	}
	tenantID := middleware.GetTenantID(r.Context())
	inputs := make([]pipelinesvc.AddStepInput, 0, len(req.Steps))
	for _, st := range req.Steps {
		inputs = append(inputs, toAddStepInput(tenantID, "", st))
	}
	rep, err := h.service.ValidateGraph(r.Context(), pipelinesvc.ValidateGraphInput{TenantID: tenantID, Steps: inputs})
	if err != nil {
		h.handleStepError(w, err)
		return
	}
	out := PipelineGraphValidationResponse{
		Valid:    rep.Valid(),
		Errors:   make([]PipelineGraphIssueResponse, 0, len(rep.Errors)),
		Warnings: make([]PipelineGraphIssueResponse, 0, len(rep.Warnings)),
	}
	for _, is := range rep.Errors {
		out.Errors = append(out.Errors, toGraphIssueResponse(is))
	}
	for _, is := range rep.Warnings {
		out.Warnings = append(out.Warnings, toGraphIssueResponse(is))
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}

func toGraphIssueResponse(is stage.GraphIssue) PipelineGraphIssueResponse {
	return PipelineGraphIssueResponse{
		Code: is.Code, Message: is.Message, Node: is.Node,
		From: is.From, To: is.To, Adapter: string(is.Adapter),
	}
}

// toAddStepInput maps one step of a request to the service input.
func toAddStepInput(tenantID, templateID string, req CreateStepRequest) pipelinesvc.AddStepInput {
	in := pipelinesvc.AddStepInput{
		TenantID:          tenantID,
		TemplateID:        templateID,
		ID:                req.ID,
		StepKey:           req.StepKey,
		Name:              req.Name,
		Description:       req.Description,
		Order:             req.Order,
		Tool:              req.Tool,
		Capabilities:      req.Capabilities,
		Config:            req.Config,
		TimeoutSeconds:    req.TimeoutSeconds,
		DependsOn:         req.DependsOn,
		Condition:         toCondition(req.Condition),
		MaxRetries:        req.MaxRetries,
		RetryDelaySeconds: req.RetryDelaySeconds,
	}
	if req.UIPosition != nil {
		in.UIPositionX = &req.UIPosition.X
		in.UIPositionY = &req.UIPosition.Y
	}
	return in
}

// DeleteTemplate handles DELETE /api/v1/pipelines/templates/{id}
func (h *PipelineHandler) DeleteTemplate(w http.ResponseWriter, r *http.Request) {
	templateID := chi.URLParam(r, "id")
	tenantID := middleware.GetTenantID(r.Context())

	if err := h.service.DeleteTemplate(pipelineAuditCtx(r), tenantID, templateID); err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// ActivateTemplate handles POST /api/v1/pipelines/{id}/activate
func (h *PipelineHandler) ActivateTemplate(w http.ResponseWriter, r *http.Request) {
	templateID := chi.URLParam(r, "id")
	tenantID := middleware.GetTenantID(r.Context())

	isActive := true
	input := pipelinesvc.UpdateTemplateInput{
		TenantID:   tenantID,
		TemplateID: templateID,
		IsActive:   &isActive,
	}

	template, err := h.service.UpdateTemplate(pipelineAuditCtx(r), input)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(toTemplateResponse(template))
}

// DeactivateTemplate handles POST /api/v1/pipelines/{id}/deactivate
func (h *PipelineHandler) DeactivateTemplate(w http.ResponseWriter, r *http.Request) {
	templateID := chi.URLParam(r, "id")
	tenantID := middleware.GetTenantID(r.Context())

	isActive := false
	input := pipelinesvc.UpdateTemplateInput{
		TenantID:   tenantID,
		TemplateID: templateID,
		IsActive:   &isActive,
	}

	template, err := h.service.UpdateTemplate(pipelineAuditCtx(r), input)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(toTemplateResponse(template))
}

// CloneTemplateRequest represents the request body for cloning a template.
type CloneTemplateRequest struct {
	Name string `json:"name" validate:"required,min=1,max=255"`
}

// CloneTemplate handles POST /api/v1/pipelines/{id}/clone
func (h *PipelineHandler) CloneTemplate(w http.ResponseWriter, r *http.Request) {
	templateID := chi.URLParam(r, "id")
	tenantID := middleware.GetTenantID(r.Context())
	userID := middleware.GetUserID(r.Context())

	var req CloneTemplateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}

	if err := h.validator.Validate(req); err != nil {
		h.handleValidationError(w, err)
		return
	}

	input := pipelinesvc.CloneTemplateInput{
		TenantID:   tenantID,
		TemplateID: templateID,
		NewName:    req.Name,
		ClonedBy:   userID,
	}

	template, err := h.service.CloneTemplate(pipelineAuditCtx(r), input)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(toTemplateResponse(template))
}

// --- Step Handlers ---

// AddStep handles POST /api/v1/pipelines/templates/{id}/steps
func (h *PipelineHandler) AddStep(w http.ResponseWriter, r *http.Request) {
	templateID := chi.URLParam(r, "id")
	tenantID := middleware.GetTenantID(r.Context())

	var req CreateStepRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}

	if err := h.validator.Validate(req); err != nil {
		h.handleValidationError(w, err)
		return
	}

	input := pipelinesvc.AddStepInput{
		TenantID:          tenantID,
		TemplateID:        templateID,
		StepKey:           req.StepKey,
		Name:              req.Name,
		Description:       req.Description,
		Order:             req.Order,
		Tool:              req.Tool,
		Capabilities:      req.Capabilities,
		Config:            req.Config,
		TimeoutSeconds:    req.TimeoutSeconds,
		DependsOn:         req.DependsOn,
		Condition:         toCondition(req.Condition),
		MaxRetries:        req.MaxRetries,
		RetryDelaySeconds: req.RetryDelaySeconds,
	}
	if req.UIPosition != nil {
		input.UIPositionX = &req.UIPosition.X
		input.UIPositionY = &req.UIPosition.Y
	}

	step, err := h.service.AddStep(pipelineAuditCtx(r), input)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(toStepResponse(step))
}

// UpdateStepRequest represents the request body for updating a step.
type UpdateStepRequest struct {
	Name              string                 `json:"name" validate:"omitempty,min=1,max=255"`
	Description       string                 `json:"description" validate:"max=1000"`
	Order             int                    `json:"order"`
	UIPosition        *UIPositionRequest     `json:"ui_position"`
	Tool              string                 `json:"tool" validate:"max=100"`
	Capabilities      []string               `json:"capabilities" validate:"max=10,dive,max=50"`
	Config            map[string]interface{} `json:"config"`
	TimeoutSeconds    int                    `json:"timeout_seconds"`
	DependsOn         []string               `json:"depends_on" validate:"max=20,dive,max=50"`
	Condition         *StepConditionRequest  `json:"condition"`
	MaxRetries        int                    `json:"max_retries"`
	RetryDelaySeconds int                    `json:"retry_delay_seconds"`
}

// UpdateStep handles PUT /api/v1/pipelines/templates/{id}/steps/{stepId}
func (h *PipelineHandler) UpdateStep(w http.ResponseWriter, r *http.Request) {
	stepID := chi.URLParam(r, "stepId")
	tenantID := middleware.GetTenantID(r.Context())
	templateID := chi.URLParam(r, "id")

	var req UpdateStepRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}

	if err := h.validator.Validate(req); err != nil {
		h.handleValidationError(w, err)
		return
	}

	input := pipelinesvc.AddStepInput{
		TenantID:          tenantID,
		TemplateID:        templateID,
		Name:              req.Name,
		Description:       req.Description,
		Order:             req.Order,
		Tool:              req.Tool,
		Capabilities:      req.Capabilities,
		Config:            req.Config,
		TimeoutSeconds:    req.TimeoutSeconds,
		DependsOn:         req.DependsOn,
		Condition:         toCondition(req.Condition),
		MaxRetries:        req.MaxRetries,
		RetryDelaySeconds: req.RetryDelaySeconds,
	}
	if req.UIPosition != nil {
		input.UIPositionX = &req.UIPosition.X
		input.UIPositionY = &req.UIPosition.Y
	}

	// Security: verify the template belongs to the tenant before mutating a
	// step under it. UpdateStep resolves the step by raw ID, so without this
	// guard a caller could modify another tenant's step (IDOR). Mirrors
	// DeleteStep below.
	if _, err := h.service.GetTemplate(r.Context(), tenantID, templateID); err != nil {
		h.handleServiceError(w, err)
		return
	}

	step, err := h.service.UpdateStep(pipelineAuditCtx(r), stepID, input)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(toStepResponse(step))
}

// DeleteStep handles DELETE /api/v1/pipelines/templates/{id}/steps/{stepId}
func (h *PipelineHandler) DeleteStep(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.GetTenantID(r.Context())
	templateID := chi.URLParam(r, "id")
	stepID := chi.URLParam(r, "stepId")

	// Security: First verify template belongs to tenant
	_, err := h.service.GetTemplate(r.Context(), tenantID, templateID)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	if err := h.service.DeleteStep(pipelineAuditCtx(r), tenantID, stepID); err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// --- Run Handlers ---

// TriggerRun handles POST /api/v1/pipelines/runs
func (h *PipelineHandler) TriggerRun(w http.ResponseWriter, r *http.Request) {
	var req TriggerRunRequest
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

	input := pipelinesvc.TriggerPipelineInput{
		TenantID:    tenantID,
		TemplateID:  req.TemplateID,
		AssetID:     req.AssetID,
		TriggerType: req.TriggerType,
		TriggeredBy: userID,
		Context:     req.Context,
	}

	run, err := h.service.TriggerPipeline(pipelineAuditCtx(r), input)
	if err != nil {
		// A refused asset_id (unknown, deleted, another tenant's, or out of
		// the caller's data scope) gets one generic answer.
		if errors.Is(err, pipelinesvc.ErrRunAssetNotFound) {
			apierror.NotFound("Asset").WriteJSON(w)
			return
		}
		h.handleServiceError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(toRunResponse(run))
}

// GetRun handles GET /api/v1/pipelines/runs/{id}
func (h *PipelineHandler) GetRun(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.GetTenantID(r.Context())
	runID := chi.URLParam(r, "id")

	// Read by the caller's tenant: another tenant's run is not found.
	run, err := h.service.GetRunWithStepsForTenant(r.Context(), tenantID, runID)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	resp := toRunResponse(run)
	tasks, err := h.service.GetRunTasks(r.Context(), run)
	if err != nil {
		h.logger.Error("failed to read run tasks", "run_id", run.ID.String(), "error", err)
		apierror.InternalServerError("failed to read the run's tasks").WriteJSON(w)
		return
	}
	if tasks != nil {
		resp.TaskSummary = toRunTaskSummaryResponse(tasks.Summary)
		resp.Tasks = toRunTaskResponses(tasks.Items)
		resp.TasksTruncated = tasks.Truncated
		resp.TasksNextCursor = tasks.NextCursor
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// ListRuns handles GET /api/v1/pipelines/runs
func (h *PipelineHandler) ListRuns(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.GetTenantID(r.Context())

	input := pipelinesvc.ListRunsInput{
		TenantID:   tenantID,
		PipelineID: r.URL.Query().Get("pipeline_id"),
		AssetID:    r.URL.Query().Get("asset_id"),
		Status:     r.URL.Query().Get("status"),
		Sort:       r.URL.Query().Get("sort"),
		Page:       parseQueryInt(r.URL.Query().Get("page"), 1),
		PerPage:    parseQueryIntBounded(r.URL.Query().Get("per_page"), 20, 1, MaxPerPage),
	}

	result, err := h.service.ListRuns(r.Context(), input)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	summaries, err := h.service.RunTaskSummaries(r.Context(), tenantID, result.Data)
	if err != nil {
		h.logger.Error("failed to summarize run tasks", "error", err)
		apierror.InternalServerError("failed to read the runs' tasks").WriteJSON(w)
		return
	}
	scanNames, err := h.service.RunScanNames(r.Context(), tenantID, result.Data)
	if err != nil {
		h.logger.Error("failed to name run scans", "error", err)
		apierror.InternalServerError("failed to read the runs' scans").WriteJSON(w)
		return
	}
	items := make([]*RunResponse, len(result.Data))
	for i, run := range result.Data {
		items[i] = toRunResponse(run)
		if sum, ok := summaries[run.ID]; ok {
			items[i].TaskSummary = toRunTaskSummaryResponse(sum)
		}
		if run.ScanID != nil {
			items[i].ScanName = scanNames[*run.ScanID]
		}
	}

	resp := map[string]interface{}{
		"items":       items,
		"total":       result.Total,
		"page":        result.Page,
		"per_page":    result.PerPage,
		"total_pages": result.TotalPages,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// ListRunTasks handles GET /api/v1/pipeline-runs/{id}/tasks
// @Summary      List a run's tasks
// @Description  One page of the run's tasks (one dispatched command each) in dispatch order. Page with next_cursor. Targets are counted, not listed.
// @Tags         Pipelines
// @Produce      json
// @Param        id        path      string  true   "Run ID"
// @Param        cursor    query     string  false  "next_cursor of the previous page"
// @Param        per_page  query     int     false  "Tasks per page (1-200)" default(50)
// @Success      200  {object}  RunTaskPageResponse
// @Failure      400  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /pipeline-runs/{id}/tasks [get]
func (h *PipelineHandler) ListRunTasks(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.GetTenantID(r.Context())
	runID := chi.URLParam(r, "id")
	q := r.URL.Query()

	perPage := 0
	if raw := q.Get("per_page"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil {
			apierror.BadRequest("per_page must be a number").WriteJSON(w)
			return
		}
		perPage = n
		if perPage == 0 {
			perPage = -1 // explicit 0 is out of range, not "default"
		}
	}

	page, err := h.service.ListRunTasksPage(r.Context(), tenantID, runID, q.Get("cursor"), perPage)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}
	resp := RunTaskPageResponse{Data: toRunTaskResponses(page.Items), NextCursor: page.NextCursor}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// CancelRun handles POST /api/v1/pipelines/runs/{id}/cancel
func (h *PipelineHandler) CancelRun(w http.ResponseWriter, r *http.Request) {
	runID := chi.URLParam(r, "id")
	tenantID := middleware.GetTenantID(r.Context())

	if err := h.service.CancelRun(pipelineAuditCtx(r), tenantID, runID); err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// --- Conversion Helpers ---

func toTriggers(triggers []TriggerRequest) []pipeline.Trigger {
	result := make([]pipeline.Trigger, len(triggers))
	for i, t := range triggers {
		result[i] = pipeline.Trigger{
			Type:     pipeline.TriggerType(t.Type),
			Schedule: t.Schedule,
			Webhook:  t.Webhook,
			Filters:  t.Filters,
		}
	}
	return result
}

func toSettings(settings *PipelineSettingsRequest) *pipeline.Settings {
	if settings == nil {
		return nil
	}
	s := &pipeline.Settings{
		MaxParallelSteps:     settings.MaxParallelSteps,
		FailFast:             settings.FailFast,
		RetryFailedSteps:     settings.RetryFailedSteps,
		TimeoutSeconds:       settings.TimeoutSeconds,
		NotifyOnComplete:     settings.NotifyOnComplete,
		NotifyOnFailure:      settings.NotifyOnFailure,
		NotificationChannels: settings.NotificationChannels,
	}
	if settings.SensorPreference != "" {
		s.SensorPreference = pipeline.SensorPreference(settings.SensorPreference)
	}
	return s
}

func toCondition(cond *StepConditionRequest) *pipeline.Condition {
	if cond == nil {
		return nil
	}
	return &pipeline.Condition{
		Type:  pipeline.ConditionType(cond.Type),
		Value: cond.Value,
	}
}

func toUIPosition(pos *UIPositionRequest) *pipeline.UIPosition {
	if pos == nil {
		return nil
	}
	return &pipeline.UIPosition{
		X: pos.X,
		Y: pos.Y,
	}
}

func toTemplateResponse(t *pipeline.Template) *TemplateResponse {
	triggers := make([]TriggerResponse, len(t.Triggers))
	for i, tr := range t.Triggers {
		triggers[i] = TriggerResponse{
			Type:     string(tr.Type),
			Schedule: tr.Schedule,
			Webhook:  tr.Webhook,
			Filters:  tr.Filters,
		}
	}

	steps := make([]StepResponse, len(t.Steps))
	for i, s := range t.Steps {
		steps[i] = *toStepResponse(s)
	}

	resp := &TemplateResponse{
		ID:               t.ID.String(),
		TenantID:         t.TenantID.String(),
		Name:             t.Name,
		Description:      t.Description,
		Version:          t.Version,
		IsActive:         t.IsActive,
		IsSystemTemplate: t.IsSystemTemplate,
		Triggers:         triggers,
		Settings: PipelineSettingsResponse{
			MaxParallelSteps:     t.Settings.MaxParallelSteps,
			FailFast:             t.Settings.FailFast,
			RetryFailedSteps:     t.Settings.RetryFailedSteps,
			TimeoutSeconds:       t.Settings.TimeoutSeconds,
			NotifyOnComplete:     t.Settings.NotifyOnComplete,
			NotifyOnFailure:      t.Settings.NotifyOnFailure,
			NotificationChannels: t.Settings.NotificationChannels,
			SensorPreference:     string(t.Settings.SensorPreference),
		},
		Tags:      t.Tags,
		Steps:     steps,
		CreatedAt: t.CreatedAt.Format("2006-01-02T15:04:05Z07:00"),
		UpdatedAt: t.UpdatedAt.Format("2006-01-02T15:04:05Z07:00"),
	}

	// Add UI positions for visual builder
	if t.UIStartPosition != nil {
		resp.UIStartPosition = &UIPositionResponse{X: t.UIStartPosition.X, Y: t.UIStartPosition.Y}
	}
	if t.UIEndPosition != nil {
		resp.UIEndPosition = &UIPositionResponse{X: t.UIEndPosition.X, Y: t.UIEndPosition.Y}
	}

	return resp
}

func toStepResponse(s *pipeline.Step) *StepResponse {
	resp := &StepResponse{
		ID:          s.ID.String(),
		StepKey:     s.StepKey,
		Name:        s.Name,
		Description: s.Description,
		Order:       s.StepOrder,
		UIPosition: UIPositionResponse{
			X: s.UIPosition.X,
			Y: s.UIPosition.Y,
		},
		Tool:              s.Tool,
		Capabilities:      s.Capabilities,
		Config:            s.Config,
		TimeoutSeconds:    s.TimeoutSeconds,
		DependsOn:         s.DependsOn,
		MaxRetries:        s.MaxRetries,
		RetryDelaySeconds: s.RetryDelaySeconds,
	}

	if s.Condition.Type != "" {
		resp.Condition = &StepConditionResponse{
			Type:  string(s.Condition.Type),
			Value: s.Condition.Value,
		}
	}

	return resp
}

func toRunResponse(r *pipeline.Run) *RunResponse {
	resp := &RunResponse{
		ID:             r.ID.String(),
		TenantID:       r.TenantID.String(),
		PipelineID:     r.PipelineID.String(),
		TriggerType:    string(r.TriggerType),
		TriggeredBy:    r.TriggeredBy,
		Status:         string(r.Status),
		TotalSteps:     r.TotalSteps,
		CompletedSteps: r.CompletedSteps,
		FailedSteps:    r.FailedSteps,
		SkippedSteps:   r.SkippedSteps,
		TotalFindings:  r.TotalFindings,
		ErrorMessage:   r.ErrorMessage,
		CreatedAt:      r.CreatedAt.Format("2006-01-02T15:04:05Z07:00"),
	}

	if r.AssetID != nil {
		aid := r.AssetID.String()
		resp.AssetID = &aid
	}

	if r.ScanID != nil {
		sid := r.ScanID.String()
		resp.ScanID = &sid
	}

	if r.ScanProfileID != nil {
		spid := r.ScanProfileID.String()
		resp.ScanProfileID = &spid
	}

	if r.ScheduledFor != nil {
		sf := r.ScheduledFor.Format("2006-01-02T15:04:05Z07:00")
		resp.ScheduledFor = &sf
	}
	if r.DeadlineAt != nil {
		d := r.DeadlineAt.Format("2006-01-02T15:04:05Z07:00")
		resp.DeadlineAt = &d
	}
	resp.UnfinishedTargetCount = r.UnfinishedTargetCount

	if r.QualityGateResult != nil {
		resp.QualityGateResult = r.QualityGateResult
	}

	if r.StartedAt != nil {
		ts := r.StartedAt.Format("2006-01-02T15:04:05Z07:00")
		resp.StartedAt = &ts
	}

	if r.CompletedAt != nil {
		ts := r.CompletedAt.Format("2006-01-02T15:04:05Z07:00")
		resp.CompletedAt = &ts
	}

	if len(r.StepRuns) > 0 {
		resp.StepRuns = make([]StepRunResponse, len(r.StepRuns))
		for i, sr := range r.StepRuns {
			resp.StepRuns[i] = toStepRunResponse(sr)
		}
	}

	// Extract filtering result from context if present
	if r.Context != nil {
		if filteringResult, ok := r.Context["filtering_result"]; ok {
			resp.FilteringResult = toFilteringResultResponse(filteringResult)
		}
		resp.Dispatch = toRunDispatchResponse(r.Context)
	}

	return resp
}

// toRunDispatchResponse reads the dispatch report the scan trigger stores in
// the run context. Values round-trip through JSON so the same code reads a
// freshly built context and one loaded from the database.
func toRunDispatchResponse(runContext map[string]any) *RunDispatchResponse {
	keys := []string{"resolved_target_count", "excluded_target_count", "dispatch_warnings", "uncovered_targets", "zone_routing", "sensor_routing"}
	present := map[string]any{}
	for _, k := range keys {
		if v, ok := runContext[k]; ok && v != nil {
			present[k] = v
		}
	}
	if len(present) == 0 {
		return nil
	}
	raw, err := json.Marshal(present)
	if err != nil {
		return nil
	}
	var in struct {
		Resolved  int                  `json:"resolved_target_count"`
		Excluded  int                  `json:"excluded_target_count"`
		Warnings  []string             `json:"dispatch_warnings"`
		Uncovered []RunUncoveredTarget `json:"uncovered_targets"`
		Routing   *RunZoneRouting      `json:"zone_routing"`
		Sensor    string               `json:"sensor_routing"`
	}
	if err := json.Unmarshal(raw, &in); err != nil {
		return nil
	}
	return &RunDispatchResponse{
		ResolvedTargets:  in.Resolved,
		ExcludedTargets:  in.Excluded,
		Warnings:         in.Warnings,
		UncoveredTargets: in.Uncovered,
		ZoneRouting:      in.Routing,
		SensorRouting:    in.Sensor,
	}
}

// toFilteringResultResponse converts filtering result from context to response type.
func toFilteringResultResponse(result any) *FilteringResultResponse {
	if result == nil {
		return nil
	}

	// Type assertion - FilteringResult may come from scan package
	// We handle both map[string]any (from JSON) and direct struct
	switch v := result.(type) {
	case map[string]any:
		resp := &FilteringResultResponse{}
		if total, ok := v["total_assets"].(int); ok {
			resp.TotalAssets = total
		}
		if scanned, ok := v["scanned_assets"].(int); ok {
			resp.ScannedAssets = scanned
		}
		if skipped, ok := v["skipped_assets"].(int); ok {
			resp.SkippedAssets = skipped
		}
		if unclassified, ok := v["unclassified_assets"].(int); ok {
			resp.UnclassifiedAssets = unclassified
		}
		if pct, ok := v["compatibility_percent"].(float64); ok {
			resp.CompatibilityPercent = pct
		}
		if filtered, ok := v["was_filtered"].(bool); ok {
			resp.WasFiltered = filtered
		}
		if toolName, ok := v["tool_name"].(string); ok {
			resp.ToolName = toolName
		}
		if targets, ok := v["supported_targets"].([]string); ok {
			resp.SupportedTargets = targets
		}
		if scannedByType, ok := v["scanned_by_type"].(map[string]int); ok {
			resp.ScannedByType = scannedByType
		}
		if skippedByType, ok := v["skipped_by_type"].(map[string]int); ok {
			resp.SkippedByType = skippedByType
		}
		return resp

	default:
		// Try to access fields directly if it's a struct with exported fields
		// This handles the case where FilteringResult struct is passed directly
		return toFilteringResultFromStruct(v)
	}
}

// toFilteringResultFromStruct converts a struct to FilteringResultResponse.
func toFilteringResultFromStruct(v any) *FilteringResultResponse {
	if v == nil {
		return nil
	}

	// Handle the actual FilteringResult type from scan service
	if fr, ok := v.(*scansvc.FilteringResult); ok && fr != nil {
		resp := &FilteringResultResponse{
			TotalAssets:          fr.TotalAssets,
			ScannedAssets:        fr.ScannedAssets,
			SkippedAssets:        fr.SkippedAssets,
			UnclassifiedAssets:   fr.UnclassifiedAssets,
			CompatibilityPercent: fr.CompatibilityPercent,
			ScannedByType:        fr.ScannedByType,
			SkippedByType:        fr.SkippedByType,
			WasFiltered:          fr.WasFiltered,
			ToolName:             fr.ToolName,
			SupportedTargets:     fr.SupportedTargets,
		}

		// Convert skip reasons
		if len(fr.SkipReasons) > 0 {
			resp.SkipReasons = make([]SkipReasonResponse, len(fr.SkipReasons))
			for i, sr := range fr.SkipReasons {
				resp.SkipReasons[i] = SkipReasonResponse{
					AssetType: sr.AssetType,
					Count:     sr.Count,
					Reason:    sr.Reason,
				}
			}
		}

		return resp
	}

	// Return nil for unhandled types
	return nil
}

func toStepRunResponse(sr *pipeline.StepRun) StepRunResponse {
	resp := StepRunResponse{
		ID:            sr.ID.String(),
		StepKey:       sr.StepKey,
		StepName:      sr.StepName,
		Tool:          sr.Tool,
		Status:        string(sr.Status),
		ErrorMessage:  sr.ErrorMessage,
		ErrorCode:     sr.ErrorCode,
		Attempt:       sr.Attempt,
		MaxAttempts:   sr.MaxAttempts,
		FindingsCount: sr.FindingsCount,
	}
	if !sr.StepID.IsZero() {
		resp.StepID = sr.StepID.String()
	}

	if sr.StartedAt != nil {
		ts := sr.StartedAt.Format("2006-01-02T15:04:05Z07:00")
		resp.StartedAt = &ts
	}

	if sr.CompletedAt != nil {
		ts := sr.CompletedAt.Format("2006-01-02T15:04:05Z07:00")
		resp.CompletedAt = &ts
	}

	return resp
}

// handleValidationError converts validation errors to API errors.
func (h *PipelineHandler) handleValidationError(w http.ResponseWriter, err error) {
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
func (h *PipelineHandler) handleServiceError(w http.ResponseWriter, err error) {
	switch {
	case writeGraphInvalid(w, err):
	case errors.Is(err, pipeline.ErrPipelineRunActive):
		apierror.New(http.StatusConflict, apierror.Code(pipeline.ErrPipelineRunActive.Code), pipeline.ErrPipelineRunActive.Message).WriteJSON(w)
	case errors.Is(err, shared.ErrNotFound):
		apierror.NotFound("Pipeline").WriteJSON(w)
	case errors.Is(err, shared.ErrAlreadyExists):
		apierror.Conflict("Pipeline already exists").WriteJSON(w)
	case errors.Is(err, shared.ErrValidation):
		apierror.BadRequest(err.Error()).WriteJSON(w)
	case errors.Is(err, shared.ErrUnauthorized):
		apierror.Unauthorized("").WriteJSON(w)
	case errors.Is(err, shared.ErrForbidden):
		apierror.Forbidden("").WriteJSON(w)
	default:
		h.logger.Error("service error", "error", err)
		apierror.InternalError(err).WriteJSON(w)
	}
}

// handleStepError converts step-related service errors to API errors.
func (h *PipelineHandler) handleStepError(w http.ResponseWriter, err error) {
	switch {
	case writeGraphInvalid(w, err):
	case errors.Is(err, pipeline.ErrPipelineRunActive):
		apierror.New(http.StatusConflict, apierror.Code(pipeline.ErrPipelineRunActive.Code), pipeline.ErrPipelineRunActive.Message).WriteJSON(w)
	case errors.Is(err, shared.ErrNotFound):
		apierror.NotFound("Step").WriteJSON(w)
	case errors.Is(err, shared.ErrAlreadyExists):
		apierror.Conflict("Step with this key already exists in the pipeline").WriteJSON(w)
	case errors.Is(err, shared.ErrValidation):
		apierror.BadRequest(err.Error()).WriteJSON(w)
	case errors.Is(err, shared.ErrUnauthorized):
		apierror.Unauthorized("").WriteJSON(w)
	case errors.Is(err, shared.ErrForbidden):
		apierror.Forbidden("").WriteJSON(w)
	default:
		h.logger.Error("step service error", "error", err)
		apierror.InternalError(err).WriteJSON(w)
	}
}

// pipelineAuditCtx is the request context carrying the caller as the pipeline
// service's audit actor (see pipelinesvc.WithAuditActor).
func pipelineAuditCtx(r *http.Request) context.Context {
	return pipelinesvc.WithAuditActor(r.Context(), middleware.GetUserID(r.Context()))
}
